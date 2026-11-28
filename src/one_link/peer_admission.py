"""Admission policy for peers that hold no standing with this daemon.

A peer has *standing* when the owner pinned it, or when it holds a signed
capability grant that chains back to this daemon.  Every other authenticated
peer is a stranger: it proved possession of an Ed25519 key and nothing else,
and a fresh key costs nothing to mint.

Everything a stranger can make this daemon do is bounded here, in one place:

* how large a frame it may send (:func:`inbound_frame_ceiling`),
* how many frames and bytes it may send (:class:`StrangerBudget`),
* how many owner-facing prompts all strangers together may raise
  (:class:`PromptBudget`),
* how much per-peer bookkeeping it may leave behind (:class:`BoundedDict`),
* which message types are reachable without standing (:data:`MESSAGE_GATES`).

A stranger's frames are still dispatched, so each handler answers with its
own refusal; they are simply charged against that stranger's budget.

The dispatcher keeps its per-handler capability checks, because a grant is
scoped to one capability and only the handler knows which one applies.
:data:`MESSAGE_GATES` is the declared contract those checks are tested
against: ``tests/test_peer_admission.py`` parses the dispatcher and fails when
a message type is missing from the table, or when a type declared
:attr:`Gate.STANDING` reaches no trust check.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from enum import Enum
from typing import Any, Callable, Generic, Hashable, Iterable, Optional, TypeVar

from one_link.env_bounds import env_int
from one_link.wire import MAX_FRAME, UNPINNED_MAX_FRAME

log = logging.getLogger(__name__)

# Anyone who completes a handshake gets a pending peer row. Pending rows that
# carry no history are pruned beyond this count, least recently seen first.
MAX_PENDING_PEERS = env_int("ONE_LINK_MAX_PENDING_PEERS", 256, minimum=16, maximum=65_536)
# In-memory per-peer bookkeeping is keyed by a fingerprint the remote party
# chooses, so every such map is bounded and forgets its oldest entry first.
PEER_BOOKKEEPING_MAX = 4_096
# A trusted peer's standing is re-read at most this often per channel. A peer
# without standing is re-checked on every frame so pairing takes effect at once.
STANDING_RECHECK_S = 2.0

K = TypeVar("K", bound=Hashable)
V = TypeVar("V")


class Gate(Enum):
    """What a peer needs before a message type does any work."""

    #: Channel preface, liveness and pairing.  Reachable by any authenticated
    #: peer by design; the effect is confined to that peer's own records.
    OPEN = "open"
    #: The frame carries its own proof (a bearer token, a signed grant, a
    #: signed rotation certificate) and the handler verifies it.
    PROOF = "proof"
    #: The handler must consult pinned trust or a capability grant.
    STANDING = "standing"
    #: The branch only unpacks inner frames and feeds each one back through
    #: the dispatcher, where the inner type's own gate applies.
    REDISPATCH = "redispatch"
    #: Routed whole to ``call_lifecycle.CallLifecycleService``, which owns the
    #: trust, capability and provisional-admission checks for the call plane.
    CALL_PLANE = "call_plane"


MESSAGE_GATES: dict[str, Gate] = {
    # Channel preface and liveness.
    "CAPS": Gate.OPEN,
    "PRESENCE": Gate.OPEN,
    "PING": Gate.OPEN,
    # Pairing is how a stranger gains standing, so it cannot require any.
    "PAIR_REQUEST": Gate.OPEN,
    "PAIR_CONFIRM": Gate.OPEN,
    "PAIR_REJECT": Gate.OPEN,
    # Bound to a transfer this same peer already owns.
    "FILE_ABORT": Gate.OPEN,
    # Advisory about a transfer this daemon is sending to that peer.
    "BLOOM_INIT_FILTER": Gate.OPEN,
    # Self-authenticating frames.
    "SHARE_LINK_REDEEM": Gate.PROOF,
    "ROTATION_CERT": Gate.PROOF,
    "ROTATION_CERT_ACK": Gate.PROOF,
    # Unpacks to FILE_OFFER frames.
    "FILE_OFFER_BATCH": Gate.REDISPATCH,
    # Everything else needs pinned trust or a grant.
    "CAPABILITY_GRANT": Gate.STANDING,
    "SELF_MESH_PRESENCE": Gate.STANDING,
    "SELF_MESH_REMOTE_INSTRUCTION": Gate.STANDING,
    "TEXT": Gate.STANDING,
    "FILE_OFFER": Gate.STANDING,
    "FILE_CHUNK": Gate.STANDING,
    "FILE_BIN_CHUNK": Gate.STANDING,
    "FILE_NATIVE_CHUNK": Gate.STANDING,
    "FILE_CDC_CHUNK": Gate.STANDING,
    "FILE_PROVENANCE": Gate.STANDING,
    "CHUNK_QUERY": Gate.STANDING,
    "CHUNK_PULL": Gate.STANDING,
    "GROUP_EVENT": Gate.STANDING,
    "GROUP_KEY_OFFER": Gate.STANDING,
    "GROUP_MSG": Gate.STANDING,
    "GROUP_TYPING": Gate.STANDING,
    "ENDPOINT_UPDATE": Gate.STANDING,
    "REACTION": Gate.STANDING,
    "EDIT_MSG": Gate.STANDING,
    "DELETE_MSG": Gate.STANDING,
    "TYPING": Gate.STANDING,
    "READ_MARKER": Gate.STANDING,
    "MANIFEST_PUSH": Gate.STANDING,
    "MANIFEST_WANTS": Gate.STANDING,
    "FOLDER_SYNC_VERIFY": Gate.STANDING,
    "FOLDER_SYNC_COMMIT": Gate.STANDING,
    "BLOB_OFFER": Gate.STANDING,
    "BLOB_CHUNK": Gate.STANDING,
    "BLOB_REQUEST": Gate.STANDING,
    "FOLDER_OFFER_DECLINED": Gate.STANDING,
    "FOLDER_OFFER_ACCEPTED": Gate.STANDING,
    "BLOB_INVENTORY_QUERY": Gate.STANDING,
    "COVER_PACKET": Gate.STANDING,
    "PEER_VERIFY_NOTICE": Gate.STANDING,
    # Calls, recordings and voice capsules.
    "CALL_INVITE": Gate.CALL_PLANE,
    "CALL_ACCEPT": Gate.CALL_PLANE,
    "CALL_DECLINE": Gate.CALL_PLANE,
    "CALL_END": Gate.CALL_PLANE,
    "CALL_RESUME_OFFER": Gate.CALL_PLANE,
    "CALL_ICE": Gate.CALL_PLANE,
    "CALL_SDP_OFFER": Gate.CALL_PLANE,
    "CALL_SDP_ANSWER": Gate.CALL_PLANE,
    "CALL_FRAME_ATTEST": Gate.CALL_PLANE,
    "RECORDING_REQUEST": Gate.CALL_PLANE,
    "RECORDING_GRANT": Gate.CALL_PLANE,
    "RECORDING_DECLINE": Gate.CALL_PLANE,
    "RECORDING_STOP": Gate.CALL_PLANE,
    "CAPSULE_OFFER": Gate.CALL_PLANE,
    "CAPSULE_CHUNK": Gate.CALL_PLANE,
    "CAPSULE_COMPLETE": Gate.CALL_PLANE,
    "CAPSULE_RECEIPT": Gate.CALL_PLANE,
}


def inbound_frame_ceiling(has_standing: bool) -> int:
    """Largest frame this daemon will buffer and parse for a peer."""

    return MAX_FRAME if has_standing else UNPINNED_MAX_FRAME


class BoundedDict(OrderedDict, Generic[K, V]):
    """A dict that forgets its oldest entry instead of growing without limit.

    Used for per-peer bookkeeping keyed by a fingerprint that a remote party
    chooses.  Writing a key makes it the youngest entry; reads do not reorder,
    so a lookup-heavy hot path pays nothing extra.
    """

    def __init__(self, maxlen: int) -> None:
        if maxlen < 1:
            raise ValueError("maxlen must be at least 1")
        super().__init__()
        self.maxlen = maxlen

    def __setitem__(self, key: K, value: V) -> None:
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.maxlen:
            self.popitem(last=False)


class _TokenBucket:
    """Token bucket on a monotonic clock."""

    __slots__ = ("_capacity", "_clock", "_refill_per_s", "_stamp", "_tokens")

    def __init__(
        self,
        capacity: float,
        refill_per_s: float,
        clock: Callable[[], float],
    ) -> None:
        self._capacity = float(capacity)
        self._refill_per_s = float(refill_per_s)
        self._clock = clock
        self._tokens = float(capacity)
        self._stamp = clock()

    def take(self, amount: float = 1.0) -> bool:
        now = self._clock()
        elapsed = now - self._stamp
        if elapsed > 0:
            self._tokens = min(
                self._capacity, self._tokens + elapsed * self._refill_per_s
            )
            self._stamp = now
        if amount > self._tokens:
            return False
        self._tokens -= amount
        return True


#: A stranger may send this many frames at once, then this many per second.
STRANGER_FRAME_BURST = 128
STRANGER_FRAMES_PER_S = 2.0
#: A stranger may send this many bytes at once, then this many per second.
STRANGER_BYTE_BURST = 2 * 1024 * 1024
STRANGER_BYTES_PER_S = 64 * 1024


class StrangerBudget:
    """Per-connection allowance for a peer without standing.

    Pairing, presence and keep-alives fit inside the burst many times over.
    A connection that exhausts the allowance is closed by the caller; the
    peer may reconnect, where the handshake limiter and the connection caps
    apply again.
    """

    __slots__ = ("_bytes", "_frames")

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._frames = _TokenBucket(STRANGER_FRAME_BURST, STRANGER_FRAMES_PER_S, clock)
        self._bytes = _TokenBucket(STRANGER_BYTE_BURST, STRANGER_BYTES_PER_S, clock)

    def admit(self, frame_bytes: int) -> bool:
        """Charge one frame.  ``False`` means the allowance is spent."""

        return self._frames.take(1.0) and self._bytes.take(float(frame_bytes))


#: All strangers together may raise this many owner-facing prompts at once,
#: then one more every ``PROMPT_REFILL_S`` seconds.
PROMPT_BURST = 16
PROMPT_REFILL_S = 10.0


class PromptBudget:
    """Daemon-wide allowance for prompts raised by peers without standing.

    A per-peer limit does not help when every prompt comes from a different
    throwaway identity.  This budget is shared by all strangers, so the owner
    sees a bounded number of pair requests and capability requests no matter
    how many identities ask.
    """

    __slots__ = ("_bucket",)

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._bucket = _TokenBucket(PROMPT_BURST, 1.0 / PROMPT_REFILL_S, clock)

    def admit(self) -> bool:
        return self._bucket.take(1.0)


def unique_pinned_match(needle: str, pinned: Iterable[Any]) -> Optional[str]:
    """Fingerprint of the one pinned peer ``needle`` names, else ``None``.

    Tried in order, and the first rule that matches anything decides:

    1. a whole name: fingerprint, short ID, hostname, alias or display name,
       compared without regard to case;
    2. a fingerprint prefix of at least 8 hex digits;
    3. part of a hostname, alias or display name ("computer" for
       "Computer 2").

    Whichever rule matches, the answer is a peer only when exactly one peer
    matches it. The old lookup returned whichever matching peer was seen
    last, so "al" could deliver to "malory"; a queued send must never guess
    its recipient.
    """
    lowered = needle.strip().lower()
    if not lowered:
        return None
    records = list(pinned)

    def labels(rec: Any) -> list[str]:
        return [
            value.lower()
            for value in (rec.hostname or "", rec.local_alias or "", rec.display_name)
            if value
        ]

    def whole(rec: Any) -> bool:
        return lowered in (rec.fingerprint, rec.short_id.lower(), *labels(rec))

    def fingerprint_prefix(rec: Any) -> bool:
        return rec.fingerprint.startswith(lowered)

    def part(rec: Any) -> bool:
        return any(lowered in label for label in labels(rec))

    rules = [whole]
    if len(lowered) >= 8 and all(c in "0123456789abcdef" for c in lowered):
        rules.append(fingerprint_prefix)
    rules.append(part)
    for rule in rules:
        matches = {rec.fingerprint for rec in records if rule(rec)}
        if len(matches) == 1:
            return matches.pop()
        if matches:
            log.warning(
                "peer name %r matches %d pinned peers; refusing to guess",
                needle[:32],
                len(matches),
            )
            return None
    return None


class PeerAdmission:
    """One daemon's decisions about peers that hold no standing.

    Kept outside ``Daemon`` on purpose: the daemon asks questions
    (``has_standing``, ``prompt_admitted``) and this object owns the answers
    and the state behind them.
    """

    def __init__(self, daemon: Any) -> None:
        self._daemon = daemon
        self._prompts = PromptBudget()

    def has_standing(self, peer_fp: str, peer_pub: bytes | None = None) -> bool:
        """True when the owner pinned this peer or a signed grant vouches for it.

        A grant counts when this daemon issued it or a pinned peer did; the
        per-capability decision stays with ``Daemon._capability_allowed``.
        Any lookup failure answers ``False``.
        """
        daemon = self._daemon
        state = daemon.state
        if state is None:
            return False
        try:
            rec = state.get_peer(peer_fp)
        except Exception:
            return False
        if rec is not None:
            if rec.trust == "pinned":
                return True
            if rec.trust == "rejected":
                return False
        store = getattr(daemon, "_cap_store", None)
        pub = peer_pub or (rec.pubkey if rec is not None else None)
        if store is None or not pub:
            return False
        try:
            from one_link.identity import fingerprint_of

            my_pub = daemon.me.public_bytes
            for grant in store.list_grants_for(subject_pub=bytes(pub)):
                granter = bytes(grant.granter_pub)
                if granter == my_pub or daemon._is_pinned(fingerprint_of(granter)):
                    return True
        except Exception:
            return False
        return False

    def bind_channel(self, channel: Any, peer_fp: str) -> Callable[[int], bool]:
        """Tie an authenticated channel to the peer's standing.

        Installs the channel's frame-ceiling policy, which the channel
        consults once per inbound frame after the length prefix arrives, so
        pinning or revoking a peer changes what its open connections may
        send without a reconnect.

        Returns ``admit(frame_bytes)`` for the connection's read loop. It
        answers ``True`` for a peer with standing, and charges a peer
        without standing against an allowance that pairing fits inside many
        times over; ``False`` means the allowance is spent and the caller
        should hang up.
        """
        standing = False
        checked_at = 0.0

        def ceiling() -> int:
            nonlocal standing, checked_at
            now = time.monotonic()
            if not standing or now - checked_at >= STANDING_RECHECK_S:
                standing = self.has_standing(peer_fp, channel.peer_ed_pub)
                checked_at = now
            return inbound_frame_ceiling(standing)

        channel.inbound_frame_policy = ceiling
        channel.max_inbound_frame = ceiling()
        budget = StrangerBudget()

        def admit(frame_bytes: int) -> bool:
            return channel.max_inbound_frame >= MAX_FRAME or budget.admit(frame_bytes)

        return admit

    def prune_pending_peers(self) -> None:
        """Forget surplus pending peers that never became anything."""
        daemon = self._daemon
        if daemon.state is None:
            return
        protect = set(daemon._inbound_live_channels)
        protect.update(daemon._outbound_sessions)
        try:
            removed = daemon.state.prune_pending_peers(keep=MAX_PENDING_PEERS, protect=protect)
        except Exception as exc:
            log.warning("pending peer prune failed: %s", exc)
            return
        if removed:
            log.info("pruned %d pending peers with no history", removed)

    def after_handshake(self, record: Any) -> None:
        """Called once a connecting peer's record has been written."""
        if record.trust == "pending":
            self.prune_pending_peers()

    async def refuse(self, channel: Any, msg: dict, reason: str) -> None:
        """Answer ``msg`` with an ACK that carries ``rejected=reason``."""
        from one_link.wire import encode_msg, make_msg

        await channel.send(
            encode_msg(
                make_msg("ACK", self._daemon.me.short_id, of=msg.get("id"), rejected=reason)
            )
        )

    def prompt_admitted(self, peer_fp: str) -> bool:
        """May this peer raise a prompt for the owner right now?

        A peer with standing always may. Every other peer draws on one
        allowance shared by all of them, so a crowd of throwaway identities
        cannot bury a real request or push a pairing the owner started out
        of the pairing table.
        """
        if self.has_standing(peer_fp) or self._prompts.admit():
            return True
        log.info("prompt allowance for unpaired peers is spent; refusing %s", peer_fp[:8])
        return False

    def pair_reject_allowed(self, peer_fp: str) -> bool:
        """Does a PAIR_REJECT from this peer mean anything?

        Only from a peer that is part of a pairing in progress or is already
        pinned. Anyone else would otherwise mint a permanent "rejected"
        record per throwaway key.
        """
        from one_link.pairing import PairState

        daemon = self._daemon
        ctx = daemon.pairing.get(peer_fp)
        if ctx is not None and ctx.state in (
            PairState.REQUESTED,
            PairState.INCOMING,
            PairState.CONFIRMED,
        ):
            return True
        return bool(daemon._is_pinned(peer_fp))


class PerDaemon:
    """Class attribute that gives each daemon its own :class:`PeerAdmission`.

    Built on first use and then stored on the instance, so a daemon created
    without running ``__init__`` (as many tests do) still gets one.
    """

    def __set_name__(self, owner: type, name: str) -> None:
        self._name = name

    def __get__(self, daemon: Any, owner: type | None = None) -> Any:
        if daemon is None:
            return self
        controller = PeerAdmission(daemon)
        daemon.__dict__[self._name] = controller
        return controller
