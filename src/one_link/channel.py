"""Encrypted bidirectional channel between two peers.

The live default is the version-3, mutually confirmed X25519 + ML-KEM-768
hybrid handshake. Ed25519 signatures bind the negotiated suite, identities,
ephemeral keys and transcript. Missing native support fails closed unless an
explicit migration policy permits classical operation. Browser WebRTC uses
its separate DTLS/DataChannel protocol; this channel's PQ claim does not apply
to that browser transport.

The following describes the retained classical migration protocol only:
    1. Initiator -> Responder
       HELLO = init_pub_ed25519 || init_pub_x25519 || nonce_init || sig_init
       sig_init signs: "OL1|HELLO|" + init_pub_ed25519 + init_pub_x25519 + nonce_init
    2. Responder -> Initiator
       REPLY = resp_pub_ed25519 || resp_pub_x25519 || nonce_resp || sig_resp
       sig_resp signs: "OL1|REPLY|" + nonce_init + resp_pub_ed25519 + resp_pub_x25519 + nonce_resp

After both sides verify the other's signature, they:
    shared = X25519(my_x25519_priv, peer_x25519_pub)
    salt   = nonce_init || nonce_resp
    transcript = SHA256(HELLO || REPLY)
    keys   = HKDF(shared, salt, info="OL1/keys|" + transcript, L=64)
    tx_key = keys[0:32]   # initiator -> responder
    rx_key = keys[32:64]  # responder -> initiator

Each side keeps a 64-bit send counter (starts at 0) used as the ChaCha20-Poly1305 nonce
(little-endian, padded to 12 bytes). AAD = "OL1/data|" + transcript.

v0.8.2 Double Ratchet activation
================================

The legacy mode above uses a STATIC tx/rx key pair for the lifetime
of the channel. v0.7.2 shipped an audited Signal-style Double Ratchet
primitive (one_link.double_ratchet); v0.8.2 wires it in.

Activation flow:
  1. Handshake completes as before. Channel stashes the X25519 ephemeral
     PRIVATE key and the peer's X25519 ephemeral PUBLIC key for ratchet
     bootstrap (these were previously discarded after key derivation).
  2. Both sides exchange CAPS frames (legacy-encrypted). Daemon notes
     `note_caps_sent()` after sending CAPS and `note_caps_received(features)`
     when CAPS arrives.
  3. When BOTH flags are set AND both feature lists contain
     DOUBLE_RATCHET_V1, `maybe_activate_ratchet(role)` initialises the
     ratchet state from the handshake bootstrap — and from that point
     forward every send/recv goes through the ratchet, providing forward
     secrecy + post-compromise security.

Cutover: the authenticated, transcript-bound CAPS frame is the final
legacy-AEAD frame in each direction.  Once that exact sequence boundary
is recorded, legacy ciphertext is never accepted again.  Alice can send
ratcheted application data immediately.  Bob's outbound calls queue behind
an event until his first authenticated Alice ratchet frame derives his send
chain; there is no guessed "legacy grace window" and no downgrade fallback.

Wire-format on the ratchet path:
    [length-prefix, unchanged] [42-byte Header.encode()] [ciphertext]

AAD = header.encode() || transcript_hash. Splicing a ratchet frame
across channels fails AEAD (different transcript_hash).

Backward compatibility: peers that don't advertise DOUBLE_RATCHET_V1
stay on legacy. The activation is symmetric — either both speak
ratchet or both stay legacy.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import logging
import os
import struct
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from one_link.double_ratchet import RatchetState
    from one_link.native_transfer import NativeTransferDuplexSession

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from one_link.capabilities import PQ_HYBRID_HANDSHAKE_V1
from one_link.identity import Identity, fingerprint_of, verify
from one_link.wire import read_frame, write_frame, write_frame_nowait

log = logging.getLogger(__name__)

# External audit 2026-05-18 ES-1: legacy v1 HELLO downgrade telemetry.
#
# A v1 HELLO is self-signed, so an unauthenticated remote can mint an
# unlimited number of valid keys.  Keying an ordinary dict by every claimed
# key therefore turns an observability feature into a memory-DoS primitive.
# Only identities which the daemon confirms are *currently pinned* receive a
# per-peer slot.  Unknown identities feed one saturating aggregate counter.
# The known-peer table is additionally TTL/LRU bounded in case a device has a
# very large or churn-heavy trust roster.
_V1_SIG_KNOWN_MAX_ENTRIES: int = 1024
_V1_SIG_KNOWN_TTL_S: float = 24.0 * 60.0 * 60.0
_V1_SIG_COUNTER_MAX: int = (1 << 63) - 1
_v1_sig_fallback_counts: "OrderedDict[bytes, tuple[int, float]]" = OrderedDict()
_v1_sig_unknown_attempts: int = 0
_v1_sig_known_attempts: int = 0
_v1_sig_known_evictions: int = 0
_v1_sig_telemetry_lock = threading.Lock()


def _saturating_increment(value: int) -> int:
    return value if value >= _V1_SIG_COUNTER_MAX else value + 1


def _prune_v1_sig_known_locked(now: float) -> None:
    """Expire stale known-peer telemetry while the caller holds the lock."""
    cutoff = now - _V1_SIG_KNOWN_TTL_S
    stale = [peer for peer, (_count, seen_at) in _v1_sig_fallback_counts.items() if seen_at <= cutoff]
    for peer in stale:
        _v1_sig_fallback_counts.pop(peer, None)


def _bump_v1_sig_counter(
    peer_ed_pub: bytes,
    *,
    is_pinned: bool,
    now: float | None = None,
) -> int:
    """Record one cryptographically valid legacy-v1 HELLO attempt.

    Per-key detail is retained only for a caller-confirmed pinned identity.
    Unknown/self-minted identities share a single fixed-memory counter.  The
    returned value is the relevant per-peer or aggregate count for logging.
    """
    if len(peer_ed_pub) != 32:
        raise ValueError("legacy-v1 telemetry key must be 32 bytes")
    observed_at = time.monotonic() if now is None else float(now)
    global _v1_sig_unknown_attempts, _v1_sig_known_attempts, _v1_sig_known_evictions
    with _v1_sig_telemetry_lock:
        if not is_pinned:
            _v1_sig_unknown_attempts = _saturating_increment(_v1_sig_unknown_attempts)
            return _v1_sig_unknown_attempts

        _prune_v1_sig_known_locked(observed_at)
        _v1_sig_known_attempts = _saturating_increment(_v1_sig_known_attempts)
        previous = _v1_sig_fallback_counts.pop(peer_ed_pub, (0, observed_at))[0]
        count = _saturating_increment(previous)
        # Reinsert at the tail: OrderedDict order is the deterministic LRU
        # order, independent of hash randomisation.
        _v1_sig_fallback_counts[peer_ed_pub] = (count, observed_at)
        while len(_v1_sig_fallback_counts) > _V1_SIG_KNOWN_MAX_ENTRIES:
            _v1_sig_fallback_counts.popitem(last=False)
            _v1_sig_known_evictions = _saturating_increment(_v1_sig_known_evictions)
        return count


def v1_sig_fallback_summary(*, now: float | None = None) -> dict[str, int]:
    """Return bounded legacy-v1 downgrade telemetry.

    Hex keys are pinned peer public-key prefixes.  Reserved keys begin with
    ``__`` and expose aggregate known/unknown attempts plus LRU eviction
    pressure. No untrusted public key is ever retained solely for telemetry.
    """
    observed_at = time.monotonic() if now is None else float(now)
    with _v1_sig_telemetry_lock:
        _prune_v1_sig_known_locked(observed_at)
        summary = {
            peer.hex()[:16]: count
            for peer, (count, _seen_at) in _v1_sig_fallback_counts.items()
        }
        summary["__unknown_attempts__"] = _v1_sig_unknown_attempts
        summary["__known_attempts__"] = _v1_sig_known_attempts
        summary["__known_evictions__"] = _v1_sig_known_evictions
        summary["__known_tracked__"] = len(_v1_sig_fallback_counts)
        return summary


# 2026-05-22 audit Batch V — handshake nonce replay cache.
#
# An attacker who captures one valid HELLO frame from a paired peer
# can re-mail it to the same responder N times. Each delivery forces
# a fresh Ed25519 verify + X25519 ephemeral + HKDF + sig_r emission
# — about 200 µs of unaccounted CPU per replay. Session keys end up
# different (responder picks fresh ``x_priv`` each call) so the
# attack is harmless to confidentiality, but it's a free CPU
# amplifier: one captured HELLO → unbounded crypto work.
#
# Defence: per-(peer_ed_pub, nonce_i) → first-seen-ts cache, 60 s
# window, bounded to 8 192 entries with FIFO eviction. A replay
# inside the window is rejected before any signature work.
#
# The cache is module-local and guarded explicitly so free-threaded Python and
# test/application threads cannot race the check-and-insert operation. Cleared
# between processes; per-process bounded; no persistence.
_HANDSHAKE_REPLAY_WINDOW_S: float = 60.0
_HANDSHAKE_REPLAY_MAX_ENTRIES: int = 8192
_handshake_replay_cache: "OrderedDict[tuple[bytes, bytes], float]" = OrderedDict()
_handshake_replay_lock = threading.Lock()


def _handshake_replay_seen(peer_ed_pub: bytes, nonce: bytes, now: float) -> bool:
    """Return True iff ``(peer_ed_pub, nonce)`` has been observed
    inside the current replay window. Inserts the entry as a side
    effect on first-seen. Bounded; FIFO-evicts when over the cap."""
    with _handshake_replay_lock:
        cache = _handshake_replay_cache
        cutoff = now - _HANDSHAKE_REPLAY_WINDOW_S
        # Drop expired entries cheaply — only those at the head are
        # candidates (insertion-ordered).
        while cache:
            oldest_k = next(iter(cache))
            if cache[oldest_k] >= cutoff:
                break
            cache.popitem(last=False)
        key = (peer_ed_pub, nonce)
        if key in cache:
            return True
        cache[key] = now
        if len(cache) > _HANDSHAKE_REPLAY_MAX_ENTRIES:
            # FIFO eviction — same audit-defense pattern as cap_store.
            with contextlib.suppress(KeyError):
                cache.popitem(last=False)
        return False


PROTO = b"OL1"
NONCE_LEN = 16
HELLO_TAG = b"OL1|HELLO|"
REPLY_TAG = b"OL1|REPLY|"
AAD_PREFIX = b"OL1/data|"
# Authenticated post-quantum channel handshake.  This is deliberately a new
# wire version, rather than overloading the fixed-length classical HELLO:
# peers either negotiate this exact suite or the connection fails.  A caller
# can enter the legacy handshake only through an explicit downgrade policy.
PQ_HANDSHAKE_MAGIC = b"OLPQ"
PQ_HANDSHAKE_VERSION = 3
PQ_SUITE_X25519_MLKEM768_V1 = 0x0001
PQ_HYBRID_HANDSHAKE_CAP = PQ_HYBRID_HANDSHAKE_V1
PQ_HELLO_TAG = b"OL1|PQ-HELLO|v3|"
PQ_REPLY_TAG = b"OL1|PQ-REPLY|v3|"
PQ_CONFIRM_TAG = b"OL1|PQ-CONFIRM|v3|"
PQ_CONFIRM_MAGIC = b"OLKC"
PQ_CHANNEL_SECRET_INFO = b"OL1/pq-hybrid/channel-secret|v3|"
PQ_CONFIRM_KEY_INFO = b"OL1/pq-hybrid/key-confirm|v3|"
PQ_MAX_OFFERED_SUITES = 8
PQ_KEM_PUBLIC_KEY_LEN = 1216
PQ_KEM_CIPHERTEXT_LEN = 1120
# v0.8.2: capability tag both peers must advertise to enable ratchet.
DR_CAP = "double_ratchet_v1"
# Extension that makes the Alice-first Double Ratchet bootstrap explicit and
# deadlock-free without changing v1 behavior for older peers.
DR_CUTOVER_CAP = "double_ratchet_cutover_v2"
DR_CUTOVER_COMMIT_PREFIX = b"\x00OL1|DR-CUTOVER-COMMIT|v2|"
# Phase C-3 (ADR-0026): capability tag both peers must advertise to
# enable the native chunk-store transport (FILE_NATIVE_CHUNK messages).
# Keep in sync with `capabilities.NATIVE_TRANSFER_INDEXED_V1`.
NATIVE_TRANSFER_CAP = "native_transfer_indexed_v1"
# v0.8.2: HKDF info label for the ratchet-bootstrap root key. Distinct
# from the legacy session-key derivation so the two are independent;
# even if the legacy AEAD keys leak, they don't reveal the ratchet
# root_key (and vice versa).
DR_ROOT_INFO = b"OL1/dr/root_seed|"
DR_HEADER_LEN = 42  # Header.encode() output length


@dataclass
class Channel:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    peer_ed_pub: bytes
    peer_short_id: str
    tx_aead: ChaCha20Poly1305
    rx_aead: ChaCha20Poly1305
    tx_seq: int = 0
    rx_seq: int = 0
    transcript_hash: bytes = b""
    # Cryptographically established handshake posture.  These fields report
    # what protected this exact channel, never what a module merely supports.
    handshake_version: int = 2
    handshake_suite: str = "x25519-classical-v2"
    pq_protected: bool = False
    key_confirmed: bool = False
    # Set after CAPS exchange (post-handshake first encrypted message).
    # None = peer hasn't sent CAPS yet (legacy or pre-CAPS).
    peer_caps: dict | None = None

    # v0.8.2: Double Ratchet bootstrap material — kept alive
    # post-handshake so we can activate the ratchet later if both
    # peers advertise DOUBLE_RATCHET_V1. Set by initiate / respond.
    _dr_role: Optional[str] = None  # "alice" | "bob"
    _dr_x_priv: Optional[X25519PrivateKey] = None
    _dr_peer_x_pub: Optional[bytes] = None
    _dr_shared: Optional[bytes] = None  # raw 32-byte ECDH output
    # Activation tracking. Both must be True before we attempt to
    # negotiate the ratchet. _peer_dr_capable is the latest known
    # state of the peer's DOUBLE_RATCHET_V1 advertisement.
    _caps_sent: bool = False
    _caps_received: bool = False
    _peer_dr_capable: bool = False
    _peer_dr_cutover_capable: bool = False
    # Phase C-3 (ADR-0026): native transfer capability tracking.
    # True iff the peer's CAPS frame included NATIVE_TRANSFER_V1.
    # Independent of ratchet status — the native pipeline derives
    # its own session secret from the DR-bootstrap material via
    # `derive_native_transfer_secret`, so we don't gate on DR
    # activation.
    _peer_native_transfer_capable: bool = False
    # Pre-derived 32-byte native-transfer seed. Cached at handshake
    # completion (or just before clearing _dr_shared in
    # maybe_activate_ratchet) so that derive_native_transfer_secret
    # works even after the DR bootstrap material has been wiped for
    # forward-secrecy reasons. Without this, a channel that has
    # activated the Double Ratchet can never derive a native
    # transfer session — the first send_file gets
    # "DR bootstrap material missing" and falls back to legacy
    # FILE_BIN_CHUNK, losing Wave 2f QUIC and ratchet-binding.
    _native_transfer_seed: Optional[bytes] = None
    # Authenticated cutover state. ``note_caps_sent`` freezes the exact local
    # final-legacy sequence (CAPS is the final legacy frame), while successful
    # activation freezes the corresponding receive boundary. Any legacy frame
    # beyond it is a protocol violation, never an activation "race".
    _legacy_tx_final_seq: Optional[int] = None
    _legacy_rx_final_seq: Optional[int] = None
    _dr_cutover_phase: str = "legacy"
    _closed: bool = False
    # Sending and ratchet mutation are stateful. Serialize concurrent callers
    # and make Bob wait without buffering unbounded plaintext internally.
    _send_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _ratchet_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)
    _caps_negotiated: asyncio.Event = field(
        default_factory=asyncio.Event,
        init=False,
        repr=False,
    )
    _dr_send_ready: asyncio.Event = field(
        default_factory=asyncio.Event,
        init=False,
        repr=False,
    )
    _peer_caps_snapshot: Optional[frozenset[str]] = None
    _dr_cutover_commit_sent: bool = False
    _dr_cutover_commit_received: bool = False
    # When non-None, channel is in ratchet mode. send/recv branch
    # to the ratchet path and the legacy AEADs go unused. Set
    # exactly once per channel by maybe_activate_ratchet.
    # Lazy-imported under TYPE_CHECKING so we don't pull
    # double_ratchet at module import time (it pulls cryptography
    # primitives). Runtime contract: None until
    # maybe_activate_ratchet flips it, then a RatchetState until
    # close().
    _dr_state: Optional["RatchetState"] = None
    # Cached direction-safe facade for FILE_NATIVE_CHUNK.  The facade owns
    # independent TX and RX NativeTransferSession ratchets; sharing one
    # ratchet bidirectionally repeats chunk-index zero's key/nonce and also
    # desynchronises reverse-direction traffic after the first receive.
    _native_transfer_session: Optional["NativeTransferDuplexSession"] = None
    # Never recreate a native facade under the same authenticated channel
    # roots: doing so resets both chunk counters to zero and repeats AEAD
    # key/nonces.  A caller may clear the cached object to request fallback,
    # but native transfer can resume only after a fresh channel handshake.
    _native_transfer_session_created: bool = False

    def __post_init__(self) -> None:
        # 2026-05-22 audit T2-K: eagerly derive the native-transfer
        # seed at handshake completion, BEFORE any send/recv path can
        # call get_or_create_native_transfer_session. Without this,
        # the CAPS-receive task and the first chunk-send task race
        # through ``derive_native_transfer_secret``'s "if _seed is
        # None" branch — and any await in either caller's code path
        # opens an interleave window where both run. The derivation
        # is deterministic (same transcript + same _dr_shared) so
        # the worst case today is duplicated work; the lock-free
        # contract here makes the racy attribute-write/wipe ordering
        # impossible to observe at all.
        if (
            self._native_transfer_seed is None
            and self._dr_shared is not None
            and self.transcript_hash
        ):
            try:
                self._native_transfer_seed = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.transcript_hash,
                    info=b"OL1/native-transfer/seed|v1",
                ).derive(self._dr_shared)
            except (TypeError, ValueError) as exc:
                # Non-fatal: derive on demand later. Common path is
                # tests that build a Channel with synthetic state.
                log.debug(
                    "Channel.__post_init__: eager seed derive failed "
                    "(will lazy-derive on first use): %s",
                    exc,
                )

    def _nonce(self, seq: int) -> bytes:
        return seq.to_bytes(12, "little")

    @property
    def transcript_hex(self) -> str:
        return self.transcript_hash.hex()

    def _aad(self) -> bytes:
        return AAD_PREFIX + self.transcript_hash

    # ─── Phase C-3 native transfer integration (ADR-0025) ─────────────
    def derive_native_transfer_secret(self) -> bytes:
        """Derive the 32-byte root for native transfer traffic secrets.

        This root is domain-separated from legacy AEAD and the Double
        Ratchet.  It is *not* used directly for chunk encryption: callers
        derive initiator→responder and responder→initiator traffic roots via
        :meth:`derive_native_transfer_direction_secrets`, preventing the two
        channel directions from reusing an AEAD key/nonce at the same chunk
        index.

        The same derivation runs on both peers (deterministic from
        ``transcript_hash`` + the DR bootstrap shared secret), so
        sender + receiver hold matching native sessions without
        any wire-format change.

        The seed is cached on first derivation (or pre-derived in
        ``maybe_activate_ratchet`` before the DR bootstrap is wiped
        for forward secrecy), so callers after ratchet activation
        still see a valid secret.
        """
        if self._native_transfer_seed is not None:
            return self._native_transfer_seed
        if self._dr_shared is None:
            raise RuntimeError(
                "channel cannot derive native transfer secret: DR "
                "bootstrap material missing (handshake incomplete)"
            )
        seed = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.transcript_hash,
            info=b"OL1/native-transfer/seed|v1",
        ).derive(self._dr_shared)
        self._native_transfer_seed = seed
        return seed

    def derive_native_transfer_direction_secrets(self) -> tuple[bytes, bytes]:
        """Return local ``(tx_secret, rx_secret)`` for native transfer.

        Both peers first derive the same canonical initiator→responder and
        responder→initiator roots from the authenticated channel transcript.
        The handshake role then maps those roots to local TX/RX, so Alice TX
        exactly matches Bob RX and Bob TX exactly matches Alice RX while the
        two traffic directions remain cryptographically independent.
        """
        from one_link.native_transfer import derive_directional_secrets

        initiator_to_responder, responder_to_initiator = derive_directional_secrets(
            self.derive_native_transfer_secret(),
            transcript_hash=self.transcript_hash,
        )
        if self._dr_role == "alice":
            return initiator_to_responder, responder_to_initiator
        if self._dr_role == "bob":
            return responder_to_initiator, initiator_to_responder
        raise RuntimeError(
            "channel cannot map native transfer directions: authenticated handshake role missing"
        )

    def get_or_create_native_transfer_session(
        self,
        *,
        cipher_backend: str = "fast",
        store_root: "Path | None" = None,
    ):
        """Lazy, cached version of :meth:`establish_native_transfer`.

        Daemon callers invoke this on every chunk.  The returned facade is
        built once and routes encryption to its TX ratchet and decryption to
        its independent RX ratchet."""
        if self._native_transfer_session is None:
            self._native_transfer_session = self.establish_native_transfer(
                cipher_backend=cipher_backend,
                store_root=store_root,
            )
        return self._native_transfer_session

    def establish_native_transfer(
        self,
        *,
        cipher_backend: str = "fast",
        store_root: "Path | None" = None,
    ):
        """Build a direction-safe native transfer facade for this channel.

        The daemon keeps its existing single-object API, while the facade owns
        separate role-bound TX/RX sessions.  Alice TX matches Bob RX and vice
        versa; local TX can never consume or collide with local RX ratchet
        state.

        ``cipher_backend`` defaults to ``"fast"`` (cryptography.hazmat
        BoringSSL); pass ``"native"`` for the ring-backed
        ``ol_aead.AeadCipher`` multi-frame layout (use when partial-
        chunk integrity is needed)."""
        from one_link import native_transfer as _native_transfer

        if not _native_transfer.HAS_NATIVE:
            raise RuntimeError(
                "channel.establish_native_transfer requires "
                "one_link_native; build via `cd native && maturin "
                "develop --release`"
            )
        if self._native_transfer_session_created:
            raise RuntimeError(
                "native transfer session cannot be recreated on the same "
                "channel (would reuse chunk key/nonces); reopen the secure "
                "channel or fall back to the legacy transport"
            )
        tx_secret, rx_secret = self.derive_native_transfer_direction_secrets()
        session = _native_transfer.duplex_session_from_directional_secrets(
            tx_secret,
            rx_secret,
            cipher_backend=cipher_backend,
            store_root=store_root,
        )
        self._native_transfer_session_created = True
        self._native_transfer_session = session
        return session

    @property
    def is_ratchet_active(self) -> bool:
        """v0.8.2: True after both sides exchanged CAPS containing
        DOUBLE_RATCHET_V1 and the ratchet state was successfully
        bootstrapped. Read-only — flipped exactly once."""
        return self._dr_state is not None

    # ─── v0.8.2: caps-driven ratchet activation ────────────────────

    def note_caps_sent(self) -> None:
        """Freeze the local CAPS frame as the final legacy-AEAD frame.

        The daemon calls this synchronously after ``send(CAPS)`` returns.
        Moving the boundary on a duplicate call would make already-emitted
        application frames appear legitimate, so only an exact idempotent
        repeat is accepted.
        """
        if self._caps_sent:
            if self._legacy_tx_final_seq != self.tx_seq:
                raise RuntimeError("cannot move the final legacy CAPS boundary")
            return
        self._legacy_tx_final_seq = self.tx_seq
        self._caps_sent = True

    def note_caps_received(self, features: list[str] | tuple[str, ...] | set[str]) -> None:
        """Daemon calls this immediately after parsing the peer's
        CAPS frame. Records DR + native-transfer capabilities, marks
        recv-side ready."""
        if features is None:
            features = []
        # Normalize to a set once so membership checks are O(1).
        feature_set = frozenset(features)
        if self._caps_received:
            if self._peer_caps_snapshot != feature_set:
                raise RuntimeError("peer CAPS changed after the authenticated cutover boundary")
            return
        self._peer_caps_snapshot = feature_set
        self._peer_dr_capable = DR_CAP in feature_set
        self._peer_dr_cutover_capable = DR_CUTOVER_CAP in feature_set
        self._peer_native_transfer_capable = NATIVE_TRANSFER_CAP in feature_set
        self._caps_received = True
        self._caps_negotiated.set()

    @property
    def peer_native_transfer_capable(self) -> bool:
        """True iff the peer's CAPS frame advertised
        ``NATIVE_TRANSFER_V1`` (ADR-0026). Read-only — set by
        :meth:`note_caps_received`."""
        return self._peer_native_transfer_capable

    def maybe_activate_ratchet(self) -> bool:
        """If both sides have exchanged CAPS, both advertise
        DOUBLE_RATCHET_V1, and we have the bootstrap material from
        the handshake, initialise the ratchet state and flip the
        channel to ratchet mode.

        Returns True iff the channel just transitioned to ratchet
        mode on this call. Idempotent on subsequent calls.
        """
        if self._dr_state is not None:
            return False  # already active
        if not (self._caps_sent and self._caps_received):
            return False
        if not self._peer_dr_capable:
            return False  # peer doesn't speak DR
        if (
            self._dr_role is None
            or self._dr_shared is None
            or self._dr_peer_x_pub is None
            or self._dr_x_priv is None
        ):
            self._dr_cutover_phase = "failed"
            self._dr_send_ready.set()
            log.warning(
                "channel ratchet activation requested but bootstrap "
                "material missing for peer %s — cutover failed closed",
                self.peer_short_id,
            )
            return False
        if self._legacy_tx_final_seq is None:
            self._dr_cutover_phase = "failed"
            self._dr_send_ready.set()
            raise RuntimeError("ratchet cutover missing local final-legacy CAPS boundary")
        if self.tx_seq != self._legacy_tx_final_seq:
            self._dr_cutover_phase = "failed"
            self._dr_send_ready.set()
            raise RuntimeError(
                "legacy application frame emitted after CAPS and before ratchet activation"
            )
        try:
            from one_link.double_ratchet import (
                init_alice,
                init_bob,
            )

            # Derive a root_key distinct from the legacy AEAD keys.
            # If legacy keys leak, the DR bootstrap stays safe; if
            # the bootstrap leaks, legacy still has its own keys.
            root_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.transcript_hash,
                info=DR_ROOT_INFO,
            ).derive(self._dr_shared)
            if self._dr_role == "alice":
                self._dr_state = init_alice(
                    shared_secret=root_key,
                    peer_pub=self._dr_peer_x_pub,
                )
            elif self._dr_role == "bob":
                self._dr_state = init_bob(
                    shared_secret=root_key,
                    dh_priv=self._dr_x_priv,
                )
            else:
                raise RuntimeError(
                    f"channel ratchet: unknown role {self._dr_role!r} "
                    f"for {self.peer_short_id}"
                )
            # The peer CAPS has already authenticated under legacy AEAD and
            # its application-level channel_bind was checked before this
            # method is called. Freeze that exact receive sequence as the
            # final legacy boundary. Stream ordering makes any later legacy
            # frame necessarily post-boundary and therefore invalid.
            self._legacy_rx_final_seq = self.rx_seq
            if self._dr_role == "alice":
                self._dr_cutover_phase = "ratchet_ready"
                self._dr_send_ready.set()
            else:
                # Signal's responder state intentionally has no send chain
                # until it authenticates Alice's first DR header. Outbound
                # calls wait on this event instead of silently downgrading.
                self._dr_cutover_phase = "ratchet_wait_peer"
                self._dr_send_ready.clear()
            log.info(
                "channel ratchet activated for peer %s as %s",
                self.peer_short_id,
                self._dr_role,
            )
            # Pre-derive + cache the native-transfer seed BEFORE
            # wiping the DR bootstrap material. Without this the
            # first post-ratchet send_file would fail to build a
            # NativeTransferSession ("DR bootstrap material missing")
            # and degrade to legacy FILE_BIN_CHUNK, losing the
            # Wave 2f QUIC fast path. The seed is a one-way HKDF
            # output bound to a distinct domain tag, so caching it
            # doesn't widen the forward-secrecy surface.
            if self._native_transfer_seed is None:
                self._native_transfer_seed = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.transcript_hash,
                    info=b"OL1/native-transfer/seed|v1",
                ).derive(self._dr_shared)
            # Drop the legacy bootstrap material — we no longer need
            # the X25519 priv key once the ratchet is rolling.
            self._dr_x_priv = None
            self._dr_shared = None
            self._dr_peer_x_pub = None
            return True
        except Exception as e:
            self._dr_cutover_phase = "failed"
            self._dr_send_ready.set()
            log.error(
                "channel ratchet activation FAILED for %s: %s — closing rather than downgrading",
                self.peer_short_id,
                e,
            )
            self._dr_state = None
            raise

    # ─── send / recv ───────────────────────────────────────────────

    def _can_send_ratchet(self) -> bool:
        """Return whether authenticated ratchet sending is available."""
        if self._dr_state is None:
            return False
        return getattr(self._dr_state, "send_chain_key", None) is not None

    def _cutover_commit_payload(self) -> bytes:
        if self._legacy_tx_final_seq is None or self._legacy_rx_final_seq is None:
            raise RuntimeError("ratchet cutover boundaries are incomplete")
        return (
            DR_CUTOVER_COMMIT_PREFIX
            + self.transcript_hash
            + struct.pack(
                ">QQ",
                self._legacy_tx_final_seq,
                self._legacy_rx_final_seq,
            )
        )

    def _validate_cutover_commit(self, plaintext: bytes) -> None:
        expected_size = len(DR_CUTOVER_COMMIT_PREFIX) + 32 + 16
        if len(plaintext) != expected_size:
            raise RuntimeError("malformed ratchet cutover commit")
        offset = len(DR_CUTOVER_COMMIT_PREFIX)
        committed_transcript = plaintext[offset : offset + 32]
        remote_tx_final, remote_rx_final = struct.unpack(">QQ", plaintext[offset + 32 :])
        if committed_transcript != self.transcript_hash:
            raise RuntimeError("ratchet cutover commit transcript mismatch")
        if (
            remote_tx_final != self._legacy_rx_final_seq
            or remote_rx_final != self._legacy_tx_final_seq
        ):
            raise RuntimeError("ratchet cutover commit legacy sequence mismatch")

    async def _send_cutover_commit_locked(self) -> bool:
        """Send Alice's authenticated boundary commit with the send lock held."""
        if not self._peer_dr_cutover_capable or self._dr_role != "alice":
            return False
        if self._dr_cutover_commit_sent:
            return False
        if self._dr_state is None or not self._can_send_ratchet():
            raise RuntimeError("ratchet cutover commit requested before Alice send readiness")
        await self._send_ratchet(self._cutover_commit_payload())
        self._dr_cutover_commit_sent = True
        return True

    async def send_ratchet_cutover_commit(self) -> bool:
        """Emit the negotiated v2 commit before either peer needs app data.

        The daemon awaits this immediately after Alice activates. Calling it
        for Bob, an older v1 peer, or after an existing commit is an idempotent
        no-op. Ordinary :meth:`send` also enforces commit-before-application as
        a defensive backstop for non-daemon channel users.
        """
        # Bob cannot emit this control frame. Return before taking the send
        # lock because a Bob application send may legitimately hold that lock
        # while waiting for Alice's first authenticated DR frame.
        if not self._peer_dr_cutover_capable or self._dr_role != "alice":
            return False
        async with self._send_lock:
            if self._closed:
                raise RuntimeError("cannot commit ratchet cutover on a closed channel")
            return await self._send_cutover_commit_locked()

    async def _wait_for_outbound_mode(self) -> None:
        """Resolve CAPS/DR cutover without ever emitting post-CAPS legacy.

        Application sends that race mandatory CAPS negotiation wait for the
        peer's authenticated CAPS. If DR was negotiated, Bob then waits for
        the first authenticated peer DR frame to derive his sending chain.
        Closing the channel wakes both waits and fails them deterministically.
        """
        if self._caps_sent and not self._caps_received:
            await self._caps_negotiated.wait()
        if self._closed:
            raise RuntimeError("channel closed while waiting for ratchet cutover")
        # Receiving peer CAPS first is valid on a full-duplex stream. Until
        # ``note_caps_sent`` freezes our boundary, one legacy send is the local
        # CAPS response; the daemon's mandatory-first-frame validator prevents
        # application data from exploiting that protocol slot.
        if self._caps_sent and self._caps_received and self._peer_dr_capable:
            if self._dr_state is None:
                raise RuntimeError("peer negotiated Double Ratchet but activation is not healthy")
            if self._dr_cutover_phase == "ratchet_wait_peer":
                await self._dr_send_ready.wait()
                if self._closed:
                    raise RuntimeError("channel closed while waiting for ratchet send chain")
                if self._dr_cutover_phase != "ratchet_ready":
                    raise RuntimeError("ratchet cutover failed before send readiness")
                if not self._can_send_ratchet():
                    raise RuntimeError("ratchet send-ready signal violated channel invariant")
            elif not self._can_send_ratchet():
                raise RuntimeError("ratchet marked ready without a sending chain")

    async def send(self, plaintext: bytes) -> None:
        async with self._send_lock:
            await self._wait_for_outbound_mode()
            if self._dr_state is not None:
                await self._send_cutover_commit_locked()
                await self._send_ratchet(plaintext)
                return
            await self._wait_writer_capacity(len(plaintext) + 16 + 4)
            nonce = self._nonce(self.tx_seq)
            self.tx_seq += 1
            ct = self.tx_aead.encrypt(nonce, plaintext, self._aad())
            await write_frame(self.writer, ct)

    async def queue_send(self, plaintext: bytes) -> None:
        """Encrypt and write a frame without awaiting socket drain.

        File transfer callers use this for bounded windows: write several
        chunks, then call ``flush`` before awaiting ACKs. Normal chat/control
        paths keep using ``send`` so small messages retain immediate
        backpressure and error visibility.
        """
        async with self._send_lock:
            await self._wait_for_outbound_mode()
            if self._dr_state is not None:
                await self._send_cutover_commit_locked()
                await self._queue_send_ratchet(plaintext)
                return
            # Relay-backed writers expose an optional capacity hook because
            # their StreamWriter-compatible write() method is synchronous
            # while the underlying WebSocket send is async. Awaiting it before
            # advancing the nonce keeps pipelined windows byte-bounded.
            await self._wait_writer_capacity(len(plaintext) + 16 + 4)
            nonce = self._nonce(self.tx_seq)
            self.tx_seq += 1
            ct = self.tx_aead.encrypt(nonce, plaintext, self._aad())
            write_frame_nowait(self.writer, ct)

    async def _wait_writer_capacity(self, framed_size: int) -> None:
        wait_writable = getattr(self.writer, "wait_writable", None)
        if wait_writable is not None:
            await wait_writable(framed_size)

    async def flush(self) -> None:
        await self.writer.drain()

    async def recv(self) -> bytes:
        # The authenticated CAPS frame is the exact final legacy boundary.
        # Once DR is active, accepting even correctly authenticated legacy
        # bytes would be a downgrade; parse/decrypt exclusively as DR.
        if self._dr_state is not None:
            while True:
                payload = await read_frame(self.reader)
                # One RatchetState contains both directional root/chain state.
                # A concurrent send and receive must not interleave their DH
                # mutations, even though network reads/writes remain duplex.
                async with self._ratchet_lock:
                    plaintext = self._decode_ratchet_payload(payload)
                    is_cutover_commit = plaintext.startswith(DR_CUTOVER_COMMIT_PREFIX)
                    if is_cutover_commit:
                        if not self._peer_dr_cutover_capable or self._dr_role != "bob":
                            raise RuntimeError("unexpected ratchet cutover control frame")
                        if self._dr_cutover_commit_received:
                            raise RuntimeError("duplicate ratchet cutover commit")
                        # Validate both authenticated legacy boundaries before
                        # releasing Bob's queued outbound calls. DR AEAD alone
                        # authenticates the sender, not the claimed boundary.
                        try:
                            self._validate_cutover_commit(plaintext)
                        except RuntimeError:
                            self._dr_cutover_phase = "failed"
                            self._dr_send_ready.set()
                            raise

                    if self._dr_cutover_phase == "ratchet_wait_peer":
                        if not self._can_send_ratchet():
                            raise RuntimeError(
                                "authenticated peer ratchet frame did not derive responder send chain"
                            )
                        self._dr_cutover_phase = "ratchet_ready"
                        self._dr_send_ready.set()

                    if is_cutover_commit:
                        self._dr_cutover_commit_received = True
                        # Internal control frames never escape into JSON/binary
                        # application dispatch. Continue to the next app frame;
                        # Bob's queued senders were released above.
                        continue
                return plaintext
        if self._caps_sent and self._caps_received and self._peer_dr_capable:
            raise RuntimeError("peer negotiated Double Ratchet but receive state is unavailable")
        # Legacy path.
        # v0.20.7 (security audit M2): increment rx_seq AFTER successful
        # decrypt so a single bit-flip / injected garbage frame does not
        # permanently desync the channel. On decrypt failure the exception
        # propagates and the
        # channel is closed by the caller, so leaving rx_seq unmodified
        # is safe (the channel will not be reused).
        ct = await read_frame(self.reader)
        nonce = self._nonce(self.rx_seq)
        pt = self.rx_aead.decrypt(nonce, ct, self._aad())
        self.rx_seq += 1
        return pt

    def _decode_ratchet_payload(self, payload: bytes) -> bytes:
        """Synchronous DR-decrypt of an already-read frame payload.
        Split from network reads so authentication and cutover-state changes
        can run atomically under ``_ratchet_lock``."""
        from one_link.double_ratchet import (
            Header as DRHeader,
            decrypt as dr_decrypt,
        )

        # All four ratchet methods are only reached after
        # ``is_ratcheting`` returns True, which guarantees
        # ``_dr_state is not None``. External audit 2026-05-18 ES-18:
        # converted from `assert` to explicit raise so the invariant
        # survives `python -O` (which strips asserts). The runtime
        # cost is one branch per send/recv; negligible.
        if self._dr_state is None:
            raise RuntimeError("ratchet not yet activated")
        if len(payload) < DR_HEADER_LEN:
            raise RuntimeError(
                f"ratchet frame too short: {len(payload)} bytes "
                f"(need at least {DR_HEADER_LEN} for header)"
            )
        header = DRHeader.decode(payload[:DR_HEADER_LEN])
        ct = payload[DR_HEADER_LEN:]
        return dr_decrypt(
            self._dr_state,
            header,
            ct,
            ad=self.transcript_hash,
        )

    async def _send_ratchet(self, plaintext: bytes) -> None:
        from one_link.double_ratchet import encrypt as dr_encrypt

        # ES-18: explicit raise, not assert (python -O strips asserts).
        if self._dr_state is None:
            raise RuntimeError("ratchet not yet activated")
        await self._wait_writer_capacity(len(plaintext) + DR_HEADER_LEN + 16 + 4)
        async with self._ratchet_lock:
            header, ct = dr_encrypt(
                self._dr_state,
                plaintext,
                ad=self.transcript_hash,
            )
        # Wire layout: [Header (DR_HEADER_LEN bytes)][ciphertext]
        await write_frame(self.writer, header.encode() + ct)

    async def _queue_send_ratchet(self, plaintext: bytes) -> None:
        from one_link.double_ratchet import encrypt as dr_encrypt

        # ES-18: explicit raise, not assert.
        if self._dr_state is None:
            raise RuntimeError("ratchet not yet activated")
        await self._wait_writer_capacity(len(plaintext) + DR_HEADER_LEN + 16 + 4)
        async with self._ratchet_lock:
            header, ct = dr_encrypt(
                self._dr_state,
                plaintext,
                ad=self.transcript_hash,
            )
        write_frame_nowait(self.writer, header.encode() + ct)

    async def _recv_ratchet(self) -> bytes:
        from one_link.double_ratchet import (
            Header as DRHeader,
            decrypt as dr_decrypt,
        )

        # ES-18: explicit raise, not assert.
        if self._dr_state is None:
            raise RuntimeError("ratchet not yet activated")
        payload = await read_frame(self.reader)
        if len(payload) < DR_HEADER_LEN:
            raise RuntimeError(
                f"ratchet frame too short: {len(payload)} bytes "
                f"(need at least {DR_HEADER_LEN} for header)"
            )
        header = DRHeader.decode(payload[:DR_HEADER_LEN])
        ct = payload[DR_HEADER_LEN:]
        async with self._ratchet_lock:
            return dr_decrypt(
                self._dr_state,
                header,
                ct,
                ad=self.transcript_hash,
            )

    async def close(self) -> None:
        self._closed = True
        self._dr_cutover_phase = "closed"
        # Wake any application send queued behind CAPS/ratchet readiness so it
        # terminates rather than leaking a task after the transport closes.
        self._caps_negotiated.set()
        self._dr_send_ready.set()
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (OSError, RuntimeError) as exc:
            # Socket/loop teardown is best-effort, but it must not be silent:
            # repeated close failures are a useful explanation for reconnect
            # churn and duplicate transfer attempts.
            log.debug(
                "channel close failed for %s: %s",
                self.peer_short_id,
                exc,
                exc_info=True,
            )


def _x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv, pub


def _sha256(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def _derive_keys(
    shared: bytes,
    salt: bytes,
    transcript_hash: bytes,
) -> tuple[bytes, bytes]:
    out = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"OL1/keys|" + transcript_hash,
    ).derive(shared)
    return out[:32], out[32:64]


async def _initiate_classical(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    expected_responder_ed_pub: Optional[bytes] = None,
) -> Channel:
    """Open an outbound encrypted channel.

    v0.20.7 (security audit M1): when ``expected_responder_ed_pub`` is
    provided, the initiator binds it into the HELLO signature
    (``sig_i = me.sign(HELLO_TAG + me_pub + x_pub + nonce_i + resp_pub)``)
    AND strictly equality-checks the actual REPLY's responder pubkey
    against the claim. Together these defeat the unknown-key-share
    attack: an attacker who re-routes the HELLO to a different
    (paired) responder C cannot get C to verify the sig (the bound
    pubkey identifies the original target), and even if C did
    somehow accept, the initiator catches the redirect at the REPLY
    pubkey check.

    Unbound v1 handshakes are rejected by default because they do not bind the
    responder identity and are vulnerable to unknown-key-share splicing. An
    operator performing a deliberately isolated legacy migration may set
    ``ONE_LINK_ALLOW_V1_HELLO=1`` temporarily on both endpoints. Normal paired
    and QR flows already know the responder key and must pass it here.
    """
    if expected_responder_ed_pub is not None and len(expected_responder_ed_pub) != 32:
        raise ValueError(
            f"expected_responder_ed_pub must be 32 bytes, got {len(expected_responder_ed_pub)}"
        )
    if expected_responder_ed_pub is None and os.environ.get("ONE_LINK_ALLOW_V1_HELLO") != "1":
        raise ValueError(
            "expected_responder_ed_pub is required for an identity-bound HELLO; "
            "legacy unbound v1 is disabled (temporary migration override: "
            "ONE_LINK_ALLOW_V1_HELLO=1)"
        )
    x_priv, x_pub = _x25519_keypair()
    nonce_i = os.urandom(NONCE_LEN)
    if expected_responder_ed_pub is not None:
        sig_i = me.sign(HELLO_TAG + me.public_bytes + x_pub + nonce_i + expected_responder_ed_pub)
    else:
        sig_i = me.sign(HELLO_TAG + me.public_bytes + x_pub + nonce_i)
    hello = me.public_bytes + x_pub + nonce_i + sig_i
    await write_frame(writer, hello)

    reply = await read_frame(reader)
    if len(reply) != 32 + 32 + NONCE_LEN + 64:
        raise RuntimeError(f"bad REPLY length: {len(reply)}")
    r_ed = reply[0:32]
    r_x = reply[32:64]
    nonce_r = reply[64 : 64 + NONCE_LEN]
    sig_r = reply[64 + NONCE_LEN :]
    if not verify(r_ed, sig_r, REPLY_TAG + nonce_i + r_ed + r_x + nonce_r):
        raise RuntimeError("REPLY signature invalid")
    # v0.20.7 (M1): catch UKS redirect where attacker re-routes our
    # HELLO to a different responder. The only unbound case is the explicit,
    # migration-only v1 override validated at function entry.
    if expected_responder_ed_pub is not None and r_ed != expected_responder_ed_pub:
        raise RuntimeError(
            "REPLY pubkey does not match expected responder identity "
            "(possible unknown-key-share redirect)"
        )

    transcript_hash = _sha256(hello + reply)
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(r_x))
    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + nonce_r, transcript_hash)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=r_ed,
        peer_short_id=fingerprint_of(r_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_i_to_r),
        rx_aead=ChaCha20Poly1305(k_r_to_i),
        transcript_hash=transcript_hash,
        # v0.8.2: ratchet-bootstrap material. Held until
        # maybe_activate_ratchet seeds the RatchetState; cleared
        # afterwards.
        _dr_role="alice",
        _dr_x_priv=x_priv,
        _dr_peer_x_pub=r_x,
        _dr_shared=shared,
    )


async def _respond_classical(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    is_pinned_peer: Callable[[bytes], bool] | None = None,
    hello: bytes | None = None,
) -> Channel:
    """Accept an inbound encrypted channel.

    ``is_pinned_peer`` is the owning daemon's current trust-roster lookup. It
    is consulted only after a legacy-v1 HELLO signature verifies and controls
    whether downgrade telemetry may retain a per-peer slot. Missing or broken
    lookups fail closed to fixed-memory aggregate telemetry.
    """
    if hello is None:
        hello = await read_frame(reader)
    if len(hello) != 32 + 32 + NONCE_LEN + 64:
        raise RuntimeError(f"bad HELLO length: {len(hello)}")
    i_ed = hello[0:32]
    i_x = hello[32:64]
    nonce_i = hello[64 : 64 + NONCE_LEN]
    sig_i = hello[64 + NONCE_LEN :]
    # 2026-05-22 audit Batch V — handshake nonce replay defence.
    # Reject identical (peer_pubkey, nonce_i) inside the 60 s window
    # BEFORE any signature / X25519 / HKDF work. An attacker who
    # captured one valid HELLO would otherwise force unbounded
    # Ed25519+X25519+HKDF cycles per replay. Stays single-µs on the
    # happy path (hash + dict lookup).
    if _handshake_replay_seen(i_ed, nonce_i, time.monotonic()):
        raise RuntimeError(
            "HELLO replay rejected (duplicate nonce inside "
            f"{int(_HANDSHAKE_REPLAY_WINDOW_S)} s window)"
        )
    # v0.20.7 (security audit M1): try the v2 sig (with our pubkey
    # bound in) first to defeat unknown-key-share. The v1 signature material
    # exists only for an explicitly enabled legacy migration. Normal
    # first-meet flows obtain the responder identity through pairing/QR and use
    # the bound v2 material.
    sig_v2_material = HELLO_TAG + i_ed + i_x + nonce_i + me.public_bytes
    sig_v1_material = HELLO_TAG + i_ed + i_x + nonce_i
    if verify(i_ed, sig_i, sig_v2_material):
        pass  # v2 sig — UKS-defended path, the common case once peers upgrade.
    elif verify(i_ed, sig_i, sig_v1_material):
        pinned = False
        if is_pinned_peer is not None:
            try:
                pinned = bool(is_pinned_peer(i_ed))
            except Exception as exc:
                # Trust-store failure must not turn an untrusted key into a
                # retained per-peer metric. Keep the attempt observable via
                # the unknown aggregate and surface the lookup failure.
                log.warning(
                    "channel.respond: pinned-peer telemetry lookup failed: %s",
                    exc,
                )
        v1_count = _bump_v1_sig_counter(i_ed, is_pinned=pinned)
        telemetry_class = "pinned" if pinned else "unknown"
        if os.environ.get("ONE_LINK_ALLOW_V1_HELLO") != "1":
            log.warning(
                "channel.respond: rejected legacy v1 HELLO sig from peer %s "
                "because it lacks responder identity binding. telemetry=%s "
                "v1-attempt count: %d.",
                i_ed.hex()[:16],
                telemetry_class,
                v1_count,
            )
            raise RuntimeError("HELLO signature invalid (legacy unbound v1 is disabled)")
        # Explicit migration-only compatibility path. It remains observable so
        # operators can remove the override as soon as the old peer upgrades.
        log.warning(
            "channel.respond: migration override accepted legacy v1 HELLO from %s; "
            "responder identity binding and UKS defence are NOT active. "
            "telemetry=%s v1-fallback count: %d. Remove "
            "ONE_LINK_ALLOW_V1_HELLO after upgrade.",
            i_ed.hex()[:16],
            telemetry_class,
            v1_count,
        )
    else:
        raise RuntimeError("HELLO signature invalid")

    x_priv, x_pub = _x25519_keypair()
    nonce_r = os.urandom(NONCE_LEN)
    sig_r = me.sign(REPLY_TAG + nonce_i + me.public_bytes + x_pub + nonce_r)
    reply = me.public_bytes + x_pub + nonce_r + sig_r
    await write_frame(writer, reply)

    transcript_hash = _sha256(hello + reply)
    shared = x_priv.exchange(X25519PublicKey.from_public_bytes(i_x))
    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + nonce_r, transcript_hash)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=i_ed,
        peer_short_id=fingerprint_of(i_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_r_to_i),
        rx_aead=ChaCha20Poly1305(k_i_to_r),
        transcript_hash=transcript_hash,
        # v0.8.2: bob-side ratchet bootstrap. Bob's x_priv is the
        # initial dh_send for init_bob; first ratchet ratchet-step
        # happens when alice's first ratchet message arrives.
        _dr_role="bob",
        _dr_x_priv=x_priv,
        _dr_peer_x_pub=i_x,
        _dr_shared=shared,
    )


@dataclass(frozen=True)
class _PQHello:
    """Strictly decoded v3 initiator flight."""

    offered_suites: tuple[int, ...]
    initiator_ed: bytes
    initiator_x25519: bytes
    nonce: bytes
    kem_public_key: bytes
    signature: bytes
    unsigned: bytes


@dataclass(frozen=True)
class _PQReply:
    """Strictly decoded v3 responder flight."""

    selected_suite: int
    hello_hash: bytes
    responder_ed: bytes
    responder_x25519: bytes
    nonce: bytes
    kem_ciphertext: bytes
    signature: bytes
    unsigned: bytes


def _encode_pq_hello_unsigned(
    *,
    offered_suites: tuple[int, ...],
    initiator_ed: bytes,
    initiator_x25519: bytes,
    nonce: bytes,
    kem_public_key: bytes,
) -> bytes:
    if not offered_suites or len(offered_suites) > PQ_MAX_OFFERED_SUITES:
        raise ValueError("PQ HELLO must offer between 1 and 8 suites")
    if offered_suites != tuple(sorted(set(offered_suites))):
        raise ValueError("PQ HELLO suites must be unique and canonically sorted")
    if any(not 0 < suite <= 0xFFFF for suite in offered_suites):
        raise ValueError("PQ HELLO suite identifiers must be non-zero u16 values")
    if len(initiator_ed) != 32 or len(initiator_x25519) != 32:
        raise ValueError("PQ HELLO identity and X25519 public keys must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"PQ HELLO nonce must be {NONCE_LEN} bytes")
    if len(kem_public_key) != PQ_KEM_PUBLIC_KEY_LEN:
        raise ValueError(
            f"PQ HELLO ML-KEM hybrid public key must be {PQ_KEM_PUBLIC_KEY_LEN} bytes"
        )
    suite_bytes = b"".join(struct.pack(">H", suite) for suite in offered_suites)
    return (
        PQ_HANDSHAKE_MAGIC
        + bytes((PQ_HANDSHAKE_VERSION, len(offered_suites)))
        + suite_bytes
        + initiator_ed
        + initiator_x25519
        + nonce
        + kem_public_key
    )


def _parse_pq_hello(raw: bytes) -> _PQHello:
    minimum = 4 + 1 + 1 + 2 + 32 + 32 + NONCE_LEN + PQ_KEM_PUBLIC_KEY_LEN + 64
    if len(raw) < minimum:
        raise RuntimeError(f"bad PQ HELLO length: {len(raw)}")
    if raw[:4] != PQ_HANDSHAKE_MAGIC:
        raise RuntimeError("bad PQ HELLO magic")
    if raw[4] != PQ_HANDSHAKE_VERSION:
        raise RuntimeError(f"unsupported PQ handshake version: {raw[4]}")
    suite_count = raw[5]
    if not 0 < suite_count <= PQ_MAX_OFFERED_SUITES:
        raise RuntimeError("invalid PQ HELLO suite count")
    expected = 4 + 1 + 1 + (2 * suite_count) + 32 + 32 + NONCE_LEN + PQ_KEM_PUBLIC_KEY_LEN + 64
    if len(raw) != expected:
        raise RuntimeError(f"bad PQ HELLO length: {len(raw)} (expected {expected})")
    offset = 6
    offered = tuple(
        struct.unpack(">H", raw[offset + (2 * index) : offset + (2 * index) + 2])[0]
        for index in range(suite_count)
    )
    if offered != tuple(sorted(set(offered))) or any(suite == 0 for suite in offered):
        raise RuntimeError("PQ HELLO suite offer is not canonical")
    offset += 2 * suite_count
    initiator_ed = raw[offset : offset + 32]
    offset += 32
    initiator_x25519 = raw[offset : offset + 32]
    offset += 32
    nonce = raw[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    kem_public_key = raw[offset : offset + PQ_KEM_PUBLIC_KEY_LEN]
    offset += PQ_KEM_PUBLIC_KEY_LEN
    signature = raw[offset : offset + 64]
    return _PQHello(
        offered_suites=offered,
        initiator_ed=initiator_ed,
        initiator_x25519=initiator_x25519,
        nonce=nonce,
        kem_public_key=kem_public_key,
        signature=signature,
        unsigned=raw[:-64],
    )


def _encode_pq_reply_unsigned(
    *,
    selected_suite: int,
    hello_hash: bytes,
    responder_ed: bytes,
    responder_x25519: bytes,
    nonce: bytes,
    kem_ciphertext: bytes,
) -> bytes:
    if not 0 < selected_suite <= 0xFFFF:
        raise ValueError("PQ REPLY selected suite must be a non-zero u16")
    if len(hello_hash) != 32:
        raise ValueError("PQ REPLY hello hash must be 32 bytes")
    if len(responder_ed) != 32 or len(responder_x25519) != 32:
        raise ValueError("PQ REPLY identity and X25519 public keys must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"PQ REPLY nonce must be {NONCE_LEN} bytes")
    if len(kem_ciphertext) != PQ_KEM_CIPHERTEXT_LEN:
        raise ValueError(
            f"PQ REPLY ML-KEM hybrid ciphertext must be {PQ_KEM_CIPHERTEXT_LEN} bytes"
        )
    return (
        PQ_HANDSHAKE_MAGIC
        + bytes((PQ_HANDSHAKE_VERSION,))
        + struct.pack(">H", selected_suite)
        + hello_hash
        + responder_ed
        + responder_x25519
        + nonce
        + kem_ciphertext
    )


def _parse_pq_reply(raw: bytes) -> _PQReply:
    expected = 4 + 1 + 2 + 32 + 32 + 32 + NONCE_LEN + PQ_KEM_CIPHERTEXT_LEN + 64
    if len(raw) != expected:
        if len(raw) == 32 + 32 + NONCE_LEN + 64:
            raise RuntimeError(
                "PQ REPLY signature invalid (legacy/classical reply rejected as a downgrade)"
            )
        raise RuntimeError(f"bad PQ REPLY length: {len(raw)} (expected {expected})")
    if raw[:4] != PQ_HANDSHAKE_MAGIC:
        raise RuntimeError("bad PQ REPLY magic")
    if raw[4] != PQ_HANDSHAKE_VERSION:
        raise RuntimeError(f"unsupported PQ handshake version: {raw[4]}")
    selected_suite = struct.unpack(">H", raw[5:7])[0]
    if selected_suite == 0:
        raise RuntimeError("PQ REPLY selected an invalid zero suite")
    offset = 7
    hello_hash = raw[offset : offset + 32]
    offset += 32
    responder_ed = raw[offset : offset + 32]
    offset += 32
    responder_x25519 = raw[offset : offset + 32]
    offset += 32
    nonce = raw[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    kem_ciphertext = raw[offset : offset + PQ_KEM_CIPHERTEXT_LEN]
    offset += PQ_KEM_CIPHERTEXT_LEN
    signature = raw[offset : offset + 64]
    return _PQReply(
        selected_suite=selected_suite,
        hello_hash=hello_hash,
        responder_ed=responder_ed,
        responder_x25519=responder_x25519,
        nonce=nonce,
        kem_ciphertext=kem_ciphertext,
        signature=signature,
        unsigned=raw[:-64],
    )


def _pqkem_runtime():
    """Return the exact native ML-KEM ABI or fail closed before wire I/O."""
    from one_link import pq_hybrid, pqkem_native

    probe = getattr(pqkem_native, "runtime_is_usable", None)
    usable = bool(probe()) if callable(probe) else bool(pqkem_native.HAS_NATIVE)
    sizes_match = (
        pqkem_native.HYBRID_PUBLIC_KEY_LEN == PQ_KEM_PUBLIC_KEY_LEN
        and pqkem_native.HYBRID_CIPHERTEXT_LEN == PQ_KEM_CIPHERTEXT_LEN
        and pqkem_native.SHARED_SECRET_LEN == 32
    )
    if not usable or not sizes_match:
        raise pq_hybrid.PQUnavailableError(
            "live PQ channel handshake requires the verified one_link_native.pqkem "
            "ML-KEM-768 + X25519 ABI; refusing a classical or NullKEM downgrade"
        )
    return pqkem_native


def _safe_x25519_exchange(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    if len(peer_public) != 32:
        raise RuntimeError("X25519 peer public key must be 32 bytes")
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        raise RuntimeError("invalid or low-order X25519 public key") from exc
    if hmac.compare_digest(shared, b"\x00" * 32):
        raise RuntimeError("invalid or low-order X25519 public key")
    return shared


def _derive_pq_channel_secret(
    *,
    classical_shared: bytes,
    kem_shared: bytes,
    salt: bytes,
    transcript_hash: bytes,
    suite: int,
) -> bytes:
    """Extract both independent contributions into one transcript-bound root."""
    if len(classical_shared) != 32 or len(kem_shared) != 32:
        raise RuntimeError("PQ hybrid inputs must both be 32-byte shared secrets")
    if len(transcript_hash) != 32:
        raise RuntimeError("PQ hybrid transcript hash must be 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=PQ_CHANNEL_SECRET_INFO + struct.pack(">H", suite) + transcript_hash,
    ).derive(classical_shared + kem_shared)


def _derive_pq_confirmation_key(
    shared_secret: bytes,
    transcript_hash: bytes,
    suite: int,
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=PQ_CONFIRM_KEY_INFO + struct.pack(">H", suite),
    ).derive(shared_secret)


def _build_pq_confirmation(
    *,
    confirmation_key: bytes,
    transcript_hash: bytes,
    suite: int,
    role: bytes,
    prior_tag: bytes = b"",
) -> bytes:
    if role not in (b"I", b"R"):
        raise ValueError("PQ confirmation role must be I or R")
    if len(transcript_hash) != 32:
        raise ValueError("PQ confirmation transcript must be 32 bytes")
    if prior_tag and len(prior_tag) != 32:
        raise ValueError("PQ confirmation prior tag must be 32 bytes")
    prefix = (
        PQ_CONFIRM_MAGIC
        + bytes((PQ_HANDSHAKE_VERSION,))
        + struct.pack(">H", suite)
        + role
        + transcript_hash
    )
    tag = hmac.digest(confirmation_key, PQ_CONFIRM_TAG + prefix + prior_tag, "sha256")
    return prefix + tag


def _verify_pq_confirmation(
    raw: bytes,
    *,
    confirmation_key: bytes,
    transcript_hash: bytes,
    suite: int,
    role: bytes,
    prior_tag: bytes = b"",
) -> bytes:
    expected_len = 4 + 1 + 2 + 1 + 32 + 32
    if len(raw) != expected_len:
        raise RuntimeError(f"bad PQ key-confirmation length: {len(raw)}")
    expected = _build_pq_confirmation(
        confirmation_key=confirmation_key,
        transcript_hash=transcript_hash,
        suite=suite,
        role=role,
        prior_tag=prior_tag,
    )
    if not hmac.compare_digest(raw, expected):
        raise RuntimeError("PQ key confirmation failed")
    return raw[-32:]


async def _initiate_pq(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    expected_responder_ed_pub: bytes,
) -> Channel:
    if len(expected_responder_ed_pub) != 32:
        raise ValueError(
            f"expected_responder_ed_pub must be 32 bytes, got {len(expected_responder_ed_pub)}"
        )
    pqkem = _pqkem_runtime()
    x_priv, x_pub = _x25519_keypair()
    nonce_i = os.urandom(NONCE_LEN)
    kem_public, kem_secret = pqkem.keypair()
    kem_public_bytes = bytes(kem_public.to_bytes())
    offered = (PQ_SUITE_X25519_MLKEM768_V1,)
    hello_unsigned = _encode_pq_hello_unsigned(
        offered_suites=offered,
        initiator_ed=me.public_bytes,
        initiator_x25519=x_pub,
        nonce=nonce_i,
        kem_public_key=kem_public_bytes,
    )
    hello = hello_unsigned + me.sign(PQ_HELLO_TAG + hello_unsigned + expected_responder_ed_pub)
    await write_frame(writer, hello)

    raw_reply = await read_frame(reader)
    reply = _parse_pq_reply(raw_reply)
    hello_hash = _sha256(hello)
    if not hmac.compare_digest(reply.hello_hash, hello_hash):
        raise RuntimeError("PQ REPLY is bound to a different HELLO")
    if reply.selected_suite not in offered:
        raise RuntimeError("PQ REPLY selected a suite the initiator did not offer")
    if reply.selected_suite != PQ_SUITE_X25519_MLKEM768_V1:
        raise RuntimeError("PQ REPLY selected an unsupported suite")
    if not hmac.compare_digest(reply.responder_ed, expected_responder_ed_pub):
        raise RuntimeError(
            "PQ REPLY pubkey does not match expected responder identity "
            "(possible unknown-key-share redirect)"
        )
    if not verify(
        reply.responder_ed,
        reply.signature,
        PQ_REPLY_TAG + reply.unsigned,
    ):
        raise RuntimeError("PQ REPLY signature invalid")

    classical_shared = _safe_x25519_exchange(x_priv, reply.responder_x25519)
    kem_ciphertext = pqkem.ciphertext_from_bytes(reply.kem_ciphertext)
    kem_shared = bytes(pqkem.decapsulate(kem_secret, kem_ciphertext))
    del kem_secret
    transcript_hash = _sha256(hello + raw_reply)
    shared = _derive_pq_channel_secret(
        classical_shared=classical_shared,
        kem_shared=kem_shared,
        salt=nonce_i + reply.nonce,
        transcript_hash=transcript_hash,
        suite=reply.selected_suite,
    )
    confirmation_key = _derive_pq_confirmation_key(
        shared,
        transcript_hash,
        reply.selected_suite,
    )
    initiator_confirmation = _build_pq_confirmation(
        confirmation_key=confirmation_key,
        transcript_hash=transcript_hash,
        suite=reply.selected_suite,
        role=b"I",
    )
    await write_frame(writer, initiator_confirmation)
    raw_responder_confirmation = await read_frame(reader)
    _verify_pq_confirmation(
        raw_responder_confirmation,
        confirmation_key=confirmation_key,
        transcript_hash=transcript_hash,
        suite=reply.selected_suite,
        role=b"R",
        prior_tag=initiator_confirmation[-32:],
    )

    k_i_to_r, k_r_to_i = _derive_keys(shared, nonce_i + reply.nonce, transcript_hash)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=reply.responder_ed,
        peer_short_id=fingerprint_of(reply.responder_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_i_to_r),
        rx_aead=ChaCha20Poly1305(k_r_to_i),
        transcript_hash=transcript_hash,
        handshake_version=PQ_HANDSHAKE_VERSION,
        handshake_suite=PQ_HYBRID_HANDSHAKE_CAP,
        pq_protected=True,
        key_confirmed=True,
        _dr_role="alice",
        _dr_x_priv=x_priv,
        _dr_peer_x_pub=reply.responder_x25519,
        _dr_shared=shared,
    )


async def _respond_pq(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    raw_hello: bytes,
) -> Channel:
    hello = _parse_pq_hello(raw_hello)
    if _handshake_replay_seen(hello.initiator_ed, hello.nonce, time.monotonic()):
        raise RuntimeError(
            "PQ HELLO replay rejected (duplicate nonce inside "
            f"{int(_HANDSHAKE_REPLAY_WINDOW_S)} s window)"
        )
    if not verify(
        hello.initiator_ed,
        hello.signature,
        PQ_HELLO_TAG + hello.unsigned + me.public_bytes,
    ):
        raise RuntimeError("PQ HELLO signature invalid")
    supported = (PQ_SUITE_X25519_MLKEM768_V1,)
    selected_suite = next(
        (suite for suite in supported if suite in hello.offered_suites),
        None,
    )
    if selected_suite is None:
        raise RuntimeError("PQ HELLO offered no mutually supported suite")
    pqkem = _pqkem_runtime()
    kem_public = pqkem.public_key_from_bytes(hello.kem_public_key)
    kem_ciphertext, kem_shared_raw = pqkem.encapsulate(kem_public)
    kem_shared = bytes(kem_shared_raw)
    kem_ciphertext_bytes = bytes(kem_ciphertext.to_bytes())

    x_priv, x_pub = _x25519_keypair()
    nonce_r = os.urandom(NONCE_LEN)
    hello_hash = _sha256(raw_hello)
    reply_unsigned = _encode_pq_reply_unsigned(
        selected_suite=selected_suite,
        hello_hash=hello_hash,
        responder_ed=me.public_bytes,
        responder_x25519=x_pub,
        nonce=nonce_r,
        kem_ciphertext=kem_ciphertext_bytes,
    )
    reply = reply_unsigned + me.sign(PQ_REPLY_TAG + reply_unsigned)
    await write_frame(writer, reply)

    classical_shared = _safe_x25519_exchange(x_priv, hello.initiator_x25519)
    transcript_hash = _sha256(raw_hello + reply)
    shared = _derive_pq_channel_secret(
        classical_shared=classical_shared,
        kem_shared=kem_shared,
        salt=hello.nonce + nonce_r,
        transcript_hash=transcript_hash,
        suite=selected_suite,
    )
    confirmation_key = _derive_pq_confirmation_key(shared, transcript_hash, selected_suite)
    raw_initiator_confirmation = await read_frame(reader)
    initiator_tag = _verify_pq_confirmation(
        raw_initiator_confirmation,
        confirmation_key=confirmation_key,
        transcript_hash=transcript_hash,
        suite=selected_suite,
        role=b"I",
    )
    responder_confirmation = _build_pq_confirmation(
        confirmation_key=confirmation_key,
        transcript_hash=transcript_hash,
        suite=selected_suite,
        role=b"R",
        prior_tag=initiator_tag,
    )
    await write_frame(writer, responder_confirmation)

    k_i_to_r, k_r_to_i = _derive_keys(shared, hello.nonce + nonce_r, transcript_hash)
    return Channel(
        reader=reader,
        writer=writer,
        peer_ed_pub=hello.initiator_ed,
        peer_short_id=fingerprint_of(hello.initiator_ed)[:8],
        tx_aead=ChaCha20Poly1305(k_r_to_i),
        rx_aead=ChaCha20Poly1305(k_i_to_r),
        transcript_hash=transcript_hash,
        handshake_version=PQ_HANDSHAKE_VERSION,
        handshake_suite=PQ_HYBRID_HANDSHAKE_CAP,
        pq_protected=True,
        key_confirmed=True,
        _dr_role="bob",
        _dr_x_priv=x_priv,
        _dr_peer_x_pub=hello.initiator_x25519,
        _dr_shared=shared,
    )


def _legacy_handshake_override_enabled(explicit: bool | None) -> bool:
    if explicit is not None:
        return explicit
    return (
        os.environ.get("ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE") == "1"
        or os.environ.get("ONE_LINK_ALLOW_V1_HELLO") == "1"
    )


def configured_handshake_policy() -> dict[str, object]:
    """Describe configured defaults without asserting any live session's suite.

    The receiver migration switch and explicit initiator downgrade arguments
    are distinct. Connection evidence lives on Channel.handshake_suite and
    Channel.pq_protected; merely advertising a capability is not that evidence.
    """
    return {
        "default_version": PQ_HANDSHAKE_VERSION,
        "default_suite": PQ_HYBRID_HANDSHAKE_CAP,
        "default_key_agreement": "X25519 + ML-KEM-768",
        "default_requires_native_pq": True,
        "classical_receiver_override": _legacy_handshake_override_enabled(None),
        "unbound_v1_migration_override": os.environ.get("ONE_LINK_ALLOW_V1_HELLO") == "1",
        "automatic_downgrade": False,
        "evidence_scope": "configured policy; inspect each channel's negotiated suite",
        "browser_webrtc_pq_qualified": False,
    }


def _reject_legacy_hello_by_policy(
    raw_hello: bytes,
    me: Identity,
    *,
    is_pinned_peer: Callable[[bytes], bool] | None,
) -> None:
    """Preserve precise malformed/signature errors, then reject valid legacy."""
    expected = 32 + 32 + NONCE_LEN + 64
    if len(raw_hello) != expected:
        raise RuntimeError(f"bad HELLO length: {len(raw_hello)}")
    initiator_ed = raw_hello[:32]
    initiator_x = raw_hello[32:64]
    nonce = raw_hello[64 : 64 + NONCE_LEN]
    signature = raw_hello[64 + NONCE_LEN :]
    if _handshake_replay_seen(initiator_ed, nonce, time.monotonic()):
        raise RuntimeError(
            "HELLO replay rejected (duplicate nonce inside "
            f"{int(_HANDSHAKE_REPLAY_WINDOW_S)} s window)"
        )
    v2 = HELLO_TAG + initiator_ed + initiator_x + nonce + me.public_bytes
    v1 = HELLO_TAG + initiator_ed + initiator_x + nonce
    if verify(initiator_ed, signature, v2):
        raise RuntimeError(
            "legacy classical handshake rejected: live channels require the "
            "versioned X25519+ML-KEM-768 suite (explicit migration override: "
            "ONE_LINK_ALLOW_CLASSICAL_HANDSHAKE=1)"
        )
    if not verify(initiator_ed, signature, v1):
        raise RuntimeError("HELLO signature invalid")
    pinned = False
    if is_pinned_peer is not None:
        try:
            pinned = bool(is_pinned_peer(initiator_ed))
        except Exception as exc:
            log.warning(
                "channel.respond: pinned-peer telemetry lookup failed: %s",
                exc,
            )
    count = _bump_v1_sig_counter(initiator_ed, is_pinned=pinned)
    log.warning(
        "channel.respond: rejected legacy v1 HELLO from %s; PQ hybrid is "
        "required. telemetry=%s v1-attempt count: %d",
        initiator_ed.hex()[:16],
        "pinned" if pinned else "unknown",
        count,
    )
    raise RuntimeError(
        "HELLO signature invalid (legacy unbound v1 is disabled; PQ hybrid required)"
    )


async def initiate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    expected_responder_ed_pub: Optional[bytes] = None,
    allow_classical_downgrade: bool = False,
    force_classical_handshake: bool = False,
) -> Channel:
    """Open an authenticated, mutually-confirmed PQ-hybrid channel.

    The default path requires the native ML-KEM runtime and never retries a
    rejected v3 flight as classical.  A legacy handshake is reachable only
    through an explicit caller decision; forcing it additionally requires the
    downgrade flag so a single accidental boolean cannot remove PQ protection.
    """
    if force_classical_handshake:
        if not allow_classical_downgrade:
            raise ValueError(
                "force_classical_handshake requires allow_classical_downgrade=True"
            )
        log.warning(
            "explicitly forcing legacy X25519-only channel handshake; this "
            "connection has no ML-KEM harvest-now-decrypt-later protection"
        )
        return await _initiate_classical(
            reader,
            writer,
            me,
            expected_responder_ed_pub=expected_responder_ed_pub,
        )
    if expected_responder_ed_pub is None:
        if os.environ.get("ONE_LINK_ALLOW_V1_HELLO") == "1":
            log.warning(
                "ONE_LINK_ALLOW_V1_HELLO explicitly selected the legacy "
                "X25519-only migration handshake; no ML-KEM protection"
            )
            return await _initiate_classical(
                reader,
                writer,
                me,
                expected_responder_ed_pub=None,
            )
        raise ValueError(
            "expected_responder_ed_pub is required for the authenticated PQ handshake; "
            "legacy unbound v1 is disabled"
        )
    try:
        return await _initiate_pq(
            reader,
            writer,
            me,
            expected_responder_ed_pub=expected_responder_ed_pub,
        )
    except Exception as exc:
        from one_link.pq_hybrid import PQUnavailableError

        if not isinstance(exc, PQUnavailableError) or not allow_classical_downgrade:
            raise
        log.warning(
            "native PQ runtime unavailable; explicit caller policy permits a "
            "legacy X25519-only handshake"
        )
        return await _initiate_classical(
            reader,
            writer,
            me,
            expected_responder_ed_pub=expected_responder_ed_pub,
        )


async def respond(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    me: Identity,
    *,
    is_pinned_peer: Callable[[bytes], bool] | None = None,
    allow_classical_downgrade: bool | None = None,
) -> Channel:
    """Accept v3 PQ channels and fail closed on legacy/classical peers."""
    raw_hello = await read_frame(reader)
    if raw_hello.startswith(PQ_HANDSHAKE_MAGIC):
        return await _respond_pq(reader, writer, me, raw_hello=raw_hello)
    if not _legacy_handshake_override_enabled(allow_classical_downgrade):
        _reject_legacy_hello_by_policy(
            raw_hello,
            me,
            is_pinned_peer=is_pinned_peer,
        )
        raise RuntimeError("unreachable legacy handshake policy state")
    log.warning(
        "explicit migration policy accepted a legacy X25519-only channel; "
        "this connection has no ML-KEM harvest-now-decrypt-later protection"
    )
    return await _respond_classical(
        reader,
        writer,
        me,
        is_pinned_peer=is_pinned_peer,
        hello=raw_hello,
    )
