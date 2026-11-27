"""Call lifecycle orchestration behind an explicit daemon port.

The daemon owns peers, sessions, trust and capability policy, and transport.
This module owns what happens *to a call* between those systems:

* inbound wire dispatch for ``CALL_*`` / ``RECORDING_*`` frames (manager
  admission, SAS gating of first-contact calls, kind/capability enforcement);
* the bounded pre-invite SDP/ICE backfill and its provisional admissions;
* flushing ``CallAPI``/``CallManager`` outputs into wire delivery and UI tail
  events, including registry reaping of completed calls;
* restart-resumable call persistence (``CallResumeLedger``);
* invite-timer expiry and the registry maintenance step of the immune tick;
* reliable call-signal delivery with a fresh-channel fallback.

``CallLifecycleService`` talks to the daemon only through
:class:`CallLifecyclePort`. Every policy that belongs to another subsystem is a
port operation, not logic copied here: the capability decision for a call kind,
the trust-ledger verdict for an inbound invite, pin state, peer resolution and
transport. The port is evaluated at call time, so a replaced registry, state
store or overridden daemon seam is always observed.

Ownership contracts:

* ``CallMediaBackfill`` is the single owner of the SDP/ICE caches and the
  provisional admission table. Every cache key is peer- and kind-bound,
  capability-authorized, globally and per-peer bounded, and expires on a
  monotonic TTL. Media is never evicted for a call that has a live manager.
* ``CallResumeLedger`` owns the on-disk resume file: atomic publication,
  bounded record size, age limits and tolerant decoding. A corrupt or partial
  file restores nothing; it never raises into daemon construction.
* Delivery failures, malformed outputs and broadcast failures are logged and
  skipped, exactly as the daemon did before extraction; no failure path in
  wire dispatch raises into the receive loop.

Compatibility: ``Daemon`` keeps a thin adapter under every historical method
name that still has a caller (source or test) and exposes the backfill/ledger
state under its historical attribute names. Internal calls between the
operations below stay inside the service; a daemon-level override intercepts
external callers, and the explicit seams in the port (``save_resume_ledger``,
``send_to``, ``send_control``, ``call_capability_allowed``,
``trust_decision_for_inbound``, ``is_pinned``, ``broadcast_tail``,
``resolve_peer_for_outbound``, ``resolve_for_send``, ``peer_fp_from_peer``)
intercept the service itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional, Protocol, Sequence

from one_link.fault_observability import report_best_effort_failure
from one_link.pairing import compute_sas_words, format_sas_words
from one_link.wire import encode_msg, make_msg

_module_log = logging.getLogger(__name__)

#: Wire types whose delivery is idempotent by ``call_id`` and may therefore be
#: retried once over a fresh control channel.
CALL_SIGNAL_RETRYABLE_TYPES: frozenset[str] = frozenset(
    {
        "CALL_INVITE",
        "CALL_ACCEPT",
        "CALL_DECLINE",
        "CALL_END",
        "CALL_SDP_OFFER",
        "CALL_SDP_ANSWER",
        "CALL_ICE",
        "CALL_FRAME_ATTEST",
        "RECORDING_START",
        "RECORDING_STOP",
        "SAS_CONFIRM",
        "SAS_DECLINE",
    }
)

#: Wire types that map 1:1 onto a ``ManagerEventKind`` once a manager exists.
_WIRE_EVENT_KINDS: Mapping[str, str] = {
    "CALL_DECLINE": "WIRE_CALL_DECLINE",
    "CALL_END": "WIRE_CALL_END",
    "CALL_RESUME_OFFER": "WIRE_RESUME_OFFER",
    "RECORDING_REQUEST": "WIRE_RECORDING_REQUEST",
    "RECORDING_GRANT": "WIRE_RECORDING_GRANT",
    "RECORDING_DECLINE": "WIRE_RECORDING_DECLINE",
    "RECORDING_STOP": "WIRE_RECORDING_STOP",
}

CAPSULE_TRANSPORT_TYPES: frozenset[str] = frozenset(
    {"CAPSULE_OFFER", "CAPSULE_CHUNK", "CAPSULE_COMPLETE", "CAPSULE_RECEIPT"}
)

_LIVE_PHASES = frozenset({"INVITING", "RINGING", "ACTIVE", "ASYNC_CAPTURE"})


# ─── ports ─────────────────────────────────────────────────────────────


class CallRegistryPort(Protocol):
    """The ``CallManagerRegistry`` operations call orchestration uses."""

    def get(self, call_id: str) -> Any | None: ...

    def get_for_peer(self, call_id: str, peer_master_vk_hex: str) -> Any | None: ...

    def open(
        self,
        *,
        call_id: str,
        peer_master_vk_hex: str,
        local_role: str,
        local_master_vk_hex: str,
        started_at_ms: int,
        negotiated_capabilities: frozenset[str] = frozenset(),
        call_kind: str = "voice",
    ) -> Any: ...

    def close(self, call_id: str) -> None: ...

    def active_call_ids(self) -> Sequence[str]: ...

    def reap_stale_pending(self) -> Sequence[str]: ...


class CallEventRecorder(Protocol):
    """The reliability-backend surface used during resume restoration."""

    def record_event(self, event: dict[str, Any]) -> Any: ...


@dataclass(frozen=True)
class CallLifecyclePolicy:
    """Bounds read from the daemon for each operation (instance-overridable)."""

    preinvite_ttl_s: float = 30.0
    preinvite_cache_max: int = 64
    preinvite_cache_per_peer_max: int = 4
    signal_send_timeout_s: float = 6.0
    ice_backfill_max: int = 32
    resume_max_age_ms: int = 12 * 60 * 60 * 1000


class CallLifecyclePort(Protocol):
    """Exactly what call orchestration needs from the daemon."""

    # identity
    def local_short_id(self) -> str: ...

    def local_fingerprint(self) -> str: ...

    def local_public_bytes(self) -> bytes: ...

    # call engines
    def call_registry(self) -> CallRegistryPort: ...

    def call_reliability(self) -> CallEventRecorder: ...

    def call_policy(self) -> CallLifecyclePolicy: ...

    # decisions owned by other daemon subsystems
    def call_capability_allowed(self, peer_fp: str, call_kind: str) -> bool: ...

    def trust_decision_for_inbound(self, peer_fp: str) -> Any | None: ...

    def is_pinned(self, peer_fp: str) -> bool: ...

    # peer resolution and transport
    def resolve_peer_for_outbound(self, peer_fp: str) -> Any | None: ...

    async def resolve_for_send(self, peer_fp: str) -> Any | None: ...

    def peer_fp_from_peer(self, peer: Any) -> str | None: ...

    def live_inbound_channels(self, peer_fp: str) -> Sequence[Any]: ...

    async def send_to(self, peer: Any, msgs: list[dict]) -> Any: ...

    async def send_control(self, peer: Any, msg: dict) -> Any: ...

    # side effects owned elsewhere
    def broadcast_tail(self, event: dict) -> None: ...

    def save_resume_ledger(self) -> None: ...

    async def commit_outbound_capsule(self, mgr: Any, capsule: Any) -> None: ...

    async def handle_capsule_transport_message(
        self, *, channel: Any, msg: dict, peer_fp: str
    ) -> None: ...

    def open_predictive_call(self, call_id: str) -> None: ...


class CallClock(Protocol):
    def monotonic(self) -> float: ...

    def wall_ms(self) -> int: ...


class SystemCallClock:
    """Reads the process clocks at call time (so patched clocks are honored)."""

    def monotonic(self) -> float:
        return time.monotonic()

    def wall_ms(self) -> int:
        return int(time.time() * 1000)


# ─── owned state ───────────────────────────────────────────────────────


class CallMediaBackfill:
    """Latest SDP per call, recent ICE per call, and provisional admissions.

    ``admissions`` maps a not-yet-invited ``call_id`` to
    ``(peer_fp, call_kind, admitted_at_monotonic)`` in LRU order.
    """

    def __init__(self) -> None:
        self.sdp: dict[str, dict[str, str]] = {}
        self.ice: dict[str, list[dict]] = {}
        self.admissions: OrderedDict[str, tuple[str, str, float]] = OrderedDict()

    def media_for(self, call_id: str) -> tuple[dict[str, str], list[dict]]:
        return dict(self.sdp.get(call_id, {})), list(self.ice.get(call_id, []))

    def discard(self, call_id: str) -> None:
        self.admissions.pop(call_id, None)
        self.sdp.pop(call_id, None)
        self.ice.pop(call_id, None)


class CallResumeLedger:
    """Atomic, tolerant persistence of restart-resumable call records."""

    VERSION = 1

    def __init__(
        self,
        path: Path,
        *,
        enabled: bool = True,
        replace: Callable[[Path, Path], None] | None = None,
    ) -> None:
        self.path = Path(path)
        self.enabled = bool(enabled)
        self.lock = threading.Lock()
        self._replace = replace if replace is not None else os.replace

    def write(self, records: list[dict], *, now_ms: int) -> None:
        """Publish *records* atomically. Errors propagate to the caller."""

        payload = {"version": self.VERSION, "saved_at_ms": int(now_ms), "calls": records}
        path = self.path
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
        try:
            tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            self._replace(tmp, path)
        except BaseException:
            # A failed publication leaves the previous ledger authoritative
            # and must not accumulate private temporary files.
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise

    def read(self) -> list[Any] | None:
        """Return the stored record list, or ``None`` for absent/invalid files."""

        if not self.path.is_file():
            return None
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        calls = payload.get("calls")
        if not isinstance(calls, list):
            return None
        return calls


# ─── service ───────────────────────────────────────────────────────────


class CallLifecycleService:
    """Own call admission, media backfill, output flushing and resume state."""

    def __init__(
        self,
        port: CallLifecyclePort,
        *,
        ledger: CallResumeLedger,
        backfill: CallMediaBackfill | None = None,
        clock: CallClock | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.port = port
        self.ledger = ledger
        self.backfill = backfill if backfill is not None else CallMediaBackfill()
        self.clock: CallClock = clock if clock is not None else SystemCallClock()
        self.log = logger if logger is not None else _module_log

    # ── kind / admission ─────────────────────────────────────────────

    def call_kind_for_payload(
        self,
        *,
        msg: dict,
        call_id: str,
        sdp_payload: Any = None,
    ) -> str:
        """Resolve and verify a call kind against bound state and SDP truth."""

        from one_link.call_manager import normalize_call_kind

        explicit = None
        if "call_kind" in msg:
            explicit = normalize_call_kind(msg.get("call_kind"))
        video_sdp = False
        if sdp_payload is not None:
            normalized_sdp = str(sdp_payload.sdp).replace("\r", "\n").lower()
            video_sdp = any(
                line.strip().startswith("m=video") for line in normalized_sdp.split("\n")
            )

        bound_kind = None
        mgr = self.port.call_registry().get(call_id)
        if mgr is not None:
            bound_kind = mgr.state.call_kind
        else:
            admission = self.backfill.admissions.get(call_id)
            if admission is not None:
                bound_kind = admission[1]

        if explicit is not None and bound_kind is not None and explicit != bound_kind:
            raise ValueError("call kind conflicts with bound call")
        if video_sdp and explicit == "voice":
            raise ValueError("voice call cannot carry video media")
        if video_sdp and bound_kind == "voice":
            raise ValueError("voice call cannot carry video media")
        if bound_kind is not None:
            return bound_kind
        if explicit is not None:
            return explicit
        return "video" if video_sdp else "voice"

    def prune_backfill_admissions(self) -> tuple[str, ...]:
        now = self.clock.monotonic()
        ttl_s = self.port.call_policy().preinvite_ttl_s
        admissions = self.backfill.admissions
        expired: list[str] = []
        for call_id, (_peer_fp, _kind, admitted_at) in tuple(admissions.items()):
            if max(0.0, now - admitted_at) < ttl_s:
                continue
            expired.append(call_id)
            admissions.pop(call_id, None)
            # Never evict media for a manager that was promoted but whose
            # provisional admission survived an interrupted cleanup.
            if self.port.call_registry().get(call_id) is None:
                self.backfill.sdp.pop(call_id, None)
                self.backfill.ice.pop(call_id, None)
        return tuple(expired)

    def admit_backfill(
        self,
        *,
        call_id: str,
        peer_fp: str,
        call_kind: str,
        trust_checked: bool = False,
    ) -> bool:
        """Authorize and reserve one bounded pre-invite media namespace."""

        from one_link.call_manager import (
            CallIdentityMismatchError,
            normalize_call_kind,
            validate_call_id,
        )

        try:
            call_id = validate_call_id(call_id)
            call_kind = normalize_call_kind(call_kind)
        except (TypeError, ValueError):
            return False
        self.prune_backfill_admissions()
        try:
            mgr = self.port.call_registry().get_for_peer(call_id, peer_fp)
        except (CallIdentityMismatchError, ValueError):
            return False
        if mgr is not None:
            return mgr.state.call_kind == call_kind and self.port.call_capability_allowed(
                peer_fp, call_kind
            )

        admissions = self.backfill.admissions
        existing = admissions.get(call_id)
        if existing is not None:
            if existing[0] != peer_fp or existing[1] != call_kind:
                return False
            if not self.port.call_capability_allowed(peer_fp, call_kind):
                return False
            admissions.move_to_end(call_id)
            return True

        # Reject a new namespace at the cheap bounded-admission layer before
        # consulting disk-backed trust/capability state.
        policy = self.port.call_policy()
        if len(admissions) >= policy.preinvite_cache_max:
            return False
        peer_entries = sum(
            1 for admitted_peer, _kind, _at in admissions.values() if admitted_peer == peer_fp
        )
        if peer_entries >= policy.preinvite_cache_per_peer_max:
            return False
        if not trust_checked:
            decision = self.port.trust_decision_for_inbound(peer_fp)
            if decision is None:
                if not self.port.is_pinned(peer_fp):
                    return False
            elif not decision.allow_call:
                return False
        if not self.port.call_capability_allowed(peer_fp, call_kind):
            return False
        admissions[call_id] = (peer_fp, call_kind, self.clock.monotonic())
        return True

    def promote_backfill(self, call_id: str) -> None:
        self.backfill.admissions.pop(call_id, None)

    def remove_backfill(self, call_id: str) -> None:
        self.backfill.discard(call_id)

    def media_cache_is_bound(self, *, call_id: str, peer_fp: str) -> bool:
        from one_link.call_manager import CallIdentityMismatchError

        try:
            if self.port.call_registry().get_for_peer(call_id, peer_fp) is not None:
                return True
        except (CallIdentityMismatchError, ValueError):
            return False
        admission = self.backfill.admissions.get(call_id)
        return admission is not None and admission[0] == peer_fp

    # ── media forwarding ─────────────────────────────────────────────

    def forward_sdp_to_ui(
        self,
        *,
        call_id: str,
        peer_master_vk_hex: str,
        kind: str,
        sdp_payload: Any,
    ) -> None:
        """Cache the latest SDP for the call and push it to the browser tail."""

        if sdp_payload is None:
            return
        if not self.media_cache_is_bound(call_id=call_id, peer_fp=peer_master_vk_hex):
            self.log.warning(
                "refusing unbound SDP cache write for call=%s peer=%s",
                call_id[:8],
                peer_master_vk_hex[:8],
            )
            return
        try:
            self.backfill.sdp.setdefault(call_id, {})[kind] = sdp_payload.sdp
            self.port.save_resume_ledger()
            self.port.broadcast_tail({
                "type": "call_event",
                "tail_kind": kind,
                "call_id": call_id,
                "peer_master_vk_hex": peer_master_vk_hex,
                "sdp": sdp_payload.sdp,
                "sdp_kind": sdp_payload.kind.to_str(),
            })
        except Exception as exc:
            self.log.warning(
                "SDP cache/broadcast failed for call=%s kind=%s: %s",
                call_id,
                kind,
                exc,
            )

    def forward_ice_to_ui(
        self,
        *,
        call_id: str,
        peer_master_vk_hex: str,
        candidate_payload: Any,
    ) -> None:
        """Cache (bounded) and broadcast a browser ICE candidate.

        ICE often arrives before the remote browser has accepted the call or
        before a WebSocket is attached; the backfill makes setup recoverable
        instead of depending on perfect event ordering.
        """

        if not self.media_cache_is_bound(call_id=call_id, peer_fp=peer_master_vk_hex):
            self.log.warning(
                "refusing unbound ICE cache write for call=%s peer=%s",
                call_id[:8],
                peer_master_vk_hex[:8],
            )
            return
        try:
            ev = {
                "type": "call_event",
                "tail_kind": "ice_candidate",
                "call_id": call_id,
                "peer_master_vk_hex": peer_master_vk_hex,
                "candidate": candidate_payload.candidate,
                "sdp_mid": candidate_payload.sdp_mid,
                "sdp_m_line_index": candidate_payload.sdp_m_line_index,
                "end_of_candidates": candidate_payload.end_of_candidates,
            }
            pending = self.backfill.ice.setdefault(call_id, [])
            pending.append({
                "candidate": ev["candidate"],
                "sdp_mid": ev["sdp_mid"],
                "sdp_m_line_index": ev["sdp_m_line_index"],
                "end_of_candidates": ev["end_of_candidates"],
            })
            del pending[: -self.port.call_policy().ice_backfill_max]
            self.port.save_resume_ledger()
            self.port.broadcast_tail(ev)
        except Exception as exc:
            self.log.warning(
                "ICE cache/broadcast failed for call=%s: %s",
                call_id,
                exc,
            )

    # ── output flushing ──────────────────────────────────────────────

    def _group_wire_messages(
        self,
        messages: Iterable[Any],
        *,
        malformed: str,
        make_failed: str,
    ) -> dict[str, list[dict]]:
        by_peer: dict[str, list[dict]] = {}
        for m in messages:
            try:
                peer_fp = m.peer_master_vk_hex
                msg_type = m.type
                payload = dict(m.payload or {})
            except Exception as exc:
                self.log.warning(malformed, exc)
                continue
            try:
                wire_msg = make_msg(msg_type, self.port.local_short_id(), **payload)
            except Exception as exc:
                self.log.warning(make_failed, msg_type, exc)
                continue
            by_peer.setdefault(peer_fp, []).append(wire_msg)
        return by_peer

    async def flush_api_response(self, response: Any) -> tuple[str, ...]:
        """Deliver a ``CallAPI`` response: outbound wire, tail events, reaping.

        Returns the peers (deduped, in first-seen order) whose messages were
        handed to call-signal delivery without raising. Unknown peers,
        malformed payloads and delivery failures are logged and skipped.
        """

        if response is None:
            return ()
        finalized_capsule = getattr(response, "finalized_capsule", None)
        if finalized_capsule is not None:
            mgr = self.port.call_registry().get(finalized_capsule.call_id)
            await self.port.commit_outbound_capsule(mgr, finalized_capsule)
        delivered: list[str] = []

        outbound = getattr(response, "outbound", ()) or ()
        if outbound:
            by_peer = self._group_wire_messages(
                outbound,
                malformed="flush_call_api: malformed outbound message: %s",
                make_failed="flush_call_api: make_msg failed for %s: %s",
            )
            for peer_fp, msgs in by_peer.items():
                peer = self.port.resolve_peer_for_outbound(peer_fp)
                if peer is None:
                    self.log.warning(
                        "flush_call_api: no peer record for %s; dropping %d outbound msg(s)",
                        peer_fp[:16],
                        len(msgs),
                    )
                    continue
                try:
                    await self.send_call_signal(peer, msgs)
                except Exception as exc:
                    self.log.warning(
                        "flush_call_api: call signal delivery failed for %s: %s",
                        peer_fp[:16],
                        exc,
                    )
                    continue
                delivered.append(peer_fp)

        for ev in getattr(response, "tail_events", ()) or ():
            try:
                payload = dict(ev.payload or {})
                payload.setdefault("call_id", response.call_id)
                if response.call_id:
                    mgr = self.port.call_registry().get(response.call_id)
                    if mgr is not None:
                        payload.setdefault("peer_master_vk_hex", mgr.state.peer_master_vk_hex)
                        payload.setdefault("call_kind", mgr.state.call_kind)
                self.port.broadcast_tail({
                    "type": "call_event",
                    "tail_kind": ev.kind.name.lower(),
                    **payload,
                })
            except Exception as exc:
                self.log.warning("flush_call_api: broadcast_tail failed: %s", exc)

        if getattr(response, "call_complete", False) and response.call_id:
            try:
                self.remove_backfill(response.call_id)
                self.port.call_registry().close(response.call_id)
            except Exception as exc:
                report_best_effort_failure(
                    self.log,
                    "completed_call_registry_close",
                    exc,
                )
        self.port.save_resume_ledger()
        return tuple(delivered)

    async def _deliver_grouped(self, by_peer: dict[str, list[dict]], *, failure: str) -> None:
        timeout = self.port.call_policy().signal_send_timeout_s
        for peer_fp, msgs in by_peer.items():
            peer = self.port.resolve_peer_for_outbound(peer_fp)
            if peer is None:
                continue
            try:
                await asyncio.wait_for(self.port.send_to(peer, msgs), timeout=timeout)
            except Exception as exc:
                self.log.warning(failure, peer_fp[:8], exc)
                continue

    async def flush_manager_output(self, mgr: Any, output: Any) -> None:
        """Side-effect step for one ``ManagerOutput``.

        Mirrors :meth:`flush_api_response` for the manager's own field names
        (``outbound_msgs`` and ``consent_msgs``), which travel over the
        reusable session under the call-signal timeout.
        """

        finalized_capsule = getattr(output, "finalized_capsule", None)
        if finalized_capsule is not None:
            await self.port.commit_outbound_capsule(mgr, finalized_capsule)

        outbound = getattr(output, "outbound_msgs", ()) or ()
        if outbound:
            await self._deliver_grouped(
                self._group_wire_messages(
                    outbound,
                    malformed="flush_manager_output: malformed outbound: %s",
                    make_failed="flush_manager_output: make_msg failed for %s: %s",
                ),
                failure="call signaling delivery failed for %s: %s",
            )

        # Consent-channel messages (RECORDING_*) ride the same path.
        consent = getattr(output, "consent_msgs", ()) or ()
        if consent:
            await self._deliver_grouped(
                self._group_wire_messages(
                    consent,
                    malformed="flush_manager_output: malformed consent message: %s",
                    make_failed="flush_manager_output: consent make_msg failed for %s: %s",
                ),
                failure="recording-consent delivery failed for %s: %s",
            )

        call_id = getattr(mgr, "call_id", "")
        for ev in getattr(output, "tail_events", ()) or ():
            try:
                payload = dict(ev.payload or {})
                payload.setdefault("call_id", call_id)
                payload.setdefault(
                    "peer_master_vk_hex",
                    getattr(getattr(mgr, "state", None), "peer_master_vk_hex", ""),
                )
                payload.setdefault(
                    "call_kind",
                    getattr(getattr(mgr, "state", None), "call_kind", "voice"),
                )
                self.port.broadcast_tail({
                    "type": "call_event",
                    "tail_kind": ev.kind.name.lower(),
                    **payload,
                })
            except Exception as exc:
                self.log.warning(
                    "call tail event broadcast failed for call=%s: %s",
                    call_id,
                    exc,
                )

        if getattr(output, "call_complete", False):
            try:
                self.remove_backfill(getattr(mgr, "call_id", ""))
                self.port.call_registry().close(getattr(mgr, "call_id", ""))
            except Exception as exc:
                self.log.warning(
                    "completed call cleanup failed for call=%s: %s",
                    getattr(mgr, "call_id", ""),
                    exc,
                )
        self.port.save_resume_ledger()

    async def handle_manager_output(self, mgr: Any, event: Any) -> None:
        """Run one event through a ``CallManager`` and flush the result."""

        try:
            output = mgr.handle(event)
        except Exception as exc:
            self.log.warning("CallManager.handle raised on %s: %s", event.kind.name, exc)
            return
        try:
            await self.flush_manager_output(mgr, output)
        except Exception as exc:
            self.log.warning("flush_manager_output raised for %s: %s", event.kind.name, exc)

    # ── timers and registry maintenance ──────────────────────────────

    async def expire_invite_if_due(self, mgr: Any, *, now_ms: int) -> bool:
        """Drive the FSM timer for an unanswered outbound/inbound invite."""

        from one_link.call_manager import ManagerEvent, ManagerEventKind

        lifecycle = mgr.state.lifecycle
        if lifecycle.phase.name not in {"INVITING", "RINGING"}:
            return False
        timer_started_ms = lifecycle.invite_sent_at_ms or lifecycle.started_at_ms
        if timer_started_ms <= 0 or now_ms - timer_started_ms < lifecycle.invite_timeout_ms:
            return False
        timeout_output = mgr.handle(
            ManagerEvent(kind=ManagerEventKind.INVITE_TIMER_EXPIRED, occurred_at_ms=now_ms)
        )
        await self.flush_manager_output(mgr, timeout_output)
        return True

    def maintain_registry(self) -> tuple[str, ...]:
        """Expire provisional media, reap stale pending calls, persist, list.

        Returns the active call ids for this tick. Exceptions propagate so the
        tick loop can account for a broken registry once per interval.
        """

        self.prune_backfill_admissions()
        registry = self.port.call_registry()
        stale_call_ids = registry.reap_stale_pending()
        for stale_call_id in stale_call_ids:
            self.remove_backfill(stale_call_id)
        if stale_call_ids:
            self.port.save_resume_ledger()
        return tuple(registry.active_call_ids())

    @staticmethod
    def is_live_phase(mgr: Any) -> bool:
        return mgr.phase.name in _LIVE_PHASES

    # ── call-signal delivery ─────────────────────────────────────────

    @staticmethod
    def call_signal_retryable(msgs: list[dict]) -> bool:
        """Call signaling is keyed by call_id, so a one-shot fresh-session
        retry is safe when the reusable session closed before ACK. Never do
        this for chat/file frames, where a duplicate would be user-visible.
        """

        if not msgs:
            return False
        return all(str(m.get("t") or "") in CALL_SIGNAL_RETRYABLE_TYPES for m in msgs)

    async def send_call_signal(self, peer: Any, msgs: list[dict]) -> None:
        """Deliver call signaling over the strongest available path.

        The reusable encrypted session is tried first under the call-signal
        timeout. If it fails and every frame is idempotent, each frame is sent
        best-effort over the newest live inbound channel, then over a fresh
        encrypted control channel. A fresh-channel failure is raised only when
        no live channel accepted the frames.
        """

        timeout = self.port.call_policy().signal_send_timeout_s
        try:
            await asyncio.wait_for(self.port.send_to(peer, msgs), timeout=timeout)
            return
        except Exception as exc:
            if not self.call_signal_retryable(msgs):
                raise
            self.log.info(
                "call_signal: reusable session failed for %s; trying "
                "reverse/fresh control channel: %s",
                getattr(peer, "short_id", "?"),
                exc,
            )
        peer_fp = self.port.peer_fp_from_peer(peer)
        live_sent = False
        if peer_fp:
            live = list(self.port.live_inbound_channels(peer_fp))
            for channel in reversed(live):
                try:
                    for msg in msgs:
                        await asyncio.wait_for(channel.send(encode_msg(msg)), timeout=timeout)
                    live_sent = True
                    self.log.debug(
                        "call_signal: sent best-effort reverse frame(s) "
                        "over existing channel for %s",
                        peer_fp[:8],
                    )
                    break
                except Exception as exc:
                    report_best_effort_failure(
                        self.log,
                        "call_signal_existing_channel",
                        exc,
                        level=logging.DEBUG,
                        interval_s=30.0,
                    )
                    continue
        last_exc: Exception | None = None
        if peer_fp:
            with contextlib.suppress(Exception):
                fresh = await self.port.resolve_for_send(peer_fp)
                if fresh is not None:
                    peer = fresh
        for msg in msgs:
            try:
                await asyncio.wait_for(self.port.send_control(peer, msg), timeout=timeout)
            except Exception as exc:
                last_exc = exc
                break
        if last_exc is not None:
            if live_sent:
                self.log.info(
                    "call_signal: fresh control failed for %s after best-effort reverse send: %s",
                    getattr(peer, "short_id", "?"),
                    last_exc,
                )
                return
            raise last_exc

    # ── inbound wire dispatch ────────────────────────────────────────

    def _refuse_call(self, *, call_id: str, peer_fp: str, user_message: str) -> None:
        self.port.broadcast_tail({
            "type": "call_event",
            "tail_kind": "call_refused",
            "call_id": call_id,
            "peer_master_vk_hex": peer_fp,
            "user_message": user_message,
        })

    def _first_contact_sas_words(self, channel: Any) -> str:
        """Transcript-bound five-word phrase; raises when it cannot be made."""

        transcript = getattr(channel, "transcript_hash", None)
        if not isinstance(transcript, (bytes, bytearray, memoryview)):
            raise TypeError("channel transcript hash is unavailable")
        transcript_bytes = bytes(transcript)
        if len(transcript_bytes) != 32:
            raise ValueError("channel transcript hash must be 32 bytes")
        return format_sas_words(
            compute_sas_words(
                self.port.local_public_bytes(),
                channel.peer_ed_pub,
                transcript_hash=transcript_bytes,
            )
        )

    async def _admit_inbound_invite(
        self,
        *,
        channel: Any,
        msg: dict,
        peer_fp: str,
        call_id: str,
        now_ms: int,
    ) -> None:
        from one_link.call_manager import CallRegistryError, ManagerEvent, ManagerEventKind
        from one_link.call_sdp_signaling import extract_offer

        # Parse every optional media field before allocating a manager. A
        # malformed attached offer is a malformed invite, not a valid ring
        # event with its attacker-controlled body silently ignored.
        try:
            sdp_offer = extract_offer(msg)
            call_kind = self.call_kind_for_payload(msg=msg, call_id=call_id, sdp_payload=sdp_offer)
        except Exception as exc:
            self.log.warning("living-presence: CALL_INVITE %s malformed: %s", call_id[:8], exc)
            return
        # Audit C2: route the inbound identity through the TrustLedger BEFORE
        # opening a manager. A refusal never instantiates a CallManager.
        decision = self.port.trust_decision_for_inbound(peer_fp)
        if decision is None and not self.port.is_pinned(peer_fp):
            # Verifier failures must not become an implicit allow. Pinned
            # (SAS-authenticated) peers keep service; first contact waits.
            self._refuse_call(
                call_id=call_id,
                peer_fp=peer_fp,
                user_message=(
                    "Identity verification is temporarily unavailable. "
                    "Please retry before connecting."
                ),
            )
            self.log.warning(
                "CALL_INVITE refused from unpinned peer %s because "
                "trust verification was unavailable",
                peer_fp[:8],
            )
            return
        if decision is not None and not decision.allow_call:
            self._refuse_call(call_id=call_id, peer_fp=peer_fp, user_message=decision.explanation)
            self.log.info(
                "CALL_INVITE refused by trust ledger from %s: %s",
                peer_fp[:8],
                getattr(getattr(decision, "new_state", None), "name", "deny"),
            )
            return
        call_sas_words: Optional[str] = None
        if decision is not None and decision.needs_reverify:
            # First-contact calls are allowed only when the user can verify the
            # same transcript-bound phrase on both endpoints. A missing or
            # invalid transcript refuses the call instead of degrading to TOFU.
            try:
                call_sas_words = self._first_contact_sas_words(channel)
            except (AttributeError, TypeError, ValueError) as exc:
                self._refuse_call(
                    call_id=call_id,
                    peer_fp=peer_fp,
                    user_message=(
                        "This first call could not create a secure "
                        "five-word verification phrase. Please reconnect "
                        "and try again."
                    ),
                )
                self.log.warning(
                    "CALL_INVITE refused from unpinned peer %s because "
                    "the transcript-bound SAS was unavailable: %s",
                    peer_fp[:8],
                    exc,
                )
                return
        already_admitted = call_id in self.backfill.admissions
        if not self.admit_backfill(
            call_id=call_id,
            peer_fp=peer_fp,
            call_kind=call_kind,
            trust_checked=True,
        ):
            self.log.info(
                "living-presence: CALL_INVITE %s from %s denied by "
                "call capability/capacity policy",
                call_id[:8],
                peer_fp[:8],
            )
            return
        try:
            mgr = self.port.call_registry().open(
                call_id=call_id,
                peer_master_vk_hex=peer_fp,
                local_role="recipient",
                local_master_vk_hex=self.port.local_fingerprint(),
                started_at_ms=now_ms,
                call_kind=call_kind,
            )
        except (CallRegistryError, ValueError) as exc:
            if not already_admitted:
                self.remove_backfill(call_id)
            self.log.warning(
                "living-presence: CALL_INVITE %s admission refused: %s",
                call_id[:8],
                exc,
            )
            return
        self.promote_backfill(call_id)
        # Open predictive continuity so the receive path can track confirm
        # ratios immediately. Idempotent and optional.
        try:
            self.port.open_predictive_call(call_id)
        except Exception as exc:
            self.log.debug("predictive continuity unavailable for call=%s: %s", call_id, exc)
        event = ManagerEvent(
            kind=ManagerEventKind.WIRE_CALL_INVITE,
            occurred_at_ms=now_ms,
            data={"peer_master_vk_hex": peer_fp, "call_kind": call_kind},
        )
        self.forward_sdp_to_ui(
            call_id=call_id,
            peer_master_vk_hex=peer_fp,
            kind="sdp_offer",
            sdp_payload=sdp_offer,
        )
        if decision is not None and decision.needs_reverify:
            assert call_sas_words is not None
            self.port.broadcast_tail({
                "type": "call_event",
                "tail_kind": "sas_verification_required",
                "call_id": call_id,
                "peer_master_vk_hex": peer_fp,
                "sas_words": call_sas_words,
                "user_message": decision.explanation,
            })
        await self.handle_manager_output(mgr, event)

    def _accept_preinvite_media(self, *, t: str, msg: dict, peer_fp: str, call_id: str) -> None:
        """SDP and ICE may race ahead of CALL_INVITE; cache and forward them."""

        from one_link.call_sdp_signaling import extract_answer, extract_offer, parse_ice_message

        label = {"CALL_SDP_OFFER": "SDP offer", "CALL_SDP_ANSWER": "SDP answer"}.get(t, "ICE")
        # One name per wire shape: an ICE candidate and an SDP body are
        # different types and take different paths below.
        ice_payload = None
        sdp_payload = None
        try:
            if t == "CALL_ICE":
                _cid, ice_payload = parse_ice_message(msg)
                call_kind = self.call_kind_for_payload(msg=msg, call_id=call_id)
            else:
                sdp_payload = extract_offer(msg) if t == "CALL_SDP_OFFER" else extract_answer(msg)
                if sdp_payload is None:
                    raise ValueError(f"missing {label}")
                call_kind = self.call_kind_for_payload(
                    msg=msg, call_id=call_id, sdp_payload=sdp_payload
                )
        except Exception as exc:
            if t == "CALL_ICE":
                self.log.warning("living-presence: CALL_ICE %s: malformed: %s", call_id[:8], exc)
            else:
                self.log.warning("living-presence: %s %s: %s", t, call_id[:8], exc)
            return
        if not self.admit_backfill(call_id=call_id, peer_fp=peer_fp, call_kind=call_kind):
            self.log.info(
                "living-presence: unauthorized %s %s from %s dropped",
                label,
                call_id[:8],
                peer_fp[:8],
            )
            return
        if t == "CALL_ICE":
            self.forward_ice_to_ui(
                call_id=call_id,
                peer_master_vk_hex=peer_fp,
                candidate_payload=ice_payload,
            )
        else:
            self.forward_sdp_to_ui(
                call_id=call_id,
                peer_master_vk_hex=peer_fp,
                kind="sdp_offer" if t == "CALL_SDP_OFFER" else "sdp_answer",
                sdp_payload=sdp_payload,
            )

    def handle_frame_attest(self, *, msg: dict, peer_fp: str, channel: Any, call_id: str) -> None:
        """Tier β: verify an inbound rolling-window FrameProvenance and tail it.

        Hash matching against locally aggregated audio happens in the browser
        (the only side that sees raw audio); the daemon verifies the sender's
        signature and forwards the attestation with its verdict.
        """

        try:
            from one_link.frame_provenance import from_wire_dict, to_ui_dict
            from one_link.live_frame_provenance import _verify_live_signature
        except Exception:
            return
        raw = msg.get("attestation")
        if not isinstance(raw, dict):
            return
        try:
            attestation = from_wire_dict(raw)
        except Exception as exc:
            self.log.warning("CALL_FRAME_ATTEST %s: malformed: %s", call_id[:8], exc)
            return
        try:
            sender_pub_bytes = channel.peer_ed_pub
        except Exception:
            return
        verified = _verify_live_signature(attestation, sender_pub_bytes)
        try:
            ui_dict = to_ui_dict(attestation, verified=verified)
        except Exception:
            return
        try:
            self.port.broadcast_tail({
                "type": "call_event",
                "tail_kind": "frame_attestation",
                "call_id": call_id,
                "peer_master_vk_hex": peer_fp,
                "verified": verified,
                **ui_dict,
            })
        except Exception as exc:
            self.log.warning(
                "frame attestation evidence broadcast failed for call=%s: %s",
                call_id,
                exc,
            )

    async def dispatch_wire_message(
        self,
        *,
        channel: Any,
        msg: dict,
        peer_fp: str,
        peer_sid: str,
    ) -> None:
        """Route one inbound call-plane frame. Never raises into the recv loop.

        ``CALL_INVITE`` opens a manager after trust, SAS, kind and capability
        admission. SDP/ICE may precede the invite and are cached under a
        bounded provisional admission. Every other frame requires an existing
        manager owned by the same peer and a still-granted capability.
        """

        from one_link.call_manager import (
            CallIdentityMismatchError,
            ManagerEvent,
            ManagerEventKind,
            validate_call_id,
        )
        from one_link.call_sdp_signaling import extract_answer

        t = msg.get("t")
        if t in CAPSULE_TRANSPORT_TYPES:
            await self.port.handle_capsule_transport_message(
                channel=channel, msg=msg, peer_fp=peer_fp
            )
            return
        try:
            call_id = validate_call_id(msg.get("call_id"))
        except (TypeError, ValueError):
            self.log.warning(
                "living-presence: %s from %s invalid call_id; dropping", t, peer_fp[:8]
            )
            return

        now_ms_ = self.clock.wall_ms()

        if t == "CALL_INVITE":
            await self._admit_inbound_invite(
                channel=channel, msg=msg, peer_fp=peer_fp, call_id=call_id, now_ms=now_ms_
            )
            return

        if t in {"CALL_SDP_OFFER", "CALL_SDP_ANSWER", "CALL_ICE"}:
            self._accept_preinvite_media(t=t, msg=msg, peer_fp=peer_fp, call_id=call_id)
            return

        # All other messages require an existing manager.
        try:
            mgr = self.port.call_registry().get_for_peer(call_id, peer_fp)
        except (CallIdentityMismatchError, ValueError):
            self.log.warning(
                "living-presence: cross-peer call-id collision for %s from %s; dropping %s",
                call_id[:8],
                peer_fp[:8],
                t,
            )
            return
        if mgr is None:
            self.log.info(
                "living-presence: %s for unknown call_id %s from %s; dropping",
                t,
                call_id[:8],
                peer_fp[:8],
            )
            return
        try:
            call_kind = self.call_kind_for_payload(msg=msg, call_id=call_id)
        except ValueError as exc:
            self.log.warning("living-presence: %s kind mismatch for %s: %s", t, call_id[:8], exc)
            return
        if not self.port.call_capability_allowed(peer_fp, call_kind):
            self.log.info(
                "living-presence: %s denied after call capability revocation for %s/%s",
                t,
                peer_fp[:8],
                call_id[:8],
            )
            return

        if t == "CALL_ACCEPT":
            try:
                # ``None`` is valid for a legacy/audio fallback; a present
                # malformed object was already rejected by extract_answer.
                sdp_answer = extract_answer(msg)
                call_kind = self.call_kind_for_payload(
                    msg=msg, call_id=call_id, sdp_payload=sdp_answer
                )
            except Exception as exc:
                self.log.warning(
                    "living-presence: CALL_ACCEPT %s: bad SDP answer: %s", call_id[:8], exc
                )
                return
            if not self.port.call_capability_allowed(peer_fp, call_kind):
                return
            event = ManagerEvent(
                kind=ManagerEventKind.WIRE_CALL_ACCEPT,
                occurred_at_ms=now_ms_,
                data={"peer_master_vk_hex": peer_fp, "call_kind": call_kind},
            )
            self.forward_sdp_to_ui(
                call_id=call_id,
                peer_master_vk_hex=peer_fp,
                kind="sdp_answer",
                sdp_payload=sdp_answer,
            )
            await self.handle_manager_output(mgr, event)
            return

        if t == "CALL_FRAME_ATTEST":
            self.handle_frame_attest(msg=msg, peer_fp=peer_fp, channel=channel, call_id=call_id)
            return

        event_kind = _WIRE_EVENT_KINDS.get(str(t))
        if event_kind is not None:
            event = ManagerEvent(
                kind=ManagerEventKind[event_kind],
                occurred_at_ms=now_ms_,
                data={"peer_master_vk_hex": peer_fp},
            )
            await self.handle_manager_output(mgr, event)

    # ── restart resume ───────────────────────────────────────────────

    def snapshot_for_resume(self, mgr: Any) -> dict | None:
        """Return a bounded, local-only call record for restart recovery."""

        try:
            lifecycle = mgr.state.lifecycle
            phase_name = lifecycle.phase.name.lower()
            if phase_name == "ended":
                return None
            call_id = str(getattr(mgr, "call_id", "") or "")
            if not call_id:
                return None
            ice_max = self.port.call_policy().ice_backfill_max
            sdp_backfill = dict(self.backfill.sdp.get(call_id, {}))
            ice_backfill = list(self.backfill.ice.get(call_id, []))[-ice_max:]
            return {
                "version": 1,
                "saved_at_ms": self.clock.wall_ms(),
                "call_id": call_id,
                "peer_master_vk_hex": str(lifecycle.peer_master_vk_hex),
                "local_role": str(lifecycle.local_role),
                "call_kind": str(getattr(mgr.state, "call_kind", "voice")),
                "local_master_vk_hex": str(self.port.local_fingerprint()),
                "negotiated_capabilities": sorted(
                    str(x) for x in mgr.state.session.negotiated_capabilities
                ),
                "lifecycle": {
                    "phase": phase_name,
                    "started_at_ms": int(lifecycle.started_at_ms),
                    "invite_sent_at_ms": int(lifecycle.invite_sent_at_ms),
                    "accepted_at_ms": int(lifecycle.accepted_at_ms),
                    "ended_at_ms": int(lifecycle.ended_at_ms),
                    "end_cause": lifecycle.end_cause.name.lower(),
                    "resume_window_close_at_ms": int(lifecycle.resume_window_close_at_ms),
                    "invite_timeout_ms": int(lifecycle.invite_timeout_ms),
                    "resume_window_ms": int(lifecycle.resume_window_ms),
                },
                "media_backfill": {"sdp": sdp_backfill, "ice": ice_backfill},
            }
        except Exception:
            return None

    def save_resume_ledger(self) -> None:
        """Persist active call truth atomically so a restart can rejoin."""

        if not self.ledger.enabled:
            return
        try:
            with self.ledger.lock:
                registry = self.port.call_registry()
                records = []
                for call_id in registry.active_call_ids():
                    mgr = registry.get(call_id)
                    if mgr is None:
                        continue
                    rec = self.snapshot_for_resume(mgr)
                    if rec is not None:
                        records.append(rec)
                self.ledger.write(records, now_ms=self.clock.wall_ms())
        except Exception as exc:
            self.log.debug("call resume ledger save failed: %s", exc)

    def restore_resume_ledger(self) -> int:
        """Restore restart-resumable call state; returns calls restored."""

        if not self.ledger.enabled:
            return 0
        try:
            calls = self.ledger.read()
        except Exception as exc:
            self.log.debug("call resume ledger load failed: %s", exc)
            return 0
        if calls is None:
            return 0
        try:
            from one_link.call_signaling import CallPhase, CallState, EndCause
        except Exception:
            return 0

        now_ms = self.clock.wall_ms()
        policy = self.port.call_policy()
        registry = self.port.call_registry()
        restored = 0
        for rec in calls:
            if not isinstance(rec, dict):
                continue
            try:
                saved_at = int(rec.get("saved_at_ms") or 0)
                if saved_at and now_ms - saved_at > policy.resume_max_age_ms:
                    continue
                call_id = str(rec.get("call_id") or "")
                peer_fp = str(rec.get("peer_master_vk_hex") or "")
                role = str(rec.get("local_role") or "")
                if not call_id or not peer_fp or role not in {"originator", "recipient"}:
                    continue
                _life = rec.get("lifecycle")
                life = _life if isinstance(_life, dict) else {}
                phase = CallPhase[str(life.get("phase") or "").upper()]
                if phase == CallPhase.ENDED:
                    continue
                end_cause_name = str(life.get("end_cause") or "unset").upper()
                end_cause = EndCause.__members__.get(end_cause_name, EndCause.UNSET)
                started_at_ms = int(life.get("started_at_ms") or saved_at or now_ms)
                mgr = registry.open(
                    call_id=call_id,
                    peer_master_vk_hex=peer_fp,
                    local_role=role,
                    local_master_vk_hex=self.port.local_fingerprint(),
                    started_at_ms=started_at_ms,
                    negotiated_capabilities=frozenset(
                        str(x) for x in (rec.get("negotiated_capabilities") or [])
                    ),
                    call_kind=str(rec.get("call_kind") or "voice"),
                )
                mgr.state.lifecycle = CallState(
                    call_id=call_id,
                    peer_master_vk_hex=peer_fp,
                    local_role=role,
                    phase=phase,
                    started_at_ms=started_at_ms,
                    invite_sent_at_ms=int(life.get("invite_sent_at_ms") or 0),
                    accepted_at_ms=int(life.get("accepted_at_ms") or 0),
                    ended_at_ms=int(life.get("ended_at_ms") or 0),
                    end_cause=end_cause,
                    resume_window_close_at_ms=int(life.get("resume_window_close_at_ms") or 0),
                    invite_timeout_ms=int(life.get("invite_timeout_ms") or 30_000),
                    resume_window_ms=int(life.get("resume_window_ms") or 600_000),
                )
                _mb = rec.get("media_backfill")
                media = _mb if isinstance(_mb, dict) else {}
                _sdp = media.get("sdp")
                sdp = _sdp if isinstance(_sdp, dict) else {}
                _ice = media.get("ice")
                ice = _ice if isinstance(_ice, list) else []
                self.backfill.sdp[call_id] = {
                    str(k): str(v)
                    for k, v in sdp.items()
                    if k in {"sdp_offer", "sdp_answer"} and isinstance(v, str)
                }
                self.backfill.ice[call_id] = [
                    item for item in ice[-policy.ice_backfill_max :] if isinstance(item, dict)
                ]
                self.port.call_reliability().record_event({
                    "call_id": call_id,
                    "event": "client_rejoin_requested",
                    "reason": "daemon_restart",
                })
                restored += 1
            except Exception as exc:
                self.log.debug("skipping call resume record: %s", exc)
                continue
        if restored:
            self.log.info("restored %d active call(s) from resume ledger", restored)
        return restored
