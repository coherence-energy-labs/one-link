"""``/api/v1/calls`` route group: lifecycle actions, snapshots, trace, media audit.

``CallRouter`` owns the HTTP contract of the owner UI's call surface:

* ``POST /api/v1/calls``: parse and dispatch one action. Lifecycle actions go
  through ``CallAPI`` and are flushed to the wire by the daemon; ``rejoin``
  and ``report_call_event`` are answered here; media-plane and telemetry tier
  actions (SDP/ICE relay, frame attestation, RTC metrics, predictive
  continuity, handoff) are delegated back to the host unchanged;
* ``GET /api/v1/calls``, ``GET /api/v1/calls/{call_id}`` and
  ``GET /api/v1/calls/{call_id}/trace``: call snapshots built by ONE
  projection (the list, detail and rejoin views previously each carried a copy
  of it), plus backend authority and media reliability state;
* the privacy-safe media audit (:class:`CallMediaAuditLog`): browser state
  machine breadcrumbs and aggregate RTC counters only, never SDP, ICE
  candidates, addresses, device or peer names, file names or content.

The router sees the UI server and daemon only through :class:`CallRouteHost`.
Route registration (literal ``add_get``/``add_post`` lines that the UI
contract gate cross-checks), authentication guards and the capsule upload
routes stay with the server.

Every response body, status code and plain-language message is identical to
the pre-extraction handlers.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol, Sequence

from aiohttp import web

from one_link.fault_observability import report_best_effort_failure

_module_log = logging.getLogger(__name__)

CALL_NOT_ACTIVE = "This call is no longer active."
CALL_GONE = "Call is no longer active."
REQUEST_SHAPE = "Request shape was unexpected."


# ─── host port ─────────────────────────────────────────────────────────


class CallRegistryView(Protocol):
    def active_call_ids(self) -> Sequence[str]: ...

    def get(self, call_id: str) -> Any | None: ...


class CallReliabilityView(Protocol):
    def record_event(self, event: dict) -> Any: ...

    def recommendation_for(self, call_id: str) -> Any: ...

    def session_for(self, call_id: str) -> Any: ...

    def recovery_intent_for(self, call_id: str) -> Any: ...

    def trace_for(self, call_id: str) -> dict: ...


class CallJsonApi(Protocol):
    def handle_json(self, body: dict) -> Any: ...


class CallRouteHost(Protocol):
    """Exactly what the call route group needs from the UI server/daemon."""

    def call_registry(self) -> CallRegistryView: ...

    def call_api(self) -> CallJsonApi: ...

    def call_reliability(self) -> CallReliabilityView: ...

    def call_capability_allowed(self, peer_fp: str, call_kind: str) -> bool: ...

    async def flush_call_api_response(self, response: Any) -> Iterable[str]: ...

    def peer_record(self, peer_fp: str) -> Any | None: ...

    def call_media_backfill(self, call_id: str) -> tuple[Mapping[str, str], Sequence[dict]]: ...

    def webrtc_route_policy(self, call_id: str) -> dict: ...

    def call_media_audit_path(self) -> Path: ...

    async def dispatch_extension_action(self, action: str, body: dict) -> web.Response | None: ...


# ─── privacy-safe media audit ──────────────────────────────────────────

MEDIA_EVENTS = frozenset(
    {
        "local_media_ready", "negotiation_starting", "offer_preparing", "offer_sent",
        "offer_send_failed", "answer_preparing", "answer_sent", "answer_send_failed",
        "answer_resend", "answer_resent", "answer_resend_failed", "offer_resend",
        "offer_resent", "offer_resend_failed", "accept_resend", "waiting_for_media_offer",
        "remote_offer_received", "remote_answer_received", "remote_track_connected",
        "remote_track_muted", "remote_track_unmuted", "remote_track_ended",
        "remote_video_metadata", "remote_video_resize", "remote_video_playing",
        "remote_video_waiting", "remote_video_stalled", "remote_video_error",
        "remote_video_no_frames", "remote_surface_synced", "media_path_repair",
        "media_path_repair_failed", "ice_restart_requested", "remote_playback_revive",
        "pc_rebuild_start", "pc_rebuild_offer_sent", "attest_recorder_start_failed",
        "microphone_changed", "microphone_change_failed", "camera_changed",
        "camera_change_failed", "audio_output_changed", "audio_output_change_failed",
        "media_device_changed", "video_fit_changed", "screen_share_started",
        "screen_share_stopped", "screen_share_failed", "screen_share_unavailable",
        "pip_started", "pip_failed", "pip_unavailable", "background_blur_changed",
        "voicemail_capsule_requested", "capsule_capture_started",
        "capsule_chunk_upload_failed", "capsule_capture_finalized",
        "capsule_capture_finalize_failed", "group_call_requested", "call_hold_started",
        "call_hold_ended", "layout_changed", "captions_started", "captions_stopped",
        "captions_failed", "captions_unavailable", "voice_processing_changed",
        "call_debug_copied", "call_debug_copy_failed", "tau_media_adapted",
        "tau_capture_adapted", "tau_capture_adapt_failed", "ice_host_only_mode",
        "ice_relay_ready", "relay_escape_requested", "remote_media_frozen",
        "network_resume_repair", "network_offline", "duplicate_remote_offer_ignored",
        "sas_words_shown", "sas_words_missing", "offer_collision",
        "offer_collision_recovery_start", "offer_collision_rollback",
        "offer_collision_rebuild", "offer_collision_recovered",
        "offer_collision_recovery_failed", "ice_state_changed",
        "backend_recommendation_received", "backend_recommendation_applied",
        "backend_recommendation_failed", "session_authority_seen", "recovery_intent_seen",
        "recovery_intent_applied", "recovery_intent_failed", "call_trace_exported",
        "call_trace_export_failed", "relay_probe_completed", "relay_probe_failed",
        "turn_credentials_refreshed", "turn_credentials_refresh_failed",
        "client_rejoin_requested", "client_rejoin_media_ready", "client_rejoin_failed",
        "auto_call_trace_captured", "auto_call_trace_failed",
    }
)
MEDIA_EVENT_REASONS = frozenset(
    {
        "start", "accept", "active", "watchdog", "metrics", "duplicate_offer",
        "offer_collision", "offer_echo", "ringing_backfill", "answered", "no_answer",
        "stalled_media", "media_path_repair", "contain", "cover", "repair",
        "renderer_detached", "playback_revive", "ice_state_changed",
        "connection_state_changed", "remote_audio_ended", "remote_video_ended", "focus",
        "split", "compact", "observe", "hold", "watch", "backend_recommendation",
        "revive_playback", "renegotiate", "audio_first_repair", "ice_restart", "downshift",
        "rebuild_peer_connection", "backend_ice_restart", "backend_renegotiate",
        "backend_audio_first_repair", "negotiating", "connected", "degraded",
        "reconnecting", "recovered", "failed", "restart_ice", "force_relay",
        "recovery_intent", "relay_probe", "credential_refresh", "credential_expiring",
        "browser_rejoin", "backfill_active", "media_rejoin", "daemon_restart",
        "auto_trace", "sustained_media_freeze", "watchdog_no_media_movement",
    }
)
MEDIA_EVENT_STATES = frozenset(
    {
        "new", "checking", "connected", "completed", "failed", "disconnected", "closed",
        "connecting", "enabled", "disabled", "full", "steady", "survival", "auto",
        "direct", "relay", "same", "negotiating", "degraded", "recovered", "audio_first",
        "healthy", "poor", "unknown",
    }
)
RTC_STATES = frozenset(
    {
        "new", "checking", "connected", "completed", "failed", "disconnected", "closed",
        "connecting", "stable", "have-local-offer", "have-remote-offer",
        "have-local-pranswer", "have-remote-pranswer", "gathering", "complete",
    }
)
RELAY_HEALTH = frozenset({"healthy", "degraded", "poor", "unknown"})
_TRACK_COUNTS = (
    "local_audio_tracks", "local_video_tracks", "local_live_audio_tracks",
    "local_live_video_tracks", "remote_audio_tracks", "remote_video_tracks",
    "remote_live_audio_tracks", "remote_live_video_tracks", "remote_muted_audio_tracks",
    "remote_muted_video_tracks",
)
_MEDIA_COUNTERS = (
    "inbound_audio_bytes", "inbound_audio_packets", "inbound_video_bytes",
    "inbound_video_packets", "inbound_video_frames_decoded", "inbound_video_frames_dropped",
    "remote_video_width", "remote_video_height", "remote_video_ready_state",
)


def _token(body: Mapping[str, Any], name: str, allowed: frozenset[str]) -> str | None:
    raw = body.get(name)
    if not isinstance(raw, str):
        return None
    clean = raw.strip().lower()
    return clean if clean in allowed else None


def _clamped_int(body: Mapping[str, Any], name: str, lo: int, hi: int) -> int | None:
    raw = body.get(name)
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return max(lo, min(value, hi))


def _finite_or_none(body: Mapping[str, Any], name: str) -> float | None:
    raw = body.get(name)
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return None if value != value else value


def sanitize_media_event(body: Mapping[str, Any], *, now_ms: int) -> dict | None:
    """Audit row for one browser media-driver event, or ``None`` to drop it.

    Only fixed slugs survive; free text from the browser never does.
    """

    call_id = str(body.get("call_id") or "")
    event = str(body.get("event") or "").strip().lower()
    if not call_id or event not in MEDIA_EVENTS:
        return None
    repair_stage = None
    if "repair_stage" in body:
        try:
            repair_stage = max(0, min(3, int(body.get("repair_stage") or 0)))
        except (TypeError, ValueError):
            repair_stage = None
    return {
        "ts_ms": int(now_ms),
        "row_type": "event",
        "call_id": call_id,
        "event": event,
        "reason": _token(body, "reason", MEDIA_EVENT_REASONS),
        "media_kind": _token(body, "media_kind", frozenset({"audio", "video"})),
        "state": _token(body, "state", MEDIA_EVENT_STATES),
        "ok": bool(body.get("ok")) if "ok" in body else None,
        "repair_stage": repair_stage,
    }


def sanitize_media_metrics(body: Mapping[str, Any], *, now_ms: int) -> dict | None:
    """Audit row of RTC state-machine and aggregate counters, or ``None``."""

    call_id = str(body.get("call_id") or "")
    if not call_id:
        return None
    health_state = body.get("media_health_state")
    best_relay = str(body.get("best_relay_health") or "").strip().lower()
    row: dict[str, Any] = {
        "ts_ms": int(now_ms),
        "row_type": "metrics",
        "call_id": call_id,
        "ice_connection_state": _token(body, "ice_connection_state", RTC_STATES),
        "connection_state": _token(body, "connection_state", RTC_STATES),
        "ice_gathering_state": _token(body, "ice_gathering_state", RTC_STATES),
        "signaling_state": _token(body, "signaling_state", RTC_STATES),
        "has_local_description": bool(body.get("has_local_description")),
        "has_remote_description": bool(body.get("has_remote_description")),
    }
    for name in _TRACK_COUNTS:
        row[name] = _clamped_int(body, name, 0, 32)
    for name in _MEDIA_COUNTERS:
        row[name] = _clamped_int(body, name, 0, 10_000_000_000)
    row.update({
        "remote_video_paused": bool(body.get("remote_video_paused")),
        "rtt_ms": _finite_or_none(body, "rtt_ms"),
        "jitter_ms": _finite_or_none(body, "jitter_ms"),
        "loss_rate": _finite_or_none(body, "loss_rate"),
        "bandwidth_estimate_kbps": _finite_or_none(body, "bandwidth_estimate_kbps"),
        "media_health_state": (
            str(health_state).strip().lower() if isinstance(health_state, str) else None
        ),
        "media_health_severity": _clamped_int(body, "media_health_severity", 0, 32),
        "remote_video_src_attached": bool(body.get("remote_video_src_attached")),
        "remote_audio_src_attached": bool(body.get("remote_audio_src_attached")),
        "ice_relay_ready": bool(body.get("ice_relay_ready")),
        "relay_escape_active": bool(body.get("relay_escape_active")),
        "best_relay_health": best_relay if best_relay in RELAY_HEALTH else None,
        "best_relay_score": _finite_or_none(body, "best_relay_score"),
    })
    return row


class CallMediaAuditLog:
    """Append-only JSONL audit of sanitized call media rows. Never raises."""

    def __init__(
        self,
        path: Callable[[], Path],
        *,
        wall_ms: Callable[[], int] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._path = path
        self._wall_ms = wall_ms if wall_ms is not None else (lambda: int(time.time() * 1000))
        self.log = logger if logger is not None else _module_log

    def _append(self, row: dict) -> None:
        path = self._path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    def append_event(self, body: Mapping[str, Any]) -> bool:
        try:
            row = sanitize_media_event(body, now_ms=self._wall_ms())
            if row is None:
                return False
            self._append(row)
            return True
        except Exception as exc:
            self.log.debug("call media event audit append failed: %s", exc)
            return False

    def append_metrics(self, body: Mapping[str, Any]) -> bool:
        try:
            row = sanitize_media_metrics(body, now_ms=self._wall_ms())
            if row is None:
                return False
            self._append(row)
            return True
        except Exception as exc:
            self.log.debug("call media audit append failed: %s", exc)
            return False


# ─── projections ───────────────────────────────────────────────────────


def call_authority_snapshot(mgr: Any) -> dict:
    """Backend authority state the browser's recovery logic keys off."""

    phase = mgr.phase.name.lower()
    if mgr.is_complete:
        authority_state = "ended"
    elif mgr.is_resumable:
        authority_state = "recovered"
    elif mgr.is_capturing:
        authority_state = "degraded"
    elif mgr.is_active:
        authority_state = "connected"
    elif phase == "ringing":
        authority_state = "ringing"
    elif phase == "inviting":
        authority_state = "negotiating"
    else:
        authority_state = phase
    return {
        "state": authority_state,
        "phase": phase,
        "is_active": bool(mgr.is_active),
        "is_resumable": bool(mgr.is_resumable),
        "is_complete": bool(mgr.is_complete),
    }


def _json_400() -> web.Response:
    return web.json_response({"ok": False, "user_message": REQUEST_SHAPE}, status=400)


# ─── router ────────────────────────────────────────────────────────────


class CallRouter:
    def __init__(
        self,
        host: CallRouteHost,
        *,
        logger: logging.Logger | None = None,
        wall_ms: Callable[[], int] | None = None,
    ) -> None:
        self.host = host
        self.log = logger if logger is not None else _module_log
        self.media_audit = CallMediaAuditLog(
            host.call_media_audit_path, wall_ms=wall_ms, logger=self.log
        )

    # ── projections ──────────────────────────────────────────────────

    def peer_label(self, peer_fp: str, *, failure_key: str) -> str:
        label = peer_fp[:8]
        try:
            rec = self.host.peer_record(peer_fp)
            if rec is not None:
                label = (
                    getattr(rec, "local_alias", None)
                    or getattr(rec, "display_name", None)
                    or getattr(rec, "hostname", None)
                    or label
                )
        except Exception as peer_exc:
            report_best_effort_failure(self.log, failure_key, peer_exc, level=logging.DEBUG)
        return label

    def snapshot(
        self,
        call_id: str,
        mgr: Any,
        *,
        detail: bool,
        failure_key: str,
    ) -> dict:
        """The one call projection. ``detail`` adds session telemetry fields."""

        peer_fp = mgr.state.peer_master_vk_hex
        local_role = mgr.state.local_role
        session = mgr.session_snapshot() if detail else None
        peer_label = self.peer_label(peer_fp, failure_key=failure_key)
        sdp_backfill, ice_backfill = self.host.call_media_backfill(call_id)
        out: dict[str, Any] = {"ok": True} if detail else {}
        out.update({
            "call_id": call_id,
            "peer_master_vk_hex": peer_fp,
            "peer_label": peer_label,
            "local_role": local_role,
            "call_kind": getattr(mgr.state, "call_kind", "voice"),
            "is_incoming": local_role == "recipient",
            "pending_sdp_offer": sdp_backfill.get("sdp_offer"),
            "pending_sdp_answer": sdp_backfill.get("sdp_answer"),
            "pending_ice_candidates": ice_backfill,
            "phase": mgr.phase.name.lower(),
            "consent_phase": mgr.consent_phase.name.lower(),
        })
        if session is not None:
            recording = session.recording_state.value
            out.update({
                "intensity": session.current_intensity.name.lower(),
                "current_rung": session.current_rung_value.name.lower(),
                "recording_state": int(recording if recording is not None else 0),
            })
        reliability = self.host.call_reliability()
        out.update({
            "is_active": mgr.is_active,
            "is_capturing": mgr.is_capturing,
            "is_resumable": mgr.is_resumable,
            "is_complete": mgr.is_complete,
            "backend_authority": call_authority_snapshot(mgr),
            "path_recommendation": reliability.recommendation_for(call_id),
            "media_session_authority": reliability.session_for(call_id),
            "media_recovery_intent": reliability.recovery_intent_for(call_id),
        })
        return out

    def _live_manager(self, call_id: object) -> Any | None:
        if not isinstance(call_id, str) or not call_id:
            return None
        return self.host.call_registry().get(call_id)

    # ── actions ──────────────────────────────────────────────────────

    def report_call_event(self, body: dict) -> web.Response:
        """Browser posts privacy-safe WebRTC state-machine breadcrumbs."""

        call_id = body.get("call_id")
        if not isinstance(call_id, str) or not call_id:
            return web.json_response({"ok": False, "user_message": CALL_GONE})
        reliability = self.host.call_reliability()
        reliability.record_event(body)
        self.media_audit.append_event(body)
        return web.json_response({
            "ok": True,
            "call_id": call_id,
            "session_authority": reliability.session_for(call_id),
            "recovery_intent": reliability.recovery_intent_for(call_id),
        })

    def rejoin(self, body: dict) -> web.Response:
        """Restore the media engine against an existing backend-owned call."""

        call_id = body.get("call_id")
        mgr = self._live_manager(call_id)
        if mgr is None or mgr.is_complete:
            return web.json_response({"ok": False, "user_message": CALL_NOT_ACTIVE}, status=404)
        assert isinstance(call_id, str)
        reliability = self.host.call_reliability()
        reliability.record_event({
            "call_id": call_id,
            "event": "client_rejoin_requested",
            "reason": str(body.get("reason") or "browser_rejoin"),
        })
        snap = self.snapshot(call_id, mgr, detail=True, failure_key="call_peer_label")
        snap["rejoin"] = {
            "allowed": bool(mgr.is_active or mgr.phase.name.lower() in {"inviting", "ringing"}),
            "same_call_id": True,
            "requires_media_restart": bool(mgr.is_active),
        }
        snap["session_authority"] = reliability.session_for(call_id)
        snap["recovery_intent"] = reliability.recovery_intent_for(call_id)
        return web.json_response(snap)

    async def action(self, request: web.Request) -> web.Response:
        """POST /api/v1/calls: dispatch one action and flush its effects."""

        try:
            body = await request.json()
        except Exception:
            return _json_400()
        if not isinstance(body, dict):
            return _json_400()
        raw_action = body.get("action")
        action_name = raw_action.strip().lower() if isinstance(raw_action, str) else ""

        if action_name == "report_call_event":
            return self.report_call_event(body)
        if action_name == "rejoin":
            return self.rejoin(body)
        extension = await self.host.dispatch_extension_action(action_name, body)
        if extension is not None:
            return extension

        if action_name == "initiate":
            from one_link.call_manager import normalize_call_kind

            try:
                call_kind = normalize_call_kind(body.get("kind"))
            except ValueError:
                return web.json_response(
                    {"ok": False, "user_message": "Choose a voice or video call."},
                    status=400,
                )
            peer_fp = body.get("peer_master_vk_hex")
            if not isinstance(peer_fp, str) or not self.host.call_capability_allowed(
                peer_fp, call_kind
            ):
                return web.json_response(
                    {
                        "ok": False,
                        "call_kind": call_kind,
                        "user_message": "That contact is not allowed to use this call type.",
                    },
                    status=403,
                )
            body = dict(body)
            body["kind"] = call_kind

        result = self.host.call_api().handle_json(body)
        delivered: tuple[str, ...] = ()
        try:
            delivered = tuple(await self.host.flush_call_api_response(result))
        except Exception as exc:
            self.log.warning("flush_call_api_response failed: %s", exc)
        outbound = [{"type": m.type, "peer": m.peer_master_vk_hex} for m in result.outbound]
        if action_name == "initiate" and result.ok and result.outbound and not delivered:
            peer_label = str(body.get("peer_label") or "That device").strip()
            return web.json_response({
                "ok": False,
                "call_id": result.call_id,
                "call_kind": result.call_kind,
                "phase": result.phase,
                "consent_phase": result.consent_phase,
                "user_message": (
                    f"{peer_label} is not reachable right now. "
                    "Open One Link on that device, then try again."
                ),
                "call_complete": result.call_complete,
                "outbound": outbound,
                "delivered": [],
            })
        # Tail events reach the UI over the WebSocket; the HTTP reply stays small.
        return web.json_response({
            "ok": result.ok,
            "call_id": result.call_id,
            "call_kind": result.call_kind,
            "phase": result.phase,
            "consent_phase": result.consent_phase,
            "user_message": result.user_message,
            "call_complete": result.call_complete,
            "outbound": outbound,
            "delivered": list(delivered),
        })

    # ── reads ────────────────────────────────────────────────────────

    async def list_calls(self, request: web.Request) -> web.Response:
        """GET /api/v1/calls: active call snapshots."""

        registry = self.host.call_registry()
        calls = []
        for call_id in registry.active_call_ids():
            mgr = registry.get(call_id)
            if mgr is None:
                continue
            calls.append(
                self.snapshot(call_id, mgr, detail=False, failure_key="call_list_peer_label")
            )
        return web.json_response({"calls": calls})

    async def call_state(self, request: web.Request) -> web.Response:
        """GET /api/v1/calls/{call_id}: one call's snapshot."""

        call_id = request.match_info.get("call_id", "")
        mgr = self.host.call_registry().get(call_id)
        if mgr is None:
            # Doctrine §3.2.f: plain language, never a "not found" code.
            return web.json_response({"ok": False, "user_message": CALL_NOT_ACTIVE}, status=404)
        return web.json_response(
            self.snapshot(call_id, mgr, detail=True, failure_key="call_detail_peer_label")
        )

    async def call_trace(self, request: web.Request) -> web.Response:
        """GET /api/v1/calls/{call_id}/trace: privacy-safe flight recorder."""

        call_id = request.match_info.get("call_id", "")
        mgr = self.host.call_registry().get(call_id)
        if mgr is None:
            return web.json_response({"ok": False, "user_message": CALL_NOT_ACTIVE}, status=404)
        trace = self.host.call_reliability().trace_for(call_id)
        trace["backend_authority"] = call_authority_snapshot(mgr)
        trace["routePolicy"] = self.host.webrtc_route_policy(call_id)
        return web.json_response(trace)
