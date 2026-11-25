"""The /api/v1/calls route group through a fake CallRouteHost: no UIServer.

``CallAPI`` and ``CallManagerRegistry`` are the real pure engines; the host's
daemon-facing operations (capability policy, wire flush, peer records, media
backfill, route policy, tier actions, audit path) are recorded fakes.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aiohttp import web

from one_link.call_api import CallAPI
from one_link.call_manager import CallManagerRegistry, ManagerEvent, ManagerEventKind
from one_link.call_routes import (
    CallMediaAuditLog,
    CallRouter,
    call_authority_snapshot,
    sanitize_media_event,
    sanitize_media_metrics,
)

PEER = "a" * 64
ME = "b" * 64


class Reliability:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def record_event(self, event: dict) -> None:
        self.events.append(dict(event))

    def recommendation_for(self, call_id: str) -> dict:
        return {"action": "observe", "call_id": call_id}

    def session_for(self, call_id: str) -> dict:
        return {"state": "connected", "events": len(self.events)}

    def recovery_intent_for(self, call_id: str) -> dict:
        return {"intent": "none"}

    def trace_for(self, call_id: str) -> dict:
        return {"call_id": call_id, "events": list(self.events)}


class Host:
    def __init__(self, tmp_path: Path) -> None:
        self.registry = CallManagerRegistry()
        self.api = CallAPI(registry=self.registry, local_master_vk_hex=ME)
        self.reliability = Reliability()
        self.allowed = {"voice", "video"}
        self.flushed: list[Any] = []
        self.deliver = True
        self.flush_error: Exception | None = None
        self.peer: Any = SimpleNamespace(local_alias=None, display_name="Mom's laptop", hostname="mom")
        self.peer_error: Exception | None = None
        self.sdp: dict[str, dict] = {}
        self.ice: dict[str, list] = {}
        self.extension_calls: list[tuple[str, dict]] = []
        self.audit_path = tmp_path / "logs" / "call_media_audit.jsonl"

    def call_registry(self):
        return self.registry

    def call_api(self):
        return self.api

    def call_reliability(self):
        return self.reliability

    def call_capability_allowed(self, peer_fp: str, call_kind: str) -> bool:
        return call_kind in self.allowed

    async def flush_call_api_response(self, response):
        self.flushed.append(response)
        if self.flush_error is not None:
            raise self.flush_error
        if not self.deliver:
            return ()
        return tuple(dict.fromkeys(m.peer_master_vk_hex for m in response.outbound))

    def peer_record(self, peer_fp: str):
        if self.peer_error is not None:
            raise self.peer_error
        return self.peer

    def call_media_backfill(self, call_id: str):
        return dict(self.sdp.get(call_id, {})), list(self.ice.get(call_id, []))

    def webrtc_route_policy(self, call_id: str) -> dict:
        return {"mode": "auto", "call_id": call_id}

    def call_media_audit_path(self) -> Path:
        return self.audit_path

    async def dispatch_extension_action(self, action: str, body: dict):
        if action in {"send_sdp_offer", "report_metrics"}:
            self.extension_calls.append((action, body))
            return web.json_response({"ok": True, "via": action})
        return None


class Request:
    def __init__(self, body: Any = None, *, raw: bytes | None = None, call_id: str = "") -> None:
        self._body = body
        self._raw = raw
        self.match_info = {"call_id": call_id}

    async def json(self) -> Any:
        if self._raw is not None:
            return json.loads(self._raw)
        return self._body


@pytest.fixture
def host(tmp_path) -> Host:
    return Host(tmp_path)


@pytest.fixture
def router(host) -> CallRouter:
    return CallRouter(host, wall_ms=lambda: 1_700_000_000_000)


def body_of(response: web.Response) -> dict:
    return json.loads(response.body.decode("utf-8"))


def run(coro):
    return asyncio.run(coro)


def open_call(host: Host, call_id: str = "call-1", *, role: str = "recipient"):
    mgr = host.registry.open(
        call_id=call_id, peer_master_vk_hex=PEER, local_role=role,
        local_master_vk_hex=ME, started_at_ms=1_000,
    )
    if role == "recipient":
        mgr.handle(ManagerEvent(
            kind=ManagerEventKind.WIRE_CALL_INVITE, occurred_at_ms=1_000,
            data={"peer_master_vk_hex": PEER},
        ))
    return mgr


# ─── POST /api/v1/calls ────────────────────────────────────────────────


@pytest.mark.parametrize("request_obj", [Request(raw=b"{nope"), Request(["list"]), Request("text")])
def test_malformed_bodies_are_400(router, request_obj) -> None:
    response = run(router.action(request_obj))
    assert response.status == 400
    assert body_of(response) == {"ok": False, "user_message": "Request shape was unexpected."}


def test_initiate_flushes_and_reports_delivery(router, host) -> None:
    response = run(router.action(Request({"action": "initiate", "peer_master_vk_hex": PEER})))
    payload = body_of(response)
    assert payload["ok"] is True and payload["call_kind"] == "voice"
    assert payload["delivered"] == [PEER]
    assert payload["outbound"] == [{"type": "CALL_INVITE", "peer": PEER}]
    assert host.flushed and host.registry.get(payload["call_id"]) is not None


def test_initiate_unreachable_peer_says_so_plainly(router, host) -> None:
    host.deliver = False
    response = run(router.action(Request({
        "action": "initiate", "peer_master_vk_hex": PEER, "kind": "video", "peer_label": " Mom ",
    })))
    payload = body_of(response)
    assert payload["ok"] is False and payload["delivered"] == []
    assert payload["user_message"].startswith("Mom is not reachable right now.")
    assert payload["call_kind"] == "video"


def test_initiate_policy_refusals(router, host) -> None:
    bad_kind = run(router.action(Request({"action": "initiate", "peer_master_vk_hex": PEER, "kind": "hologram"})))
    assert bad_kind.status == 400
    host.allowed = {"voice"}
    denied = run(router.action(Request({"action": "initiate", "peer_master_vk_hex": PEER, "kind": "video"})))
    assert denied.status == 403 and body_of(denied)["call_kind"] == "video"
    not_a_peer = run(router.action(Request({"action": "initiate", "peer_master_vk_hex": 7})))
    assert not_a_peer.status == 403
    assert host.flushed == []


def test_flush_failure_still_answers(router, host) -> None:
    host.flush_error = RuntimeError("transport exploded")
    response = run(router.action(Request({"action": "initiate", "peer_master_vk_hex": PEER})))
    payload = body_of(response)
    assert payload["ok"] is False and payload["delivered"] == []


def test_tier_actions_are_delegated_and_unknown_actions_reach_call_api(router, host) -> None:
    response = run(router.action(Request({"action": " SEND_SDP_OFFER ", "call_id": "x"})))
    assert body_of(response) == {"ok": True, "via": "send_sdp_offer"}
    assert host.extension_calls[0][0] == "send_sdp_offer"
    unknown = run(router.action(Request({"action": "teleport"})))
    assert body_of(unknown)["ok"] is False  # CallAPI's own refusal
    assert len(host.flushed) == 1


def test_report_call_event_records_and_audits_only_safe_fields(router, host) -> None:
    missing = run(router.action(Request({"action": "report_call_event"})))
    assert body_of(missing) == {"ok": False, "user_message": "Call is no longer active."}
    response = run(router.action(Request({
        "action": "report_call_event", "call_id": "c1", "event": "OFFER_SENT",
        "reason": "metrics", "state": "connected", "media_kind": "video", "ok": True,
        "repair_stage": 9, "sdp": "v=0", "candidate": "candidate:1 1 udp 1 10.0.0.5 9 typ host",
        "peer_label": "Personal Laptop",
    })))
    assert body_of(response)["ok"] is True
    assert host.reliability.events[-1]["event"] == "OFFER_SENT"
    row = json.loads(host.audit_path.read_text(encoding="utf-8").splitlines()[-1])
    assert row == {
        "ts_ms": 1_700_000_000_000, "row_type": "event", "call_id": "c1",
        "event": "offer_sent", "reason": "metrics", "media_kind": "video",
        "state": "connected", "ok": True, "repair_stage": 3,
    }


def test_rejoin_requires_a_live_call_and_returns_restart_guidance(router, host) -> None:
    for body in ({"action": "rejoin"}, {"action": "rejoin", "call_id": "ghost"}):
        response = run(router.action(Request(body)))
        assert response.status == 404
    open_call(host, "rj-1")
    payload = body_of(run(router.action(Request({"action": "rejoin", "call_id": "rj-1"}))))
    assert payload["ok"] is True and payload["phase"] == "ringing"
    assert payload["rejoin"] == {"allowed": True, "same_call_id": True, "requires_media_restart": False}
    assert payload["session_authority"]["events"] == 1
    assert host.reliability.events[-1]["reason"] == "browser_rejoin"


# ─── reads ─────────────────────────────────────────────────────────────


LIST_KEYS = [
    "call_id", "peer_master_vk_hex", "peer_label", "local_role", "call_kind", "is_incoming",
    "pending_sdp_offer", "pending_sdp_answer", "pending_ice_candidates", "phase",
    "consent_phase", "is_active", "is_capturing", "is_resumable", "is_complete",
    "backend_authority", "path_recommendation", "media_session_authority",
    "media_recovery_intent",
]
DETAIL_KEYS = ["ok"] + LIST_KEYS[:11] + ["intensity", "current_rung", "recording_state"] + LIST_KEYS[11:]


def test_list_and_detail_snapshots_have_their_historical_shapes(router, host) -> None:
    open_call(host, "snap-1")
    host.sdp["snap-1"] = {"sdp_offer": "v=0 offer"}
    host.ice["snap-1"] = [{"candidate": "c"}]
    calls = body_of(run(router.list_calls(Request())))["calls"]
    assert len(calls) == 1 and list(calls[0]) == LIST_KEYS
    assert calls[0]["peer_label"] == "Mom's laptop"
    assert calls[0]["pending_sdp_offer"] == "v=0 offer" and calls[0]["is_incoming"] is True
    detail = body_of(run(router.call_state(Request(call_id="snap-1"))))
    assert list(detail) == DETAIL_KEYS
    assert detail["recording_state"] == 0 and detail["backend_authority"]["state"] == "ringing"


def test_peer_label_falls_back_in_order(router, host) -> None:
    host.peer = SimpleNamespace(local_alias="Mum", display_name="x", hostname="y")
    assert router.peer_label(PEER, failure_key="k") == "Mum"
    host.peer = SimpleNamespace(local_alias=None, display_name=None, hostname="desk")
    assert router.peer_label(PEER, failure_key="k") == "desk"
    host.peer = None
    assert router.peer_label(PEER, failure_key="k") == PEER[:8]
    host.peer_error = OSError("state closed")
    assert router.peer_label(PEER, failure_key="k") == PEER[:8]


def test_missing_calls_are_plain_language_404s(router) -> None:
    for handler in (router.call_state, router.call_trace):
        response = run(handler(Request(call_id="nope")))
        assert response.status == 404
        assert body_of(response) == {"ok": False, "user_message": "This call is no longer active."}


def test_trace_adds_backend_authority_and_route_policy(router, host) -> None:
    open_call(host, "tr-1")
    trace = body_of(run(router.call_trace(Request(call_id="tr-1"))))
    assert trace["backend_authority"]["phase"] == "ringing"
    assert trace["routePolicy"] == {"mode": "auto", "call_id": "tr-1"}


@pytest.mark.parametrize(
    "flags,phase,expected",
    [
        ({"is_complete": True}, "ended", "ended"),
        ({"is_resumable": True}, "resumable", "recovered"),
        ({"is_capturing": True}, "async_capture", "degraded"),
        ({"is_active": True}, "active", "connected"),
        ({}, "ringing", "ringing"),
        ({}, "inviting", "negotiating"),
        ({}, "idle", "idle"),
    ],
)
def test_authority_states(flags, phase, expected) -> None:
    mgr = SimpleNamespace(
        phase=SimpleNamespace(name=phase.upper()),
        is_complete=False, is_resumable=False, is_capturing=False, is_active=False,
    )
    for name, value in flags.items():
        setattr(mgr, name, value)
    assert call_authority_snapshot(mgr)["state"] == expected


# ─── media audit sanitizers ────────────────────────────────────────────


def test_event_sanitizer_drops_unknown_events_and_free_text() -> None:
    assert sanitize_media_event({"call_id": "c", "event": "keylogger"}, now_ms=1) is None
    assert sanitize_media_event({"event": "offer_sent"}, now_ms=1) is None
    row = sanitize_media_event(
        {"call_id": "c", "event": "offer_sent", "reason": "<script>", "repair_stage": "x"},
        now_ms=1,
    )
    assert row["reason"] is None and row["repair_stage"] is None and row["ok"] is None


def test_metrics_sanitizer_bounds_every_counter() -> None:
    row = sanitize_media_metrics({
        "call_id": "c", "ice_connection_state": "CONNECTED", "signaling_state": "evil",
        "local_audio_tracks": 99, "inbound_video_bytes": -5, "rtt_ms": float("nan"),
        "loss_rate": "0.25", "best_relay_health": "Healthy", "media_health_state": " Poor ",
        "sdp": "v=0", "candidate": "candidate:1",
    }, now_ms=5)
    assert row["ice_connection_state"] == "connected" and row["signaling_state"] is None
    assert row["local_audio_tracks"] == 32 and row["inbound_video_bytes"] == 0
    assert row["rtt_ms"] is None and row["loss_rate"] == 0.25
    assert row["best_relay_health"] == "healthy" and row["media_health_state"] == "poor"
    assert "sdp" not in row and "candidate" not in row
    assert sanitize_media_metrics({}, now_ms=5) is None


def test_audit_log_never_raises(tmp_path) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    log = CallMediaAuditLog(lambda: blocked, wall_ms=lambda: 1)  # the "file" is a directory
    assert log.append_event({"call_id": "c", "event": "offer_sent"}) is False
    assert log.append_metrics({"call_id": "c"}) is False
    ok = CallMediaAuditLog(lambda: tmp_path / "a" / "audit.jsonl", wall_ms=lambda: 1)
    assert ok.append_metrics({"call_id": "c"}) is True
    assert ok.append_event({"call_id": "c", "event": "nope"}) is False
