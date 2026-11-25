"""CallLifecycleService exercised through a fake port: no Daemon, no network.

The registry is the real ``CallManagerRegistry`` engine (pure state); every
daemon-owned decision (capability, trust, pins, transport, persistence seam)
is a fake implementing ``CallLifecyclePort`` and records what it was asked.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from one_link.call_api import ApiOutboundMessage, ApiResponse
from one_link.call_lifecycle import (
    CallLifecyclePolicy,
    CallLifecycleService,
    CallMediaBackfill,
    CallResumeLedger,
)
from one_link.call_manager import (
    CallManagerRegistry,
    ManagerEvent,
    ManagerEventKind,
    TailEvent,
    TailEventKind,
)
from one_link.call_sdp_signaling import (
    CALL_INVITE_SDP_V1,
    IceCandidatePayload,
    SdpKind,
    SdpPayload,
    attach_offer_to_invite,
)
from one_link.wire import decode_msg

PEER = "a" * 64
OTHER = "c" * 64
ME = "b" * 64
OFFER_VOICE = "v=0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
OFFER_VIDEO = OFFER_VOICE + "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"


class FakeClock:
    def __init__(self) -> None:
        self.mono = 100.0
        self.wall = 1_700_000_000_000

    def monotonic(self) -> float:
        return self.mono

    def wall_ms(self) -> int:
        return self.wall


@dataclass
class Decision:
    allow_call: bool = True
    needs_reverify: bool = False
    explanation: str = "ok"
    new_state: Any = None


@dataclass
class FakeChannel:
    sent: list = field(default_factory=list)
    fail: bool = False
    transcript_hash: Any = None
    peer_ed_pub: bytes = b"\x01" * 32

    async def send(self, data: bytes) -> None:
        if self.fail:
            raise ConnectionError("channel closed")
        self.sent.append(decode_msg(data))


class FakePort:
    """Implements CallLifecyclePort; every effect is recorded."""

    def __init__(self) -> None:
        self.registry = CallManagerRegistry()
        self.policy = CallLifecyclePolicy(signal_send_timeout_s=0.5)
        self.allowed_kinds: dict[str, set[str]] = {PEER: {"voice", "video"}, OTHER: {"voice"}}
        self.decision: Decision | None = Decision()
        self.pinned: set[str] = {PEER}
        self.peers: dict[str, Any] = {PEER: SimpleNamespace(short_id="peer"), OTHER: None}
        self.tail: list[dict] = []
        self.saves = 0
        self.sent: list[tuple[Any, list[dict]]] = []
        self.control: list[dict] = []
        self.send_error: Exception | None = None
        self.control_error: Exception | None = None
        self.live: dict[str, list[FakeChannel]] = {}
        self.capsules: list[tuple] = []
        self.capsule_frames: list[dict] = []
        self.predictive: list[str] = []
        self.reliability = SimpleNamespace(events=[])
        self.reliability.record_event = self.reliability.events.append
        self.trust_queries: list[str] = []

    def local_short_id(self) -> str:
        return "me"

    def local_fingerprint(self) -> str:
        return ME

    def local_public_bytes(self) -> bytes:
        return b"\x02" * 32

    def call_registry(self):
        return self.registry

    def call_reliability(self):
        return self.reliability

    def call_policy(self) -> CallLifecyclePolicy:
        return self.policy

    def call_capability_allowed(self, peer_fp: str, call_kind: str) -> bool:
        return call_kind in self.allowed_kinds.get(peer_fp, set())

    def trust_decision_for_inbound(self, peer_fp: str):
        self.trust_queries.append(peer_fp)
        return self.decision

    def is_pinned(self, peer_fp: str) -> bool:
        return peer_fp in self.pinned

    def resolve_peer_for_outbound(self, peer_fp: str):
        return self.peers.get(peer_fp)

    async def resolve_for_send(self, peer_fp: str):
        return self.peers.get(peer_fp)

    def peer_fp_from_peer(self, peer) -> str | None:
        return PEER if peer is self.peers.get(PEER) else None

    def live_inbound_channels(self, peer_fp: str):
        return self.live.get(peer_fp, ())

    async def send_to(self, peer, msgs):
        if self.send_error is not None:
            raise self.send_error
        self.sent.append((peer, list(msgs)))

    async def send_control(self, peer, msg):
        if self.control_error is not None:
            raise self.control_error
        self.control.append(msg)

    def broadcast_tail(self, event: dict) -> None:
        self.tail.append(event)

    def save_resume_ledger(self) -> None:
        self.saves += 1

    async def commit_outbound_capsule(self, mgr, capsule) -> None:
        self.capsules.append((mgr, capsule))

    async def handle_capsule_transport_message(self, *, channel, msg, peer_fp) -> None:
        self.capsule_frames.append(msg)

    def open_predictive_call(self, call_id: str) -> None:
        self.predictive.append(call_id)

    def tail_kinds(self) -> list[str]:
        return [event["tail_kind"] for event in self.tail]


@pytest.fixture
def port() -> FakePort:
    return FakePort()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def service(port, clock, tmp_path) -> CallLifecycleService:
    ledger = CallResumeLedger(tmp_path / "resume.json", enabled=True)
    return CallLifecycleService(port, ledger=ledger, clock=clock)


def sdp(text: str = OFFER_VOICE) -> SdpPayload:
    return SdpPayload(schema=CALL_INVITE_SDP_V1, kind=SdpKind.OFFER, sdp=text)


def ice(n: int = 0) -> IceCandidatePayload:
    return IceCandidatePayload(
        schema=CALL_INVITE_SDP_V1,
        candidate=f"candidate:{n} 1 udp 1 10.0.0.{n} 9 typ host",
        sdp_mid="0",
        sdp_m_line_index=0,
        end_of_candidates=False,
    )


def wire(t: str, call_id: str, **fields) -> dict:
    return {"t": t, "id": "f" * 32, "ts": 1, "from": "peer", "call_id": call_id, **fields}


def run(coro):
    return asyncio.run(coro)


# ─── pre-invite media admission ────────────────────────────────────────


def test_preinvite_media_is_admitted_bound_and_forwarded(service, port) -> None:
    assert service.admit_backfill(call_id="call-1", peer_fp=PEER, call_kind="voice")
    service.forward_ice_to_ui(call_id="call-1", peer_master_vk_hex=PEER, candidate_payload=ice())
    assert service.backfill.ice["call-1"][0]["sdp_mid"] == "0"
    assert port.tail_kinds() == ["ice_candidate"]
    assert port.saves == 1
    # Another peer can neither read nor write that namespace.
    assert not service.media_cache_is_bound(call_id="call-1", peer_fp=OTHER)
    assert not service.admit_backfill(call_id="call-1", peer_fp=OTHER, call_kind="voice")
    # A kind change for an admitted namespace is refused.
    assert not service.admit_backfill(call_id="call-1", peer_fp=PEER, call_kind="video")


def test_unbound_media_writes_are_refused(service, port) -> None:
    service.forward_sdp_to_ui(
        call_id="never-admitted", peer_master_vk_hex=PEER, kind="sdp_offer", sdp_payload=sdp()
    )
    service.forward_ice_to_ui(
        call_id="never-admitted", peer_master_vk_hex=PEER, candidate_payload=ice()
    )
    assert service.backfill.sdp == {} and service.backfill.ice == {}
    assert port.tail == [] and port.saves == 0


def test_ice_backfill_is_bounded(service, port) -> None:
    port.policy = CallLifecyclePolicy(ice_backfill_max=3)
    assert service.admit_backfill(call_id="call-1", peer_fp=PEER, call_kind="voice")
    for n in range(7):
        service.forward_ice_to_ui(
            call_id="call-1", peer_master_vk_hex=PEER, candidate_payload=ice(n)
        )
    candidates = [item["candidate"] for item in service.backfill.ice["call-1"]]
    assert candidates == [ice(n).candidate for n in (4, 5, 6)]


def test_admission_capacity_is_global_and_per_peer(service, port) -> None:
    port.policy = CallLifecyclePolicy(preinvite_cache_max=3, preinvite_cache_per_peer_max=2)
    assert service.admit_backfill(call_id="p1", peer_fp=PEER, call_kind="voice")
    assert service.admit_backfill(call_id="p2", peer_fp=PEER, call_kind="voice")
    assert not service.admit_backfill(call_id="p3", peer_fp=PEER, call_kind="voice")
    port.pinned.add(OTHER)
    assert service.admit_backfill(call_id="o1", peer_fp=OTHER, call_kind="voice")
    assert not service.admit_backfill(call_id="o2", peer_fp=OTHER, call_kind="voice")
    assert list(service.backfill.admissions) == ["p1", "p2", "o1"]


def test_admission_requires_trust_and_capability(service, port) -> None:
    port.decision = Decision(allow_call=False)
    assert not service.admit_backfill(call_id="t1", peer_fp=PEER, call_kind="voice")
    port.decision = None  # verifier unavailable: only pinned peers keep service
    assert service.admit_backfill(call_id="t2", peer_fp=PEER, call_kind="voice")
    assert not service.admit_backfill(call_id="t3", peer_fp=OTHER, call_kind="voice")
    port.decision = Decision()
    assert not service.admit_backfill(call_id="t4", peer_fp=OTHER, call_kind="video")
    # trust_checked skips the ledger query but never the capability check.
    port.trust_queries.clear()
    assert service.admit_backfill(
        call_id="t5", peer_fp=PEER, call_kind="voice", trust_checked=True
    )
    assert port.trust_queries == []
    for bad in ("", "x" * 200, None):
        assert not service.admit_backfill(call_id=bad, peer_fp=PEER, call_kind="voice")


def test_expired_admissions_drop_media_but_never_a_live_managers(service, port, clock) -> None:
    for call_id in ("stale", "promoted"):
        assert service.admit_backfill(call_id=call_id, peer_fp=PEER, call_kind="voice")
        service.forward_ice_to_ui(
            call_id=call_id, peer_master_vk_hex=PEER, candidate_payload=ice()
        )
    port.registry.open(
        call_id="promoted",
        peer_master_vk_hex=PEER,
        local_role="recipient",
        local_master_vk_hex=ME,
        started_at_ms=1,
    )
    clock.mono += port.policy.preinvite_ttl_s - 0.01
    assert service.prune_backfill_admissions() == ()
    clock.mono += 0.02
    assert service.prune_backfill_admissions() == ("stale", "promoted")
    assert "stale" not in service.backfill.ice
    assert "promoted" in service.backfill.ice
    assert service.backfill.admissions == {}


def test_call_kind_resolution_and_media_truth(service, port) -> None:
    assert service.call_kind_for_payload(msg={}, call_id="k1") == "voice"
    assert service.call_kind_for_payload(msg={}, call_id="k1", sdp_payload=sdp(OFFER_VIDEO)) == "video"
    with pytest.raises(ValueError, match="cannot carry video"):
        service.call_kind_for_payload(
            msg={"call_kind": "voice"}, call_id="k1", sdp_payload=sdp(OFFER_VIDEO)
        )
    assert service.admit_backfill(call_id="k2", peer_fp=PEER, call_kind="voice")
    with pytest.raises(ValueError, match="conflicts"):
        service.call_kind_for_payload(msg={"call_kind": "video"}, call_id="k2")
    with pytest.raises(ValueError, match="cannot carry video"):
        service.call_kind_for_payload(msg={}, call_id="k2", sdp_payload=sdp(OFFER_VIDEO))
    assert service.call_kind_for_payload(msg={}, call_id="k2") == "voice"


# ─── inbound wire dispatch ─────────────────────────────────────────────


def test_invite_opens_a_ringing_manager_and_promotes_its_media(service, port) -> None:
    run(service.dispatch_wire_message(
        channel=FakeChannel(),
        msg=wire("CALL_SDP_OFFER", "inv-1", **attach_offer_to_invite({}, sdp=OFFER_VOICE)),
        peer_fp=PEER,
        peer_sid="peer",
    ))
    assert "inv-1" in service.backfill.admissions
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_INVITE", "inv-1"), peer_fp=PEER, peer_sid="peer"
    ))
    mgr = port.registry.get("inv-1")
    assert mgr is not None and mgr.state.local_role == "recipient"
    assert mgr.phase.name == "RINGING"
    assert "inv-1" not in service.backfill.admissions  # promoted
    assert service.backfill.sdp["inv-1"]["sdp_offer"] == OFFER_VOICE
    assert port.predictive == ["inv-1"]
    assert "show_ring" in port.tail_kinds()
    assert port.saves >= 2


def test_invite_refusals_never_open_a_manager(service, port) -> None:
    port.decision = Decision(allow_call=False, explanation="identity changed")
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_INVITE", "ref-1"), peer_fp=PEER, peer_sid="p"
    ))
    port.decision = None
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_INVITE", "ref-2"), peer_fp=OTHER, peer_sid="p"
    ))
    assert port.registry.get("ref-1") is None and port.registry.get("ref-2") is None
    refusals = [event for event in port.tail if event["tail_kind"] == "call_refused"]
    assert [event["call_id"] for event in refusals] == ["ref-1", "ref-2"]
    assert refusals[0]["user_message"] == "identity changed"
    assert "temporarily unavailable" in refusals[1]["user_message"]


def test_first_contact_invite_needs_a_transcript_bound_phrase(service, port) -> None:
    port.decision = Decision(needs_reverify=True, explanation="verify the phrase")
    run(service.dispatch_wire_message(
        channel=FakeChannel(transcript_hash=None),
        msg=wire("CALL_INVITE", "sas-missing"),
        peer_fp=PEER,
        peer_sid="p",
    ))
    assert port.registry.get("sas-missing") is None
    assert port.tail[-1]["tail_kind"] == "call_refused"

    run(service.dispatch_wire_message(
        channel=FakeChannel(transcript_hash=b"\x07" * 32),
        msg=wire("CALL_INVITE", "sas-ok"),
        peer_fp=PEER,
        peer_sid="p",
    ))
    assert port.registry.get("sas-ok") is not None
    sas = [event for event in port.tail if event["tail_kind"] == "sas_verification_required"]
    assert len(sas) == 1 and len(sas[0]["sas_words"].split()) == 5


def test_non_invite_frames_need_an_owned_live_manager(service, port) -> None:
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_END", "ghost"), peer_fp=PEER, peer_sid="p"
    ))
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_INVITE", "own-1"), peer_fp=PEER, peer_sid="p"
    ))
    tail_before = len(port.tail)
    # A different peer cannot end someone else's call.
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_END", "own-1"), peer_fp=OTHER, peer_sid="o"
    ))
    assert port.registry.get("own-1") is not None and len(port.tail) == tail_before
    # Capability revoked mid-call: frames are dropped.
    port.allowed_kinds[PEER] = set()
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_END", "own-1"), peer_fp=PEER, peer_sid="p"
    ))
    assert port.registry.get("own-1") is not None
    port.allowed_kinds[PEER] = {"voice"}
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_END", "own-1"), peer_fp=PEER, peer_sid="p"
    ))
    assert port.registry.get("own-1") is None  # ended and reaped
    assert "own-1" not in service.backfill.sdp


def test_capsule_frames_and_bad_call_ids_are_routed_or_dropped(service, port) -> None:
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg={"t": "CAPSULE_CHUNK", "x": 1}, peer_fp=PEER, peer_sid="p"
    ))
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg={"t": "CALL_INVITE", "call_id": ""}, peer_fp=PEER, peer_sid="p"
    ))
    assert port.capsule_frames == [{"t": "CAPSULE_CHUNK", "x": 1}]
    assert len(port.registry) == 0


# ─── flushing ──────────────────────────────────────────────────────────


def _response(call_id: str, *peers: str, complete: bool = False) -> ApiResponse:
    return ApiResponse(
        ok=True,
        call_id=call_id,
        outbound=tuple(
            ApiOutboundMessage(type="CALL_INVITE", peer_master_vk_hex=fp, payload={"call_id": call_id})
            for fp in peers
        ),
        tail_events=(TailEvent(kind=TailEventKind.PHASE_CHANGED, payload={"phase": "inviting"}),),
        call_complete=complete,
    )


def test_flush_delivers_per_peer_and_reports_only_delivered(service, port) -> None:
    delivered = run(service.flush_api_response(_response("fl-1", PEER, OTHER, PEER)))
    assert delivered == (PEER,)  # OTHER has no peer record
    assert len(port.sent) == 1 and [m["t"] for m in port.sent[0][1]] == ["CALL_INVITE"] * 2
    assert port.tail[-1] == {
        "type": "call_event", "tail_kind": "phase_changed", "phase": "inviting", "call_id": "fl-1"
    }
    assert port.saves == 1
    assert run(service.flush_api_response(None)) == ()


def test_flush_reaps_a_completed_call(service, port) -> None:
    port.registry.open(
        call_id="fl-2", peer_master_vk_hex=PEER, local_role="originator",
        local_master_vk_hex=ME, started_at_ms=1,
    )
    assert service.admit_backfill(call_id="fl-2", peer_fp=PEER, call_kind="voice")
    service.forward_sdp_to_ui(
        call_id="fl-2", peer_master_vk_hex=PEER, kind="sdp_offer", sdp_payload=sdp()
    )
    run(service.flush_api_response(_response("fl-2", complete=True)))
    assert port.registry.get("fl-2") is None
    assert "fl-2" not in service.backfill.sdp


def test_signal_falls_back_to_live_channel_then_fresh_control(service, port) -> None:
    peer = port.peers[PEER]
    msgs = [{"t": "CALL_INVITE", "call_id": "sig-1", "id": "1" * 32, "ts": 1, "from": "me"}]
    port.send_error = ConnectionError("stale session")
    live = FakeChannel()
    port.live[PEER] = [FakeChannel(fail=True), live]
    run(service.send_call_signal(peer, msgs))
    assert [m["call_id"] for m in live.sent] == ["sig-1"]
    assert [m["call_id"] for m in port.control] == ["sig-1"]

    # Live channel delivered, fresh control failed: the frame is out; no raise.
    port.control_error = OSError("dial failed")
    run(service.send_call_signal(peer, msgs))
    # Nothing delivered anywhere: the last error surfaces.
    port.live[PEER] = []
    with pytest.raises(OSError, match="dial failed"):
        run(service.send_call_signal(peer, msgs))


def test_non_call_frames_are_never_retried(service, port) -> None:
    port.send_error = ConnectionError("stale session")
    with pytest.raises(ConnectionError):
        run(service.send_call_signal(port.peers[PEER], [{"t": "TEXT", "id": "x"}]))
    assert port.control == []
    assert not CallLifecycleService.call_signal_retryable([])


def test_signal_send_is_bounded_by_the_policy_timeout(service, port) -> None:
    async def stuck(peer, msgs):
        await asyncio.sleep(30)

    port.send_to = stuck  # type: ignore[assignment]
    port.policy = CallLifecyclePolicy(signal_send_timeout_s=0.05)
    port.control_error = OSError("no route")
    with pytest.raises(OSError):
        run(asyncio.wait_for(service.send_call_signal(port.peers[PEER], [{"t": "CALL_END"}]), 5))


# ─── timers and registry maintenance ───────────────────────────────────


def test_unanswered_inbound_invite_expires_and_is_reaped(service, port) -> None:
    run(service.dispatch_wire_message(
        channel=FakeChannel(), msg=wire("CALL_INVITE", "exp-1"), peer_fp=PEER, peer_sid="p"
    ))
    mgr = port.registry.get("exp-1")
    lifecycle = mgr.state.lifecycle
    started = lifecycle.invite_sent_at_ms or lifecycle.started_at_ms
    assert not run(service.expire_invite_if_due(mgr, now_ms=started + 1))
    assert run(service.expire_invite_if_due(mgr, now_ms=started + lifecycle.invite_timeout_ms))
    assert port.registry.get("exp-1") is None


def test_maintain_registry_reaps_stale_pending_calls(service, port) -> None:
    clock_value = [0.0]
    port.registry = CallManagerRegistry(clock=lambda: clock_value[0], pending_ttl_s=5.0)
    port.registry.open(
        call_id="pend-1", peer_master_vk_hex=PEER, local_role="originator",
        local_master_vk_hex=ME, started_at_ms=1,
    )
    service.backfill.sdp["pend-1"] = {"sdp_offer": OFFER_VOICE}
    assert service.maintain_registry() == ("pend-1",)
    assert port.saves == 0
    clock_value[0] = 10.0
    assert service.maintain_registry() == ()
    assert "pend-1" not in service.backfill.sdp
    assert port.saves == 1


# ─── restart resume ────────────────────────────────────────────────────


def _active_call(port: FakePort, call_id: str):
    mgr = port.registry.open(
        call_id=call_id, peer_master_vk_hex=PEER, local_role="originator",
        local_master_vk_hex=ME, started_at_ms=1_000, call_kind="video",
    )
    mgr.handle(ManagerEvent(kind=ManagerEventKind.USER_INITIATE_CALL, occurred_at_ms=1_000))
    mgr.handle(ManagerEvent(
        kind=ManagerEventKind.WIRE_CALL_ACCEPT, occurred_at_ms=1_100,
        data={"peer_master_vk_hex": PEER, "call_kind": "video"},
    ))
    return mgr


def test_resume_ledger_round_trips_active_calls(port, clock, tmp_path) -> None:
    path = tmp_path / "logs" / "resume.json"
    first = CallLifecycleService(port, ledger=CallResumeLedger(path), clock=clock)
    _active_call(port, "res-1")
    first.backfill.sdp["res-1"] = {"sdp_offer": OFFER_VIDEO, "junk": "x"}
    first.backfill.ice["res-1"] = [{"sdp_mid": "0"}] * 40
    first.save_resume_ledger()
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert [record["call_id"] for record in stored["calls"]] == ["res-1"]
    assert len(stored["calls"][0]["media_backfill"]["ice"]) == 32

    restarted_port = FakePort()
    second = CallLifecycleService(restarted_port, ledger=CallResumeLedger(path), clock=clock)
    assert second.restore_resume_ledger() == 1
    mgr = restarted_port.registry.get("res-1")
    assert mgr.phase.name == "ACTIVE" and mgr.state.call_kind == "video"
    assert second.backfill.sdp["res-1"] == {"sdp_offer": OFFER_VIDEO}
    assert restarted_port.reliability.events[-1]["reason"] == "daemon_restart"


def test_resume_ledger_skips_stale_ended_and_corrupt_input(port, clock, tmp_path) -> None:
    path = tmp_path / "resume.json"
    service = CallLifecycleService(port, ledger=CallResumeLedger(path), clock=clock)
    assert service.restore_resume_ledger() == 0  # absent
    path.write_text("{not json", encoding="utf-8")
    assert service.restore_resume_ledger() == 0  # corrupt: tolerated
    path.write_text(json.dumps({"calls": "nope"}), encoding="utf-8")
    assert service.restore_resume_ledger() == 0
    now = clock.wall
    records = [
        {"call_id": "old", "peer_master_vk_hex": PEER, "local_role": "originator",
         "saved_at_ms": now - 13 * 3600 * 1000, "lifecycle": {"phase": "active"}},
        {"call_id": "done", "peer_master_vk_hex": PEER, "local_role": "originator",
         "saved_at_ms": now, "lifecycle": {"phase": "ended"}},
        {"call_id": "badrole", "peer_master_vk_hex": PEER, "local_role": "attacker",
         "saved_at_ms": now, "lifecycle": {"phase": "active"}},
        {"call_id": "badphase", "peer_master_vk_hex": PEER, "local_role": "originator",
         "saved_at_ms": now, "lifecycle": {"phase": "warp"}},
        "not-a-record",
        {"call_id": "good", "peer_master_vk_hex": PEER, "local_role": "recipient",
         "saved_at_ms": now, "lifecycle": {"phase": "ringing"}},
    ]
    path.write_text(json.dumps({"calls": records}), encoding="utf-8")
    assert service.restore_resume_ledger() == 1
    assert port.registry.active_call_ids() == ("good",)


def test_disabled_ledger_neither_reads_nor_writes(port, clock, tmp_path) -> None:
    path = tmp_path / "resume.json"
    service = CallLifecycleService(port, ledger=CallResumeLedger(path, enabled=False), clock=clock)
    _active_call(port, "off-1")
    service.save_resume_ledger()
    assert not path.exists()
    path.write_text(json.dumps({"calls": []}), encoding="utf-8")
    assert service.restore_resume_ledger() == 0


def test_failed_publication_keeps_old_ledger_and_leaves_no_temp(port, clock, tmp_path) -> None:
    path = tmp_path / "resume.json"
    path.write_text(json.dumps({"version": 1, "calls": []}), encoding="utf-8")

    def broken_replace(source: Path, target: Path) -> None:
        raise PermissionError("replace refused")

    service = CallLifecycleService(
        port, ledger=CallResumeLedger(path, replace=broken_replace), clock=clock
    )
    _active_call(port, "pub-1")
    service.save_resume_ledger()  # best effort: logged, never raised
    assert json.loads(path.read_text(encoding="utf-8"))["calls"] == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["resume.json"]


def test_backfill_container_discards_one_call_completely() -> None:
    backfill = CallMediaBackfill()
    backfill.sdp["x"] = {"sdp_offer": "v=0"}
    backfill.ice["x"] = [{}]
    backfill.admissions["x"] = (PEER, "voice", 1.0)
    assert backfill.media_for("x") == ({"sdp_offer": "v=0"}, [{}])
    backfill.discard("x")
    assert backfill.media_for("x") == ({}, [])
    assert "x" not in backfill.admissions
