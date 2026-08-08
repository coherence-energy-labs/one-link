import asyncio
import time

import pytest

from one_link.hardware_inventory import (
    HardwareInventory,
    HardwarePath,
    collect_hardware_inventory,
)
from one_link.transport_adapters.static import StaticPathAdapter, adapters_from_paths, score_probe
from one_link.transport_adapters.route_memory import DurableRouteCandidateAdapter
from one_link.transport_adapters.onefield import OneFieldLoopbackAdapter
from one_link.wire import read_frame, write_frame
from one_link.transport_activation import (
    ActivationIntent,
    ActivationState,
    activation_plan_for,
    activation_plans_for,
)
from one_link.transport_fabric import UniversalCommsFabric, observations_from_scores
from one_link.transport_adapters.base import AdapterProbe, RouteScore


class CountingAdapter:
    adapter_id = "counting.fast"
    kind = "lan"

    def __init__(self):
        self.probe_calls = 0
        self.score_from_probe_calls = 0
        self.score_calls = 0

    def probe(self):
        self.probe_calls += 1
        return AdapterProbe(
            adapter_id=self.adapter_id,
            kind=self.kind,
            available=True,
            bulk_capable=True,
            control_capable=True,
            estimated_bps=100_000_000,
            privacy="direct_local",
        )

    def score_from_probe(self, probe, *, intent=None, peer=None):
        self.score_from_probe_calls += 1
        return RouteScore(
            adapter_id=probe.adapter_id,
            route_name=probe.route_name,
            score=0.8,
            estimated_bps=probe.estimated_bps,
            latency_ms=probe.latency_ms,
            reliability=1.0,
            privacy=probe.privacy,
            reason="counted without re-probe",
            usable_for_bulk=True,
            usable_for_control=True,
        )

    def score(self, *, intent=None, peer=None):
        self.score_calls += 1
        raise AssertionError("plan should reuse probes for score_from_probe adapters")


def test_hardware_inventory_can_be_collected_with_deterministic_runner():
    def runner(argv, timeout):
        if argv[:3] == ["netsh", "wlan", "show"]:
            return 0, "Hosted network supported  : Yes\nWi-Fi Direct", ""
        return 1, "", "not available"

    inv = collect_hardware_inventory(
        env={
            "ONE_LINK_ASSUME_BLE": "1",
            "ONE_LINK_ENABLE_AUDIO_CONTROL": "1",
            "ONEFIELD_MESH_ROOT": "Z:\\does-not-exist",
        },
        runner=runner,
    )

    kinds = {p.kind for p in inv.paths}
    assert "lan" in kinds
    assert "loopback" in kinds
    assert "ble_control" in kinds
    assert "qr_control" in kinds
    assert any(p.kind == "storage_courier" and p.available for p in inv.paths)


def test_hardware_inventory_can_enable_onefield_loopback():
    inv = collect_hardware_inventory(
        env={
            "ONE_LINK_ENABLE_ONEFIELD_LOOPBACK": "1",
            "ONEFIELD_MESH_ROOT": "Z:\\does-not-need-to-exist-for-loopback",
        },
        runner=lambda _argv, _timeout: (1, "", ""),
    )

    onefield = next(p for p in inv.paths if p.kind == "onefield")
    assert onefield.available
    assert onefield.bulk_capable
    assert onefield.safety_state == "ok"
    assert "RF transmit disabled" in " ".join(onefield.notes)


def test_hardware_inventory_reports_ethernet_link_local(monkeypatch):
    monkeypatch.setattr(
        "one_link.hardware_inventory._local_ip_addresses",
        lambda: ("169.254.10.20", "fe80::abcd%12", "127.0.0.1"),
    )

    inv = collect_hardware_inventory(env={}, runner=lambda _argv, _timeout: (1, "", ""))
    ethernet = next(p for p in inv.paths if p.kind == "ethernet")

    assert ethernet.available
    assert ethernet.bulk_capable
    assert ethernet.range_hint == "direct_cable_or_switch"
    assert "169.254.10.20" in " ".join(ethernet.notes)


def test_strongest_bulk_path_prefers_fast_available_direct_path():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="webrtc",
                available=True,
                bulk_capable=True,
                estimated_bps=80_000_000,
                privacy="direct_or_relayed_internet",
            ),
            HardwarePath(
                kind="wifi_direct",
                available=True,
                bulk_capable=True,
                estimated_bps=480_000_000,
                privacy="direct_local",
            ),
            HardwarePath(
                kind="ble_control",
                available=True,
                bulk_capable=False,
                estimated_bps=200_000,
                privacy="proximity",
            ),
        ),
    )

    best = inv.strongest_bulk_path()
    assert best is not None
    assert best.kind == "wifi_direct"


def test_static_adapter_scores_unavailable_as_zero():
    adapter = StaticPathAdapter(HardwarePath(
        kind="wifi_direct",
        available=False,
        bulk_capable=True,
        estimated_bps=480_000_000,
        privacy="direct_local",
    ))

    score = adapter.score()

    assert score.score == 0.0
    assert not score.usable_for_bulk
    assert score.reason == "adapter unavailable"


def test_score_probe_keeps_control_only_paths_but_below_bulk():
    ble = StaticPathAdapter(HardwarePath(
        kind="ble_control",
        available=True,
        bulk_capable=False,
        estimated_bps=200_000,
        privacy="proximity",
    )).score()
    lan = StaticPathAdapter(HardwarePath(
        kind="lan",
        available=True,
        bulk_capable=True,
        estimated_bps=900_000_000,
        privacy="direct_local",
    )).score()

    assert ble.usable_for_control
    assert not ble.usable_for_bulk
    assert lan.score > ble.score


def test_fabric_feeds_existing_transfer_brain_with_adapter_observations():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="lan",
                adapter_id="lan.test",
                available=True,
                bulk_capable=True,
                estimated_bps=900_000_000,
                privacy="direct_local",
            ),
            HardwarePath(
                kind="webrtc",
                adapter_id="webrtc.test",
                available=True,
                bulk_capable=True,
                estimated_bps=80_000_000,
                privacy="direct_or_relayed_internet",
            ),
            HardwarePath(
                kind="storage_courier",
                adapter_id="courier.test",
                available=True,
                bulk_capable=True,
                estimated_bps=120_000_000,
                privacy="offline_physical",
                requires_user_action=True,
            ),
        ),
    )
    fabric = UniversalCommsFabric(adapters_from_paths(inv.paths))

    plan = fabric.plan(
        size_bytes=8 * 1024 * 1024,
        supports_cdc=True,
        supports_swarm=False,
        prior_hit_rate=0.25,
        speeds={"cdc_mib_s": 900.0},
    )
    truth = plan.route_truth()

    assert plan.best_score is not None
    assert plan.best_score.route_name == "lan"
    assert truth["kind"] == "Local network"
    assert truth["transfer"]["route"] == "lan"
    assert truth["activation_state"] in {"ready", "ask_user"}
    assert any(o.route == "lan" and o.ok for o in plan.observations)
    assert plan.timing_ms is not None
    assert plan.timing_ms["total_ms"] >= 0.0
    # The route brain's 3-adapter budget is ~8.5 ms of WALL clock. This
    # test is about feeding observations to the transfer brain, not
    # benchmarking — and a wall-clock health classification flips to
    # "warm"/"slow" under heavy load (full suite + a GC pause) through no
    # fault of the planner. Assert the telemetry is produced + classified
    # with a valid token; the dedicated scale test below keeps the strict
    # timing budget (it has an explicit, generous 250 ms guard).
    assert plan.timing_ms["health"] in {"fast", "warm", "slow"}
    assert plan.to_dict()["performance"]["adapter_count"] == 3.0


@pytest.mark.asyncio
async def test_onefield_loopback_adapter_passes_frames_without_rf_transmit():
    adapter = OneFieldLoopbackAdapter(HardwarePath(
        kind="onefield",
        adapter_id="onefield.loopback",
        available=True,
        bulk_capable=True,
        control_capable=True,
        estimated_bps=5_000_000,
        privacy="same_machine",
        range_hint="software_loopback",
        safety_state="ok",
        notes=("software loopback; RF transmit disabled",),
    ))

    probe = adapter.probe()
    assert probe.available
    assert probe.bulk_capable
    assert probe.safety_state == "ok"

    route = await adapter.prepare()
    assert route.metadata["rf_transmit"] is False
    session = await adapter.open(route)
    await session.send_frame(b"encrypted-one-link-frame")
    assert await session.recv_frame() == b"encrypted-one-link-frame"
    stats = await session.stats()
    assert stats.frames_sent == 1
    assert stats.frames_received == 1


def test_fabric_uses_onefield_loopback_as_real_adapter():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="onefield",
                adapter_id="onefield.loopback",
                available=True,
                bulk_capable=True,
                control_capable=True,
                estimated_bps=5_000_000,
                privacy="same_machine",
                range_hint="software_loopback",
                safety_state="ok",
                notes=("software loopback; RF transmit disabled",),
            ),
        ),
    )

    plan = UniversalCommsFabric.from_inventory(inv).plan(size_bytes=4096, supports_cdc=True)

    assert plan.best_score is not None
    assert plan.best_score.adapter_id == "onefield.loopback"
    assert plan.best_score.route_name == "onefield"
    assert plan.best_score.usable_for_bulk is True
    assert plan.to_dict()["performance"]["adapter_count"] == 1.0


def test_fabric_plan_reuses_probe_results_for_scoring():
    adapter = CountingAdapter()
    fabric = UniversalCommsFabric((adapter,))

    plan = fabric.plan(size_bytes=1024, supports_cdc=False)

    assert plan.best_score is not None
    assert adapter.probe_calls == 1
    assert adapter.score_from_probe_calls == 1
    assert adapter.score_calls == 0


def test_fabric_ranks_verified_remembered_route_as_real_path():
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="webrtc",
                adapter_id="webrtc.slow",
                available=True,
                bulk_capable=True,
                estimated_bps=45_000_000,
                privacy="direct_or_relayed_internet",
            ),
        ),
    )
    fabric = UniversalCommsFabric.from_inventory_and_candidates(
        inv,
        (
            {
                "peer_fp": "a" * 64,
                "route": "lan",
                "transport": "tcp",
                "host": "192.168.1.42",
                "port": 17117,
                "source": "session_open",
                "verified": True,
                "attempts": 3,
                "successes": 3,
                "failures": 0,
                "latency_ms": 4,
                "bandwidth_bps": 900_000_000,
            },
        ),
    )

    plan = fabric.plan(size_bytes=128 * 1024 * 1024, supports_cdc=True)
    truth = plan.route_truth()

    assert plan.best_score is not None
    assert plan.best_score.adapter_id.startswith("remembered.aaaaaaaa.lan.tcp")
    assert plan.best_score.route_name == "lan"
    assert truth["kind"] == "Local network"
    assert truth["estimated_bps"] == 900_000_000
    assert truth["reason"] == "verified remembered route"
    assert any(p.adapter_id.startswith("remembered.") and p.available for p in plan.probes)


def test_fabric_plan_stays_fast_with_many_remembered_routes():
    candidates = tuple(
        {
            "peer_fp": f"{i:064x}",
            "route": "lan" if i % 3 else "ethernet",
            "transport": "tcp",
            "host": f"10.0.{i // 255}.{i % 255}",
            "port": 17117,
            "source": "session_open",
            "verified": True,
            "attempts": 4,
            "successes": 4,
            "failures": 0,
            "latency_ms": float(1 + (i % 20)),
            "bandwidth_bps": float(100_000_000 + i),
        }
        for i in range(512)
    )
    inv = HardwareInventory(
        platform="test",
        hostname="unit",
        paths=(
            HardwarePath(
                kind="lan",
                adapter_id="lan.test",
                available=True,
                bulk_capable=True,
                estimated_bps=900_000_000,
                privacy="direct_local",
            ),
        ),
    )
    fabric = UniversalCommsFabric.from_inventory_and_candidates(inv, candidates)

    started = time.perf_counter()
    plan = fabric.plan(size_bytes=256 * 1024 * 1024, supports_cdc=True, supports_swarm=True)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    assert plan.best_score is not None
    assert plan.timing_ms is not None
    assert plan.timing_ms["adapter_count"] == 513.0

    # WHY THIS IS A SCALING ASSERTION AND NOT A STOPWATCH.
    #
    # This previously required `elapsed_ms < 250.0`. That is a claim about the MACHINE, not the
    # planner: it passes on a developer laptop and fails on a shared CI runner at ~680 ms, and it
    # had been failing on every pull request's Linux suite for exactly that reason -- red on work
    # that could not possibly have caused it, which is how a gate stops being read at all.
    #
    # WHERE THE 680 ms CAME FROM, measured rather than shrugged at. The old assertion timed the
    # FIRST plan() in the process, which pays one-time lazy initialisation, inside a suite that had
    # already run ~9,400 tests. On this machine: first call 157 ms, warmed calls 7.7 ms, and a
    # single gen2 gc.collect() over a suite-sized heap 228 ms. One-time warm-up plus a GC pause
    # landing inside the measured window, on a runner several times slower, is the whole gap.
    # Neither number is the planner's steady-state cost, which is what the test claims to police.
    # Best-of-k below excludes both, so the ratio compares like with like.
    #
    # The property the name promises is that planning stays fast AS REMEMBERED ROUTES GROW. That
    # is about growth, and growth is measurable on any machine: compare the same planner against
    # 4x the routes, in this process, under this load. Linear is ~4x, quadratic ~16x. A ceiling of
    # 8x still refuses the regression this test exists to catch -- an accidental O(n^2) scan over
    # candidates -- while surviving a runner three times slower than a laptop.
    small_ms = _best_plan_ms(_fabric_with_routes(inv, 128))
    large_ms = _best_plan_ms(_fabric_with_routes(inv, 512))
    growth = large_ms / max(small_ms, 0.05)
    assert growth < 8.0, (
        f"planning grew {growth:.1f}x for 4x the remembered routes "
        f"({small_ms:.1f}ms -> {large_ms:.1f}ms); that is superlinear, and a route brain that "
        "degrades with the size of the mesh gets slower exactly as a user's network gets richer")

    # A catastrophic floor, deliberately loose: this fires on a planner that has genuinely fallen
    # over, on any hardware, and stays quiet about how fast the runner happens to be.
    assert elapsed_ms < 5000.0, f"planning 513 routes took {elapsed_ms:.0f}ms"
    assert plan.timing_ms["health"] in {"fast", "warm", "slow"}


def _fabric_with_routes(inv, count: int):
    """The same fabric shape at a different number of remembered routes."""
    return UniversalCommsFabric.from_inventory_and_candidates(
        inv,
        tuple(
            {
                "peer_fp": f"{i:064x}",
                "route": "lan" if i % 3 else "ethernet",
                "transport": "tcp",
                "host": f"10.0.{i // 255}.{i % 255}",
                "port": 17117,
                "source": "session_open",
                "verified": True,
                "attempts": 4,
                "successes": 4,
                "failures": 0,
                "latency_ms": float(1 + (i % 20)),
                "bandwidth_bps": float(100_000_000 + i),
            }
            for i in range(count)
        ),
    )


def _best_plan_ms(fabric, repeats: int = 3) -> float:
    """BEST of k, not the mean. A shared runner's scheduler adds time; it never subtracts it,
    so the minimum is the closest thing to the planner's own cost that a noisy box can report."""
    best = float("inf")
    for _ in range(repeats):
        started = time.perf_counter()
        fabric.plan(size_bytes=256 * 1024 * 1024, supports_cdc=True, supports_swarm=True)
        best = min(best, (time.perf_counter() - started) * 1000.0)
    return best


def test_timing_health_labels_are_computed_not_measured():
    """The health label's LOGIC, tested deterministically.

    The assertion this replaces (`health in {"fast", "warm"}` after a real plan) could only pass
    on a machine fast enough to land inside the budget -- so it tested the runner and left the
    threshold arithmetic itself unchecked. Feeding `_timing_health` known numbers checks the part
    that can actually be wrong, and does it identically on every machine.
    """
    from one_link.transport_fabric import _timing_health

    # budget = 8 + min(92, count * 0.18); warm is up to 2.5x that; beyond is slow.
    assert _timing_health(1.0, 0) == "fast"
    assert _timing_health(8.0, 0) == "fast"          # boundary is inclusive
    assert _timing_health(8.1, 0) == "warm"
    assert _timing_health(20.0, 0) == "warm"         # 2.5x of 8.0
    assert _timing_health(20.1, 0) == "slow"

    # The budget grows with adapter count, and CLAMPS at 92ms of allowance.
    assert _timing_health(99.0, 513) == "fast"       # budget 100.0
    assert _timing_health(100.0, 513) == "fast"
    assert _timing_health(101.0, 513) == "warm"
    assert _timing_health(250.0, 513) == "warm"      # 2.5x of 100.0
    assert _timing_health(251.0, 513) == "slow"
    assert _timing_health(100.0, 10_000) == "fast", (
        "the allowance no longer clamps; an unbounded budget would call any slowness healthy "
        "as long as the mesh was large enough")

    # A negative count must not produce a budget below the floor.
    assert _timing_health(8.0, -5) == "fast"


def test_fabric_keeps_unverified_remembered_route_out_of_bulk_path():
    fabric = UniversalCommsFabric.from_inventory_and_candidates(
        HardwareInventory(platform="test", hostname="unit", paths=()),
        (
            {
                "peer_fp": "b" * 64,
                "route": "lan",
                "transport": "tcp",
                "host": "192.168.1.55",
                "port": 17117,
                "source": "qr_bootstrap",
                "verified": False,
                "attempts": 0,
                "successes": 0,
                "failures": 0,
            },
        ),
    )

    plan = fabric.plan(size_bytes=1024 * 1024, supports_cdc=False)

    assert plan.best_score is not None
    assert plan.best_score.score == 0.0
    assert plan.best_score.reason == "remembered route awaiting verification"
    assert not plan.best_score.usable_for_bulk
    assert plan.probes[0].safety_state == "needs_verification"


@pytest.mark.asyncio
async def test_verified_remembered_tcp_route_opens_framed_session():
    async def handle(reader, writer):
        try:
            frame = await read_frame(reader)
            await write_frame(writer, b"echo:" + frame)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    adapter = DurableRouteCandidateAdapter({
        "peer_fp": "c" * 64,
        "route": "ethernet",
        "transport": "tcp",
        "host": "127.0.0.1",
        "port": port,
        "source": "endpoint_verify",
        "verified": True,
        "attempts": 1,
        "successes": 1,
        "failures": 0,
    })

    try:
        route = await adapter.prepare()
        session = await adapter.open(route)
        await session.send_frame(b"hello")
        assert await session.recv_frame() == b"echo:hello"
        stats = await session.stats()
        assert stats.frames_sent == 1
        assert stats.frames_received == 1
        assert stats.bytes_sent == 5
        assert stats.bytes_received == 10
        repair = await session.repair("test")
        assert repair.action == "reopen_route"
        await session.close()
    finally:
        server.close()
        await server.wait_closed()


def test_observations_from_scores_penalizes_control_only_routes():
    scores = (
        score_probe(StaticPathAdapter(HardwarePath(
            kind="ble_control",
            available=True,
            bulk_capable=False,
            estimated_bps=200_000,
            privacy="proximity",
        )).probe()),
    )

    obs = observations_from_scores(scores)

    assert obs[0].route == "ble_control"
    assert obs[0].ok
    assert obs[0].energy_cost > 1.0


def test_activation_blocks_bulk_over_control_only_path():
    score = score_probe(StaticPathAdapter(HardwarePath(
        kind="ble_control",
        adapter_id="ble.test",
        available=True,
        bulk_capable=False,
        estimated_bps=200_000,
        privacy="proximity",
    )).probe())

    plan = activation_plan_for(score, intent=ActivationIntent(needs_bulk=True))

    assert plan.state == ActivationState.ASK_USER
    assert not plan.automatic
    assert plan.needs_user
    assert "control-only" in plan.reason


def test_activation_auto_opens_low_risk_verified_trusted_path():
    probe = StaticPathAdapter(HardwarePath(
        kind="wifi_direct",
        adapter_id="wifi.test",
        available=True,
        bulk_capable=True,
        estimated_bps=480_000_000,
        privacy="direct_local",
    )).probe()
    score = score_probe(probe)

    plan = activation_plan_for(
        score,
        probe,
        intent=ActivationIntent(trusted_peer=True, verified_peer=True),
    )

    assert plan.state == ActivationState.ACTIVE
    assert plan.automatic
    assert not plan.needs_user
    assert "local paths never require cloud storage" in plan.safeguards


def test_activation_requires_user_for_admin_path():
    probe = StaticPathAdapter(HardwarePath(
        kind="private_hotspot",
        adapter_id="admin.hotspot",
        available=True,
        bulk_capable=True,
        estimated_bps=300_000_000,
        privacy="direct_local",
        requires_admin=True,
    )).probe()
    score = score_probe(probe)

    plan = activation_plan_for(
        score,
        probe,
        intent=ActivationIntent(trusted_peer=True, verified_peer=True),
    )

    assert plan.state == ActivationState.ASK_USER
    assert not plan.automatic
    assert plan.next_action == "ask_user_for_permission"


def test_activation_summary_sorts_safe_ready_paths_first():
    probes = (
        StaticPathAdapter(HardwarePath(
            kind="webrtc",
            adapter_id="relayish",
            available=True,
            bulk_capable=True,
            estimated_bps=80_000_000,
            privacy="direct_or_relayed_internet",
        )).probe(),
        StaticPathAdapter(HardwarePath(
            kind="lan",
            adapter_id="lan",
            available=True,
            bulk_capable=True,
            estimated_bps=900_000_000,
            privacy="direct_local",
        )).probe(),
    )
    scores = tuple(score_probe(p) for p in probes)

    plans = activation_plans_for(
        scores,
        probes,
        intent=ActivationIntent(trusted_peer=True, verified_peer=True),
    )

    assert plans[0].route_name == "lan"
    assert plans[0].automatic
