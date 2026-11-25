"""RUN-01: request handlers must never block the daemon's asyncio loop.

Measured root causes (event-loop watchdog stacks): the first browser-peer
signalling request imported aiortc/PyAV on the loop, and /api/status reached
the hardware inventory's ``subprocess.run`` on the loop. Each behavioural test
runs a ticker on the loop while the slow operation is in progress and asserts
the ticker never stalls longer than a small bound; on the pre-fix code each of
them stalls for the full injected delay. A structural gate keeps the known
blocking calls out of every ``async def`` in the daemon and the UI server.
"""

from __future__ import annotations

import ast
import asyncio
import builtins
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import one_link.hardware_inventory as hardware_inventory
import one_link.server as server_mod
from one_link.daemon import Daemon
from one_link.fabric_snapshot import FabricSnapshotCache, pending_fabric_snapshot
from one_link.off_loop_import import OffLoopImporter

REPO = Path(__file__).resolve().parent.parent
SLOW_S = 0.6
#: Generous for Windows timer granularity (15.6 ms) and CI noise, and still
#: far below the injected stall.
MAX_GAP_S = 0.25


class LoopTicker:
    """Records the largest scheduling gap of a 10 ms ticker."""

    def __init__(self) -> None:
        self.max_gap = 0.0
        self.ticks = 0
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def _run(self) -> None:
        last = time.perf_counter()
        while not self._stop.is_set():
            await asyncio.sleep(0.01)
            now = time.perf_counter()
            self.max_gap = max(self.max_gap, now - last)
            self.ticks += 1
            last = now

    async def __aenter__(self) -> "LoopTicker":
        self._task = asyncio.create_task(self._run())
        await asyncio.sleep(0.03)
        return self

    async def __aexit__(self, *exc: object) -> None:
        self._stop.set()
        assert self._task is not None
        await self._task


# ─── OffLoopImporter ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_slow_import_runs_off_loop_and_is_shared_by_concurrent_callers() -> None:
    calls: list[str] = []

    def slow_import(name: str):
        calls.append(name)
        time.sleep(SLOW_S)
        return SimpleNamespace(__name__=name)

    importer = OffLoopImporter(slow_import)
    async with LoopTicker() as ticker:
        first, second = await asyncio.gather(
            importer.load("heavy.module"),
            importer.load("heavy.module"),
        )
    assert first is second
    assert calls == ["heavy.module"]
    assert ticker.max_gap < MAX_GAP_S, ticker.max_gap
    # A finished import is served without a thread hop or another import.
    assert importer.job("heavy.module").done()
    assert await importer.load("heavy.module") is first
    assert calls == ["heavy.module"]


@pytest.mark.asyncio
async def test_missing_module_is_cached_as_unavailable() -> None:
    calls: list[str] = []

    def missing(name: str):
        calls.append(name)
        raise ImportError(f"No module named {name!r}")

    importer = OffLoopImporter(missing)
    assert await importer.load_optional("absent") is None
    assert await importer.load_optional("absent") is None
    with pytest.raises(ImportError):
        await importer.load("absent")
    assert calls == ["absent"]


@pytest.mark.asyncio
async def test_non_import_failure_is_raised_and_retried() -> None:
    attempts: list[int] = []

    def flaky(name: str):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("native library failed to load")
        return SimpleNamespace(__name__=name)

    importer = OffLoopImporter(flaky)
    with pytest.raises(OSError, match="native library"):
        await importer.load("codec")
    module = await importer.load("codec")
    assert module.__name__ == "codec"
    assert len(attempts) == 2


@pytest.mark.asyncio
async def test_cancelled_waiter_does_not_cancel_the_shared_import() -> None:
    def slow_import(name: str):
        time.sleep(0.2)
        return SimpleNamespace(__name__=name)

    importer = OffLoopImporter(slow_import)
    waiter = asyncio.create_task(importer.load("shared"))
    await asyncio.sleep(0.02)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    module = await importer.load("shared")
    assert module.__name__ == "shared"


def test_importer_rejects_relative_and_empty_names() -> None:
    importer = OffLoopImporter(lambda name: SimpleNamespace())
    for bad in ("", ".relative"):
        with pytest.raises(ValueError):
            importer.job(bad)


# ─── browser-peer signalling (aiortc) ──────────────────────────────────


@pytest.mark.asyncio
async def test_peer_rtc_signaling_never_imports_aiortc_on_the_loop(monkeypatch) -> None:
    """The handler's first act used to be ``from aiortc import ...``."""

    real_import = builtins.__import__

    def slow_absent_aiortc(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and (name == "aiortc" or name.startswith("aiortc.")):
            time.sleep(SLOW_S)
            raise ImportError("aiortc unavailable in this test")
        return real_import(name, globals, locals, fromlist, level)

    # A private importer: the process-wide one must not cache this failure.
    monkeypatch.setattr(server_mod, "OFF_LOOP_IMPORTS", OffLoopImporter(), raising=False)
    monkeypatch.setattr(builtins, "__import__", slow_absent_aiortc)
    srv = server_mod.UIServer.__new__(server_mod.UIServer)

    async with LoopTicker() as ticker:
        response = await srv._peer_rtc_signaling(SimpleNamespace())

    assert response.status == 501
    assert response.text == "aiortc not installed"
    assert ticker.max_gap < MAX_GAP_S, ticker.max_gap


# ─── fabric snapshot (hardware inventory) ──────────────────────────────


def _slow_inventory_patch(monkeypatch) -> list[float]:
    calls: list[float] = []
    original = hardware_inventory.collect_hardware_inventory

    def slow_inventory(*args, **kwargs):
        calls.append(time.perf_counter())
        time.sleep(SLOW_S)
        kwargs.setdefault("runner", lambda _argv, _timeout: (1, "", ""))
        return original(*args, **kwargs)

    monkeypatch.setattr(hardware_inventory, "collect_hardware_inventory", slow_inventory)
    return calls


@pytest.mark.asyncio
async def test_status_fabric_snapshot_never_probes_hardware_on_the_loop(monkeypatch) -> None:
    calls = _slow_inventory_patch(monkeypatch)
    daemon = Daemon.__new__(Daemon)
    daemon.state = None

    async with LoopTicker() as ticker:
        first = daemon._fabric_snapshot()
        second = daemon._fabric_snapshot()
        refresh = daemon._fabric_snapshots.refresh_in_flight()
        assert refresh is not None
        await refresh
    assert ticker.max_gap < MAX_GAP_S, ticker.max_gap
    assert first == pending_fabric_snapshot()
    assert second == pending_fabric_snapshot()
    assert len(calls) == 1, "concurrent stale reads must share one refresh"

    fresh = daemon._fabric_snapshot()
    assert fresh["ok"] is True
    assert "refreshing" not in fresh
    assert fresh["inventory"]["paths"]
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_status_handler_serves_stale_snapshot_while_refreshing(monkeypatch) -> None:
    """The UI server's status/fabric surfaces read the daemon cache seam."""

    now = [1000.0]
    computed: list[list] = []

    def compute(candidates: list) -> dict:
        computed.append(candidates)
        time.sleep(SLOW_S)
        return {"ok": True, "generation": len(computed), "scores": [], "activation": [], "probes": []}

    cache = FabricSnapshotCache(
        route_candidates=lambda: [{"route": "lan"}],
        compute=compute,
        clock=lambda: now[0],
    )
    assert (await cache.refresh())["generation"] == 1
    now[0] += 31.0
    daemon = SimpleNamespace(state=None, _fabric_snapshot=cache.snapshot)
    srv = server_mod.UIServer.__new__(server_mod.UIServer)
    srv.daemon = daemon

    async with LoopTicker() as ticker:
        served = srv._safe_fabric_snapshot(summary=True)
        await cache.refresh_in_flight()
    assert ticker.max_gap < MAX_GAP_S, ticker.max_gap
    assert served["ok"] is True
    assert served["cache_age_s"] == 31.0
    assert cache.snapshot()["generation"] == 2
    assert computed == [[{"route": "lan"}], [{"route": "lan"}]]


def test_fabric_snapshot_never_serves_beyond_the_stale_bound() -> None:
    now = [0.0]
    cache = FabricSnapshotCache(
        route_candidates=lambda: [],
        compute=lambda _c: {"ok": True},
        clock=lambda: now[0],
        max_stale_s=60.0,
    )
    assert cache.snapshot()["ok"] is True

    async def read_on_loop() -> dict:
        snapshot = cache.snapshot()
        task = cache.refresh_in_flight()
        assert task is not None
        await task
        return snapshot

    now[0] = 61.0
    assert asyncio.run(read_on_loop()) == pending_fabric_snapshot()
    now[0] = 62.0
    assert cache.snapshot(max_age_s=30.0)["ok"] is True


def test_fabric_route_candidate_failure_degrades_to_no_candidates() -> None:
    seen: list[list] = []

    def broken() -> list:
        raise RuntimeError("state store closed")

    cache = FabricSnapshotCache(
        route_candidates=broken,
        compute=lambda candidates: seen.append(candidates) or {"ok": True},
    )
    assert cache.snapshot()["ok"] is True
    assert seen == [[]]


# ─── structural gate ───────────────────────────────────────────────────

BLOCKING_CALLS = frozenset(
    {
        "subprocess.run",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.call",
        "time.sleep",
        "collect_hardware_inventory",
    }
)
HEAVY_IMPORTS = frozenset({"aiortc", "av"})


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _direct_body_nodes(function: ast.AsyncFunctionDef):
    """Walk an async function without descending into nested sync scopes,
    whose bodies may legitimately run on a worker thread."""

    nested_scopes = (ast.FunctionDef, ast.Lambda, ast.ClassDef)
    stack = [node for node in function.body if not isinstance(node, nested_scopes)]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(
            child for child in ast.iter_child_nodes(node) if not isinstance(child, nested_scopes)
        )


def blocking_sites(source: str, label: str) -> list[str]:
    sites: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for inner in _direct_body_nodes(node):
            if isinstance(inner, ast.Call) and _dotted(inner.func) in BLOCKING_CALLS:
                sites.append(f"{label}:{inner.lineno} {node.name} calls {_dotted(inner.func)}")
            elif isinstance(inner, ast.Import):
                for alias in inner.names:
                    if alias.name.split(".")[0] in HEAVY_IMPORTS:
                        sites.append(f"{label}:{inner.lineno} {node.name} imports {alias.name}")
            elif isinstance(inner, ast.ImportFrom) and inner.level == 0:
                if (inner.module or "").split(".")[0] in HEAVY_IMPORTS:
                    sites.append(f"{label}:{inner.lineno} {node.name} imports {inner.module}")
    return sites


def test_no_async_function_calls_known_blocking_operations_directly() -> None:
    found: list[str] = []
    for relative in ("src/one_link/daemon.py", "src/one_link/server.py"):
        source = (REPO / relative).read_text(encoding="utf-8")
        found.extend(blocking_sites(source, relative))
    assert found == []


def test_blocking_gate_detects_each_pattern_and_ignores_worker_scopes() -> None:
    sample = (
        "import asyncio, subprocess, time\n"
        "async def handler():\n"
        "    from aiortc import RTCPeerConnection\n"
        "    import av\n"
        "    subprocess.run(['x'])\n"
        "    time.sleep(1)\n"
        "    collect_hardware_inventory()\n"
        "    def worker():\n"
        "        time.sleep(1)\n"
        "    await asyncio.to_thread(worker)\n"
        "    await asyncio.to_thread(collect_hardware_inventory)\n"
        "def sync_helper():\n"
        "    time.sleep(1)\n"
    )
    found = blocking_sites(sample, "sample")
    assert sorted(site.split(" ", 1)[1] for site in found) == sorted(
        [
            "handler imports aiortc",
            "handler imports av",
            "handler calls subprocess.run",
            "handler calls time.sleep",
            "handler calls collect_hardware_inventory",
        ]
    )
