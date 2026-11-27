"""Universal Comms Fabric snapshots that never probe hardware on the event loop.

Building a fabric snapshot runs the hardware inventory, which shells out to OS
tools (``netsh wlan show drivers`` and Bluetooth probes, 4 s timeouts each) and
resolves this host's own name (bounded at 5 s per address family). The daemon
used to do that synchronously inside ``/api/status``, ``/api/metrics`` and
``/api/fabric*`` request handlers once per 30 s cache window, so a status poll
could stall every request, WebSocket and timer for seconds.

:class:`FabricSnapshotCache` keeps the existing cached-snapshot contract and
moves the cost off the loop:

* a fresh snapshot (younger than ``max_age_s``) is returned as before;
* with no running event loop in the calling thread (CLI, worker threads,
  synchronous tests), a stale snapshot is recomputed inline, as before;
* on an event-loop thread, a stale snapshot is served immediately with its
  true ``cache_age_s`` and ``refreshing: True`` while ONE background refresh
  recomputes it on a worker thread (stale-while-revalidate). A snapshot older
  than ``max_stale_s`` is never served; the caller gets an explicit pending
  snapshot instead of an arbitrarily old one;
* route candidates are read on the calling thread (the state store is not
  shared with the worker); only the probe and the pure planning run off-loop.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Optional

log = logging.getLogger(__name__)

FABRIC_SNAPSHOT_MAX_STALE_S = 300.0

RouteCandidates = Callable[[], list]
FabricCompute = Callable[[list], dict]


def _unavailable(reason: str, *, error: str) -> dict[str, Any]:
    return {
        "ok": False,
        "cache_age_s": 0.0,
        "error": error,
        "inventory": {"paths": []},
        "route_truth": {"state": "Waiting for device", "reason": reason},
        "scores": [],
        "activation": [],
        "probes": [],
        "performance": {},
    }


def compute_fabric_snapshot(route_candidates: list) -> dict[str, Any]:
    """Probe local hardware and plan the fabric. Blocking; never raises."""

    try:
        from one_link.hardware_inventory import collect_hardware_inventory
        from one_link.transport_fabric import UniversalCommsFabric

        inventory = collect_hardware_inventory()
        fabric = UniversalCommsFabric.from_inventory_and_candidates(inventory, route_candidates)
        plan = fabric.plan(
            size_bytes=64 * 1024 * 1024,
            supports_cdc=True,
            supports_swarm=True,
            prior_hit_rate=0.0,
        )
        return {
            "ok": True,
            "cache_age_s": 0.0,
            "inventory": inventory.to_dict(),
            "route_truth": plan.route_truth(),
            "scores": [s.to_dict() for s in plan.scores],
            "activation": [a.to_dict() for a in plan.activation],
            "probes": [p.to_dict() for p in plan.probes],
            "performance": dict(plan.timing_ms or {}),
        }
    except Exception as exc:
        return _unavailable("fabric probe unavailable", error=str(exc))


def pending_fabric_snapshot() -> dict[str, Any]:
    snapshot = _unavailable(
        "fabric probe is running off the event loop",
        error="fabric probe pending",
    )
    snapshot["refreshing"] = True
    return snapshot


def _running_loop() -> Optional[asyncio.AbstractEventLoop]:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


class FabricSnapshotCache:
    """Cached fabric snapshot with off-loop stale-while-revalidate refresh."""

    def __init__(
        self,
        *,
        route_candidates: RouteCandidates,
        compute: FabricCompute = compute_fabric_snapshot,
        clock: Callable[[], float] | None = None,
        max_stale_s: float = FABRIC_SNAPSHOT_MAX_STALE_S,
    ) -> None:
        self._route_candidates = route_candidates
        self._compute = compute
        self._clock = clock if clock is not None else time.monotonic
        self.max_stale_s = float(max_stale_s)
        self._snapshot: dict[str, Any] | None = None
        self._stored_at = 0.0
        self._refresh: tuple[asyncio.AbstractEventLoop, asyncio.Task] | None = None

    def _candidates(self) -> list:
        try:
            return list(self._route_candidates() or [])
        except Exception as exc:
            log.debug("fabric route candidates unavailable: %s", exc)
            return []

    def _store(self, snapshot: dict[str, Any]) -> dict[str, Any]:
        self._snapshot = dict(snapshot)
        self._stored_at = self._clock()
        return snapshot

    def _served(self, age: float, *, refreshing: bool) -> dict[str, Any]:
        assert self._snapshot is not None
        out = dict(self._snapshot)
        out["cache_age_s"] = round(age, 3)
        if refreshing:
            out["refreshing"] = True
        return out

    def refresh_in_flight(self) -> asyncio.Task | None:
        if self._refresh is None:
            return None
        loop, task = self._refresh
        if task.done() or loop is not _running_loop():
            return None
        return task

    def _schedule(self, loop: asyncio.AbstractEventLoop) -> asyncio.Task:
        task = self.refresh_in_flight()
        if task is None:
            task = loop.create_task(self.refresh())
            task.add_done_callback(
                lambda done: done.exception() if not done.cancelled() else None
            )
            self._refresh = (loop, task)
        return task

    async def refresh(self) -> dict[str, Any]:
        """Recompute now: candidates on the loop, probe and plan off-loop."""

        candidates = self._candidates()
        snapshot = await asyncio.to_thread(self._compute, candidates)
        return dict(self._store(snapshot))

    def snapshot(self, *, max_age_s: float = 30.0) -> dict[str, Any]:
        """Return the best snapshot available without blocking a running loop."""

        now = self._clock()
        age = now - self._stored_at
        if self._snapshot is not None and age <= max(0.0, float(max_age_s)):
            return self._served(age, refreshing=False)
        loop = _running_loop()
        if loop is None:
            return dict(self._store(self._compute(self._candidates())))
        self._schedule(loop)
        if self._snapshot is not None and age <= self.max_stale_s:
            return self._served(age, refreshing=True)
        return pending_fabric_snapshot()
