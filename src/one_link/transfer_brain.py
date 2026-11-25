"""Adaptive transfer planning inspired by Coherence NPE.

This module is deliberately deterministic and dependency-light. It ports the
parts of Coherence that matter for One Link transfers:

* calibration tiers from adaptive cost models;
* Pareto-frontier strategy selection;
* an autonomic health regulator for route degradation;
* route memory that learns from observed latency/bandwidth/failure.

The daemon can use it incrementally without changing the wire protocol. The
first production value is simple: avoid expensive planning work unless it is
likely to save more than it costs.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping

from one_link.fault_observability import report_best_effort_failure
from one_link.transfer_routes import PAYLOAD_ATTEMPT_WINDOW, resumed_share

log = logging.getLogger(__name__)


MiB = 1024 * 1024


class CalibrationTier(str, Enum):
    COLD = "cold"
    WARMING = "warming"
    WARM = "warm"
    HOT = "hot"
    VERIFIED = "verified"


class TransferMode(str, Enum):
    HASH_STREAM = "hash_stream"
    FIXED_MANIFEST = "fixed_manifest"
    CDC_MANIFEST = "cdc_manifest"
    SWARM_CDC = "swarm_cdc"
    WAIT = "wait"


class HealthState(str, Enum):
    HEALTHY = "healthy"
    OBSERVING = "observing"
    CONSTRAINED = "constrained"
    REPAIR = "repair"


@dataclass(frozen=True)
class EngineStats:
    """EWMA performance memory for one local transfer engine."""

    samples: int = 0
    mib_s: float = 0.0
    savings_ratio: float = 0.0
    reliability: float = 1.0

    def observe(
        self,
        *,
        mib_s: float,
        savings_ratio: float,
        ok: bool = True,
        alpha: float = 0.25,
    ) -> "EngineStats":
        samples = self.samples + 1
        speed = max(0.001, float(mib_s))
        savings = _clamp01(savings_ratio)
        reliability_sample = 1.0 if ok else 0.0
        if self.samples <= 0:
            return EngineStats(
                samples=samples,
                mib_s=speed,
                savings_ratio=savings,
                reliability=reliability_sample,
            )
        return EngineStats(
            samples=samples,
            mib_s=self.mib_s * (1.0 - alpha) + speed * alpha,
            savings_ratio=self.savings_ratio * (1.0 - alpha) + savings * alpha,
            reliability=self.reliability * (1.0 - alpha) + reliability_sample * alpha,
        )


class TransferPerformanceOracle:
    """Small deterministic feedback loop for local transfer engines.

    Route memory learns peer/path quality. This class learns what *this
    machine* is actually achieving for stream, fixed-manifest, and CDC sends.
    The daemon feeds it completed transfer reports, then the transfer brain
    gets calibrated speeds instead of stale constants.
    """

    def __init__(self) -> None:
        self._stats: dict[str, EngineStats] = {}

    def observe(
        self,
        *,
        method: str,
        report: Mapping[str, object],
        ok: bool = True,
    ) -> None:
        engine = self._engine_for_method(method)
        raw = _as_float(report.get("raw_bytes_sent"))
        effective = _as_float(report.get("effective_payload_bytes"))
        raw_bps = _as_float(report.get("raw_throughput_bps"))
        effective_bps = _as_float(report.get("effective_throughput_bps"))
        savings = _as_float(report.get("bandwidth_savings_ratio"))
        if engine == "cdc":
            bps = max(effective_bps, raw_bps)
            payload = max(effective, raw)
        else:
            bps = raw_bps
            payload = raw
        if bps <= 0.0 and payload > 0.0:
            return
        mib_s = (bps / 8.0) / MiB
        self._stats[engine] = self._stats.get(engine, EngineStats()).observe(
            mib_s=mib_s,
            savings_ratio=savings,
            ok=ok,
        )

    def observe_failure(self, *, method: str) -> None:
        engine = self._engine_for_method(method)
        self._stats[engine] = self._stats.get(engine, EngineStats()).observe(
            mib_s=max(0.001, self._stats.get(engine, EngineStats()).mib_s or 1.0),
            savings_ratio=self._stats.get(engine, EngineStats()).savings_ratio,
            ok=False,
        )

    def speeds(
        self,
        *,
        native_cdc: bool,
        defaults: Mapping[str, float] | None = None,
    ) -> dict[str, float]:
        base = {
            "hash_mib_s": 1500.0,
            "fixed_mib_s": 1400.0 if native_cdc else 1100.0,
            "cdc_mib_s": 950.0 if native_cdc else 8.0,
        }
        if defaults:
            base.update({k: float(v) for k, v in defaults.items()})
        stream = self._stats.get("stream")
        fixed = self._stats.get("fixed")
        cdc = self._stats.get("cdc")
        if stream and stream.samples >= 2 and stream.reliability >= 0.70:
            # Stream throughput is not hash CPU speed, but it is the best
            # lower bound for the local end-to-end baseline.
            base["hash_mib_s"] = max(base["hash_mib_s"] * 0.50, stream.mib_s)
        if fixed and fixed.samples >= 2 and fixed.reliability >= 0.70:
            base["fixed_mib_s"] = max(base["fixed_mib_s"] * 0.50, fixed.mib_s)
        if cdc and cdc.samples >= 2 and cdc.reliability >= 0.70:
            floor = 80.0 if native_cdc else 4.0
            base["cdc_mib_s"] = max(floor, cdc.mib_s)
        return {k: round(float(v), 3) for k, v in base.items()}

    def snapshot(self) -> dict[str, dict[str, float | int]]:
        return {
            k: {
                "samples": v.samples,
                "mib_s": round(v.mib_s, 3),
                "savings_ratio": round(v.savings_ratio, 6),
                "reliability": round(v.reliability, 4),
            }
            for k, v in sorted(self._stats.items())
        }

    @staticmethod
    def _engine_for_method(method: str) -> str:
        m = str(method or "").lower()
        if "cdc" in m:
            return "cdc"
        if "fixed" in m or "manifest" in m:
            return "fixed"
        return "stream"


@dataclass(frozen=True)
class TransferRouteObservation:
    route: str
    ok: bool
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    energy_cost: float = 1.0


@dataclass(frozen=True)
class MeshNodeSignal:
    """Live evidence for a trusted node in the personal mesh.

    This is the practical form of the Coherence/Tau idea for One Link:
    the score is not mystical, it is earned from trust, route quality,
    chunk overlap, freshness, and local cost. Higher coherence means this
    node should be used earlier for routing, chunk claims, and verification.
    """

    peer_fp: str
    trust_score: float = 0.5
    reliability: float = 0.5
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    chunk_hit_rate: float = 0.0
    freshness: float = 1.0
    energy_cost: float = 1.0
    route_kind: str = "unknown"

    @property
    def coherence(self) -> float:
        latency = self.latency_ms if self.latency_ms is not None else 250.0
        latency_score = 1.0 / (1.0 + max(0.0, latency) / 50.0)
        bandwidth = self.bandwidth_bps if self.bandwidth_bps is not None else 0.0
        bandwidth_score = min(1.0, max(0.0, bandwidth) / 1_000_000_000.0)
        energy_score = 1.0 / (1.0 + max(0.0, self.energy_cost - 1.0))
        value = (
            0.28 * _clamp01(self.trust_score)
            + 0.24 * _clamp01(self.reliability)
            + 0.18 * bandwidth_score
            + 0.12 * latency_score
            + 0.12 * _clamp01(self.chunk_hit_rate)
            + 0.04 * _clamp01(self.freshness)
            + 0.02 * energy_score
        )
        return round(_clamp01(value), 6)


@dataclass(frozen=True)
class VerificationTask:
    index: int
    chunk_hash: str
    priority: float
    reason: str


@dataclass(frozen=True)
class RouteStats:
    route: str
    observations: int = 0
    successes: int = 0
    failures: int = 0
    latency_ema_ms: float | None = None
    bandwidth_ema_bps: float | None = None
    energy_ema: float = 1.0

    @property
    def reliability(self) -> float:
        # Jeffreys-style smoothing prevents cold routes from looking perfect.
        return (self.successes + 0.5) / max(1.0, self.observations + 1.0)

    @property
    def tier(self) -> CalibrationTier:
        if self.observations < 4:
            return CalibrationTier.COLD
        if self.observations < 12:
            return CalibrationTier.WARMING
        if self.observations < 32:
            return CalibrationTier.WARM
        if self.failures == 0 and self.observations >= 64:
            return CalibrationTier.VERIFIED
        return CalibrationTier.HOT

    @property
    def confidence(self) -> float:
        base = {
            CalibrationTier.COLD: 0.25,
            CalibrationTier.WARMING: 0.45,
            CalibrationTier.WARM: 0.65,
            CalibrationTier.HOT: 0.82,
            CalibrationTier.VERIFIED: 0.95,
        }[self.tier]
        return round(base * self.reliability, 4)

    def observe(self, obs: TransferRouteObservation, *, alpha: float = 0.25) -> "RouteStats":
        latency = self.latency_ema_ms
        bandwidth = self.bandwidth_ema_bps
        energy = self.energy_ema
        if obs.ok and obs.latency_ms is not None:
            latency = obs.latency_ms if latency is None else latency * (1 - alpha) + obs.latency_ms * alpha
        if obs.ok and obs.bandwidth_bps is not None:
            bandwidth = obs.bandwidth_bps if bandwidth is None else bandwidth * (1 - alpha) + obs.bandwidth_bps * alpha
        energy = energy * (1 - alpha) + max(0.01, float(obs.energy_cost)) * alpha
        return RouteStats(
            route=obs.route,
            observations=self.observations + 1,
            successes=self.successes + (1 if obs.ok else 0),
            failures=self.failures + (0 if obs.ok else 1),
            latency_ema_ms=latency,
            bandwidth_ema_bps=bandwidth,
            energy_ema=energy,
        )


@dataclass(frozen=True)
class TransferCandidate:
    mode: TransferMode
    route: str
    estimated_ms: float
    estimated_wire_bytes: int
    manifest_cpu_ms: float
    reliability: float
    energy_score: float
    confidence: float
    coherence_score: float = 0.0
    parallelism: int = 1
    route_latency_ms: float | None = None
    route_bandwidth_bps: float | None = None
    verification_head: tuple[int, ...] = ()
    reasons: tuple[str, ...] = ()

    def dominates(self, other: "TransferCandidate") -> bool:
        return (
            self.estimated_ms <= other.estimated_ms
            and self.estimated_wire_bytes <= other.estimated_wire_bytes
            and self.manifest_cpu_ms <= other.manifest_cpu_ms
            and self.energy_score <= other.energy_score
            and self.reliability >= other.reliability
            and self.coherence_score >= other.coherence_score
            and (
                self.estimated_ms < other.estimated_ms
                or self.estimated_wire_bytes < other.estimated_wire_bytes
                or self.reliability > other.reliability
                or self.coherence_score > other.coherence_score
            )
        )


@dataclass(frozen=True)
class TransferBrainDecision:
    selected: TransferCandidate
    frontier: tuple[TransferCandidate, ...]
    health: HealthState
    action: str

    def to_dict(self) -> dict:
        return {
            "selected": self.selected.mode.value,
            "route": self.selected.route,
            "estimated_ms": round(self.selected.estimated_ms, 3),
            "estimated_wire_bytes": self.selected.estimated_wire_bytes,
            "manifest_cpu_ms": round(self.selected.manifest_cpu_ms, 3),
            "reliability": round(self.selected.reliability, 4),
            "confidence": round(self.selected.confidence, 4),
            "coherence_score": round(self.selected.coherence_score, 4),
            "parallelism": self.selected.parallelism,
            "route_latency_ms": (
                round(self.selected.route_latency_ms, 3)
                if self.selected.route_latency_ms is not None else None
            ),
            "route_bandwidth_bps": (
                round(self.selected.route_bandwidth_bps, 3)
                if self.selected.route_bandwidth_bps is not None else None
            ),
            "verification_head": list(self.selected.verification_head),
            "health": self.health.value,
            "action": self.action,
            "frontier": [c.mode.value for c in self.frontier],
            "reasons": list(self.selected.reasons),
        }


@dataclass(frozen=True)
class TransferAutopilotPlan:
    """Human- and machine-readable strategy for one file send.

    The planner is intentionally deterministic: given the same route memory,
    engine memory, peer caps, and file shape it returns the same answer. The
    daemon stores this in transfer metadata so the UI can explain what One Link
    is doing without exposing protocol noise.
    """

    mode: str
    route: str
    state: str
    frame_kind: str
    compression_policy: str
    chunk_size: int
    window_chunks: int
    window_bytes: int
    ack_batch: int
    retry_posture: str
    route_score: float
    confidence: float
    estimated_wire_bytes: int
    estimated_saved_bytes: int
    estimated_savings_ratio: float
    estimated_seconds: float
    estimated_mbps: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "route": self.route,
            "state": self.state,
            "frame_kind": self.frame_kind,
            "compression_policy": self.compression_policy,
            "chunk_size": self.chunk_size,
            "window_chunks": self.window_chunks,
            "window_bytes": self.window_bytes,
            "ack_batch": self.ack_batch,
            "retry_posture": self.retry_posture,
            "route_score": self.route_score,
            "confidence": self.confidence,
            "estimated_wire_bytes": self.estimated_wire_bytes,
            "estimated_saved_bytes": self.estimated_saved_bytes,
            "estimated_savings_ratio": self.estimated_savings_ratio,
            "estimated_seconds": self.estimated_seconds,
            "estimated_mbps": self.estimated_mbps,
            "reasons": list(self.reasons),
        }


def build_transfer_autopilot_plan(
    *,
    decision: Mapping[str, object] | TransferBrainDecision,
    profile: Mapping[str, int | float | str],
    size_bytes: int,
    peer_features: Iterable[str] = (),
    prior_hit_rate: float = 0.0,
    cdc_binary_feature: str = "file_cdc_binary_frame",
    stream_binary_feature: str = "file_binary_frame",
) -> TransferAutopilotPlan:
    """Create the concrete runtime plan used by daemon + UI.

    This sits one layer above `decide`: it converts "CDC on LAN is best" into
    exact runtime posture: binary-vs-JSON frames, bounded ACK batching,
    compression posture, retry mode, and the speed/savings users care about.
    """

    d: dict[str, Any] = (
        decision.to_dict() if isinstance(decision, TransferBrainDecision)
        else dict(decision)
    )
    features = {str(f) for f in peer_features}
    mode = str(d.get("selected") or "hash_stream")
    route = str(d.get("route") or "lan")
    health = str(d.get("health") or "observing")
    size = max(0, int(size_bytes))
    wire = max(0, int(d.get("estimated_wire_bytes") or size))
    saved = max(0, size - wire)
    savings = _clamp01(max(float(prior_hit_rate or 0.0), saved / max(1, size)))
    chunk_size = max(1, int(profile.get("chunk_size") or MiB))
    window_chunks = max(1, int(profile.get("window_chunks") or 1))
    window_bytes = max(chunk_size, int(profile.get("window_bytes") or window_chunks * chunk_size))
    confidence = _clamp01(float(d.get("confidence") or 0.0))
    coherence = _clamp01(float(d.get("coherence_score") or 0.0))
    reliability = _clamp01(float(d.get("reliability") or 0.0))
    route_score = round(_clamp01((coherence * 0.45) + (reliability * 0.40) + (confidence * 0.15)), 6)

    if mode in (TransferMode.CDC_MANIFEST.value, TransferMode.SWARM_CDC.value):
        frame_kind = "cdc_binary" if cdc_binary_feature in features else "cdc_json_compat"
    else:
        frame_kind = "stream_binary" if stream_binary_feature in features else "stream_json_compat"

    compression_policy = "adaptive"
    if savings >= 0.90:
        compression_policy = "skip_heavy_compression"
    elif frame_kind.endswith("json_compat"):
        compression_policy = "adaptive_json_safe"

    if health == HealthState.REPAIR.value:
        ack_batch = 1
        retry_posture = "repair_reopen_session"
    elif health == HealthState.CONSTRAINED.value:
        ack_batch = max(1, min(2, window_chunks // 2))
        retry_posture = "cautious_retry"
    else:
        ack_batch = max(1, min(window_chunks, 8 if frame_kind.endswith("binary") else 4))
        retry_posture = "auto_resume"

    estimated_ms = max(1.0, float(d.get("estimated_ms") or 1.0))
    estimated_seconds = estimated_ms / 1000.0
    effective_mbps = (size * 8.0) / max(0.001, estimated_seconds) / 1_000_000.0
    reasons = tuple(str(r) for r in d.get("reasons") or ())
    reasons += (
        f"{frame_kind} frames",
        f"{window_chunks} chunk window",
        f"{savings:.1%} estimated bandwidth avoided",
    )

    return TransferAutopilotPlan(
        mode=mode,
        route=route,
        state=health,
        frame_kind=frame_kind,
        compression_policy=compression_policy,
        chunk_size=chunk_size,
        window_chunks=window_chunks,
        window_bytes=window_bytes,
        ack_batch=ack_batch,
        retry_posture=retry_posture,
        route_score=route_score,
        confidence=round(confidence, 6),
        estimated_wire_bytes=wire,
        estimated_saved_bytes=saved,
        estimated_savings_ratio=round(savings, 6),
        estimated_seconds=round(estimated_seconds, 3),
        estimated_mbps=round(effective_mbps, 3),
        reasons=reasons,
    )


def transfer_performance_summary(
    *,
    report: Mapping[str, object],
    plan: Mapping[str, object] | TransferAutopilotPlan | None = None,
    elapsed_s: float | None = None,
) -> dict[str, object]:
    """UI-ready transfer truth: speed, savings, ETA, and what happened."""

    p = plan.to_dict() if isinstance(plan, TransferAutopilotPlan) else dict(plan or {})
    effective = int(_as_float(report.get("effective_payload_bytes")))
    raw = int(_as_float(report.get("raw_bytes_sent")))
    wire = int(_as_float(report.get("wire_bytes_sent")))
    skipped = int(_as_float(report.get("skipped_bytes")))
    saved = int(_as_float(report.get("saved_bytes")))
    effective_bps = _as_float(report.get("effective_throughput_bps"))
    wire_bps = _as_float(report.get("wire_throughput_bps"))
    elapsed = max(0.001, float(elapsed_s if elapsed_s is not None else 0.0))
    if elapsed_s is None and effective_bps > 0 and effective > 0:
        elapsed = max(0.001, (effective * 8.0) / effective_bps)
    savings = _clamp01(_as_float(report.get("bandwidth_savings_ratio")))
    return {
        "state": "done" if effective >= 0 else "sending",
        "mode": p.get("mode"),
        "route": p.get("route"),
        "frame_kind": p.get("frame_kind"),
        "effective_mbps": round(effective_bps / 1_000_000.0, 3),
        "wire_mbps": round(wire_bps / 1_000_000.0, 3),
        "elapsed_ms": int(round(elapsed * 1000.0)),
        "raw_bytes_sent": raw,
        "wire_bytes_sent": wire,
        "skipped_bytes": skipped,
        "saved_bytes": saved,
        "bandwidth_savings_ratio": round(savings, 6),
        "optimization_multiplier": round(effective / max(1, wire), 3),
        "plain_english": _performance_plain_english(
            frame_kind=str(p.get("frame_kind") or ""),
            skipped_bytes=skipped,
            savings_ratio=savings,
        ),
    }


def _performance_plain_english(
    *,
    frame_kind: str,
    skipped_bytes: int,
    savings_ratio: float,
) -> str:
    if skipped_bytes > 0 and savings_ratio >= 0.90:
        return "Most of this file was already known, so One Link sent only the missing pieces."
    if "binary" in frame_kind:
        return "One Link used the fast binary transfer path for this device."
    return "One Link used the safest compatible transfer path for this device."


def adapt_pipeline_profile(
    profile: Mapping[str, int],
    decision: Mapping[str, object] | TransferBrainDecision,
    *,
    max_window_chunks: int = 32,
    max_window_bytes: int = 64 * MiB,
) -> dict[str, int | float | str]:
    """Tune chunk pipeline depth from the current brain decision.

    This is intentionally bounded. A strong LAN/mesh path gets enough
    in-flight work to fill the pipe; an observing/constrained/repair path
    backs off so a flaky session does less damage before the auto-healer
    refreshes it.
    """

    if isinstance(decision, TransferBrainDecision):
        d = decision.to_dict()
    else:
        d = dict(decision)
    chunk_size = max(1, int(profile.get("chunk_size") or MiB))
    base_chunks = max(1, int(profile.get("window_chunks") or 1))
    base_bytes = max(chunk_size, int(profile.get("window_bytes") or base_chunks * chunk_size))
    health = str(d.get("health") or "observing")
    coherence = float(d.get("coherence_score") or 0.0)
    reliability = float(d.get("reliability") or 0.0)
    parallelism = max(1, int(d.get("parallelism") or 1))
    route_latency = d.get("route_latency_ms")
    route_bandwidth = d.get("route_bandwidth_bps")

    multiplier = 1.0
    reason = "steady"
    if health == HealthState.REPAIR.value:
        multiplier = 0.35
        reason = "repair_backoff"
    elif health == HealthState.CONSTRAINED.value:
        multiplier = 0.55
        reason = "constrained_backoff"
    elif health == HealthState.OBSERVING.value:
        multiplier = 0.80
        reason = "observing_probe"
    elif coherence >= 0.88 and reliability >= 0.90:
        multiplier = 2.0
        reason = "coherent_fast_lane"
    elif coherence >= 0.72 and reliability >= 0.80:
        multiplier = 1.5
        reason = "coherent_lane"

    if parallelism > 1 and health == HealthState.HEALTHY.value:
        multiplier *= min(1.75, 1.0 + (parallelism - 1) * 0.18)
        reason = "mesh_parallel_lane" if reason == "steady" else reason

    tuned_chunks = max(1, min(max_window_chunks, int(round(base_chunks * multiplier))))
    desired_bytes = max(chunk_size, tuned_chunks * chunk_size, int(base_bytes * multiplier))
    if health == HealthState.HEALTHY.value:
        try:
            latency_ms = float(route_latency) if route_latency is not None else 0.0
            bandwidth_bps = float(route_bandwidth) if route_bandwidth is not None else 0.0
        except (TypeError, ValueError):
            latency_ms = 0.0
            bandwidth_bps = 0.0
        if latency_ms > 0.0 and bandwidth_bps > 0.0:
            # BDP-aware fast lane: keep enough chunks in flight to fill the
            # measured pipe, plus a small cushion for ACK jitter. This is the
            # practical route to "use the real link, not a fixed guess".
            bdp_bytes = int((bandwidth_bps * (latency_ms / 1000.0)) / 8.0)
            cushion = 2.5 if coherence >= 0.85 else 1.75
            desired_bytes = max(desired_bytes, int(bdp_bytes * cushion))
            if reason == "steady":
                reason = "bdp_fast_lane"
    tuned_bytes = min(max_window_bytes, desired_bytes)
    tuned_chunks = max(1, min(max_window_chunks, tuned_bytes // chunk_size))
    return {
        "chunk_size": chunk_size,
        "window_chunks": int(tuned_chunks),
        "window_bytes": int(tuned_chunks * chunk_size),
        "multiplier": round(multiplier, 4),
        "reason": reason,
    }


def transfer_result_report(
    *,
    raw_bytes: int,
    wire_bytes: int,
    elapsed_s: float,
    skipped_bytes: int = 0,
    resumed_bytes: int = 0,
) -> dict[str, int | float | str]:
    """Summarize ONE send attempt's efficiency for route learning and UI.

    The report says so itself (``accounting_window``): on a ledger row that
    took several attempts it describes the last one, and the row's
    ``raw_bytes``/``wire_bytes`` and ``payload_transfer_totals`` describe the
    transfer.

    ``raw_bytes`` is what this sender actually read and pushed. ``wire_bytes``
    is what crossed the channel after compression/protocol choice.
    ``skipped_bytes`` is payload the peer already had when this attempt was
    offered, which matters because the user experiences it as delivered even
    though the network did not carry it again.

    ``resumed_bytes`` is what earlier attempts of the same transfer moved.
    The part of it the peer kept was carried by the network, in another
    attempt's time: it is reported as ``resumed_bytes`` and counts neither as
    skipped, as saved, nor as this attempt's effective payload.  Without that
    split a resumed send reports its own earlier work as prior knowledge.
    """

    raw = max(0, int(raw_bytes))
    wire = max(0, int(wire_bytes))
    resumed = resumed_share(skipped_bytes, resumed_bytes)
    skipped = max(0, int(skipped_bytes)) - resumed
    elapsed = max(0.001, float(elapsed_s))
    effective = raw + skipped
    saved = max(0, effective - wire)
    return {
        "accounting_window": PAYLOAD_ATTEMPT_WINDOW,
        "raw_bytes_sent": raw,
        "wire_bytes_sent": wire,
        "skipped_bytes": skipped,
        "resumed_bytes": resumed,
        "effective_payload_bytes": effective,
        "saved_bytes": saved,
        "raw_throughput_bps": round((raw * 8.0) / elapsed, 3),
        "wire_throughput_bps": round((wire * 8.0) / elapsed, 3),
        "effective_throughput_bps": round((effective * 8.0) / elapsed, 3),
        "wire_efficiency_ratio": round(wire / max(1, effective), 6),
        "bandwidth_savings_ratio": round(saved / max(1, effective), 6),
    }


class AdaptiveTransferScheduler:
    """ACK-clocked runtime controller for one active file transfer.

    The transfer brain chooses an initial plan. This scheduler keeps tuning
    that plan while bytes are moving: fast ACKs open the window gradually,
    slow ACKs shrink it, and a compact black-box timeline explains what
    happened later without dumping protocol internals on the user.
    """

    def __init__(
        self,
        profile: Mapping[str, Any],
        *,
        min_window_chunks: int = 1,
        max_window_chunks: int = 32,
        max_window_bytes: int | None = None,
        timeline_limit: int = 80,
    ) -> None:
        self.chunk_size = max(1, int(profile.get("chunk_size") or MiB))
        self.min_window_chunks = max(1, int(min_window_chunks))
        requested_max_chunks = max(
            self.min_window_chunks,
            int(max_window_chunks),
        )
        if max_window_bytes is None:
            byte_limited_max_chunks = requested_max_chunks
        else:
            byte_limited_max_chunks = max(
                1,
                int(max_window_bytes) // self.chunk_size,
            )
        self.max_window_chunks = max(
            self.min_window_chunks,
            min(requested_max_chunks, byte_limited_max_chunks),
        )
        self.max_window_bytes = self.max_window_chunks * self.chunk_size
        self.window_chunks = max(
            self.min_window_chunks,
            min(self.max_window_chunks, int(profile.get("window_chunks") or 1)),
        )
        self.window_bytes = self.window_chunks * self.chunk_size
        growth_step_bytes = max(
            self.chunk_size,
            int(profile.get("growth_step_bytes") or self.chunk_size),
        )
        self.growth_step_chunks = max(
            1,
            growth_step_bytes // self.chunk_size,
        )
        self.reason = str(profile.get("reason") or "runtime")
        self.timeline_limit = max(8, int(timeline_limit))
        self._good_acks = 0
        self._ack_count = 0
        self._ack_ema_ms: float | None = None
        self._last_event_ms = 0
        self._timeline: list[dict[str, int | float | str]] = []
        target = profile.get("target_ack_ms")
        if target is None:
            target = profile.get("route_latency_ms")
        try:
            target_f = float(target) if target is not None else 80.0
        except (TypeError, ValueError):
            target_f = 80.0
        self.target_ack_ms = max(8.0, min(2000.0, target_f * 2.5))
        self._record(
            "start",
            window=self.window_chunks,
            target_ack_ms=round(self.target_ack_ms, 3),
            reason=self.reason,
        )

    def can_send(self, in_flight_chunks: int) -> bool:
        return int(in_flight_chunks) < self.window_chunks

    def observe_ack(
        self,
        *,
        ack_ms: float,
        raw_bytes: int,
        wire_bytes: int,
        in_flight_chunks: int,
    ) -> None:
        ack = max(0.001, float(ack_ms))
        self._ack_count += 1
        if self._ack_ema_ms is None:
            self._ack_ema_ms = ack
        else:
            self._ack_ema_ms = self._ack_ema_ms * 0.75 + ack * 0.25
        if ack <= self.target_ack_ms * 1.35:
            self._good_acks += 1
            if self._good_acks >= max(2, self.window_chunks) and self.window_chunks < self.max_window_chunks:
                self.window_chunks = min(
                    self.max_window_chunks,
                    self.window_chunks + self.growth_step_chunks,
                )
                self.window_bytes = self.window_chunks * self.chunk_size
                self._good_acks = 0
                self._record(
                    "window_up",
                    window=self.window_chunks,
                    growth_step_chunks=self.growth_step_chunks,
                    ack_ms=round(ack, 3),
                    ack_ema_ms=round(self._ack_ema_ms, 3),
                )
        elif ack >= self.target_ack_ms * 4.0 and self.window_chunks > self.min_window_chunks:
            old = self.window_chunks
            self.window_chunks = max(self.min_window_chunks, self.window_chunks // 2)
            self.window_bytes = self.window_chunks * self.chunk_size
            self._good_acks = 0
            self._record(
                "window_down",
                window=self.window_chunks,
                previous_window=old,
                ack_ms=round(ack, 3),
                ack_ema_ms=round(self._ack_ema_ms, 3),
            )
        elif self._ack_count <= 4:
            self._record(
                "ack_sample",
                window=self.window_chunks,
                ack_ms=round(ack, 3),
                in_flight=max(0, int(in_flight_chunks)),
                wire_bytes=max(0, int(wire_bytes)),
                raw_bytes=max(0, int(raw_bytes)),
            )

    def observe_retry(self, *, reason: str, in_flight_chunks: int = 0) -> None:
        old = self.window_chunks
        self.window_chunks = max(self.min_window_chunks, self.window_chunks // 2)
        self.window_bytes = self.window_chunks * self.chunk_size
        self._good_acks = 0
        self._record(
            "retry_or_reopen",
            window=self.window_chunks,
            previous_window=old,
            in_flight=max(0, int(in_flight_chunks)),
            reason=str(reason)[:80],
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "window_chunks": self.window_chunks,
            "window_bytes": self.window_bytes,
            "max_window_chunks": self.max_window_chunks,
            "max_window_bytes": self.max_window_bytes,
            "growth_step_chunks": self.growth_step_chunks,
            "target_ack_ms": round(self.target_ack_ms, 3),
            "ack_count": self._ack_count,
            "ack_ema_ms": (
                round(self._ack_ema_ms, 3) if self._ack_ema_ms is not None else None
            ),
            "timeline": list(self._timeline),
        }

    def _record(self, event: str, **fields: int | float | str) -> None:
        self._last_event_ms += 1
        row: dict[str, int | float | str] = {"seq": self._last_event_ms, "event": event}
        row.update(fields)
        self._timeline.append(row)
        if len(self._timeline) > self.timeline_limit:
            del self._timeline[:len(self._timeline) - self.timeline_limit]


def pareto_frontier(candidates: Iterable[TransferCandidate]) -> tuple[TransferCandidate, ...]:
    items = tuple(candidates)
    frontier = [
        c for c in items
        if not any(other is not c and other.dominates(c) for other in items)
    ]
    return tuple(sorted(
        frontier,
        key=lambda c: (
            c.estimated_ms,
            c.estimated_wire_bytes,
            c.energy_score,
            -c.reliability,
            -c.coherence_score,
            c.mode.value,
            c.route,
        ),
    ))


class AdaptiveTransferBrain:
    """Learns route cost and chooses a transfer strategy.

    Phase C-3 (ADRs 0019 and 0027): when
    ``one_link_native.bandit`` is available, observations train a
    :class:`BanditRouteSelector` and ``decide()`` uses its Thompson
    sample for the route-choice axis. EMA route statistics remain
    inputs to cost/reliability calculations and the explicit rollback
    path; they are not a second route-ranking policy. No bandit control
    loop is currently wired for chunk size, parallelism, FEC ratio,
    prefetch, pacing, or compression threshold."""

    DEFAULT_HASH_MIB_S = 1500.0
    DEFAULT_FIXED_MIB_S = 1100.0
    DEFAULT_CDC_MIB_S = 8.0
    DEFAULT_ROUTE_BPS = 80_000_000.0

    def __init__(self) -> None:
        self._routes: dict[str, RouteStats] = {}
        # Phase C-3 route bandit. Built lazily on first observe() so
        # the route arms match what the daemon actually sees.
        self._bandit: BanditRouteSelector | None = None

    def observe(self, obs: TransferRouteObservation) -> None:
        current = self._routes.get(obs.route, RouteStats(route=obs.route))
        self._routes[obs.route] = current.observe(obs)
        self._bandit_record(obs)

    def _bandit_record(self, obs: TransferRouteObservation) -> None:
        """Record a route observation for the authoritative route bandit.

        Failures in this optional native optimization are isolated so
        the safe Pareto/EMA rollback path remains available."""
        try:
            from . import bandit_native

            if not bandit_native.HAS_NATIVE:
                return
        except ImportError:
            return
        # Build the bandit lazily and grow as new routes appear. The
        # ol_bandit Bandit is fixed-arity, so we re-create it when a
        # new route is observed. This is cheap (microseconds) and
        # only happens at route discovery; the steady-state path is
        # straight-line update().
        seen_routes = tuple(sorted(self._routes.keys()))
        if self._bandit is None or self._bandit.routes != seen_routes:
            try:
                self._bandit = BanditRouteSelector(seen_routes, seed=0xCAFE_BABE)
            except Exception:
                self._bandit = None
                return
        # TransferRouteObservation reports bandwidth in bits-per-second
        # already; pass it through directly. `ok=False` records a
        # zero-reward failure regardless of bandwidth.
        try:
            self._bandit.record_outcome(
                obs.route,
                bandwidth_bps=float(obs.bandwidth_bps or 0.0),
                success=bool(obs.ok),
            )
        except Exception:
            # A divergence (e.g. unknown arm) silently drops the
            # observation; the safe Pareto/EMA fallback remains available.
            return

    def best_route_bandit(self) -> str | None:
        """Return the route arm with the highest posterior mean.

        This diagnostic differs from ``decide()``'s exploratory Thompson
        sample. Returns ``None`` when the bandit is not initialized."""
        return self._bandit.best_route() if self._bandit is not None else None

    def route_stats(self) -> tuple[RouteStats, ...]:
        return tuple(sorted(
            self._routes.values(),
            key=lambda s: (-s.reliability, -(s.bandwidth_ema_bps or 0.0), s.route),
        ))

    def decide(
        self,
        *,
        size_bytes: int,
        supports_cdc: bool,
        supports_swarm: bool = False,
        prior_hit_rate: float | None = None,
        routes: Iterable[str] | None = None,
        mesh_nodes: Iterable[MeshNodeSignal] | None = None,
        verification_head: Iterable[int] | None = None,
        observed_hash_mib_s: float | None = None,
        observed_fixed_mib_s: float | None = None,
        observed_cdc_mib_s: float | None = None,
    ) -> TransferBrainDecision:
        size = max(0, int(size_bytes))
        hit_rate = min(1.0, max(0.0, float(prior_hit_rate or 0.0)))
        candidate_routes = tuple(routes or (s.route for s in self.route_stats()) or ("lan",))
        # Phase C-3 (ADR-0027): bandit-driven route picker. Per the
        # plan's stress-test #3, the bandit replaces EMA ranking for
        # the route-choice axis. When the bandit has been seeded by
        # observations and we have ≥2 candidate routes, Thompson-sample
        # one route and constrain decide()'s candidate generation to
        # that route only. The Pareto frontier still picks the MODE
        # within the chosen route (hash mode / fixed-size / CDC /
        # swarm / etc.).
        #
        # Roll back via ONE_LINK_BANDIT_ROUTE_PICKER=0 for production
        # incidents that need the legacy multi-route Pareto search.
        if (
            self._bandit is not None
            and len(candidate_routes) > 1
            and os.environ.get("ONE_LINK_BANDIT_ROUTE_PICKER", "1") != "0"
        ):
            try:
                bandit_pick = self._bandit.select_route()
                if bandit_pick in candidate_routes:
                    candidate_routes = (bandit_pick,)
            except Exception as exc:
                # Bandit divergence (e.g. arm-count mismatch) observably
                # falls back to the legacy multi-route path. Never
                # break a transfer because of a bandit hiccup.
                report_best_effort_failure(
                    log,
                    "bandit_route_selection",
                    exc,
                    interval_s=30.0,
                )
        mesh = tuple(mesh_nodes or ())
        mesh_coherence = max((n.coherence for n in mesh), default=0.5)
        mesh_parallelism = max(1, min(8, sum(1 for n in mesh if n.coherence >= 0.55)))
        verification = tuple(int(i) for i in (verification_head or ()))[:8]
        candidates: list[TransferCandidate] = []
        for route in candidate_routes:
            stats = self._routes.get(route, RouteStats(route=route))
            candidates.extend(self._candidates_for_route(
                route=route,
                stats=stats,
                size_bytes=size,
                supports_cdc=supports_cdc,
                supports_swarm=supports_swarm,
                prior_hit_rate=hit_rate,
                hash_mib_s=observed_hash_mib_s or self.DEFAULT_HASH_MIB_S,
                fixed_mib_s=observed_fixed_mib_s or self.DEFAULT_FIXED_MIB_S,
                cdc_mib_s=observed_cdc_mib_s or self.DEFAULT_CDC_MIB_S,
                mesh_coherence=mesh_coherence,
                mesh_parallelism=mesh_parallelism,
                verification_head=verification,
            ))
        frontier = pareto_frontier(candidates)
        selected = min(
            frontier or tuple(candidates),
            key=lambda c: (
                c.estimated_ms / max(0.05, c.reliability),
                c.estimated_wire_bytes,
                c.manifest_cpu_ms,
                -c.coherence_score,
                c.mode.value,
            ),
        )
        health, action = self._regulate(selected)
        return TransferBrainDecision(
            selected=selected,
            frontier=frontier,
            health=health,
            action=action,
        )

    def _candidates_for_route(
        self,
        *,
        route: str,
        stats: RouteStats,
        size_bytes: int,
        supports_cdc: bool,
        supports_swarm: bool,
        prior_hit_rate: float,
        hash_mib_s: float,
        fixed_mib_s: float,
        cdc_mib_s: float,
        mesh_coherence: float,
        mesh_parallelism: int,
        verification_head: tuple[int, ...],
    ) -> tuple[TransferCandidate, ...]:
        route_bps = stats.bandwidth_ema_bps or self.DEFAULT_ROUTE_BPS
        route_ms = (size_bytes * 8.0 / max(1.0, route_bps)) * 1000.0
        latency = stats.latency_ema_ms or 10.0
        reliability = stats.reliability
        confidence = stats.confidence
        route_coherence = route_coherence_score(stats)
        coherence = round((route_coherence * 0.70) + (mesh_coherence * 0.30), 6)

        def cpu_ms(speed_mib_s: float) -> float:
            return (size_bytes / MiB) / max(0.001, speed_mib_s) * 1000.0

        out = [
            TransferCandidate(
                mode=TransferMode.HASH_STREAM,
                route=route,
                estimated_ms=latency + route_ms + cpu_ms(hash_mib_s),
                estimated_wire_bytes=size_bytes,
                manifest_cpu_ms=cpu_ms(hash_mib_s),
                reliability=reliability,
                energy_score=stats.energy_ema,
                confidence=confidence,
                coherence_score=coherence,
                route_latency_ms=latency,
                route_bandwidth_bps=route_bps,
                verification_head=verification_head,
                reasons=("fastest compatible baseline",),
            ),
            TransferCandidate(
                mode=TransferMode.FIXED_MANIFEST,
                route=route,
                estimated_ms=latency + route_ms + cpu_ms(fixed_mib_s),
                estimated_wire_bytes=size_bytes,
                manifest_cpu_ms=cpu_ms(fixed_mib_s),
                reliability=reliability,
                energy_score=stats.energy_ema * 0.92,
                confidence=confidence,
                coherence_score=coherence,
                route_latency_ms=latency,
                route_bandwidth_bps=route_bps,
                verification_head=verification_head,
                reasons=("aligned-block high-throughput manifest",),
            ),
        ]
        if supports_cdc:
            wire_bytes = int(size_bytes * (1.0 - prior_hit_rate))
            cdc_route_ms = (wire_bytes * 8.0 / max(1.0, route_bps)) * 1000.0
            out.append(TransferCandidate(
                mode=TransferMode.CDC_MANIFEST,
                route=route,
                estimated_ms=latency + cdc_route_ms + cpu_ms(cdc_mib_s),
                estimated_wire_bytes=wire_bytes,
                manifest_cpu_ms=cpu_ms(cdc_mib_s),
                reliability=reliability,
                energy_score=stats.energy_ema * (1.0 - prior_hit_rate * 0.7),
                confidence=confidence,
                coherence_score=round(min(1.0, coherence + prior_hit_rate * 0.15), 6),
                parallelism=1,
                route_latency_ms=latency,
                route_bandwidth_bps=route_bps,
                verification_head=verification_head,
                reasons=(f"prior hit estimate {prior_hit_rate:.1%}",),
            ))
            if supports_swarm:
                out.append(TransferCandidate(
                    mode=TransferMode.SWARM_CDC,
                    route=route,
                    estimated_ms=latency + cdc_route_ms * max(0.22, 0.75 / mesh_parallelism) + cpu_ms(cdc_mib_s),
                    estimated_wire_bytes=wire_bytes,
                    manifest_cpu_ms=cpu_ms(cdc_mib_s),
                    reliability=min(0.995, reliability + 0.08),
                    energy_score=stats.energy_ema * (1.0 - prior_hit_rate * 0.8),
                    confidence=confidence * 0.95,
                    coherence_score=round(min(1.0, coherence + 0.10 + prior_hit_rate * 0.18), 6),
                    parallelism=mesh_parallelism,
                    route_latency_ms=latency,
                    route_bandwidth_bps=route_bps,
                    verification_head=verification_head,
                    reasons=("multiple trusted sources can split missing chunks",),
                ))
        return tuple(out)

    def _regulate(self, selected: TransferCandidate) -> tuple[HealthState, str]:
        if selected.reliability < 0.35:
            return HealthState.REPAIR, "refresh_route_and_reopen_session"
        if selected.coherence_score < 0.30:
            return HealthState.REPAIR, "seek_better_mesh_route"
        if selected.reliability < 0.60:
            return HealthState.CONSTRAINED, "prefer_simplest_verified_protocol"
        if selected.confidence < 0.35:
            return HealthState.OBSERVING, "collect_more_route_evidence"
        return HealthState.HEALTHY, "send"


class BanditRouteSelector:
    """Route-arm bandit for route selection (ADR-0019, Phase C item
    #5). Replaces the EMA-derived route ranking in
    :class:`AdaptiveTransferBrain` when ``one_link_native.bandit`` is
    available.

    Each candidate route is one bandit arm; the reward signal is the
    observed bandwidth normalized into ``[0, 1]``. The bandit's
    Beta-Bernoulli Thompson sampling explores under-tested routes
    while exploiting known-good ones; per stress-test #3 it
    SUBSUMES the EMA route memory rather than coexisting with it.
    """

    # Bandit reward is in [0, 1]. We saturate at this throughput so a
    # 1 Gbps observation maps to roughly 1.0 reward; lower observations
    # produce proportional reward, terminal failure produces 0.
    REWARD_SATURATION_BPS = 1_000_000_000.0

    def __init__(self, routes: tuple[str, ...], *, seed: int = 0xBABE_F00D) -> None:
        if not routes:
            raise ValueError("BanditRouteSelector requires at least one route")
        from . import bandit_native

        if not bandit_native.HAS_NATIVE:
            raise RuntimeError(
                "BanditRouteSelector requires one_link_native.bandit; "
                "build via `cd native && maturin develop --release`"
            )
        self._routes: tuple[str, ...] = tuple(routes)
        self._route_to_arm: dict[str, int] = {r: i for i, r in enumerate(self._routes)}
        self._bandit = bandit_native.bandit(len(self._routes), seed)

    @property
    def routes(self) -> tuple[str, ...]:
        return self._routes

    def select_route(self) -> str:
        """Thompson-sample an arm and return the corresponding route."""
        return self._routes[self._bandit.select()]

    def record_outcome(self, route: str, *, bandwidth_bps: float, success: bool) -> None:
        """Update the bandit with observed throughput.

        Failed observations (``success=False``) record reward 0; a
        successful observation maps ``bandwidth_bps`` into ``[0, 1]``
        by clamping at :attr:`REWARD_SATURATION_BPS`."""
        if route not in self._route_to_arm:
            raise KeyError(f"unknown route {route!r}; bandit arms: {self._routes}")
        if not success:
            reward = 0.0
        else:
            reward = min(1.0, max(0.0, bandwidth_bps / self.REWARD_SATURATION_BPS))
        self._bandit.update(self._route_to_arm[route], reward)

    def best_route(self) -> str:
        """Return the route with the highest posterior mean (greedy
        pick — useful for telemetry, NOT for exploration)."""
        return self._routes[self._bandit.best_arm()]

    def arm_stats(self) -> tuple[tuple[str, float, float], ...]:
        """Per-arm ``(route, alpha, beta)`` tuples for diagnostics."""
        return tuple(
            (self._routes[i], a, b) for i, (a, b) in enumerate(self._bandit.arms())
        )


def decision_from_observations(
    *,
    size_bytes: int,
    supports_cdc: bool,
    supports_swarm: bool,
    prior_hit_rate: float | None,
    observations: Iterable[TransferRouteObservation],
    routes: Iterable[str] | None = None,
    mesh_nodes: Iterable[MeshNodeSignal] | None = None,
    verification_head: Iterable[int] | None = None,
    speeds: Mapping[str, float] | None = None,
) -> TransferBrainDecision:
    brain = AdaptiveTransferBrain()
    for obs in observations:
        brain.observe(obs)
    speeds = speeds or {}
    return brain.decide(
        size_bytes=size_bytes,
        supports_cdc=supports_cdc,
        supports_swarm=supports_swarm,
        prior_hit_rate=prior_hit_rate,
        routes=routes,
        mesh_nodes=mesh_nodes,
        verification_head=verification_head,
        observed_hash_mib_s=speeds.get("hash_mib_s"),
        observed_fixed_mib_s=speeds.get("fixed_mib_s"),
        observed_cdc_mib_s=speeds.get("cdc_mib_s"),
    )


def _clamp01(value: float) -> float:
    return min(1.0, max(0.0, float(value)))


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        out = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return float(default)
    if out != out:
        return float(default)
    return out


def route_coherence_score(stats: RouteStats) -> float:
    latency = stats.latency_ema_ms if stats.latency_ema_ms is not None else 250.0
    latency_score = 1.0 / (1.0 + max(0.0, latency) / 50.0)
    bandwidth = stats.bandwidth_ema_bps if stats.bandwidth_ema_bps is not None else 0.0
    bandwidth_score = min(1.0, max(0.0, bandwidth) / 1_000_000_000.0)
    energy_score = 1.0 / (1.0 + max(0.0, stats.energy_ema - 1.0))
    value = (
        0.45 * stats.reliability
        + 0.25 * bandwidth_score
        + 0.18 * latency_score
        + 0.08 * stats.confidence
        + 0.04 * energy_score
    )
    return round(_clamp01(value), 6)


def verification_priority_order(
    chunks: Iterable[object],
    *,
    claim_counts: Mapping[str, int] | None = None,
    source_coherence: Mapping[str, float] | None = None,
    max_items: int = 16,
) -> tuple[VerificationTask, ...]:
    """Order chunk verification suspicious-first.

    Rare chunks, chunks with weak source coherence, and edge chunks get checked
    first. This borrows the forge shootout's "verify where failure is likeliest"
    idea without weakening cryptographic verification: every chunk still must
    hash correctly, we simply surface the most valuable early checks first.
    """
    claim_counts = claim_counts or {}
    source_coherence = source_coherence or {}
    rows = list(chunks)
    if not rows:
        return ()
    last_index = max(int(getattr(c, "index", 0)) for c in rows)
    tasks: list[VerificationTask] = []
    for c in rows:
        idx = int(getattr(c, "index", 0))
        h = str(getattr(c, "hash", ""))
        claims = max(0, int(claim_counts.get(h, 0)))
        coherence = _clamp01(source_coherence.get(h, 0.5))
        rarity = 1.0 / (1.0 + claims)
        edge = 1.0 if idx in (0, last_index) else 0.0
        priority = 0.58 * rarity + 0.32 * (1.0 - coherence) + 0.10 * edge
        reason = "rare_or_unclaimed" if claims <= 1 else "weak_source" if coherence < 0.45 else "edge_guard"
        tasks.append(VerificationTask(idx, h, round(priority, 6), reason))
    return tuple(sorted(tasks, key=lambda t: (-t.priority, t.index))[:max_items])
