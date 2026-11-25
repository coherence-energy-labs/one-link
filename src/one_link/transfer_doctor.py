"""Transfer Doctor: user-safe diagnosis and auto-healing decisions.

The daemon already keeps durable transfer rows. This module turns those raw
rows into a small, stable contract:

* what the user should see;
* what One Link should do next;
* whether the issue is transient or needs human attention.

It is intentionally deterministic and side-effect free so the UI, daemon, and
torture simulator can all rely on the same diagnosis vocabulary.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Mapping


AUTO_ACTIONS = {
    "wait_for_peer",
    "retry_with_backoff",
    "reopen_secure_session",
    "refresh_route",
    "retry_missing_chunk",
    "fallback_protocol",
}


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value is False:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or value is False:
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _route_label(route: Any) -> str:
    r = str(route or "").strip().lower()
    if r in {"lan", "wifi", "wifi_direct", "wifi-direct"}:
        return "Wi-Fi direct"
    if r in {"ethernet", "ethernet_direct", "ethernet-direct"}:
        return "Ethernet direct"
    if r in {"relay", "rendezvous"}:
        return "Relay"
    if r in {"local_cache", "known", "cache", "swarm"}:
        return "Known chunks"
    if not r:
        return "Best available"
    return r.replace("_", " ").replace("-", " ")


def _mbps_fact(prefix: str, mbps: float) -> str | None:
    if mbps <= 0:
        return None
    if mbps >= 100:
        shown = f"{mbps:.0f}"
    elif mbps >= 10:
        shown = f"{mbps:.1f}".rstrip("0").rstrip(".")
    else:
        shown = f"{mbps:.2f}".rstrip("0").rstrip(".")
    return f"{prefix} {shown} Mbps"


@dataclass(frozen=True)
class TransferDiagnosis:
    code: str
    label: str
    user_message: str
    action: str
    automatic: bool
    transient: bool
    severity: str
    next_retry_ms: int | None = None
    retry_in_ms: int | None = None
    route_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "label": self.label,
            "user_message": self.user_message,
            "action": self.action,
            "automatic": self.automatic,
            "transient": self.transient,
            "severity": self.severity,
            "next_retry_ms": self.next_retry_ms,
            "retry_in_ms": self.retry_in_ms,
            "route_action": self.route_action,
        }


@dataclass(frozen=True)
class RouteObservation:
    route: str
    ok: bool
    latency_ms: float | None = None
    bandwidth_bps: float | None = None
    error_code: str | None = None
    at_ms: int = 0


@dataclass(frozen=True)
class RouteCandidate:
    route: str
    score: float
    attempts: int
    successes: int
    failures: int
    latency_ms: float | None
    bandwidth_bps: float | None


def _metadata(rec: Any) -> Mapping[str, Any]:
    md = getattr(rec, "metadata", None)
    if isinstance(rec, Mapping):
        md = rec.get("metadata", md)
    return md if isinstance(md, Mapping) else {}


def _field(rec: Any, name: str, default: Any = None) -> Any:
    if isinstance(rec, Mapping):
        return rec.get(name, default)
    return getattr(rec, name, default)


def _now_delta(next_retry_ms: int | None, now_ms: int | None) -> int | None:
    if next_retry_ms is None or now_ms is None:
        return None
    return max(0, int(next_retry_ms) - int(now_ms))


def diagnose_transfer(rec: Any, *, now_ms: int | None = None) -> TransferDiagnosis:
    """Diagnose a transfer record into user-safe state.

    The labels are intentionally product language, not implementation language.
    Raw errors stay in metadata/debug logs; the user sees what One Link is doing.
    """

    status = str(_field(rec, "status", "queued") or "queued")
    direction = str(_field(rec, "direction", "out") or "out")
    md = _metadata(rec)
    delivery_state = str(md.get("delivery_state") or "").lower()
    err_class = str(md.get("error_class") or "")
    err = str(md.get("error") or "")
    code_src = " ".join((delivery_state, err_class, err)).lower()
    next_retry = md.get("next_retry_ms")
    next_retry_ms = int(next_retry) if isinstance(next_retry, (int, float)) else None
    retry_in_ms = _now_delta(next_retry_ms, now_ms)

    if status == "complete":
        return TransferDiagnosis(
            code="done",
            label="Done",
            user_message="Verified and delivered.",
            action="none",
            automatic=True,
            transient=False,
            severity="ok",
        )

    if status in ("queued", "offered") and delivery_state in ("queued", ""):
        return TransferDiagnosis(
            code="queued",
            label="Sending",
            user_message="One Link is preparing the send.",
            action="retry_with_backoff",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
        )

    if status == "active" or delivery_state == "sending":
        return TransferDiagnosis(
            code="sending",
            label="Sending",
            user_message="One Link is moving verified pieces now.",
            action="continue",
            automatic=True,
            transient=True,
            severity="info",
        )

    if "ratchet" in code_src or "desync" in code_src or "invalidtag" in code_src:
        return TransferDiagnosis(
            code="secure_session_desync",
            label="Resuming",
            user_message="One Link is refreshing the secure session and will continue automatically.",
            action="reopen_secure_session",
            automatic=True,
            transient=True,
            severity="warn",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="reopen_secure_session",
        )

    if "version" in code_src or "compat" in code_src or "protocol" in code_src:
        return TransferDiagnosis(
            code="protocol_fallback",
            label="Resuming",
            user_message="One Link is switching to the best protocol both devices understand.",
            action="fallback_protocol",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="fallback_protocol",
        )

    if "chunk" in code_src or "integrity" in code_src or "hash" in code_src:
        return TransferDiagnosis(
            code="chunk_retry",
            label="Resuming",
            user_message="One Link is retrying only the piece that did not verify.",
            action="retry_missing_chunk",
            automatic=True,
            transient=True,
            severity="warn",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="retry_missing_chunk",
        )

    if "resum" in delivery_state:
        return TransferDiagnosis(
            code="resuming",
            label="Resuming",
            user_message="One Link is continuing from the verified pieces already delivered.",
            action="retry_missing_chunk",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="retry_missing_chunk",
        )

    if "offline" in code_src or "unreachable" in code_src or "timeout" in code_src:
        return TransferDiagnosis(
            code="waiting_for_device",
            label="Waiting for device",
            user_message="One Link is waiting quietly and will resume when the device is reachable.",
            action="wait_for_peer",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="refresh_route",
        )

    if "route" in code_src or "address" in code_src or "port" in code_src:
        return TransferDiagnosis(
            code="route_refresh",
            label="Resuming",
            user_message="One Link is refreshing the device route and trying again.",
            action="refresh_route",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
            route_action="refresh_route",
        )

    if status == "paused" or bool(md.get("transient")):
        return TransferDiagnosis(
            code="retrying",
            label="Waiting for device",
            user_message="One Link saved the transfer and will retry automatically.",
            action="retry_with_backoff",
            automatic=True,
            transient=True,
            severity="info",
            next_retry_ms=next_retry_ms,
            retry_in_ms=retry_in_ms,
        )

    if "source file" in code_src or "filenotfound" in code_src:
        return TransferDiagnosis(
            code="source_missing",
            label="Needs attention",
            user_message="The original file moved or was deleted before One Link could finish.",
            action="choose_file_again",
            automatic=False,
            transient=False,
            severity="error",
        )

    if status == "failed":
        return TransferDiagnosis(
            code="needs_attention",
            label="Needs attention",
            user_message="One Link needs your attention before it can continue this transfer.",
            action="manual_review",
            automatic=False,
            transient=False,
            severity="error",
        )

    return TransferDiagnosis(
        code="unknown",
        label="Sending" if direction == "out" else "Receiving",
        user_message="One Link is tracking this transfer.",
        action="observe",
        automatic=True,
        transient=True,
        severity="info",
    )


def diagnose_exception(exc: BaseException) -> TransferDiagnosis:
    """Classify a send exception before it becomes transfer metadata."""

    class _R:
        status = "paused"
        direction = "out"
        metadata = {
            "error": str(exc),
            "error_class": type(exc).__name__,
            "transient": not isinstance(exc, (FileNotFoundError, PermissionError)),
        }

    if isinstance(exc, asyncio.TimeoutError):
        _R.metadata["error"] = "timeout"
    return diagnose_transfer(_R)


def enrich_transfer_event(event: dict[str, Any], *, now_ms: int | None = None) -> dict[str, Any]:
    """Attach doctor diagnosis to a transfer event dict."""

    diag = diagnose_transfer(event, now_ms=now_ms).to_dict()
    out = dict(event)
    out["doctor"] = diag
    out["autopilot_truth"] = transfer_autopilot_truth(out, diagnosis=diag)
    # Flatten the highest-value fields for older UI code and tests.
    out["display_state"] = diag["label"]
    out["user_message"] = diag["user_message"]
    return out


def transfer_autopilot_truth(
    rec: Any,
    *,
    diagnosis: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the user-facing transfer intelligence contract.

    The daemon records rich engineering metadata: CDC decisions, binary frame
    choices, performance reports, route observations, retry causes, and swarm
    assists. This helper turns those details into a stable product surface the
    UI can render directly. It is deterministic and side-effect free so tests,
    WebSocket events, and REST snapshots all tell the same story.
    """

    md = _metadata(rec)
    plan = _as_mapping(md.get("autopilot_plan"))
    perf = _as_mapping(md.get("performance_summary"))
    report = _as_mapping(md.get("transfer_report"))
    assist = _as_mapping(md.get("swarm_assist"))
    brain = _as_mapping(md.get("transfer_brain"))
    scheduler = _as_mapping(md.get("adaptive_scheduler"))
    diag = dict(diagnosis or diagnose_transfer(rec).to_dict())

    status = str(_field(rec, "status", "") or "").lower()
    direction = str(_field(rec, "direction", "out") or "out").lower()
    progress_bytes = _as_int(_field(rec, "progress_bytes", 0))
    total_bytes = _as_int(_field(rec, "total_bytes", _field(rec, "size", 0)))
    wire_bytes = _as_int(_field(rec, "wire_bytes", report.get("wire_bytes_sent", 0)))
    skipped_bytes = max(
        _as_int(perf.get("skipped_bytes")),
        _as_int(report.get("skipped_bytes")),
        _as_int(md.get("skipped_bytes")),
    )
    saved_bytes = max(
        _as_int(perf.get("saved_bytes")),
        _as_int(report.get("saved_bytes")),
        _as_int(md.get("saved_bytes")),
        _as_int(assist.get("assisted_bytes")),
    )
    # On a resumed attempt the receiver's chunk hit rate at the offer counts
    # chunks this same transfer delivered earlier.  The network carried those,
    # so they are not prior knowledge, and a count of chunks cannot be split
    # by bytes; ``skipped_ratio`` is already net of them and stands alone.
    resumed_bytes = max(_as_int(report.get("resumed_bytes")), _as_int(md.get("resumed_bytes")))
    savings_ratio = max(
        _as_float(perf.get("bandwidth_savings_ratio")),
        _as_float(report.get("bandwidth_savings_ratio")),
        _as_float(plan.get("estimated_savings_ratio")),
        _as_float(md.get("bandwidth_savings_ratio")),
        0.0 if resumed_bytes > 0 else _as_float(md.get("prior_hit_rate_actual")),
        _as_float(md.get("skipped_ratio")),
    )
    if savings_ratio <= 0 and total_bytes > 0 and (skipped_bytes > 0 or saved_bytes > 0):
        savings_ratio = (skipped_bytes + saved_bytes) / max(1, total_bytes)
    savings_ratio = _clamp01(savings_ratio)

    effective_mbps = max(
        _as_float(perf.get("effective_mbps")),
        _as_float(plan.get("estimated_mbps")),
        (_as_float(report.get("effective_throughput_bps")) / 1_000_000.0),
    )
    wire_mbps = max(
        _as_float(perf.get("wire_mbps")),
        (_as_float(report.get("wire_throughput_bps")) / 1_000_000.0),
    )

    route = (
        perf.get("route")
        or plan.get("route")
        or md.get("route")
        or brain.get("route")
        or ("local_cache" if assist.get("strategy") == "multi_source_chunk_pull" else "")
    )
    route_label = _route_label(route)
    frame_kind = str(
        perf.get("frame_kind")
        or plan.get("frame_kind")
        or md.get("frame_kind")
        or ""
    ).lower()
    fast_binary = bool(md.get("binary_frame")) or "binary" in frame_kind
    sent_only_missing = skipped_bytes > 0 or saved_bytes > 0 or savings_ratio >= 0.01

    facts: list[str] = []
    speed_fact = _mbps_fact("Finished at" if status == "complete" else "Sending at", effective_mbps)
    if speed_fact:
        facts.append(speed_fact)
    if savings_ratio >= 0.01:
        facts.append(f"{round(savings_ratio * 100):.0f}% already known")
    if sent_only_missing:
        facts.append("Only sent missing pieces")
    if fast_binary:
        facts.append("Using fast binary path")
    if diag.get("automatic") and diag.get("action") not in {"none", "continue", "observe"}:
        facts.append("Resuming automatically")
    pulled = _as_int(assist.get("pulled"))
    if pulled > 0:
        source_count = max(1, _as_int(assist.get("source_count"), len(_as_mapping(assist.get("sources"))) or 1))
        facts.append(
            f"Pulled {pulled} chunk{'s' if pulled != 1 else ''} from "
            f"{source_count} trusted device{'s' if source_count != 1 else ''}"
        )
    healed = _as_int(assist.get("healed"))
    if healed > 0:
        facts.append(
            f"Healed {healed} chunk{'s' if healed != 1 else ''} by switching source"
        )
    facts.append(f"Route: {route_label}")

    seen: set[str] = set()
    deduped = []
    for fact in facts:
        if fact and fact not in seen:
            seen.add(fact)
            deduped.append(fact)

    if diag.get("label") == "Done":
        headline = "Verified and delivered"
    elif speed_fact:
        headline = speed_fact
    else:
        headline = str(diag.get("label") or ("Receiving" if direction == "in" else "Sending"))

    return {
        "state": str(diag.get("code") or status or "unknown"),
        "state_label": str(diag.get("label") or headline),
        "headline": headline,
        "message": str(diag.get("user_message") or ""),
        "facts": deduped[:7],
        "route": str(route or ""),
        "route_label": route_label,
        "speed_mbps": round(effective_mbps, 3),
        "wire_mbps": round(wire_mbps, 3),
        "known_pct": round(savings_ratio * 100.0, 1),
        "sent_only_missing_pieces": bool(sent_only_missing),
        "fast_path_label": "Fast binary path" if fast_binary else "Compatible path",
        "self_healing_action": str(diag.get("action") or "observe"),
        "automatic": bool(diag.get("automatic")),
        "progress_bytes": progress_bytes,
        "total_bytes": total_bytes,
        "wire_bytes": wire_bytes,
        "saved_bytes": saved_bytes,
        "skipped_bytes": skipped_bytes,
        "parallelism": _as_int(scheduler.get("parallelism"), _as_int(plan.get("parallelism"), 1)),
    }


class RouteMemory:
    """Tiny deterministic route scorer for a peer.

    This is intentionally independent from networking. The daemon can feed it
    observations later; the simulator can already prove decisions.
    """

    def __init__(self) -> None:
        self._routes: dict[str, list[RouteObservation]] = {}

    def observe(self, obs: RouteObservation) -> None:
        self._routes.setdefault(obs.route, []).append(obs)

    def candidates(self) -> tuple[RouteCandidate, ...]:
        out: list[RouteCandidate] = []
        for route, rows in self._routes.items():
            attempts = len(rows)
            successes = sum(1 for r in rows if r.ok)
            failures = attempts - successes
            latencies = [r.latency_ms for r in rows if r.ok and r.latency_ms is not None]
            bandwidths = [r.bandwidth_bps for r in rows if r.ok and r.bandwidth_bps is not None]
            reliability = successes / max(1, attempts)
            latency = sum(latencies) / len(latencies) if latencies else None
            bandwidth = sum(bandwidths) / len(bandwidths) if bandwidths else None
            score = reliability * 100.0
            if bandwidth:
                score += min(50.0, bandwidth / 10_000_000.0)
            if latency is not None:
                score -= min(40.0, latency / 25.0)
            score -= failures * 2.0
            out.append(RouteCandidate(
                route=route,
                score=round(score, 4),
                attempts=attempts,
                successes=successes,
                failures=failures,
                latency_ms=latency,
                bandwidth_bps=bandwidth,
            ))
        return tuple(sorted(out, key=lambda c: (-c.score, c.route)))

    def best_route(self, fallback: str = "lan") -> str:
        ranked = self.candidates()
        return ranked[0].route if ranked else fallback
