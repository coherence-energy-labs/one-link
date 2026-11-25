#!/usr/bin/env python3
"""Compare measured benchmark repetitions with explicit pass/fail/inconclusive outcomes.

CI alternates matched native artifacts on one host using one benchmark harness.
Every observation is retained. Median ratios and a deterministic percentile
bootstrap interval enforce the chosen effect-size limit. An overlapping or
missing result is INCONCLUSIVE (exit 2), never a silent pass. This relative gate
is separate from production SLOs and does not establish end-to-end throughput.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import random
import statistics
import sys
from pathlib import Path


def _index_results(payload: dict) -> dict[str, float]:
    """Index benchmark name to bytes_per_second_median."""
    out: dict[str, float] = {}
    for r in payload.get("results", []):
        out[r["name"]] = float(r["bytes_per_second_median"])
    return out


def _samples(payloads: list[dict]) -> dict[str, list[float]]:
    """Retain every measured throughput observation."""
    out: dict[str, list[float]] = {}
    for payload in payloads:
        for name, value in _index_results(payload).items():
            out.setdefault(name, []).append(value)
    return out


def _host(payload: dict) -> dict:
    """The machine a result set was measured on, if it recorded one."""
    host = payload.get("host")
    return host if isinstance(host, dict) else {}


def _describe_host(host: dict) -> str:
    if not host:
        return "UNRECORDED"
    return (
        f"{host.get('platform', '?')} / python {host.get('python', '?')} "
        f"/ {host.get('cpu_count', '?')} cpus"
    )


_ARCHITECTURES = ("x86_64", "amd64", "aarch64", "arm64")


def _host_identity(host: dict) -> tuple[str, str, int | None, str]:
    """The parts of a host that actually move throughput.

    Deliberately NOT the whole platform string. GitHub rotates runner images,
    so `Linux-6.17.0-1020-azure-...` becomes `Linux-6.19.0-...` on its own
    schedule. Gating on that would turn this red on the next image bump and
    teach everyone to ignore it -- a gate that cries wolf is worse than the
    broken one it replaced, because this one is meant to be believed.

    OS family, CPU architecture, core count and the Python minor version are
    what separate a 24-core Windows desktop from a 4-core Linux VM. Kernel and
    patch revisions are noise for a throughput comparison.
    """
    platform = str(host.get("platform", ""))
    family = platform.split("-", 1)[0] or "?"
    lowered = str(host.get("machine") or platform).lower()
    architecture = next((a for a in _ARCHITECTURES if a in lowered), "?")
    # x86_64 and amd64 are the same machine under two spellings.
    if architecture == "amd64":
        architecture = "x86_64"
    if architecture == "aarch64":
        architecture = "arm64"
    cpu_count = host.get("cpu_count")
    python = ".".join(str(host.get("python", "")).split(".")[:2])
    return family, architecture, cpu_count if type(cpu_count) is int and cpu_count > 0 else None, python


def _hosts_are_comparable(a: dict, b: dict) -> tuple[bool, str]:
    """Throughput numbers only mean something between like machines.

    A raw MB/s comparison across different hardware measures the hardware, not
    the change. This gate ran for months comparing CI against a baseline
    recorded on a 24-core Windows workstation, which is why a dependency bump
    could show ChaCha "regressing" 12% while AES "improved" 293% in the same
    run: AES-NI and core count, not code.
    """
    if not a or not b:
        return False, (
            "one or both result sets record no host provenance, so they cannot "
            "be shown to be comparable"
        )
    left = _host_identity(a)
    right = _host_identity(b)
    if any(value in ("", "?", None) for value in (*left, *right)):
        return False, "one or both hosts omit OS, architecture, CPU count or Python identity"
    if a.get("host_id") and b.get("host_id") and a["host_id"] != b["host_id"]:
        return False, "recorded host identities differ"
    if left != right:
        labels = ("os family", "architecture", "cpu count", "python")
        differences = [
            f"{label} {x!r} vs {y!r}"
            for label, x, y in zip(labels, left, right)
            if x != y
        ]
        return False, "; ".join(differences)
    return True, ""


def _read_json(path: Path) -> dict:
    # PowerShell redirection can write UTF-16LE with a BOM on Windows, while CI
    # shell redirection normally writes UTF-8. Accept both so the gate measures
    # performance instead of failing on host console encoding.
    raw = path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        payload = json.loads(raw.decode("utf-16"))
    else:
        payload = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError("benchmark JSON must be an object")
    return payload


def _ratio_interval(fresh: list[float], baseline: list[float], *, paired: bool) -> tuple[float, float, float]:
    """Median effect and deterministic percentile-bootstrap uncertainty.

    The interval describes these observations; it is not a causal claim or a
    distribution-free guarantee. CI uses alternating matched runs. Independent
    resampling is retained for explicitly unpaired local comparisons.
    """
    if paired:
        ratios = [a / b for a, b in zip(fresh, baseline)]
        point = statistics.median(ratios)
    else:
        point = statistics.median(fresh) / statistics.median(baseline)
    if len(fresh) == len(baseline) == 1:
        return point, point, point
    rng = random.Random(20261124)  # public deterministic resampling
    estimates = []
    for _ in range(4000):
        if paired:
            estimates.append(statistics.median(rng.choices(ratios, k=len(ratios))))
        else:
            estimates.append(statistics.median(rng.choices(fresh, k=len(fresh))) /
                             statistics.median(rng.choices(baseline, k=len(baseline))))
    estimates.sort()
    return point, estimates[99], estimates[3900]


def _validate_payloads(payloads: list[dict], minimum: int) -> None:
    if len(payloads) < minimum:
        raise ValueError(f"need at least {minimum} complete repetitions per arm")
    names = set(_index_results(payloads[0]))
    if not names:
        raise ValueError("empty result set")
    for payload in payloads:
        rows = payload.get("results", [])
        values = _index_results(payload)
        if len(values) != len(rows):
            raise ValueError("duplicate benchmark name")
        if set(values) != names:
            raise ValueError("metric missing from one repetition")
        if any(not math.isfinite(v) or v <= 0 for v in values.values()):
            raise ValueError("throughput must be finite and positive")


def _paired_identity(fresh: list[dict], baseline: list[dict]) -> None:
    if len(fresh) != len(baseline):
        raise ValueError("paired arms must have equal repetition counts")
    session = fresh[0].get("provenance", {}).get("session_id")
    if not session:
        raise ValueError("paired measurement session is unrecorded")
    pair_ids = set()
    for a, b in zip(fresh, baseline):
        pa, pb = a.get("provenance", {}), b.get("provenance", {})
        pair_id = pa.get("pair_index")
        if pa.get("session_id") != session or pb.get("session_id") != session:
            raise ValueError("paired measurements came from different sessions")
        if pair_id is None or pair_id != pb.get("pair_index") or pair_id in pair_ids:
            raise ValueError("missing, duplicated or mismatched pair index")
        pair_ids.add(pair_id)
        if pa.get("arm") != "candidate" or pb.get("arm") != "baseline":
            raise ValueError("paired arm identity is invalid")
        for provenance in (pa, pb):
            if not provenance.get("native_source_revision"):
                raise ValueError("native source identity is unrecorded")
            if not provenance.get("native", {}).get("artifacts"):
                raise ValueError("native artifact identity is unrecorded")
        if pa.get("source_revision") != pb.get("source_revision"):
            raise ValueError("paired benchmark harnesses differ")
        ha, hb = pa.get("host", {}), pb.get("host", {})
        if not ha.get("host_id") or ha.get("host_id") != hb.get("host_id"):
            raise ValueError("paired physical host identities differ or are missing")
    for arm in (fresh, baseline):
        identities = {
            json.dumps({k: p.get("provenance", {}).get(k) for k in
                        ("native_source_revision", "native", "source_revision")}, sort_keys=True)
            for p in arm
        }
        if len(identities) != 1:
            raise ValueError("build identity changed within an arm")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--results", required=True, nargs="+", help="Candidate JSON repetitions in pair order.")
    p.add_argument("--baseline", required=True, nargs="+", help="Baseline JSON repetitions in pair order.")
    p.add_argument("--max-regression-percent", type=float, default=5.0)
    p.add_argument("--metric-limit", action="append", default=[], metavar="NAME_OR_GLOB=PERCENT")
    p.add_argument("--require-comparable-host", action="store_true")
    p.add_argument("--require-paired-runs", action="store_true")
    p.add_argument("--min-samples", type=int, default=1)
    p.add_argument("--json", type=Path, help="Write every metric decision and retained observations.")
    args = p.parse_args(argv)
    if not math.isfinite(args.max_regression_percent) or not 0 <= args.max_regression_percent < 100:
        p.error("--max-regression-percent must be finite and in [0, 100)")
    if args.min_samples < 1:
        p.error("--min-samples must be positive")
    metric_limits = {}
    for spec in args.metric_limit:
        name, _, text = spec.partition("=")
        try:
            value = float(text)
        except ValueError:
            p.error(f"--metric-limit expects NAME=PERCENT, got {spec!r}")
        if not name or not math.isfinite(value) or not 0 <= value < 100:
            p.error(f"--metric-limit expects a finite percent in [0, 100): {spec!r}")
        metric_limits[name] = value / 100

    def limit_for(name: str) -> float:
        if name in metric_limits:
            return metric_limits[name]
        matches = [(pat, value) for pat, value in metric_limits.items() if fnmatch.fnmatchcase(name, pat)]
        return max(matches, key=lambda item: len(item[0]))[1] if matches else args.max_regression_percent / 100

    try:
        fresh_payloads = [_read_json(Path(path)) for path in args.results]
        base_payloads = [_read_json(Path(path)) for path in args.baseline]
        _validate_payloads(fresh_payloads, args.min_samples)
        _validate_payloads(base_payloads, args.min_samples)
        if args.require_comparable_host:
            expected = _host(base_payloads[0])
            for payload in [*fresh_payloads, *base_payloads]:
                comparable, reason = _hosts_are_comparable(_host(payload), expected)
                if not comparable:
                    raise ValueError(f"refusing comparison across machines: {reason}")
        if args.require_paired_runs:
            _paired_identity(fresh_payloads, base_payloads)
        fresh = _samples(fresh_payloads)
        baseline = _samples(base_payloads)
        if set(fresh) != set(baseline):
            raise ValueError(f"metric sets differ: {sorted(set(fresh) ^ set(baseline))}")
        # Equal names alone do not establish equal work (different corpora,
        # sizes, modes or operation counts must never generate a speedup).
        for payload in [*fresh_payloads, *base_payloads]:
            for row in payload["results"]:
                reference = next(r for r in base_payloads[0]["results"] if r["name"] == row["name"])
                for key in ("bytes_processed", "iterations", "metadata"):
                    if row.get(key) != reference.get(key):
                        raise ValueError(f"measurement contract differs for {row['name']}: {key}")
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"INCONCLUSIVE: {exc}", file=sys.stderr)
        if args.json:
            args.json.write_text(json.dumps({"status": "inconclusive", "error": str(exc)}, indent=2), encoding="utf-8")
        return 2

    print(f"  measured on: {_describe_host(_host(fresh_payloads[0]))}")
    print(f"  {len(fresh_payloads)} candidate / {len(base_payloads)} baseline observations; median effect")
    decisions = []
    for name in sorted(baseline):
        point, lower, upper = _ratio_interval(fresh[name], baseline[name], paired=args.require_paired_runs)
        limit = limit_for(name)
        boundary = 1 - limit
        # Passing requires the lower uncertainty bound to meet the limit.
        # Overlap is inconclusive, never a successful regression gate.
        status = "fail" if upper < boundary else "pass" if lower >= boundary else "inconclusive"
        decision = {
            "name": name, "status": status, "ratio_median": point,
            "ratio_interval_95": [lower, upper], "limit_percent": limit * 100,
            "candidate_bps": fresh[name], "baseline_bps": baseline[name],
            "interval_method": "percentile bootstrap, 4000 deterministic resamples" if len(fresh[name]) > 1 or len(baseline[name]) > 1 else "single observation; descriptive only",
        }
        decisions.append(decision)
        prefix = "TOLERATED" if status == "pass" and point < 1 - args.max_regression_percent / 100 else status.upper()
        print(f"  {prefix} {name}: {(point-1)*100:+.2f}% median change; "
              f"ratio interval [{lower:.4f}, {upper:.4f}], limit {limit*100:g}%")
    status = "fail" if any(d["status"] == "fail" for d in decisions) else "inconclusive" if any(d["status"] == "inconclusive" for d in decisions) else "pass"
    report = {
        "schema": "one-link-benchmark-gate-v2", "status": status,
        "paired": args.require_paired_runs, "decisions": decisions,
        "interpretation": "Observed performance acceptance, not causal attribution or a product throughput guarantee.",
    }
    if args.json:
        args.json.write_text(json.dumps(report, indent=2, allow_nan=False), encoding="utf-8")
    if status != "pass":
        print(f"\n{status.upper()}: throughput regressed or uncertainty crosses the allowed boundary; "
              "preserve these observations and investigate before collecting a new complete paired study.", file=sys.stderr)
    else:
        print(f"\nPASS: all {len(decisions)} tracked metrics meet the stated measurement acceptance rule.")
    return {"pass": 0, "fail": 1, "inconclusive": 2}[status]


if __name__ == "__main__":
    raise SystemExit(main())
