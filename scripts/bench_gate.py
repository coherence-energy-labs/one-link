#!/usr/bin/env python3
"""File engine v2 benchmark regression gate.

Compares two ``perf_lab_native --json`` result sets and fails if any tracked
metric regresses by more than the threshold. The gate is one-way: regressions
fail, improvements are silent.

Both sides must be MEASURED, not remembered. Comparing a fresh run against a
committed file of MB/s does not work, and the two ways it fails were both
observed here:

  * A baseline recorded on a 24-core Windows workstation, compared against
    ubuntu-latest, reported ChaCha down 12% and AES up 293% in one run. That
    is AES-NI and core count, not code.
  * A baseline recorded on the SAME runner class one commit earlier reported
    AES-256KiB down 37% on an unchanged tree. Same class is not the same
    machine; shared CI has noisy neighbours.

So callers benchmark both sides on one runner in one job, and pass repeated
runs of each. ``--require-comparable-host`` refuses a mismatched comparison
outright rather than reporting a meaningless delta.

Repetition matters: even paired on one machine, a single run of a byte-
identical tree showed AES-256KiB down 9.03%. Throughput noise is one-sided --
interference only ever slows a run down -- so the fastest observation per
metric is taken across repetitions.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import sys
from pathlib import Path


def _index_results(payload: dict) -> dict[str, float]:
    """Index benchmark name to bytes_per_second_median."""
    out: dict[str, float] = {}
    for r in payload.get("results", []):
        out[r["name"]] = float(r["bytes_per_second_median"])
    return out


def _samples(payloads: list[dict]) -> dict[str, list[float]]:
    """Every observation of every metric, kept rather than collapsed.

    Throughput noise on shared CI is one-sided: a neighbour can steal cycles
    and slow a run down, but nothing makes it spuriously faster. The spread
    between repetitions is therefore a direct measurement of the interference
    on this machine right now, and it is what tells a real regression from a
    bad neighbour.
    """
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
    lowered = platform.lower()
    architecture = next((a for a in _ARCHITECTURES if a in lowered), "?")
    # x86_64 and amd64 are the same machine under two spellings.
    if architecture == "amd64":
        architecture = "x86_64"
    if architecture == "aarch64":
        architecture = "arm64"
    cpu_count = host.get("cpu_count")
    python = ".".join(str(host.get("python", "")).split(".")[:2])
    return family, architecture, cpu_count if isinstance(cpu_count, int) else None, python


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
        return json.loads(raw.decode("utf-16"))
    return json.loads(raw.decode("utf-8-sig"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--results",
        required=True,
        nargs="+",
        help=(
            "Fresh perf_lab_native JSON. Pass repeated runs of the SAME build "
            "and the fastest observation per metric is used."
        ),
    )
    p.add_argument(
        "--baseline",
        required=True,
        nargs="+",
        help="The other side's JSON, same repetition rule.",
    )
    p.add_argument(
        "--max-regression-percent",
        type=float,
        default=5.0,
        help="Maximum allowed regression vs baseline, in percent (default 5).",
    )
    p.add_argument(
        "--metric-limit",
        action="append",
        default=[],
        metavar="NAME_OR_GLOB=PERCENT",
        help=(
            "Per-metric tolerance override, repeatable. For metrics whose measured spread is "
            "dominated by something other than the code under test -- see the block-collection "
            "note in the comparison loop -- a global limit either fails constantly or has to be "
            "loosened for everything. This keeps the strict limit where it means something."
        ),
    )
    p.add_argument(
        "--require-comparable-host",
        action="store_true",
        help=(
            "Refuse to compare result sets measured on different machines. The "
            "CI gate passes this: it benchmarks the PR head and its merge base "
            "on the SAME runner, so a difference is attributable to the change."
        ),
    )
    args = p.parse_args(argv)

    results_paths = [Path(p) for p in args.results]
    baseline_paths = [Path(p) for p in args.baseline]

    missing = [p for p in results_paths if not p.is_file()]
    if missing:
        print(f"FAIL: results file missing: {missing[0]}", file=sys.stderr)
        return 2
    absent = [p for p in baseline_paths if not p.is_file()]
    if absent:
        print(
            f"NEUTRAL: baseline file missing ({absent[0]}); commit current "
            f"results as the initial baseline.",
            file=sys.stderr,
        )
        return 0

    results_payloads = [_read_json(p) for p in results_paths]
    baseline_payloads = [_read_json(p) for p in baseline_paths]
    fresh_samples = _samples(results_payloads)
    baseline_samples = _samples(baseline_payloads)
    fresh = {name: max(values) for name, values in fresh_samples.items()}
    baseline = {name: max(values) for name, values in baseline_samples.items()}

    fresh_host = _host(results_payloads[0])
    baseline_host = _host(baseline_payloads[0])
    print(
        f"  measured on: {_describe_host(fresh_host)} "
        f"(best of {len(results_payloads)})"
    )
    print(
        f"  compared to: {_describe_host(baseline_host)} "
        f"(best of {len(baseline_payloads)})"
    )

    if args.require_comparable_host:
        comparable, why = _hosts_are_comparable(fresh_host, baseline_host)
        if not comparable:
            print(
                f"FAIL: refusing to compare throughput across machines -- {why}.\n"
                "      A raw MB/s comparison between different hardware measures "
                "the hardware, not the change.",
                file=sys.stderr,
            )
            return 2

    if not baseline:
        print(f"FAIL: baseline empty: {baseline_paths[0]}", file=sys.stderr)
        return 2

    threshold = args.max_regression_percent / 100.0

    # Per-metric overrides. Parsed strictly: a typo here would silently restore the global limit
    # and the override would look applied while doing nothing.
    metric_limits: dict[str, float] = {}
    for spec in args.metric_limit:
        name, _, pct = str(spec).partition("=")
        if not name or not pct:
            raise SystemExit(f"--metric-limit expects NAME=PERCENT, got {spec!r}")
        try:
            metric_limits[name] = float(pct) / 100.0
        except ValueError:
            raise SystemExit(f"--metric-limit percent is not a number: {spec!r}") from None

    def limit_for(metric: str) -> float:
        """Exact name first, then glob. Patterns exist because the layout-sensitive metrics are a
        CLASS, not a list: naming them one at a time is how you discover the next one in CI."""
        if metric in metric_limits:
            return metric_limits[metric]
        # Most specific pattern wins, so a tighter rule can carve an exception out of a broad one
        # rather than being silently overridden by whichever happened to be declared first.
        matches = [(pat, lim) for pat, lim in metric_limits.items() if fnmatch.fnmatchcase(metric, pat)]
        if not matches:
            return threshold
        return max(matches, key=lambda kv: len(kv[0]))[1]

    failures: list[str] = []

    for name, base_bps in baseline.items():
        fresh_bps = fresh.get(name)
        if fresh_bps is None:
            failures.append(
                f"  - {name}: baseline tracks but fresh results missing this metric"
            )
            continue
        if base_bps <= 0:
            continue
        ratio = fresh_bps / base_bps
        # Two conditions, both required.
        #
        # (1) EFFECT SIZE: the best head observation is worse than the best
        #     base observation by more than the tolerance.
        # (2) SEPARATION: the best head observation is worse than the WORST
        #     base observation -- the two sample sets do not overlap at all.
        #
        # (1) alone is what failed three times running on byte-identical code:
        # -9.03% AES, then -7.75% QUIC, then -6.20% AES and -25.37% QUIC. Every
        # run put a different metric over whatever line was drawn, because a
        # point estimate cannot tell a regression from a noisy neighbour.
        #
        # (2) asks the data instead of a constant. If the head's best run is
        # still slower than every base run, the effect survived the machine's
        # own measured variance. If the sets overlap, the spread explains the
        # difference and there is nothing to report. A real regression is
        # present in every repetition, so it separates; noise does not.
        worst_base = min(baseline_samples.get(name, [base_bps]))
        separated = fresh_bps < worst_base
        # WHY SEPARATION IS NOT ENOUGH FOR EVERY METRIC, and why some carry their own limit.
        #
        # The two sample sets are collected in BLOCKS: five head runs, then five base runs, with a
        # rebuild between. Inside a block the thermal state, page cache and CPU frequency are
        # near-identical, so within-block spread is tiny; between blocks it is not. That makes the
        # sets easy to separate for reasons that have nothing to do with the diff -- the criterion
        # was meant to ask "did the effect survive the machine's variance", but a blocked design
        # hides most of that variance inside each arm.
        #
        # Measured, 2026-08-08: `native_aead_aes_decrypt_16KiB` failed at 6.31% on master with
        # `native/ol_aead/` UNCHANGED since the drift anchor -- byte-identical source on both
        # sides -- while the gate's history flapped success/failure across unrelated commits on the
        # same day. Small fixed-size AEAD blocks are dominated by code layout, which unrelated
        # changes elsewhere in the binary move around.
        #
        # So: keep 5% where it means something, and give the layout-sensitive metrics their own
        # limit rather than loosening the gate globally or deleting it.
        limit = limit_for(name)
        if ratio < (1.0 - limit) and separated:
            regress_pct = (1.0 - ratio) * 100.0
            failures.append(
                f"  - {name}: regressed {regress_pct:.2f}% (limit {limit * 100.0:g}%) "
                f"({base_bps / 1e6:.2f} MB/s -> {fresh_bps / 1e6:.2f} MB/s); "
                f"every base run was faster (worst base "
                f"{worst_base / 1e6:.2f} MB/s)"
            )
        elif ratio < (1.0 - limit):
            # Over the line but inside the machine's own spread. Say so --
            # silently passing a measured drop is how a real one hides.
            print(
                f"  noisy {name}: {(1.0 - ratio) * 100.0:.2f}% below best base, "
                f"but base itself ranged down to {worst_base / 1e6:.2f} MB/s "
                f"({len(baseline_samples.get(name, []))} runs); not separable"
            )
        elif ratio < (1.0 - threshold):
            # Past the GLOBAL limit but inside this metric's own, wider one. Report it loudly.
            # Adding the override without this line created exactly the failure the branch above
            # exists to prevent: a measured 6.3% drop passing in silence, which is how a real
            # regression hides behind a tolerance someone widened months ago.
            print(
                f"  TOLERATED {name}: {(1.0 - ratio) * 100.0:.2f}% below best base, over the "
                f"global {args.max_regression_percent:g}% limit but inside this metric's "
                f"documented {limit * 100.0:g}% tolerance"
                + (" -- AND the sample sets separated, so this is not noise; if it persists "
                   "across runners it is worth a look" if separated else "")
            )
        else:
            delta_pct = (ratio - 1.0) * 100.0
            sign = "+" if delta_pct >= 0 else ""
            print(
                f"  ok {name}: {sign}{delta_pct:.2f}% "
                f"({base_bps / 1e6:.2f} MB/s -> {fresh_bps / 1e6:.2f} MB/s)"
            )

    if failures:
        print(
            f"\nFAIL: {len(failures)} benchmark(s) regressed past their limit:",
            file=sys.stderr,
        )
        for f in failures:
            print(f, file=sys.stderr)
        print(
            "\nIf this regression is intended, update bench_baselines/ in the "
            "same PR with a justification commit message.",
            file=sys.stderr,
        )
        return 1

    print(f"\nPASS: all {len(baseline)} tracked metrics within threshold.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
