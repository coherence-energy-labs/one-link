#!/usr/bin/env python3
"""Statistical timing-leak test (dudect) of One Link's constant-time primitives.

The Valgrind audit (``scripts/run_ct_audit.py``) proves that no branch and no
memory address in the release code depends on a secret. It cannot see
variable-latency instructions or microarchitectural effects. This driver runs
``ol_ct_audit --dudect <target>`` for every target: two input classes (a
FIXED secret and fresh RANDOM secrets, identical public inputs, the same
public verdict), the class of each measurement drawn uniformly at random so
that machine noise is independent of the class, dudect's percentile crops and
Welch's t-test. See ``native/ol_ct_audit/src/timing.rs``.

Every target result carries its own power: the minimum detectable effect
(MDE), the shift of the class means that would give |t| = 4.5 with the
observed variances; ``mde80`` is the shift detected with 80 % power. This
driver recomputes every statistic from the per-crop moments and the histogram
(an independent implementation of the same formulas), then assigns:

* LEAK: |t| > 4.5 at any crop;
* PASS: no leak, and ``mde80`` is at most ``--mde-bound`` of the median
  measurement (net of the clock's overhead);
* INCONCLUSIVE-POWER: no leak seen, but the run could not have seen a leak
  of that size.

Negative controls leak by design and must be detected (else the run is
BLIND); null controls give both classes the same input distribution and must
not be flagged (else the run is BIASED).

Exit status: 0 every target as expected; 1 a leak, a blind or biased control,
an inconsistent or failed target; 3 no failure but some target
INCONCLUSIVE-POWER; 2 usage error.

Usage::

    python scripts/run_ct_timing.py --report test-results/ct-timing/report.json \\
        --host-note "dedicated runner, nothing else scheduled"
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import pathlib
import platform
import random
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field

SCHEMA = "one-link/ct-timing-report/v1"
TARGET_SCHEMA = "one-link/ct-timing-target/v1"
T_THRESHOLD = 4.5
Z_POWER_80 = 0.8416212335729143
MIN_CLASS_N = 1_000
MIN_SENSITIVITY = 0.25
PASS, LEAK, INCONCLUSIVE = "PASS", "LEAK", "INCONCLUSIVE-POWER"
# Relative tolerance between the binary's statistics and this recomputation.
RECOMPUTE_RTOL = 1e-9
ROOT = pathlib.Path(__file__).resolve().parents[1]
# A target's process may run this much longer than its measurement budget
# (setup of key pools, JSON emission) before it is killed.
SETUP_MARGIN_S = 120


# --------------------------------------------------------------- statistics


def welch(n0: int, m0: float, v0: float, n1: int, m1: float, v1: float) -> tuple[float | None, float | None]:
    """Welch's (t, se) for class 1 minus class 0; None where undefined."""
    if n0 < 2 or n1 < 2:
        return None, None
    se = math.sqrt(v0 / n0 + v1 / n1)
    if not se > 0:
        return None, se
    return (m1 - m0) / se, se


def mde80(mde: float) -> float:
    return mde * (T_THRESHOLD + Z_POWER_80) / T_THRESHOLD


def effective_sensitivity(s: float) -> float:
    return min(abs(s), 1.0)


def shift_sensitivity(
    thresholds: list[int], counts: list[int], lo: int, hi: int, j: int, crop_n: int, crop_mean: float
) -> float:
    """s = 1 - f(c) (c - m(c)) / F(c) for the crop strictly below thresholds[j].

    ``counts`` are the pooled histogram bins (bin b covers
    [thresholds[b-1], thresholds[b]), bin 0 from ``lo``, the last bin to
    ``hi`` inclusive); the density is estimated between the nearest distinct
    thresholds around c, as the binary does.
    """
    k = len(thresholds)
    total = sum(counts)
    if total == 0 or crop_n == 0:
        return 0.0
    c = thresholds[j]
    left = next((t for t in reversed(thresholds[:j]) if t < c), min(lo, c))
    right = next((t for t in thresholds[j + 1 :] if t > c), max(hi + 1, c))
    if right <= left:
        return 0.0

    def lower_edge(b: int) -> int:
        return lo if b == 0 else thresholds[b - 1]

    def upper_edge(b: int) -> int:
        return hi + 1 if b == k else thresholds[b]

    mass = sum(counts[b] for b in range(k + 1) if lower_edge(b) >= left and upper_edge(b) <= right)
    density = mass / (total * (right - left))
    fraction = crop_n / total
    return 1.0 - density * (c - crop_mean) / fraction


def pooled_mean(n0: int, m0: float, n1: int, m1: float) -> float:
    return (n0 * m0 + n1 * m1) / (n0 + n1) if n0 + n1 else 0.0


def pooled_sd(n0: int, m0: float, v0: float, n1: int, m1: float, v1: float) -> float:
    """Standard deviation of the union of two samples given their moments."""
    n = n0 + n1
    if n < 2:
        return 0.0
    m2 = v0 * max(n0 - 1, 0) + v1 * max(n1 - 1, 0) + (m1 - m0) ** 2 * n0 * n1 / n
    return math.sqrt(max(m2, 0.0) / (n - 1))


def verdict_for(max_abs_t: float | None, mde80_fraction: float | None, bound: float) -> str:
    if max_abs_t is not None and max_abs_t > T_THRESHOLD:
        return LEAK
    if mde80_fraction is not None and mde80_fraction <= bound:
        return PASS
    return INCONCLUSIVE


def close(a: float | None, b: float | None, rtol: float = RECOMPUTE_RTOL) -> bool:
    if a is None or b is None:
        return a is None and b is None
    return abs(a - b) <= rtol * max(abs(a), abs(b), 1.0)


@dataclass
class Recomputed:
    max_abs_t: float | None
    max_abs_t_row: int | None
    headline_row: int | None
    mde: float | None
    mde80: float | None
    mde80_fraction: float | None
    verdict: str
    problems: list[str] = field(default_factory=list)


def recompute(result: dict, bound: float) -> Recomputed:
    """Re-derive every statistic of one target result and check the binary's."""
    problems: list[str] = []
    crops = result["crops"]
    hist = result["histogram"]
    thresholds = [t for t in crops["threshold"][1:]]
    rows = len(crops["n_fixed"])
    if rows != len(thresholds) + 1 or any(t is None for t in thresholds):
        problems.append("crop table shape is inconsistent")
        return Recomputed(None, None, None, None, None, None, INCONCLUSIVE, problems)
    if any(b < a for a, b in zip(thresholds, thresholds[1:])):
        problems.append("crop thresholds are not non-decreasing")
    for name in ("fixed", "random"):
        counts = hist[name]
        if len(counts) != len(thresholds) + 1:
            problems.append(f"{name} histogram has {len(counts)} bins for {len(thresholds)} thresholds")
            continue
        if sum(counts) != crops[f"n_{name}"][0] or sum(counts) != result["measurements"][name]:
            problems.append(f"{name} histogram total disagrees with the uncropped count")
        running = 0
        for j in range(len(thresholds)):
            running += counts[j]
            if running != crops[f"n_{name}"][j + 1]:
                problems.append(f"{name} crop {j + 1} count {crops[f'n_{name}'][j + 1]} != histogram prefix {running}")
                break
    pooled = [a + b for a, b in zip(hist["fixed"], hist["random"])]
    quantum = result["reading_quantum"]
    peak: tuple[int, float] | None = None
    best: tuple[int, float] | None = None
    for i in range(rows):
        n0, n1 = crops["n_fixed"][i], crops["n_random"][i]
        m0, m1 = crops["mean_fixed"][i], crops["mean_random"][i]
        v0, v1 = crops["var_fixed"][i], crops["var_random"][i]
        t, se = welch(n0, m0, v0, n1, m1, v1)
        mde = None if se is None else T_THRESHOLD * se
        if not close(t, crops["t"][i]):
            problems.append(f"row {i}: t {crops['t'][i]} != recomputed {t}")
        if not close(mde, crops["mde"][i]):
            problems.append(f"row {i}: mde {crops['mde'][i]} != recomputed {mde}")
        if i == 0:
            s = 1.0
        else:
            s = shift_sensitivity(
                thresholds, pooled, hist["min"], hist["max"], i - 1, n0 + n1, pooled_mean(n0, m0, n1, m1)
            )
        if not close(s, crops["sensitivity"][i], 1e-7):
            problems.append(f"row {i}: sensitivity {crops['sensitivity'][i]} != recomputed {s}")
        eff = effective_sensitivity(s)
        shift = None if mde is None or eff <= 0 else mde / eff
        if not close(shift, crops["mde_shift"][i], 1e-7):
            problems.append(f"row {i}: mde_shift {crops['mde_shift'][i]} != recomputed {shift}")
        if t is not None and (peak is None or abs(t) > peak[1]):
            peak = (i, abs(t))
        usable = (
            n0 >= MIN_CLASS_N
            and n1 >= MIN_CLASS_N
            and abs(s) >= MIN_SENSITIVITY
            and pooled_sd(n0, m0, v0, n1, m1, v1) >= quantum
        )
        if usable and shift is not None and (best is None or shift < best[1]):
            best = (i, shift)
    net = result["net_median"]
    mde = best[1] if best else None
    m80 = mde80(mde) if mde is not None else None
    fraction = m80 / net if m80 is not None and net else None
    verdict = verdict_for(peak[1] if peak else None, fraction, bound)
    head = result.get("headline")
    if (head is None) != (best is None):
        problems.append("headline presence disagrees with the recomputation")
    elif head is not None and best is not None:
        if head["row"] != best[0] or not close(head["mde80"], m80, 1e-7):
            problems.append(f"headline row/mde80 {head['row']}/{head['mde80']} != recomputed {best[0]}/{m80}")
    if result.get("verdict") != verdict:
        problems.append(f"binary verdict {result.get('verdict')} != recomputed {verdict}")
    return Recomputed(
        max_abs_t=peak[1] if peak else None,
        max_abs_t_row=peak[0] if peak else None,
        headline_row=best[0] if best else None,
        mde=mde,
        mde80=m80,
        mde80_fraction=fraction,
        verdict=verdict,
        problems=problems,
    )


def expected(expect: str, verdict: str) -> str:
    """How a verdict reads for a target of this expectation."""
    if expect == "leak":
        return "ok" if verdict == LEAK else "blind"
    if expect == "null":
        return "biased" if verdict == LEAK else ("ok" if verdict == PASS else "inconclusive")
    if verdict == LEAK:
        return "leak"
    return "ok" if verdict == PASS else "inconclusive"


# --------------------------------------------------------------------- host


def run_text(command: list[str], timeout: float = 30) -> str | None:
    try:
        out = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    # rstrip only: `git status --porcelain` lines start with a significant space.
    return out.stdout.rstrip() if out.returncode == 0 else None


def read_text(path: str) -> str | None:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def is_wsl() -> bool:
    return "microsoft" in (read_text("/proc/version") or "").lower()


def powershell() -> str | None:
    for candidate in ("powershell", "powershell.exe", "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"):
        found = shutil.which(candidate) or (candidate if os.path.isfile(candidate) else None)
        if found:
            return found
    return None


# Top processes by CPU over a two-second window, plus memory, as JSON.
WINDOWS_LOAD_SCRIPT = (
    "$ErrorActionPreference = 'SilentlyContinue'; "
    "$a = @{}; Get-Process | ForEach-Object { if ($_.CPU -ne $null) { $a[$_.Id] = $_.CPU } }; "
    "Start-Sleep -Milliseconds 2000; "
    "$rows = Get-Process | Where-Object { $_.CPU -ne $null -and $a.ContainsKey($_.Id) } | "
    "ForEach-Object { [pscustomobject]@{ pid = $_.Id; name = $_.ProcessName; "
    "cpu_percent_of_one_core = [math]::Round(100 * ($_.CPU - $a[$_.Id]) / 2.0, 1); "
    "working_set_mb = [math]::Round($_.WorkingSet64 / 1MB, 0) } } | "
    "Sort-Object cpu_percent_of_one_core -Descending | Select-Object -First 15; "
    "$os = Get-CimInstance Win32_OperatingSystem; "
    "[pscustomobject]@{ processes = @($rows); "
    "memory_total_mb = [math]::Round($os.TotalVisibleMemorySize / 1024, 0); "
    "memory_free_mb = [math]::Round($os.FreePhysicalMemory / 1024, 0) } | ConvertTo-Json -Depth 4 -Compress"
)


def windows_load() -> dict:
    ps = powershell()
    if ps is None:
        return {"error": "powershell not found"}
    text = run_text([ps, "-NoProfile", "-NonInteractive", "-Command", WINDOWS_LOAD_SCRIPT], timeout=60)
    if not text:
        return {"error": "powershell load query failed"}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"error": "powershell load query returned no JSON"}


def linux_process_times() -> dict[int, tuple[str, int]]:
    times: dict[int, tuple[str, int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        stat = read_text(f"/proc/{entry}/stat")
        if not stat or ")" not in stat:
            continue
        name = stat[stat.index("(") + 1 : stat.rindex(")")]
        fields = stat[stat.rindex(")") + 2 :].split()
        try:
            times[int(entry)] = (name, int(fields[11]) + int(fields[12]))
        except (IndexError, ValueError):
            continue
    return times


def linux_load() -> dict:
    if sys.platform == "win32":
        raise RuntimeError("linux_load reads /proc and is not available on Windows")
    tick = os.sysconf("SC_CLK_TCK")
    before = linux_process_times()
    window = 2.0
    time.sleep(window)
    after = linux_process_times()
    rows = []
    for pid, (name, total) in after.items():
        if pid in before:
            share = 100.0 * (total - before[pid][1]) / tick / window
            rows.append({"pid": pid, "name": name, "cpu_percent_of_one_core": round(share, 1)})
    rows.sort(key=lambda r: r["cpu_percent_of_one_core"], reverse=True)
    meminfo = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        key, _, value = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            meminfo[key] = int(value.split()[0]) // 1024
    load = {
        "loadavg": (read_text("/proc/loadavg") or "").split()[:3],
        "processes": rows[:15],
        "memory_total_mb": meminfo.get("MemTotal"),
        "memory_available_mb": meminfo.get("MemAvailable"),
    }
    if is_wsl():
        # WSL2 shares the physical CPU with the Windows host: record it too.
        load["windows_host"] = windows_load()
    return load


def load_snapshot() -> dict:
    snap = {"utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    snap.update(windows_load() if platform.system() == "Windows" else linux_load())
    return snap


class BusyMeter:
    """System-wide CPU busy fraction over an interval (all logical CPUs)."""

    def __init__(self) -> None:
        self.start = self._sample()

    @staticmethod
    def _sample() -> tuple[float, float, float] | None:
        if platform.system() == "Windows":
            import ctypes
            from ctypes import wintypes

            idle, kernel, user = wintypes.FILETIME(), wintypes.FILETIME(), wintypes.FILETIME()
            if not ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
                return None

            def ticks(ft: wintypes.FILETIME) -> int:
                return (ft.dwHighDateTime << 32) | ft.dwLowDateTime

            # Kernel time includes idle time.
            return float(ticks(idle)), float(ticks(kernel) + ticks(user)), 0.0
        line = (read_text("/proc/stat") or "").splitlines()[:1]
        if not line or not line[0].startswith("cpu "):
            return None
        fields = [float(x) for x in line[0].split()[1:]]
        idle_ticks = fields[3] + (fields[4] if len(fields) > 4 else 0.0)
        steal = fields[7] if len(fields) > 7 else 0.0
        return idle_ticks, sum(fields[:8]), steal

    def stop(self) -> dict:
        end = self._sample()
        if self.start is None or end is None or end[1] <= self.start[1]:
            return {"busy_fraction": None}
        total = end[1] - self.start[1]
        busy = 1.0 - (end[0] - self.start[0]) / total
        cpus = os.cpu_count() or 1
        out = {
            "busy_fraction": round(busy, 4),
            # Our measurement thread keeps one logical CPU busy.
            "other_load_cpus": round(max(0.0, busy * cpus - 1.0), 2),
        }
        if platform.system() != "Windows":
            out["steal_fraction"] = round((end[2] - self.start[2]) / total, 4)
        return out


def host_info() -> dict:
    info: dict = {
        "system": platform.system(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "python": platform.python_version(),
    }
    if platform.system() == "Windows":
        try:
            import winreg

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            info["cpu_model"] = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
        except OSError:
            info["cpu_model"] = None
        info["power_plan"] = run_text(["powercfg", "/getactivescheme"])
        info["frequency_governor"] = "not applicable (Windows power plan above)"
    else:
        cpuinfo = read_text("/proc/cpuinfo") or ""
        model = next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("model name")), None)
        flags_line = next((line for line in cpuinfo.splitlines() if line.startswith("flags")), "")
        flags = set(flags_line.split(":", 1)[-1].split())
        info["cpu_model"] = model
        info["tsc_flags"] = sorted(flags & {"constant_tsc", "nonstop_tsc", "tsc_known_freq", "rdtscp"})
        os_release = read_text("/etc/os-release") or ""
        info["os"] = next((line.split("=", 1)[1].strip('"') for line in os_release.splitlines() if line.startswith("PRETTY_NAME=")), None)
        info["kernel"] = platform.release()
        info["wsl"] = is_wsl()
        governors = sorted({(read_text(str(p)) or "").strip() for p in pathlib.Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_governor")})
        info["frequency_governor"] = governors or (
            "unavailable: no cpufreq interface in this kernel"
            + (" (WSL2 VM; the Windows host's power plan controls frequency)" if is_wsl() else "")
        )
        no_turbo = read_text("/sys/devices/system/cpu/intel_pstate/no_turbo")
        info["intel_pstate_no_turbo"] = no_turbo.strip() if no_turbo else None
    return info


# ------------------------------------------------------------------- binary


def binary_path(native: pathlib.Path) -> pathlib.Path:
    name = "ol_ct_audit.exe" if platform.system() == "Windows" else "ol_ct_audit"
    return native / "target" / "ct-audit" / name


def build(native: pathlib.Path) -> None:
    command = ["cargo", "build", "--locked", "--profile", "ct-audit", "-p", "ol_ct_audit"]
    proc = subprocess.run(command, cwd=native, capture_output=True, text=True, timeout=3600, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"build failed ({proc.returncode}):\n{proc.stderr[-4000:]}")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def list_targets(binary: pathlib.Path) -> list[dict]:
    out = subprocess.run([str(binary), "--dudect-list"], capture_output=True, text=True, timeout=60, check=True)
    targets = [json.loads(line) for line in out.stdout.splitlines() if line.strip()]
    names = [t["name"] for t in targets]
    if not targets or len(names) != len(set(names)):
        raise SystemExit("ol_ct_audit --dudect-list returned no targets or duplicate names")
    return targets


def source_info(args: argparse.Namespace, binary: pathlib.Path) -> dict:
    commit = run_text(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    dirty = run_text(["git", "-C", str(ROOT), "status", "--porcelain", "--", "native", "scripts/run_ct_timing.py"])
    return {
        "git_commit": commit or args.source_commit,
        "git_commit_from": "git" if commit else ("--source-commit" if args.source_commit else None),
        "uncommitted_paths": dirty.splitlines() if dirty is not None else None,
        "source_note": args.source_note,
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "binary_bytes": binary.stat().st_size,
        "profile": "ct-audit (inherits release: opt-level 3, fat LTO, 1 codegen unit, panic=abort)",
    }


def run_target(binary: pathlib.Path, name: str, budget_s: float, args: argparse.Namespace, seed: int) -> dict:
    min_time_s = min(args.min_target_s, budget_s / 2)
    command = [
        str(binary),
        "--dudect", name,
        "--budget-ms", str(int(budget_s * 1000)),
        "--min-time-ms", str(int(min_time_s * 1000)),
        "--min-measurements", str(args.min_measurements),
        "--mde-goal", repr(args.mde_goal),
        "--mde-bound", repr(args.mde_bound),
        "--seed", str(seed),
    ]
    preexec = None
    if args.cpu is not None:
        if sys.platform != "linux":
            raise SystemExit("--cpu pins with sched_setaffinity, which only Linux provides")
        cpu = args.cpu

        def preexec() -> None:  # pragma: no cover - Linux only
            os.sched_setaffinity(0, {cpu})

    meter = BusyMeter()
    started = time.monotonic()
    row: dict = {"command": command, "budget_s": round(budget_s, 1)}
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=budget_s + SETUP_MARGIN_S, preexec_fn=preexec, check=False
        )
    except subprocess.TimeoutExpired:
        row.update(error=f"timed out after {budget_s + SETUP_MARGIN_S:.0f}s", wall_s=round(time.monotonic() - started, 1))
        row["load"] = meter.stop()
        return row
    row["wall_s"] = round(time.monotonic() - started, 1)
    row["load"] = meter.stop()
    row["returncode"] = proc.returncode
    if proc.returncode not in (0, 1, 4):
        row["error"] = f"exit status {proc.returncode}: {proc.stderr.strip()[-2000:]}"
        return row
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        row["error"] = f"expected one JSON line, got {len(lines)}"
        return row
    try:
        result = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        row["error"] = f"unparseable JSON: {exc}"
        return row
    if result.get("schema") != TARGET_SCHEMA or result.get("target", {}).get("name") != name:
        row["error"] = "result schema or target name mismatch"
        return row
    row["result"] = result
    return row


# ------------------------------------------------------------------- report


def dump(value, indent: int = 0) -> str:
    """JSON with objects one key per line but scalar arrays on one line."""
    pad, inner = "  " * indent, "  " * (indent + 1)
    if isinstance(value, dict):
        if not value:
            return "{}"
        items = [f"{inner}{json.dumps(k)}: {dump(v, indent + 1)}" for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + pad + "}"
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return "[" + ", ".join(json.dumps(v) for v in value) + "]"
        return "[\n" + ",\n".join(inner + dump(v, indent + 1) for v in value) + "\n" + pad + "]"
    return json.dumps(value)


def method(args: argparse.Namespace, targets: int) -> dict:
    per_test = math.erfc(T_THRESHOLD / math.sqrt(2.0))
    tests_per_target = 101
    return {
        "reference": "Reparaz, Balasch, Verbauwhede, 'Dude, is my code constant time?', DATE 2017 (dudect)",
        "classes": "class 0 holds the secret FIXED, class 1 draws a fresh RANDOM secret per call; public inputs identical; both classes reach the same public verdict (except duress_real_vs_duress, which compares the real and duress outcomes themselves)",
        "interleaving": "each measurement's class is an independent fair coin (ChaCha20), so machine noise is independent of the class: it lowers power but cannot create a class difference",
        "inputs": "every input of a batch is generated before any is timed, one slot per call; outputs are parked and dropped after the batch",
        "clock": "x86-64: lfence; rdtsc; lfence around each measurement (TSC ticks at the constant TSC rate, not core cycles); elsewhere std::time::Instant (ns)",
        "measurement": "calls_per_measurement calls of the production function through a non-inlined shim, black_box on every input and output",
        "crops": "dudect's 100 percentile thresholds 1 - 0.5^(10 (i+1) / 100), i = 0..99, from a discarded calibration sample of 20000 measurements, plus the uncropped data; values strictly below the threshold are kept; dudect also discards the first 10 measurements of each batch",
        "test": "Welch's t on each crop with online (Welford) moments; LEAK when |t| > 4.5 at any crop",
        "power": "MDE = 4.5 * sqrt(var0/n0 + var1/n1) per crop; divided by the crop's shift sensitivity min(|s|, 1), s = 1 - f(c)(c - m(c))/F(c), so it is the uniform shift of every measurement that would give |t| = 4.5; headline = the smallest over crops with >= 1000 measurements per class and |s| >= 0.25; mde80 = MDE * (4.5 + 0.8416) / 4.5 is detected with 80 % power",
        "fraction_of": "the smaller class median of the run (from an evenly thinned subsample), net of the clock's median overhead",
        "verdicts": {
            "PASS": f"max |t| <= 4.5 and mde80 <= {args.mde_bound:g} of the net median",
            "LEAK": "max |t| > 4.5 at some crop",
            "INCONCLUSIVE-POWER": f"max |t| <= 4.5 but mde80 > {args.mde_bound:g} of the net median",
        },
        "false_positive_bound": {
            "per_test_two_sided_p_at_4_5": per_test,
            "tests_per_target": tests_per_target,
            "per_target_bonferroni": per_test * tests_per_target,
            "run_bonferroni": per_test * tests_per_target * targets,
            "note": "normal approximation; the crops of one target are strongly correlated, so the true rates are lower",
        },
        "stopping": f"a target stops when its time budget ends; or, after at least {args.min_target_s:g}s and {args.min_measurements} measurements, when max |t| > 10 (decisive) or (non-control-leak targets) when mde80 <= {args.mde_goal:g} of the net median. The stop rule depends on variances, not on the sign or size of the class difference.",
    }


def summarize(rows: list[dict]) -> dict:
    summary: dict = {"targets": len(rows), "constant_time": {PASS: 0, LEAK: 0, INCONCLUSIVE: 0}}
    leak_controls = [r for r in rows if r["expect"] == "leak"]
    null_controls = [r for r in rows if r["expect"] == "null"]
    for r in rows:
        if r["expect"] == "constant_time" and r.get("verdict") in summary["constant_time"]:
            summary["constant_time"][r["verdict"]] += 1
    summary["leak_controls"] = {"total": len(leak_controls), "detected": sum(r.get("verdict") == LEAK for r in leak_controls)}
    summary["null_controls"] = {"total": len(null_controls), "flagged": sum(r.get("verdict") == LEAK for r in null_controls)}
    summary["errors"] = sum(1 for r in rows if r.get("error"))
    return summary


def table_row(name: str, expect: str, run: dict, rec: Recomputed | None) -> dict:
    row: dict = {"name": name, "expect": expect}
    if run.get("error") or rec is None:
        row.update(verdict=None, outcome="error", error=run.get("error"))
        return row
    result = run["result"]
    calls = result["target"]["calls_per_measurement"]
    tps = result["ticks_per_second"]
    meas = result["measurements"]
    row.update(
        verdict=rec.verdict,
        outcome=expected(expect, rec.verdict),
        n_fixed=meas["fixed"],
        n_random=meas["random"],
        max_abs_t=round(rec.max_abs_t, 3) if rec.max_abs_t is not None else None,
        max_abs_t_row=rec.max_abs_t_row,
        mde80_ticks=rec.mde80,
        mde80_ticks_per_call=rec.mde80 / calls if rec.mde80 is not None else None,
        mde80_ns_per_call=(rec.mde80 / calls / tps * 1e9) if rec.mde80 is not None and tps else None,
        mde80_percent=100 * rec.mde80_fraction if rec.mde80_fraction is not None else None,
        mde50_ticks=rec.mde,
        net_median_ticks=result["net_median"],
        calls_per_measurement=calls,
        stop_reason=result["stop_reason"],
        elapsed_s=round(result["elapsed_ms"] / 1000, 1),
        other_load_cpus=run.get("load", {}).get("other_load_cpus"),
    )
    if rec.problems:
        row["outcome"] = "inconsistent"
        row["problems"] = rec.problems[:20]
    return row


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--report", required=True, type=pathlib.Path)
    parser.add_argument("--native-dir", type=pathlib.Path, default=ROOT / "native")
    parser.add_argument("--binary", type=pathlib.Path, help="default: <native-dir>/target/ct-audit/ol_ct_audit")
    parser.add_argument("--no-build", action="store_true", help="use the existing binary")
    parser.add_argument("--target", action="append", default=[], help="run only these targets")
    parser.add_argument("--total-budget-s", type=float, default=780.0, help="measurement time for all targets")
    parser.add_argument("--max-target-s", type=float, default=240.0)
    parser.add_argument("--min-target-s", type=float, default=5.0, help="minimum measuring time per target")
    parser.add_argument("--min-measurements", type=int, default=200_000)
    parser.add_argument("--mde-bound", type=float, default=0.01, help="PASS needs mde80 <= this fraction")
    parser.add_argument("--mde-goal", type=float, default=0.001, help="stop early once mde80 <= this fraction")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--cpu", type=int, default=None, help="Linux: pin each target to this logical CPU")
    parser.add_argument("--host-note", default="unspecified", help="what this host is and what else runs on it")
    parser.add_argument("--quiet-machine", action="store_true", help="assert the host is a quiet, dedicated machine")
    parser.add_argument("--source-commit", default=None, help="commit to record when git is unavailable here")
    parser.add_argument("--source-note", default=None)
    args = parser.parse_args(argv)
    if not 0 < args.mde_goal <= args.mde_bound < 1:
        parser.error("need 0 < --mde-goal <= --mde-bound < 1")
    if args.cpu is not None and not hasattr(os, "sched_setaffinity"):
        parser.error("--cpu needs Linux")

    native = args.native_dir.resolve()
    binary = (args.binary or binary_path(native)).resolve()
    if not args.no_build:
        build(native)
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    seed = args.seed if args.seed is not None else random.SystemRandom().getrandbits(63)
    targets = list_targets(binary)
    if args.target:
        unknown = sorted(set(args.target) - {t["name"] for t in targets})
        if unknown:
            raise SystemExit(f"unknown targets: {unknown}")
        targets = [t for t in targets if t["name"] in set(args.target)]

    report: dict = {
        "schema": SCHEMA,
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "status": "incomplete",
        "quiet_machine": bool(args.quiet_machine),
        "host_note": args.host_note,
        "statement": (
            "Run on a host asserted to be quiet and dedicated."
            if args.quiet_machine
            else "This host is NOT a quiet machine. Classes are interleaved at random, so its load cannot "
            "create a class difference; it only raises the variance, which every target's MDE states."
        ),
        "method": method(args, len(targets)),
        "config": {
            "seed": seed,
            "total_budget_s": args.total_budget_s,
            "max_target_s": args.max_target_s,
            "min_target_s": args.min_target_s,
            "min_measurements": args.min_measurements,
            "mde_bound": args.mde_bound,
            "mde_goal": args.mde_goal,
            "cpu": args.cpu,
        },
        "source": source_info(args, binary),
        "host": host_info(),
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    report["load_before"] = load_snapshot()

    started = time.monotonic()
    rows: list[dict] = []
    runs: list[dict] = []
    for index, target in enumerate(targets):
        remaining = args.total_budget_s - (time.monotonic() - started)
        share = remaining / (len(targets) - index)
        budget = max(args.min_target_s * 2, min(args.max_target_s, share))
        run = run_target(binary, target["name"], budget, args, seed)
        rec = None
        if "result" in run:
            rec = recompute(run["result"], args.mde_bound)
            run["recomputed"] = {
                "verdict": rec.verdict,
                "max_abs_t": rec.max_abs_t,
                "max_abs_t_row": rec.max_abs_t_row,
                "headline_row": rec.headline_row,
                "mde80": rec.mde80,
                "mde80_fraction": rec.mde80_fraction,
                "problems": rec.problems,
            }
        row = table_row(target["name"], target["expect"], run, rec)
        rows.append(row)
        runs.append({"name": target["name"], "expect": target["expect"], **run})
        pct = f"{row['mde80_percent']:.4f}%" if row.get("mde80_percent") is not None else "-"
        print(
            f"{row['outcome']:>12} {row.get('verdict') or 'ERROR':<18} {target['name']:<34} "
            f"n={row.get('n_fixed', 0) + row.get('n_random', 0):>10} max|t|={row.get('max_abs_t')} "
            f"mde80={pct} ({row.get('stop_reason')}, {row.get('elapsed_s')}s)",
            flush=True,
        )
    report["measurement_wall_s"] = round(time.monotonic() - started, 1)
    report["load_after"] = load_snapshot()

    failures = []
    for row in rows:
        if row["outcome"] in ("error", "inconsistent", "blind", "biased", "leak"):
            failures.append(f"{row['name']}: {row['outcome']}" + (f" ({row.get('verdict')})" if row.get("verdict") else ""))
    if not any(r["expect"] == "leak" for r in rows) and not args.target:
        failures.append("<no negative control: the run's sensitivity is unproven>")
    inconclusive = [r["name"] for r in rows if r["outcome"] == "inconclusive"]
    report["status"] = "failed" if failures else ("inconclusive" if inconclusive else "passed")
    report["failures"] = failures
    report["inconclusive"] = inconclusive
    report["summary"] = summarize(rows)
    report["table"] = rows
    report["targets"] = runs
    args.report.write_text(dump(report) + "\n", encoding="utf-8")
    print(f"ct-timing: {report['status']}; {report['summary']}; report {args.report}")
    if failures:
        return 1
    return 3 if inconclusive else 0


if __name__ == "__main__":
    sys.exit(main())
