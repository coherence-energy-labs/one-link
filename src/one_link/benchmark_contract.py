"""Shared measurement metadata and deterministic benchmark corpora.

These helpers do not run a benchmark or change product runtime settings.
Input preparation and provenance collection belong outside the timed region.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import importlib.util
import os
import platform
import random
import subprocess
import sys
import time
import zlib
from pathlib import Path
from typing import Any


CORPORA = ("random", "compressed", "repetitive", "related")


def corpus_bytes(size: int, *, seed: int = 0, kind: str = "random") -> bytes:
    """Return exactly size deterministic bytes; related differs by a 4 KiB edit.

    ``compressed`` concatenates independently compressed random blocks. It is
    an already-compressed workload, not a claim to model a particular codec.
    ``repetitive`` deliberately preserves the old, highly compressible corpus.
    The random generator is for public test data, never key material.
    """
    if size < 0:
        raise ValueError("size must be nonnegative")
    if kind not in CORPORA:
        raise ValueError(f"unknown corpus: {kind}")
    rng = random.Random(seed)  # nosec B311 - reproducible public benchmark data
    if kind == "repetitive":
        block = rng.randbytes(min(size, 4096))
        return (block * ((size + 4095) // 4096))[:size]
    if kind == "compressed":
        out = bytearray()
        while len(out) < size:
            out.extend(zlib.compress(rng.randbytes(min(size - len(out), 65536)), 6))
        return bytes(out[:size])
    data = rng.randbytes(size)
    if kind == "related" and size:
        start = size // 2
        length = min(4096, size - start)
        edit = random.Random(seed ^ 0x4F4E454C494E4B).randbytes(length)  # nosec B311
        data = data[:start] + edit + data[start + length:]
    return data


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _git(root: Path, *args: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL,
            timeout=5, text=True,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return None


def cpu_model() -> str:
    """The CPU model string (platform.processor() is empty or generic on Linux)."""
    try:
        if os.name == "nt":
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        if os.path.exists("/proc/cpuinfo"):
            with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as info:
                for line in info:
                    if line.lower().startswith(("model name", "hardware", "cpu model")):
                        return line.split(":", 1)[1].strip()
        if platform.system() == "Darwin":
            out = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                return out.stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return platform.processor() or "unknown"


def memory_total_bytes() -> int | None:
    try:
        if sys.platform == "win32":
            import ctypes

            class Status(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

            status = Status()
            status.dwLength = ctypes.sizeof(Status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.ullTotalPhys)
            return None
        else:
            return int(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None


def _host_record() -> dict[str, Any]:
    """Host provenance with an identity that actually distinguishes machines.

    ``host_id`` used to hash only the hostname, which is identical across
    GitHub-hosted runners, so two runners in different regions reported the
    same host. It now hashes hostname, CPU model, core count, physical memory
    and the runner identity GitHub exposes, so measurements from different
    machines can never be presented as like-for-like.
    """
    runner = {
        key: os.environ.get(env)
        for key, env in (("name", "RUNNER_NAME"), ("os", "RUNNER_OS"), ("arch", "RUNNER_ARCH"),
                         ("environment", "RUNNER_ENVIRONMENT"), ("image_os", "ImageOS"),
                         ("image_version", "ImageVersion"))
        if os.environ.get(env)
    }
    model = cpu_model()
    memory = memory_total_bytes()
    identity = {"node": platform.node(), "cpu_model": model, "cpu_count": os.cpu_count(),
                "memory_total_bytes": memory, "runner": runner}
    return {
        "platform": platform.platform(), "machine": platform.machine(),
        "python": platform.python_version(), "implementation": platform.python_implementation(),
        "processor": platform.processor(), "cpu_count": os.cpu_count(),
        "cpu_model": model, "memory_total_bytes": memory, "runner": runner,
        "host_id": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
        "host_id_inputs": sorted(identity),
    }


def provenance(root: Path | None = None) -> dict[str, Any]:
    """Describe the harness, installed native artifact, host and measurement clock.

    Hashing the host name avoids exposing a workstation name while allowing
    accidental cross-host comparisons to be rejected. A paired runner also
    supplies a fresh session ID; an OS/CPU class alone is not a host identity.
    """
    root = root or Path(__file__).resolve().parents[2]
    native: dict[str, Any] = {"available": False}
    try:
        spec = importlib.util.find_spec("one_link_native")
        if spec is not None and spec.origin:
            origin = Path(spec.origin)
            candidates = [origin] if origin.suffix.lower() in {".so", ".pyd", ".dll"} else [
                *origin.parent.glob("*.so"), *origin.parent.glob("*.pyd")
            ]
            native = {
                "available": bool(candidates),
                "distribution_version": importlib.metadata.version("one-link-native"),
                "artifacts": [
                    {"name": p.name, "size": p.stat().st_size, "sha256": file_sha256(p)}
                    for p in sorted(candidates)
                ],
            }
    except (ImportError, OSError, ValueError, importlib.metadata.PackageNotFoundError):
        native["identity_status"] = "unavailable"
    clock = time.get_clock_info("perf_counter")
    return {
        "schema": "one-link-benchmark-provenance-v1",
        "source_revision": _git(root, "rev-parse", "HEAD"),
        "source_dirty": bool(_git(root, "status", "--porcelain", "--untracked-files=no")),
        "native_source_revision": os.environ.get("ONE_LINK_BENCH_NATIVE_REVISION"),
        "native": native,
        "host": _host_record(),
        "clock": {"name": "perf_counter", "monotonic": clock.monotonic, "resolution_s": clock.resolution},
        "session_id": os.environ.get("ONE_LINK_BENCH_SESSION"),
        "pair_index": os.environ.get("ONE_LINK_BENCH_PAIR"),
        "arm": os.environ.get("ONE_LINK_BENCH_ARM"),
    }


def comparison_issues(old: dict, new: dict) -> list[str]:
    """Report mismatches that make performance ratios uninterpretable."""
    issues = []
    for key in ("schema", "scale", "seed", "measurement_contract"):
        if key not in old or key not in new:
            issues.append(f"unrecorded {key}")
        elif old[key] != new[key]:
            issues.append(f"different {key}")
    for key in ("platform", "machine", "python", "processor", "host_id"):
        a = old.get("provenance", {}).get("host", {}).get(key)
        b = new.get("provenance", {}).get("host", {}).get(key)
        if a is None or b is None:
            issues.append(f"unrecorded host.{key}")
        elif a != b:
            issues.append(f"different host.{key}")
    return issues
