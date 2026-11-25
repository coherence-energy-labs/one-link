"""Shared measurement metadata and deterministic benchmark corpora.

These helpers do not run a benchmark or change product runtime settings.
Input preparation and provenance collection belong outside the timed region.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import os
import platform
import random
import subprocess
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
        "host": {
            "platform": platform.platform(), "machine": platform.machine(),
            "python": platform.python_version(), "implementation": platform.python_implementation(),
            "processor": platform.processor(), "cpu_count": os.cpu_count(),
            "host_id": hashlib.sha256(platform.node().encode()).hexdigest(),
        },
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
