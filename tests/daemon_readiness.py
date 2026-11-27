"""Bounded startup readiness for disposable browser-test daemons.

Startup is one operation: publishing files does not reset its deadline, and
only an authenticated HTTP response completes it. This is a test fixture, not
a product startup-performance allowance or a retry of a browser assertion.
"""
from __future__ import annotations

import http.client
import math
from pathlib import Path
import subprocess
from time import monotonic, sleep


def wait_for_owner_http(
    home: Path, proc: subprocess.Popen, *, timeout: float = 45.0,
) -> tuple[int, str, float]:
    """Return the owned port, bearer and elapsed time after authenticated boot."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("daemon startup budget must be finite and positive")
    started = monotonic()
    deadline = started + timeout
    phase = "ui.token + server.port"
    last_status = None
    while True:
        exit_code = proc.poll()
        if exit_code is not None:
            raise RuntimeError(
                f"test daemon exited with code {exit_code} during {phase} "
                f"after {monotonic() - started:.3f}s"
            )
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"test daemon alive but not ready during {phase} after "
                f"{monotonic() - started:.3f}s of {timeout:g}s total; "
                f"last_http_status={last_status}"
            )
        try:
            port = int((home / "data" / "server.port").read_text().strip())
            token = (home / "data" / "ui.token").read_text().strip()
        except (OSError, ValueError):
            port, token = 0, ""
        if 0 < port < 65536 and token:
            phase = "authenticated HTTP"
            remaining = deadline - monotonic()
            if remaining <= 0:
                continue
            connection = http.client.HTTPConnection(
                "127.0.0.1", port, timeout=min(1.0, remaining),
            )
            try:
                connection.request(
                    "GET", "/api/me", headers={"Authorization": f"Bearer {token}"},
                )
                response = connection.getresponse()
                last_status = response.status
                response.read(65536)
                if response.status == 200 and monotonic() < deadline:
                    # A stale port file must never qualify a child that died
                    # while its readiness request was in flight.
                    if proc.poll() is None:
                        return port, token, monotonic() - started
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
        sleep(min(0.05, max(0.0, deadline - monotonic())))
