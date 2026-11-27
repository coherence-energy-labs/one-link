from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from one_link.capabilities import CHAT, FILES, SELF_MESH_SEND
from one_link.state import State
from tests.harness import daemon_pair, wait_for_inbox_file


pytestmark = pytest.mark.timeout(180)


def _api(home: Path, method: str, path: str, body: dict | None = None) -> dict:
    port_path = home / "data" / "server.port"
    token_path = home / "data" / "ui.token"
    deadline = time.time() + 20.0
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            port = int(port_path.read_text(encoding="ascii").strip())
            token = token_path.read_text(encoding="ascii").strip()
            break
        except (OSError, ValueError) as exc:
            last_error = exc
            time.sleep(0.05)
    else:
        raise AssertionError(
            f"daemon HTTP API credentials did not appear under {home}; "
            f"last_error={last_error!r}"
        )
    data = None
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode("utf-8", errors="replace")
        raise AssertionError(
            f"{method} {path} failed with HTTP {exc.code}: {body_text}"
        ) from exc


def _wait_api_peer(home: Path, short_id: str, *, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    last: list[dict] = []
    while time.time() < deadline:
        body = _api(home, "GET", "/api/peers?include_unpaired=1")
        last = body.get("peers") or []
        for peer in last:
            if peer.get("short_id") == short_id:
                return peer
        time.sleep(0.25)
    raise AssertionError(f"peer {short_id} not visible in API; last={last!r}")


def _local_pub_b64(home: Path, short_id: str) -> str:
    state = State(db_path=home / "data" / "state.db")
    try:
        rec = state.get_peer_by_short_id(short_id)
        assert rec is not None
        return __import__("base64").urlsafe_b64encode(rec.pubkey).rstrip(b"=").decode("ascii")
    finally:
        state.close()


def _wait_self_mesh_event(
    home: Path,
    event: str,
    *,
    timeout: float = 20.0,
) -> dict:
    deadline = time.time() + timeout
    last: list[dict] = []
    while time.time() < deadline:
        state = State(db_path=home / "data" / "state.db")
        try:
            last = state.list_self_mesh_audit(limit=50)
        finally:
            state.close()
        for row in last:
            if row.get("event") == event:
                return row
        time.sleep(0.1)
    raise AssertionError(f"self-mesh event {event!r} not observed; last={last!r}")


@pytest.mark.live_daemon
def test_self_mesh_remote_send_crosses_real_daemon_transport(tmp_path: Path):
    with daemon_pair(pin_trust=True) as p:
        # Warm the encrypted channel and ensure both daemons have peer rows.
        peer_a = _wait_api_peer(p.b.home, p.a.short_id)
        peer_b = _wait_api_peer(p.a.home, p.b.short_id)
        _api(p.a.home, "POST", f"/api/peers/{peer_b['fingerprint']}/trust", {"trust": "pinned"})
        _api(p.b.home, "POST", f"/api/peers/{peer_a['fingerprint']}/trust", {"trust": "pinned"})
        _api(
            p.a.home,
            "POST",
            f"/api/peers/{peer_b['fingerprint']}/capabilities",
            {"allowed": [CHAT, FILES]},
        )
        _api(
            p.b.home,
            "POST",
            f"/api/peers/{peer_a['fingerprint']}/capabilities",
            {"allowed": [CHAT, FILES, SELF_MESH_SEND]},
        )

        root = _api(
            p.a.home,
            "POST",
            "/api/self-mesh/root",
            {"label": "My devices", "device_label": "phone-controller"},
        )
        laptop_pub_b64 = _local_pub_b64(p.a.home, p.b.short_id)
        minted = _api(
            p.a.home,
            "POST",
            "/api/self-mesh/devices/mint",
            {
                "root_pub_b64": root["root_pub_b64"],
                "device_pub_b64": laptop_pub_b64,
                "device_kind": "windows-laptop",
                "label": "Laptop source",
            },
        )
        enrolled = _api(
            p.b.home,
            "POST",
            "/api/self-mesh/devices/enroll",
            {
                "root_pub_b64": root["root_pub_b64"],
                "cert_b64": minted["cert_b64"],
                "device_kind": "windows-laptop",
                "label": "Laptop source",
                "local": True,
                "trusted": True,
            },
        )
        assert enrolled["trusted"] is True

        allowed = tmp_path / "b-self-mesh-source"
        allowed.mkdir()
        payload = allowed / "mesh-e2e.txt"
        payload.write_text("we are one across devices\n", encoding="utf-8")
        _api(
            p.b.home,
            "POST",
            "/api/self-mesh/allowed-roots",
            {"roots": [str(allowed)]},
        )

        sent = _api(
            p.a.home,
            "POST",
            "/api/self-mesh/remote-instruct",
            {
                "root_pub_b64": root["root_pub_b64"],
                "target_device_pub_b64": laptop_pub_b64,
                "peer": p.b.short_id,
                "action": "send_file_from_device",
                "scope": {
                    "path": str(payload),
                    "recipient_fp": peer_a["fingerprint"],
                    "max_bytes": 4096,
                },
            },
        )
        assert sent["ok"] is True
        assert sent["result"]["ack"]["ok"] is True
        assert sent["result"]["ack"]["action"] == "send_file_from_device"

        got = wait_for_inbox_file(
            p.a.home,
            payload.name,
            expected_size=payload.stat().st_size,
            timeout=30.0,
        )
        assert got.read_text(encoding="utf-8") == payload.read_text(encoding="utf-8")
        assert _wait_self_mesh_event(p.b.home, "command_accepted")["severity"] == "good"
        assert _wait_self_mesh_event(p.b.home, "remote_send_complete")["severity"] == "good"
        mesh = _api(p.b.home, "GET", "/api/self-mesh")
        assert any(item["status"] == "complete" for item in mesh["timeline"])
        metrics = {
            item["metric"]
            for item in mesh.get("performance_observations", [])
        }
        assert "command_verify" in metrics
        assert "remote_send_dispatch" in metrics
