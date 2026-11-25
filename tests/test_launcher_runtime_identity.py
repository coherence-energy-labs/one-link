"""Launcher identity is authenticated without evaluating dashboard diagnostics."""

from __future__ import annotations

import asyncio
import base64
import json
import os
from types import SimpleNamespace

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from one_link import __version__, app as app_mod
from one_link.build_identity import runtime_build_identity
from one_link.server import COOKIE_NAME, UIServer


class _UnavailableDashboard:
    def ui_session_token_id(self, _token):
        return None

    def __getattr__(self, name):
        raise AssertionError(f"launcher identity accessed dashboard dependency {name}")


def _unexpected_dashboard(*_args, **_kwargs):
    pytest.fail("launcher identity collected dashboard diagnostics")


@pytest.fixture
def identity_server(monkeypatch):
    daemon = SimpleNamespace(
        state=None,
        discovery=None,
        me=SimpleNamespace(fingerprint="ab" * 32, short_id="abababab", hostname="test"),
        _control_secret=base64.urlsafe_b64encode(b"k" * 32).decode("ascii").rstrip("="),
        _control_instance_id="launcher-identity-test",
        _session_stats=_unexpected_dashboard,
        _chunk_cache_stats=_unexpected_dashboard,
        _transfer_autopilot_stats=_unexpected_dashboard,
        _fabric_snapshot=_unexpected_dashboard,
    )
    server = UIServer(daemon)
    daemon.state = _UnavailableDashboard()
    daemon.discovery = _UnavailableDashboard()
    monkeypatch.setattr(server, "_safe_fabric_snapshot", _unexpected_dashboard)
    return server


@pytest.mark.asyncio
@pytest.mark.parametrize("credential", ["missing", "wrong", "query", "cookie"])
async def test_runtime_identity_retains_owner_api_authentication(identity_server, credential):
    server = identity_server
    headers = {}
    path = "/api/runtime-identity"
    if credential == "wrong":
        headers["Authorization"] = "Bearer incorrect"
    elif credential == "query":
        path += f"?t={server.token}"
    elif credential == "cookie":
        headers["Cookie"] = f"{COOKIE_NAME}={server.token}"
    async with TestClient(TestServer(server.app)) as client:
        response = await client.get(path, headers=headers)
        assert response.status == 401
        assert await response.json() == {"error": "unauthorized"}


@pytest.mark.asyncio
@pytest.mark.parametrize("headers, expected", [
    ({"Host": "unrelated.invalid"}, 421),
    ({"Origin": "https://unrelated.invalid"}, 403),
])
async def test_runtime_identity_retains_host_and_origin_guards(identity_server, headers, expected):
    server = identity_server
    async with TestClient(TestServer(server.app)) as client:
        response = await client.get(
            "/api/runtime-identity",
            headers={"Authorization": f"Bearer {server.token}", **headers},
        )
        assert response.status == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("identity_delta", [
    None,
    {"ok": False},
    {"app_version": "0.0.0"},
    {"daemon_instance_id": "another-instance"},
    {"pid": os.getpid() + 1},
    {"source_fingerprint": "another-build"},
    {"me": {"fingerprint": "cd" * 32}},
], ids=["matching", "not-ok", "version", "instance", "pid", "source", "profile"])
async def test_launcher_proves_same_connection_then_checks_lightweight_identity(
    identity_server, monkeypatch, identity_delta,
):
    server = identity_server
    observed = []

    @web.middleware
    async def observe_identity(request, handler):
        observed.append((
            request.path,
            request.headers.get("Authorization"),
            request.transport.get_extra_info("peername"),
        ))
        response = await handler(request)
        if request.path == "/api/runtime-identity":
            assert response.headers["Cache-Control"] == "no-store"
            if identity_delta:
                response.text = json.dumps({**json.loads(response.text), **identity_delta})
        return response

    server.app.middlewares.append(observe_identity)
    async with TestClient(TestServer(server.app)) as client:
        server.port = client.server.port
        status = {
            "ok": True,
            "app_version": __version__,
            **runtime_build_identity(),
            "pid": os.getpid(),
            "daemon_instance_id": server.daemon._control_instance_id,
            "ui_server_port": server.port,
            "protocol_version": "OL1.2",
            "schema_version": 1,
            "home": "authenticated-profile-home",
            "me": {"fingerprint": server.daemon.me.fingerprint},
        }
        commands = []

        def control_request(port, command, *, timeout, secret):
            assert port == 54321
            assert timeout == 2.0
            assert secret == server.daemon._control_secret
            commands.append(command)
            if command == "status":
                return dict(status)
            assert command == "ui_launch_info"
            return {
                **status,
                "token": server.token,
                "launch_nonce": "n" * 43,
            }

        monkeypatch.setattr(app_mod, "_control_request", control_request)
        resolved = await asyncio.to_thread(
            app_mod.resolve_authenticated_daemon,
            54321,
            server.daemon._control_secret,
        )
        assert commands == ["status", "ui_launch_info"]
        assert [item[0] for item in observed] == [
            "/api/local-instance-proof", "/api/runtime-identity",
        ]
        assert [item[1] for item in observed] == [None, f"Bearer {server.token}"]
        assert observed[0][2] == observed[1][2]
        if identity_delta is None:
            assert resolved is not None
            assert resolved.compatible
            assert resolved.status == status
            assert resolved.launch_nonce == "n" * 43
        else:
            assert resolved is None


def test_runtime_identity_never_reconnects_a_closed_verified_connection():
    class ClosedConnection:
        sock = None

        def request(self, *_args, **_kwargs):
            pytest.fail("launcher attempted to reconnect with an owner bearer")

    result = app_mod._ui_status_on_verified_connection(ClosedConnection(), "t" * 43)
    assert result["ok"] is False


@pytest.mark.asyncio
async def test_runtime_identity_matches_existing_dashboard_fields(identity_server, monkeypatch):
    server = identity_server
    # The full dashboard contract remains available to the UI; this comparison
    # uses inert diagnostics so it cannot run host inventory or scan a cache.
    server.daemon.state = None
    server.daemon.discovery = None
    for name in ("_session_stats", "_chunk_cache_stats", "_transfer_autopilot_stats"):
        monkeypatch.setattr(server.daemon, name, lambda: {})
    monkeypatch.setattr(server, "_safe_fabric_snapshot", lambda **_kwargs: {})
    identity = json.loads((await server.api_runtime_identity(None)).text)
    dashboard = json.loads((await server.api_status(None)).text)
    for name, value in identity.items():
        if name == "me":
            assert value == {"fingerprint": dashboard["me"]["fingerprint"]}
        else:
            assert value == dashboard[name]
    assert "performance" in dashboard
    assert "transfers" in dashboard
