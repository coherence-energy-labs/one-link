from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import app as app_mod
from one_link import control_ipc
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import COOKIE_NAME, SESSION_COOKIE_NAME, UIServer


def _secret(byte: bytes = b"k") -> str:
    return control_ipc._b64u(byte * control_ipc.CONTROL_SECRET_BYTES)


def _identity() -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private,
        public=public,
        public_bytes=public_bytes,
        fingerprint=fingerprint,
        short_id=fingerprint[:8],
        hostname="ipc-test",
    )


def test_control_secret_is_canonical_private_and_stable(tmp_path):
    first = control_ipc.load_or_create_control_secret(tmp_path)
    second = control_ipc.load_or_create_control_secret(tmp_path)

    assert first == second
    assert len(first) == 43
    assert control_ipc.read_control_secret(tmp_path) == first
    if os.name != "nt":
        assert (tmp_path / control_ipc.CONTROL_SECRET_FILE).stat().st_mode & 0o077 == 0


def test_control_secret_rejects_corrupt_existing_file(tmp_path):
    path = tmp_path / control_ipc.CONTROL_SECRET_FILE
    path.write_text("not-a-secret", encoding="ascii")

    with pytest.raises(RuntimeError, match="corrupt"):
        control_ipc.load_or_create_control_secret(tmp_path)


def test_control_secret_and_private_reader_reject_hardlink_aliases(tmp_path):
    source = tmp_path / "credential-source"
    source.write_text(_secret(), encoding="ascii")
    if os.name != "nt":
        source.chmod(0o600)
    secret_path = tmp_path / control_ipc.CONTROL_SECRET_FILE
    try:
        os.link(source, secret_path)
    except OSError as exc:  # pragma: no cover - filesystem capability
        pytest.skip(f"filesystem does not support hard links: {exc}")

    with pytest.raises(RuntimeError, match="regular private file"):
        control_ipc.read_control_secret(tmp_path)
    with pytest.raises(RuntimeError, match="regular private file"):
        control_ipc.read_private_bytes_strict(
            secret_path,
            max_bytes=128,
            label="test credential",
        )


def test_control_frame_limit_counts_the_newline_octet():
    payload = json.dumps({"value": "bounded"}, separators=(",", ":")).encode()
    receiver, sender = socket.socketpair()
    try:
        sender.sendall(payload + b"\n")
        with pytest.raises(control_ipc.ControlFrameTooLarge):
            control_ipc.recv_json_line(receiver, max_bytes=len(payload))
    finally:
        receiver.close()
        sender.close()


def test_runtime_control_hints_are_bounded_before_authentication(tmp_path):
    from one_link import daemon as daemon_mod

    hint = tmp_path / "control.port"
    hint.write_bytes(b"7" * 65)
    with pytest.raises(OSError, match="byte limit"):
        daemon_mod._read_runtime_ascii_scalar(hint, max_bytes=64)

    hint.write_bytes(b"7117\n")
    assert daemon_mod._read_runtime_ascii_scalar(hint, max_bytes=64) == "7117"


def test_runtime_control_hint_publish_is_atomic_and_replaceable(tmp_path):
    from one_link import daemon as daemon_mod

    hint = tmp_path / "control.port"
    daemon_mod._publish_runtime_ascii_scalar(hint, "7117")
    assert daemon_mod._read_runtime_ascii_scalar(hint) == "7117"

    daemon_mod._publish_runtime_ascii_scalar(hint, "7118")
    assert daemon_mod._read_runtime_ascii_scalar(hint) == "7118"
    assert list(tmp_path.glob(".control.port.*.tmp")) == []


def test_side_effect_free_control_port_read_defers_liveness_to_authenticated_caller(
    monkeypatch,
    tmp_path,
):
    from one_link import daemon as daemon_mod

    hint = tmp_path / "control.port"
    daemon_mod._publish_runtime_ascii_scalar(hint, "7117")
    monkeypatch.setattr(daemon_mod, "_control_port_path", lambda: hint)
    monkeypatch.setattr(
        daemon_mod,
        "is_daemon_alive",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("side-effect-free hint read performed a redundant probe")
        ),
    )

    assert daemon_mod.read_control_port(clear_stale=False) == 7117


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows symlinks are not portable")
def test_runtime_control_hint_publish_replaces_link_without_following(tmp_path):
    from one_link import daemon as daemon_mod

    target = tmp_path / "unrelated.txt"
    target.write_text("must-survive", encoding="ascii")
    hint = tmp_path / "control.port"
    hint.symlink_to(target)

    daemon_mod._publish_runtime_ascii_scalar(hint, "7117")

    assert target.read_text(encoding="ascii") == "must-survive"
    assert not hint.is_symlink()
    assert hint.read_text(encoding="ascii") == "7117"


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows symlinks are not portable")
def test_daemon_lock_open_rejects_link_without_clobbering_target(tmp_path):
    from one_link import daemon as daemon_mod

    target = tmp_path / "unrelated.txt"
    target.write_text("must-survive", encoding="ascii")
    lock = tmp_path / daemon_mod.DAEMON_LOCK_FILE
    lock.symlink_to(target)

    with pytest.raises(OSError):
        daemon_mod._open_daemon_lock_file(lock)

    assert target.read_text(encoding="ascii") == "must-survive"


def test_control_secret_creation_fails_closed_when_permissions_cannot_be_set(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        control_ipc,
        "_restrict_secret_file",
        lambda _path: (_ for _ in ()).throw(OSError("ACL denied")),
    )

    with pytest.raises(RuntimeError, match="permissions are unsafe"):
        control_ipc.load_or_create_control_secret(tmp_path)

    assert not (tmp_path / control_ipc.CONTROL_SECRET_FILE).exists()
    assert list(tmp_path.glob(".control.secret.*.tmp")) == []


def test_control_secret_is_not_written_before_acl_is_restricted(monkeypatch, tmp_path):
    observed_sizes: list[int] = []
    real_restrict = control_ipc._restrict_secret_file

    def observe_then_restrict(path):
        observed_sizes.append(path.stat().st_size)
        real_restrict(path)

    monkeypatch.setattr(control_ipc, "_restrict_secret_file", observe_then_restrict)

    control_ipc.load_or_create_control_secret(tmp_path)

    # The first permission operation targets the newly-created but still-empty
    # temporary file. Later calls may re-assert the final path's ACL.
    assert observed_sizes
    assert observed_sizes[0] == 0


def test_private_owner_credential_publish_is_bounded_atomic_and_private(tmp_path):
    path = tmp_path / "ui.token"
    payload = b"t" * 43

    control_ipc.write_private_bytes_strict(
        path,
        payload,
        max_bytes=128,
        label="UI owner token",
    )

    assert control_ipc.read_private_bytes_strict(
        path,
        max_bytes=128,
        label="UI owner token",
    ) == payload
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(ValueError, match="byte limit"):
        control_ipc.write_private_bytes_strict(
            path,
            b"x" * 129,
            max_bytes=128,
            label="UI owner token",
        )


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows symlinks are not portable")
def test_control_secret_rejects_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text(_secret(), encoding="ascii")
    (tmp_path / control_ipc.CONTROL_SECRET_FILE).symlink_to(target)

    with pytest.raises(RuntimeError, match="regular private file"):
        control_ipc.read_control_secret(tmp_path)


def test_mutual_auth_rejects_wrong_secret_replay_and_tampered_response():
    secret = _secret(b"a")
    wrong = _secret(b"b")
    client_nonce = control_ipc._b64u(b"c" * control_ipc.CONTROL_NONCE_BYTES)
    server_nonce = control_ipc._b64u(b"s" * control_ipc.CONTROL_NONCE_BYTES)
    next_server_nonce = control_ipc._b64u(b"n" * control_ipc.CONTROL_NONCE_BYTES)
    hello, _ = control_ipc.make_client_hello(client_nonce=client_nonce)
    challenge, _, _ = control_ipc.make_server_challenge(
        hello,
        secret,
        server_nonce=server_nonce,
    )

    with pytest.raises(control_ipc.ControlAuthenticationError):
        control_ipc.verify_server_challenge(
            challenge,
            wrong,
            client_nonce=client_nonce,
        )
    unicode_proof = dict(challenge)
    unicode_proof["server_proof"] = "\N{SNOWMAN}" * 64
    with pytest.raises(control_ipc.ControlAuthenticationError):
        control_ipc.verify_server_challenge(
            unicode_proof,
            secret,
            client_nonce=client_nonce,
        )

    assert (
        control_ipc.verify_server_challenge(
            challenge,
            secret,
            client_nonce=client_nonce,
        )
        == server_nonce
    )
    envelope, exchange = control_ipc.make_client_request(
        {"cmd": "status"},
        secret,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
    )
    request, server_exchange = control_ipc.verify_client_request(
        envelope,
        secret,
        client_nonce=client_nonce,
        server_nonce=server_nonce,
    )
    assert request == {"cmd": "status"}

    # A captured proof is bound to the daemon's fresh per-connection nonce.
    with pytest.raises(control_ipc.ControlAuthenticationError):
        control_ipc.verify_client_request(
            envelope,
            secret,
            client_nonce=client_nonce,
            server_nonce=next_server_nonce,
        )

    response_frame = control_ipc.encode_server_response(
        {"ok": True, "pid": 7},
        secret,
        server_exchange,
    )
    response_envelope = json.loads(response_frame)
    response_envelope["response"]["pid"] = 8
    with pytest.raises(control_ipc.ControlAuthenticationError):
        control_ipc.verify_server_response(response_envelope, secret, exchange)


@pytest.mark.asyncio
async def test_live_control_handler_denies_missing_wrong_credentials_and_bounds_response():
    daemon = Daemon(_identity())
    daemon._control_secret = _secret(b"z")
    server = await asyncio.start_server(
        daemon._handle_control,
        host="127.0.0.1",
        port=0,
        limit=control_ipc.CONTROL_REQUEST_MAX_BYTES + 1,
    )
    port = server.sockets[0].getsockname()[1]
    try:
        daemon._active_control_connections = (
            control_ipc.CONTROL_MAX_CONCURRENT_CONNECTIONS
        )
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        assert await asyncio.wait_for(reader.read(1), timeout=2.0) == b""
        writer.close()
        await writer.wait_closed()
        daemon._active_control_connections = 0

        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b'{"cmd":"shutdown"}\n')
        await writer.drain()
        denied = json.loads(await asyncio.wait_for(reader.readline(), timeout=2.0))
        assert denied == {"error": "unauthorized", "ok": False}
        writer.close()
        await writer.wait_closed()

        with pytest.raises(control_ipc.ControlAuthenticationError):
            await asyncio.to_thread(
                control_ipc.request_control,
                port,
                {"cmd": "status"},
                timeout=2.0,
                secret=_secret(b"y"),
            )

        result = await asyncio.to_thread(
            control_ipc.request_control,
            port,
            {"cmd": "frobnicate"},
            timeout=2.0,
            secret=daemon._control_secret,
        )
        assert result["ok"] is False
        assert "unknown cmd" in result["error"]

        daemon._control_status = lambda: {  # type: ignore[method-assign]
            "ok": True,
            "oversized": "x" * (control_ipc.CONTROL_RESPONSE_MAX_BYTES + 1024),
        }
        bounded = await asyncio.to_thread(
            control_ipc.request_control,
            port,
            {"cmd": "status"},
            timeout=4.0,
            secret=daemon._control_secret,
        )
        assert bounded == {
            "ok": False,
            "error": "control response exceeds byte limit",
        }
    finally:
        server.close()
        await server.wait_closed()


def test_signed_response_encoder_never_emits_oversized_frame():
    secret = _secret()
    request_bytes = b'{"cmd":"status"}'
    exchange = control_ipc.ControlExchange("c", "s", request_bytes)
    frame = control_ipc.encode_server_response(
        {"ok": True, "data": "x" * (control_ipc.CONTROL_RESPONSE_MAX_BYTES + 1)},
        secret,
        exchange,
    )

    assert len(frame) <= control_ipc.CONTROL_RESPONSE_MAX_BYTES
    envelope = json.loads(frame)
    assert envelope["response"]["ok"] is False


def test_signed_response_bound_includes_envelope_overhead():
    """A body just under the cap must not turn into an oversized signed line."""

    secret = _secret()
    exchange = control_ipc.ControlExchange("c", "s", b'{"cmd":"status"}')
    # This nested body is below the public limit by itself, while the protocol
    # metadata + HMAC + JSON keys push the complete wire frame above it.
    body = {"ok": True, "data": "x" * (control_ipc.CONTROL_RESPONSE_MAX_BYTES - 64)}

    frame = control_ipc.encode_server_response(body, secret, exchange)

    assert len(frame) <= control_ipc.CONTROL_RESPONSE_MAX_BYTES
    envelope = json.loads(frame)
    assert envelope["response"] == {
        "ok": False,
        "error": "control response exceeds byte limit",
    }


def test_request_encoder_and_tail_backpressure_are_bounded():
    secret = _secret()
    nonce = control_ipc._b64u(b"n" * control_ipc.CONTROL_NONCE_BYTES)
    with pytest.raises(control_ipc.ControlFrameTooLarge):
        control_ipc.make_client_request(
            {"cmd": "send", "body": "x" * control_ipc.CONTROL_REQUEST_MAX_BYTES},
            secret,
            client_nonce=nonce,
            server_nonce=nonce,
        )

    class _Transport:
        @staticmethod
        def get_write_buffer_size():
            return control_ipc.CONTROL_TAIL_MAX_PENDING_BYTES

    class _SlowWriter:
        transport = _Transport()

        def __init__(self):
            self.closed = False
            self.writes: list[bytes] = []

        def close(self):
            self.closed = True

        def write(self, value):
            self.writes.append(value)

    daemon = Daemon(_identity())
    writer = _SlowWriter()
    daemon._tail_subs.add(writer)  # type: ignore[arg-type]
    daemon._broadcast_tail({"t": "TEXT", "body": "bounded"})

    assert writer.closed is True
    assert writer.writes == []
    assert writer not in daemon._tail_subs


@pytest.mark.asyncio
async def test_control_reply_write_is_deadline_bounded(monkeypatch):
    class _StalledWriter:
        def __init__(self):
            self.writes: list[bytes] = []

        def write(self, value):
            self.writes.append(value)

        async def drain(self):
            await asyncio.Event().wait()

    daemon = Daemon(_identity())
    daemon._control_secret = _secret()
    writer = _StalledWriter()
    daemon._control_response_contexts[writer] = control_ipc.ControlExchange(
        "c",
        "s",
        b'{"cmd":"status"}',
    )
    monkeypatch.setattr(control_ipc, "CONTROL_RESPONSE_WRITE_TIMEOUT_S", 0.01)

    with pytest.raises(asyncio.TimeoutError):
        await daemon._reply(writer, {"ok": True})

    assert writer.writes


class _SpoofProofHandler(BaseHTTPRequestHandler):
    authorization_headers: list[str | None] = []

    def do_GET(self):  # noqa: N802 - stdlib handler contract
        type(self).authorization_headers.append(self.headers.get("Authorization"))
        body = json.dumps(
            {
                "ok": True,
                "daemon_instance_id": "forged",
                "pid": 999,
                "ui_server_port": self.server.server_port,
                "source_fingerprint": "forged",
                "proof": "00" * 32,
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


class _RealProofHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    secret = ""
    token = ""
    status: dict = {}
    client_ports: list[int] = []
    authorization_headers: list[str | None] = []
    request_paths: list[str] = []

    def do_GET(self):  # noqa: N802 - stdlib handler contract
        parsed = urllib.parse.urlsplit(self.path)
        type(self).request_paths.append(parsed.path)
        type(self).client_ports.append(int(self.client_address[1]))
        type(self).authorization_headers.append(self.headers.get("Authorization"))
        if parsed.path == "/api/local-instance-proof":
            challenge = urllib.parse.parse_qs(parsed.query).get("challenge", [""])[0]
            body = {
                "ok": True,
                "daemon_instance_id": self.status["daemon_instance_id"],
                "pid": self.status["pid"],
                "ui_server_port": self.server.server_port,
                "source_fingerprint": self.status["source_fingerprint"],
                "proof": control_ipc.make_ui_instance_proof(
                    self.secret,
                    challenge=challenge,
                    instance_id=self.status["daemon_instance_id"],
                    pid=self.status["pid"],
                    port=self.server.server_port,
                    source_fingerprint=self.status["source_fingerprint"],
                ),
            }
            status_code = 200
        elif parsed.path == "/api/runtime-identity":
            status_code = (
                200
                if self.headers.get("Authorization") == f"Bearer {self.token}"
                else 401
            )
            body = dict(self.status) if status_code == 200 else {"error": "unauthorized"}
        else:
            status_code = 404
            body = {"error": "not found"}
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


def test_launcher_never_sends_ui_bearer_to_spoofed_reported_port(monkeypatch):
    fake = ThreadingHTTPServer(("127.0.0.1", 0), _SpoofProofHandler)
    thread = threading.Thread(target=fake.serve_forever, daemon=True)
    thread.start()
    commands: list[str] = []
    _SpoofProofHandler.authorization_headers.clear()
    try:
        port = fake.server_port
        status = {
            "ok": True,
            "pid": 41,
            "daemon_instance_id": "real-instance",
            "app_version": app_mod.__version__,
            "source_fingerprint": app_mod.runtime_build_identity()["source_fingerprint"],
            "protocol_version": "OL1.2",
            "schema_version": 1,
            "ui_server_port": port,
            "me": {"fingerprint": "aa" * 32},
        }
        monkeypatch.setattr(
            app_mod.daemon_mod,
            "read_control_port",
            lambda clear_stale=False: 54321,
        )
        monkeypatch.setattr(app_mod, "_alive", lambda _port, **_kwargs: True)
        monkeypatch.setattr(app_mod.control_ipc, "read_control_secret", lambda: _secret())

        def control_request(_port, cmd, **_kwargs):
            commands.append(cmd)
            if cmd == "status":
                return status
            raise AssertionError("launcher requested owner credential before UI proof")

        monkeypatch.setattr(app_mod, "_control_request", control_request)
        monkeypatch.setattr(
            app_mod,
            "_ui_status_on_verified_connection",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("owner bearer was sent to spoofed UI")
            ),
        )

        assert app_mod._resolve_running_daemon() is None
        assert commands == ["status"]
        assert _SpoofProofHandler.authorization_headers == [None]
    finally:
        fake.shutdown()
        fake.server_close()
        thread.join(timeout=2.0)


def test_launcher_sends_bearer_only_on_same_authenticated_ui_connection(monkeypatch):
    secret = _secret(b"p")
    token = "t" * 43
    build_fp = app_mod.runtime_build_identity()["source_fingerprint"]
    status = {
        "ok": True,
        "pid": 4141,
        "daemon_instance_id": "real-instance",
        "app_version": app_mod.__version__,
        "source_fingerprint": build_fp,
        "protocol_version": "OL1.2",
        "schema_version": 1,
        "me": {"fingerprint": "aa" * 32},
    }
    _RealProofHandler.secret = secret
    _RealProofHandler.token = token
    _RealProofHandler.status = status
    _RealProofHandler.client_ports.clear()
    _RealProofHandler.authorization_headers.clear()
    _RealProofHandler.request_paths.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RealProofHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    commands: list[str] = []
    try:
        status["ui_server_port"] = server.server_port
        monkeypatch.setattr(
            app_mod.daemon_mod,
            "read_control_port",
            lambda clear_stale=False: 54321,
        )
        monkeypatch.setattr(app_mod, "_alive", lambda _port, **_kwargs: True)
        monkeypatch.setattr(app_mod.control_ipc, "read_control_secret", lambda: secret)

        def control_request(_port, cmd, **_kwargs):
            commands.append(cmd)
            if cmd == "status":
                return dict(status)
            if cmd == "ui_launch_info":
                return {
                    "ok": True,
                    "ui_server_port": server.server_port,
                    "token": token,
                    "daemon_instance_id": status["daemon_instance_id"],
                    "pid": status["pid"],
                    "source_fingerprint": build_fp,
                }
            raise AssertionError(cmd)

        monkeypatch.setattr(app_mod, "_control_request", control_request)

        resolved = app_mod._resolve_running_daemon()

        assert resolved is not None
        assert resolved.token == token
        assert commands == ["status", "ui_launch_info"]
        assert _RealProofHandler.authorization_headers == [None, f"Bearer {token}"]
        assert len(set(_RealProofHandler.client_ports)) == 1
        assert _RealProofHandler.request_paths == [
            "/api/local-instance-proof", "/api/runtime-identity",
        ]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


class _RemoteRequest:
    def __init__(self, *, scheme: str, ssl_object=None):
        self.scheme = scheme
        self.cookies = {COOKIE_NAME: "owner-token"}
        self.headers = {"Authorization": "Bearer owner-token"}
        self.remote = "192.168.1.50"
        self.transport = SimpleNamespace(get_extra_info=lambda name: {
            "peername": ("192.168.1.50", 50000),
            "ssl_object": ssl_object,
        }.get(name))


def test_remote_plain_http_cannot_use_owner_bearer_or_session():
    server = object.__new__(UIServer)
    server.token = "owner-token"
    server.daemon = SimpleNamespace(state=None)

    assert server._check_token(_RemoteRequest(scheme="http")) is False
    # A spoofed URL scheme is not TLS authority.
    assert server._check_token(_RemoteRequest(scheme="https")) is False

    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_object = context.wrap_bio(
        ssl.MemoryBIO(),
        ssl.MemoryBIO(),
        server_hostname="localhost",
    )
    assert server._check_token(
        _RemoteRequest(scheme="https", ssl_object=tls_object)
    ) is True

    class _StateMustNotBeTouched:
        def __getattr__(self, _name):
            raise AssertionError("remote HTTP session lookup reached state storage")

    session_request = _RemoteRequest(scheme="http")
    session_request.cookies = {
        COOKIE_NAME: "wrong-owner-token",
        SESSION_COOKIE_NAME: "a" * 36,
    }
    server.daemon = SimpleNamespace(state=_StateMustNotBeTouched())
    assert server._check_token(session_request) is False


def test_loopback_unicode_owner_credentials_fail_without_type_error():
    server = object.__new__(UIServer)
    server.token = "owner-token"
    server.daemon = SimpleNamespace(state=None)
    request = _RemoteRequest(scheme="http")
    request.remote = "127.0.0.1"
    request.transport = SimpleNamespace(
        get_extra_info=lambda _name: ("127.0.0.1", 50000)
    )
    request.cookies = {COOKIE_NAME: "owner-tokén"}
    request.headers = {"Authorization": "Bearer owner-tokén"}

    assert server._check_token(request) is False


def test_lan_connect_metadata_never_exports_owner_bearer(monkeypatch):
    server = object.__new__(UIServer)
    server.token = "owner-token-that-must-stay-local"
    server.bind_host = "0.0.0.0"
    server.port = 7117
    monkeypatch.setattr("one_link.server._detect_lan_ip", lambda: "192.168.1.25")

    info = server._connect_info()

    assert info["lan_bound"] is True
    assert info["requires_short_lived_invite"] is True
    assert info["token"] is None
    assert info["lan_url"] == "http://192.168.1.25:7117/connect"
    assert server.token not in json.dumps(info)


def test_server_source_defaults_to_loopback_and_cli_lan_is_opt_in():
    import inspect
    from one_link import cli as cli_mod
    from one_link import server as server_mod

    start_source = inspect.getsource(server_mod.UIServer.start)
    assert 'or "127.0.0.1"' in start_source
    option = next(param for param in cli_mod.app.params if param.name == "lan")
    assert option.default is False


def test_legacy_daemon_replacement_requires_absent_secret_and_verified_process(
    monkeypatch,
    tmp_path,
):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(app_mod, "data_dir", lambda: data)
    monkeypatch.setattr(app_mod, "_lock_pid", lambda: 4242)
    monkeypatch.setattr(app_mod.daemon_mod, "_pid_is_alive", lambda pid: pid == 4242)
    monkeypatch.setattr(
        app_mod.daemon_mod,
        "_pid_matches_one_link_daemon",
        lambda pid: pid == 4242,
    )
    terminated: list[int] = []
    monkeypatch.setattr(
        app_mod,
        "_terminate_pid",
        lambda pid: terminated.append(pid) or True,
    )

    assert app_mod._stop_verified_legacy_daemon() is True
    assert terminated == [4242]

    # Once an authenticated-control root exists, corruption/authentication
    # failure must never be bypassed through PID termination.
    (data / control_ipc.CONTROL_SECRET_FILE).write_text("corrupt", encoding="ascii")
    terminated.clear()
    assert app_mod._stop_verified_legacy_daemon() is None
    assert terminated == []

    (data / control_ipc.CONTROL_SECRET_FILE).unlink()
    monkeypatch.setattr(
        app_mod.daemon_mod,
        "_pid_matches_one_link_daemon",
        lambda _pid: False,
    )
    assert app_mod._stop_verified_legacy_daemon() is None
    assert terminated == []


def test_authenticated_daemon_stop_never_falls_back_to_untrusted_lock_pid(monkeypatch):
    info = app_mod.RunningDaemon(
        control_port=41000,
        server_port=7117,
        token="t" * 43,
        status={"ok": False},
    )
    monkeypatch.setattr(
        app_mod,
        "_lock_pid",
        lambda: (_ for _ in ()).throw(AssertionError("untrusted lock PID read")),
    )
    monkeypatch.setattr(
        app_mod,
        "_terminate_pid",
        lambda _pid: (_ for _ in ()).throw(AssertionError("untrusted PID killed")),
    )

    assert app_mod._stop_running_daemon(info) is False


def test_authenticated_daemon_stop_revalidates_process_before_force(monkeypatch):
    info = app_mod.RunningDaemon(
        control_port=41000,
        server_port=7117,
        token="t" * 43,
        status={"ok": True, "pid": 4242},
    )
    monkeypatch.setattr(app_mod, "_control_request", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(app_mod, "_alive", lambda *_args, **_kwargs: True)
    ticks = iter((100.0, 107.0))
    monkeypatch.setattr(
        app_mod,
        "time",
        SimpleNamespace(time=lambda: next(ticks), sleep=lambda _seconds: None),
    )
    monkeypatch.setattr(
        app_mod.daemon_mod,
        "_pid_matches_one_link_daemon",
        lambda _pid: False,
    )
    monkeypatch.setattr(
        app_mod,
        "_terminate_pid",
        lambda _pid: (_ for _ in ()).throw(AssertionError("unverified PID killed")),
    )

    assert app_mod._stop_running_daemon(info) is False
