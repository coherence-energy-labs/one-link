"""HTTP + WebSocket UI server tests.

Spins up a real daemon (which auto-starts the UI server alongside) and
hits the API surface with `aiohttp` (already a project dep). Verifies
auth, peer list, send, file upload, file list, file download, and the
WS event stream.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest

from tests.harness import daemon_pair


pytestmark = pytest.mark.timeout(120)


def _read(home: Path, name: str, timeout: float = 15.0) -> str:
    """Read a daemon-written status file with a tolerant retry loop.

    The daemon writes server.port / ui.token after the UI HTTP server
    binds — which can race the test harness, especially on Windows under
    load. Retry rather than fail spuriously."""
    p = home / "data" / name
    import time as _time
    end = _time.time() + timeout
    last_err: Exception | None = None
    while _time.time() < end:
        try:
            txt = p.read_text(encoding="utf-8").strip()
            if txt:
                return txt
        except (FileNotFoundError, OSError) as e:
            last_err = e
        _time.sleep(0.05)
    if last_err is not None:
        raise last_err
    raise FileNotFoundError(p)


def _server_addr(home: Path) -> tuple[str, str]:
    port = _read(home, "server.port")
    token = _read(home, "ui.token")
    return f"http://127.0.0.1:{port}", token


class _FakeReq:
    """Minimal aiohttp.web.Request stand-in for unit tests of API
    handlers that read `.query`. Real handlers receive a real
    aiohttp Request; tests historically passed `None`, which broke
    once handlers started reading query params.
    """

    def __init__(self, **query):
        self.query = {k: str(v) for k, v in query.items()}
        self.match_info: dict[str, str] = {}


class _FakePart:
    def __init__(
        self, name: str, *, text: str | None = None,
        data: bytes | None = None, filename: str | None = None,
    ):
        self.name = name
        self.filename = filename
        self._text = text
        self._data = data or b""
        self._offset = 0

    async def text(self) -> str:
        return self._text or ""

    async def read_chunk(self, size: int = 8192) -> bytes:
        if self._offset >= len(self._data):
            return b""
        out = self._data[self._offset:self._offset + size]
        self._offset += len(out)
        return out


class _FakeMultipart:
    def __init__(self, parts):
        self._parts = list(parts)

    def __aiter__(self):
        self._iter = iter(self._parts)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


class _FakeMultipartReq:
    content_type = "multipart/form-data; boundary=test"

    def __init__(self, parts):
        self._parts = parts
        # Conservative multipart upper bound used by the production upload
        # reservation gate. Exact framing is irrelevant to this test double;
        # it only needs to be no smaller than its file payloads.
        self.content_length = 512 + sum(
            len(getattr(part, "_data", b""))
            + len((getattr(part, "_text", None) or "").encode("utf-8"))
            for part in parts
        )

    async def multipart(self):
        return _FakeMultipart(self._parts)


@pytest.mark.asyncio
async def test_api_peers_hides_offline_pending_ghosts(tmp_path: Path):
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        me_fp = "aa" * 32
        state.upsert_peer(
            fingerprint=me_fp,
            short_id="aaaaaaaa",
            pubkey=b"\xaa" * 32,
            trust_default="pinned",
        )
        state.upsert_peer(
            fingerprint="bb" * 32,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            hostname="WeareOne",
            address="192.168.1.142",
            port=50000,
        )
        state.upsert_peer(
            fingerprint="cc" * 32,
            short_id="cccccccc",
            pubkey=b"\xcc" * 32,
            hostname="PairedBox",
            trust_default="pinned",
        )

        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint=me_fp, short_id="aaaaaaaa", hostname="me"),
        )
        server = UIServer(daemon)
        # Default: paired only — pending ghost should be filtered, pinned remains.
        resp = await server.api_peers(_FakeReq())
        body = json.loads(resp.text)
        short_ids = {p["short_id"] for p in body["peers"]}

        assert "bbbbbbbb" not in short_ids
        assert "cccccccc" in short_ids
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_filters_live_self_advertisements(tmp_path: Path):
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        me_fp = "aa" * 32
        live_self = SimpleNamespace(
            short_id="aaaaaaaa",
            hostname="I am One",
            address="192.168.1.10",
            port=50000,
            ed_pub_hex=("11" * 32),
        )
        live_other = SimpleNamespace(
            short_id="bbbbbbbb",
            hostname="Kitchen Laptop",
            address="192.168.1.11",
            port=50001,
            ed_pub_hex=("22" * 32),
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=SimpleNamespace(
                registry=SimpleNamespace(list=lambda: [live_self, live_other])
            ),
            me=SimpleNamespace(fingerprint=me_fp, short_id="aaaaaaaa", hostname="I am One"),
        )

        server = UIServer(daemon)
        # Live unpaired peers only show up in modal mode (?include_unpaired=1).
        resp = await server.api_peers(_FakeReq(include_unpaired=1))
        body = json.loads(resp.text)
        short_ids = {p["short_id"] for p in body["peers"]}

        assert "aaaaaaaa" not in short_ids
        assert "bbbbbbbb" in short_ids
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_collapses_same_host_pending_ghosts(tmp_path: Path):
    """v0.4 contract: when multiple pending peers advertise one of *our*
    hostnames, only the freshest survives in the modal. The user sees
    one entry instead of N stale daemon-instance ghosts."""
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        state.set_setting("display_name", "I am One")
        live_local_1 = SimpleNamespace(
            short_id="11111111",
            hostname="WeareOne",
            address="",
            port=0,
            ed_pub_hex=("11" * 32),
        )
        live_local_2 = SimpleNamespace(
            short_id="22222222",
            hostname="WeareOne",
            address="192.168.1.10",
            port=50001,
            ed_pub_hex=("22" * 32),
        )
        live_other = SimpleNamespace(
            short_id="33333333",
            hostname="Kitchen Laptop",
            address="192.168.1.11",
            port=50002,
            ed_pub_hex=("33" * 32),
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=SimpleNamespace(
                registry=SimpleNamespace(list=lambda: [live_local_1, live_local_2, live_other])
            ),
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="WeareOne"),
        )

        server = UIServer(daemon)
        resp = await server.api_peers(_FakeReq(include_unpaired=1))
        body = json.loads(resp.text)
        peers = {p["short_id"]: p for p in body["peers"]}

        # Only the freshest (with address+port) of the same-host pair survives.
        assert "22222222" in peers
        assert "11111111" not in peers
        # Off-host peer is untouched.
        assert "33333333" in peers
        assert peers["33333333"]["same_host"] is False
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_default_returns_paired_only(tmp_path: Path):
    """v0.4 contract — sidebar feed: only trust='pinned' peers come back
    by default. Pending mDNS hits, rejected peers, offline ghosts: all
    excluded unless the modal explicitly asks for them."""
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        me_fp = "aa" * 32
        # A paired peer (offline — only in DB).
        state.upsert_peer(
            fingerprint="bb" * 32,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            hostname="HomeMac",
            trust_default="pinned",
        )
        # A rejected peer (offline — only in DB).
        state.upsert_peer(
            fingerprint="cc" * 32,
            short_id="cccccccc",
            pubkey=b"\xcc" * 32,
            hostname="BlockedBox",
        )
        state.set_peer_trust("cc" * 32, "rejected")

        # A live, unpaired mDNS hit.
        live_unpaired = SimpleNamespace(
            short_id="33333333",
            hostname="OfficeLaptop",
            address="192.168.1.50",
            port=50000,
            ed_pub_hex="33" * 32,
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=SimpleNamespace(
                registry=SimpleNamespace(list=lambda: [live_unpaired])
            ),
            me=SimpleNamespace(fingerprint=me_fp, short_id="aaaaaaaa", hostname="me"),
        )

        server = UIServer(daemon)
        resp = await server.api_peers(_FakeReq())
        body = json.loads(resp.text)
        ids = {p["short_id"] for p in body["peers"]}

        assert ids == {"bbbbbbbb"}  # paired only
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_modal_mode_includes_live_unpaired(tmp_path: Path):
    """v0.4 contract — modal feed: include_unpaired=1 returns paired
    devices (top of list) plus live unpaired mDNS hits (bottom).
    Offline pending DB rows are still hidden — those are stale."""
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        me_fp = "aa" * 32
        state.upsert_peer(
            fingerprint="bb" * 32,
            short_id="bbbbbbbb",
            pubkey=b"\xbb" * 32,
            hostname="HomeMac",
            trust_default="pinned",
        )
        # Stale offline-pending row (would have been a ghost).
        state.upsert_peer(
            fingerprint="dd" * 32,
            short_id="dddddddd",
            pubkey=b"\xdd" * 32,
            hostname="GhostBox",
        )

        live_unpaired = SimpleNamespace(
            short_id="33333333",
            hostname="OfficeLaptop",
            address="192.168.1.50",
            port=50000,
            ed_pub_hex="33" * 32,
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=SimpleNamespace(
                registry=SimpleNamespace(list=lambda: [live_unpaired])
            ),
            me=SimpleNamespace(fingerprint=me_fp, short_id="aaaaaaaa", hostname="me"),
        )

        server = UIServer(daemon)
        resp = await server.api_peers(_FakeReq(include_unpaired=1))
        body = json.loads(resp.text)
        peers = body["peers"]
        ids = [p["short_id"] for p in peers]

        # Paired comes first; live unpaired included; stale pending excluded.
        assert "bbbbbbbb" in ids
        assert "33333333" in ids
        assert "dddddddd" not in ids
        # Sort order — paired first.
        assert ids[0] == "bbbbbbbb"
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_peers_excludes_rejected_unless_explicitly_asked(tmp_path: Path):
    """v0.4 contract — rejected peers are only visible with
    ?include_rejected=1, even in modal mode."""
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_peer(
            fingerprint="cc" * 32,
            short_id="cccccccc",
            pubkey=b"\xcc" * 32,
            hostname="BlockedBox",
        )
        state.set_peer_trust("cc" * 32, "rejected")

        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa", hostname="me"),
        )
        server = UIServer(daemon)

        # Default: rejected hidden.
        resp = await server.api_peers(_FakeReq())
        ids = {p["short_id"] for p in json.loads(resp.text)["peers"]}
        assert "cccccccc" not in ids

        # Modal: still hidden.
        resp = await server.api_peers(_FakeReq(include_unpaired=1))
        ids = {p["short_id"] for p in json.loads(resp.text)["peers"]}
        assert "cccccccc" not in ids

        # Explicit opt-in: visible.
        resp = await server.api_peers(_FakeReq(include_rejected=1))
        ids = {p["short_id"] for p in json.loads(resp.text)["peers"]}
        assert "cccccccc" in ids
    finally:
        state.close()


@pytest.mark.asyncio
async def test_api_status_and_transfers_surface_ledger(tmp_path: Path):
    from one_link.server import UIServer
    from one_link.state import State

    state = State(db_path=tmp_path / "state.db")
    try:
        state.upsert_transfer(
            id="t1",
            direction="in",
            peer_fp="aa" * 32,
            kind="file",
            name="photo.png",
            size=100,
            status="active",
            progress_bytes=50,
            total_bytes=100,
            chunks_done=1,
            chunks_total=2,
            metadata={
                "manifest": {
                    "name": "photo.png",
                    "size": 100,
                    "blob": "bb" * 32,
                    "chunks": [
                        {"index": 0, "start": 0, "end": 50, "hash": "a"},
                        {"index": 1, "start": 50, "end": 100, "hash": "b"},
                    ],
                },
                "autopilot_plan": {"frame_kind": "cdc_binary"},
                "performance_summary": {
                    "effective_mbps": 420.0,
                    "bandwidth_savings_ratio": 0.5,
                    "route": "lan",
                },
            },
        )
        daemon = SimpleNamespace(
            state=state,
            discovery=None,
            me=SimpleNamespace(fingerprint="ff" * 32, short_id="ffffffff", hostname="me"),
            _session_stats=lambda: {"open": 0, "sessions": []},
            _chunk_cache_stats=lambda: {"chunks": 0, "bytes": 0},
            _transfer_autopilot_stats=lambda: {"engines": {}, "routes": [], "route_count": 0},
        )
        server = UIServer(daemon)

        transfers_resp = await server.api_transfers(SimpleNamespace(query={}))
        transfers = json.loads(transfers_resp.text)["transfers"]
        assert transfers[0]["id"] == "t1"
        assert transfers[0]["progress_pct"] == 50.0
        assert transfers[0]["metadata"]["manifest"]["chunk_count"] == 2
        assert "chunks" not in transfers[0]["metadata"]["manifest"]
        assert transfers[0]["metadata"]["autopilot_plan"]["frame_kind"] == "cdc_binary"
        assert transfers[0]["autopilot_truth"]["speed_mbps"] == 420.0
        assert "50% already known" in transfers[0]["autopilot_truth"]["facts"]
        assert "Using fast binary path" in transfers[0]["autopilot_truth"]["facts"]
        assert "Route: Wi-Fi direct" in transfers[0]["autopilot_truth"]["facts"]

        status_resp = await server.api_status(None)
        status = json.loads(status_resp.text)
        assert status["transfers"]["active"] == 1
        assert status["performance"]["sessions"]["open"] == 0
        assert status["performance"]["transfer_autopilot"]["route_count"] == 0

        delete_resp = await server.api_delete_transfer(
            SimpleNamespace(match_info={"transfer_id": "t1"})
        )
        assert json.loads(delete_resp.text)["deleted"] is True
        assert state.list_transfers() == []

        state.upsert_transfer(
            id="t2",
            direction="out",
            peer_fp="aa" * 32,
            kind="file",
            name="done.bin",
            size=1,
            status="complete",
            progress_bytes=1,
        )
        async def _prune_json():
            return {"keep_latest": 0}
        prune_req = SimpleNamespace(json=_prune_json)
        prune_resp = await server.api_prune_transfers(prune_req)
        assert json.loads(prune_resp.text)["removed"] == 1
    finally:
        state.close()


# ─── helpers ──────────────────────────────────────────────────────────

async def _get(session, url, *, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with session.get(url, headers=headers) as r:
        return r.status, await r.text()


async def _get_json(session, url, *, token=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    async with session.get(url, headers=headers) as r:
        return r.status, await r.json()


async def _post_json(session, url, payload, *, token=None):
    headers = {"Authorization": f"Bearer {token}"}
    async with session.post(url, json=payload, headers=headers) as r:
        return r.status, await r.json()


# ─── tests ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_server_unauth_returns_401():
    with daemon_pair() as p:
        base, _token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, _ = await _get(s, f"{base}/api/me")
            assert status == 401


@pytest.mark.asyncio
async def test_server_index_serves_html_and_scopes_browser_bearer_to_origin():
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/?t={token}") as r:
                assert r.status == 200
                txt = await r.text()
                assert "<!doctype html>" in txt.lower() or "<html" in txt.lower()
                capture = txt.index("sessionStorage.setItem('ol_session_token',b)")
                scrub = txt.index("history.replaceState")
                assert capture < scrub
                assert 'localStorage.setItem("ol_session_token"' not in txt
                assert token not in txt
                assert all(c["max-age"] == "0" for c in r.cookies.values())
                # Credential-bearing bootstrap responses are never cached.
                # Clean-URL reloads below retain ETag revalidation.
                assert r.headers.get("Cache-Control") == "no-store"
                assert r.headers.get("ETag", "").startswith('"')


@pytest.mark.asyncio
async def test_server_index_returns_304_on_matching_etag():
    """Conditional GET with a matching If-None-Match must return
    304 (no body) so unchanged content costs zero bandwidth on
    every reload. Without this the ETag is decoration."""
    with daemon_pair() as p:
        base, _token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/") as r:
                etag = r.headers.get("ETag")
                assert etag
            async with s.get(
                f"{base}/",
                headers={"If-None-Match": etag},
            ) as r:
                assert r.status == 304
                assert r.headers.get("ETag") == etag


@pytest.mark.asyncio
async def test_server_bootstrap_ignores_matching_etag_and_mints_origin_session():
    """A cached public shell must not turn a credential bootstrap into 304."""
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/") as r:
                etag = r.headers.get("ETag")
                assert etag
            async with s.get(
                f"{base}/?t={token}",
                headers={"If-None-Match": etag},
            ) as r:
                assert r.status == 200
                assert r.headers.get("Cache-Control") == "no-store"
                assert all(c["max-age"] == "0" for c in r.cookies.values())
                assert "ol_persistent_session_token" in await r.text()


@pytest.mark.asyncio
async def test_stale_index_token_never_mints_loopback_owner_credentials():
    with daemon_pair() as p:
        base, _token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base}/?t=abc",
                headers={
                    "Accept": "text/html",
                    "Sec-Fetch-Dest": "document",
                },
            ) as r:
                assert r.status == 401
                txt = await r.text()
                assert "Access denied" in txt
                assert "could not authenticate this tab" in txt
                assert all(c["max-age"] == "0" for c in r.cookies.values())
                assert r.headers.get("Cache-Control") == "no-store"


@pytest.mark.asyncio
async def test_stale_index_token_still_rejects_subresource_request():
    with daemon_pair() as p:
        base, _token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base}/?t=abc",
                headers={
                    "Accept": "image/avif,image/webp,*/*",
                    "Sec-Fetch-Dest": "image",
                },
            ) as r:
                assert r.status == 401
                assert await r.text() == "unauthorized"


@pytest.mark.asyncio
async def test_local_document_reopen_without_query_token_sets_no_cookie():
    with daemon_pair() as p:
        base, _token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base}/",
                headers={
                    "Accept": "text/html",
                    "Sec-Fetch-Dest": "document",
                },
            ) as r:
                assert r.status == 200
                assert all(c["max-age"] == "0" for c in r.cookies.values())
                # 2026-05-23: cache header is now no-cache+revalidate
                # + ETag (same as bootstrap path). Bullet-proof cache
                # busting for the desktop UI bundle.
                assert r.headers.get("Cache-Control") == "no-cache, must-revalidate"
                assert r.headers.get("ETag", "").startswith('"')


@pytest.mark.asyncio
async def test_query_token_only_bootstraps_index_not_api():
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/") as r:
                assert r.status == 200
                assert all(c["max-age"] == "0" for c in r.cookies.values())

        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/?t={token}") as r:
                assert r.status == 200
                txt = await r.text()
                assert "history.replaceState" in txt
                assert all(c["max-age"] == "0" for c in r.cookies.values())
                assert token not in txt

        async with aiohttp.ClientSession() as s:
            async with s.get(f"{base}/api/me?t={token}") as r:
                assert r.status == 401


@pytest.mark.asyncio
async def test_api_me_returns_identity():
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base}/api/me", token=token)
            assert status == 200
            assert j["short_id"] == p.a.short_id
            assert "fingerprint" in j
            assert "hostname" in j


@pytest.mark.asyncio
async def test_api_peers_lists_other_peer():
    """The two paired daemons spun up by `daemon_pair()` have not gone
    through the SAS pairing flow, so the discovered peer is unpaired
    (trust=pending). It must appear under the modal endpoint
    (?include_unpaired=1) but not in the default sidebar feed."""
    with daemon_pair() as p:
        base, token = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            # Default: paired-only — should NOT contain the unpaired peer.
            status, j = await _get_json(s, f"{base}/api/peers", token=token)
            assert status == 200
            assert p.b.short_id not in {pp["short_id"] for pp in j["peers"]}

            # Modal: should contain it.
            status, j = await _get_json(
                s, f"{base}/api/peers?include_unpaired=1", token=token
            )
            assert status == 200
            assert p.b.short_id in {pp["short_id"] for pp in j["peers"]}


@pytest.mark.asyncio
async def test_api_send_text_round_trip():
    with daemon_pair(pin_trust=True) as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(
                s,
                f"{base_a}/api/send",
                {"peer": p.b.short_id, "body": "hi via api"},
                token=tok_a,
            )
            assert status == 200, j
            assert j["ok"] is True

        # Verify B received it (give the daemon a moment)
        await asyncio.sleep(0.5)
        from tests.harness import message_log
        bodies = [
            m.get("body")
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        ]
        assert "hi via api" in bodies, bodies


@pytest.mark.asyncio
async def test_api_send_to_unknown_peer_404():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(
                s, f"{base_a}/api/send",
                {"peer": "zzzzzzzz", "body": "hi"},
                token=tok_a,
            )
            assert status == 404
            assert "no peer" in j["error"].lower()


@pytest.mark.asyncio
async def test_api_send_missing_fields_400():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(s, f"{base_a}/api/send", {}, token=tok_a)
            assert status == 400


@pytest.mark.asyncio
async def test_api_send_file_round_trip(tmp_path: Path):
    with daemon_pair(pin_trust=True) as p:
        base_a, tok_a = _server_addr(p.a.home)
        # Build a real uploaded file
        sample = tmp_path / "via_api.bin"
        payload = os.urandom(123_456)
        sample.write_bytes(payload)

        form = aiohttp.FormData()
        form.add_field("peer", p.b.short_id)
        form.add_field(
            "file", payload, filename="via_api.bin",
            content_type="application/octet-stream",
        )
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{base_a}/api/send-file", data=form,
                headers={"Authorization": f"Bearer {tok_a}"},
            ) as r:
                assert r.status == 200, await r.text()
                j = await r.json()
                assert j["ok"] is True

        await asyncio.sleep(1.0)
        inbox = list((p.b.home / "data" / "inbox").iterdir())
        match = [f for f in inbox if "via_api.bin" in f.name]
        assert match, f"file not in B inbox: {inbox}"
        assert match[0].read_bytes() == payload


@pytest.mark.asyncio
async def test_api_send_file_sanitizes_uploaded_filename():
    with daemon_pair(pin_trust=True) as p:
        base_a, tok_a = _server_addr(p.a.home)
        payload = b"safe upload name"

        form = aiohttp.FormData()
        form.add_field("peer", p.b.short_id)
        form.add_field(
            "file", payload, filename="../evil.bin",
            content_type="application/octet-stream",
        )
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{base_a}/api/send-file", data=form,
                headers={"Authorization": f"Bearer {tok_a}"},
            ) as r:
                assert r.status == 200, await r.text()

        await asyncio.sleep(1.0)
        inbox = p.b.home / "data" / "inbox"
        files = list(inbox.iterdir())
        match = [f for f in files if f.name.endswith("evil.bin")]
        assert match, files
        assert all(f.parent == inbox for f in files)
        assert not (p.b.home / "data" / "evil.bin").exists()


@pytest.mark.asyncio
async def test_api_send_file_paused_keeps_staged_upload(tmp_path: Path, monkeypatch):
    """A transient send failure should become HTTP 202 + durable staged
    bytes, not a 500 followed by deleting the only upload copy."""
    from one_link.daemon import TransferPausedError
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    seen_paths: list[Path] = []

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        async def resolve_for_send(self, needle):
            return SimpleNamespace(short_id=str(needle))

        async def send_file(self, peer, path, *, transfer_id=None, rel_path=None, extra_metadata=None, **_kwargs):
            seen_paths.append(Path(path))
            raise TransferPausedError(
                "network dropped", transfer_id="t-paused", path=Path(path),
            )

    server = UIServer(_Daemon())
    resp = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"keep me", filename="resume.bin"),
    ]))
    body = json.loads(resp.text)
    assert resp.status == 202
    assert body["paused"] is True
    assert body["transfer_id"] == "t-paused"
    assert seen_paths and seen_paths[0].is_file()
    assert seen_paths[0].read_bytes() == b"keep me"


@pytest.mark.asyncio
async def test_api_send_file_missing_peer_cleans_staging_and_reservation(
    tmp_path: Path, monkeypatch,
):
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

    server = UIServer(_Daemon())
    response = await server.api_send_file(_FakeMultipartReq([
        _FakePart("file", data=b"must be removed", filename="orphan.bin"),
    ]))

    assert response.status == 400
    assert not list((tmp_path / "uploads").glob("*"))
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_api_send_file_rejects_multiple_file_parts_without_leak(
    tmp_path: Path, monkeypatch,
):
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

    server = UIServer(_Daemon())
    response = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"one", filename="one.bin"),
        _FakePart("file", data=b"two", filename="two.bin"),
    ]))

    assert response.status == 400
    assert not list((tmp_path / "uploads").glob("*"))
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_api_send_file_bounds_metadata_before_staging(
    tmp_path: Path, monkeypatch,
):
    from one_link.server import UI_UPLOAD_METADATA_LIMITS, UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

    oversized_peer = "p" * (UI_UPLOAD_METADATA_LIMITS["peer"] + 1)
    server = UIServer(_Daemon())
    response = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text=oversized_peer),
        _FakePart("file", data=b"never staged", filename="bounded.bin"),
    ]))

    assert response.status == 400
    assert not list((tmp_path / "uploads").glob("*"))
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_api_send_file_rejects_ambiguous_boolean_metadata(
    tmp_path: Path, monkeypatch,
):
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

    server = UIServer(_Daemon())
    response = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("chat_inline", text="sometimes"),
        _FakePart("file", data=b"never staged", filename="boolean.bin"),
    ]))

    assert response.status == 400
    assert not list((tmp_path / "uploads").glob("*"))
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_api_send_file_rejects_unknown_or_excess_multipart_parts(
    tmp_path: Path, monkeypatch,
):
    import one_link.server as server_module
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

    unknown_server = UIServer(_Daemon())
    unknown = await unknown_server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("unrecognized", text="ignored historically"),
        _FakePart("file", data=b"never staged", filename="unknown.bin"),
    ]))
    assert unknown.status == 400
    assert unknown_server._upload_reservations.snapshot() == ()

    # Lower the production ceiling so the test proves the counter itself,
    # independently of the stricter duplicate/unknown-field grammar.
    monkeypatch.setattr(server_module, "UI_UPLOAD_MULTIPART_MAX_PARTS", 1)
    excess_server = UIServer(_Daemon())
    excess = await excess_server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"never staged", filename="excess.bin"),
    ]))
    assert excess.status == 400
    assert not list((tmp_path / "uploads").glob("*"))
    assert excess_server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_api_send_file_resolution_failure_removes_staged_upload(
    tmp_path: Path,
    monkeypatch,
):
    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        async def resolve_for_send(self, _needle):
            raise ConnectionError("rendezvous unavailable")

    server = UIServer(_Daemon())
    response = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"must not leak", filename="orphan.bin"),
    ]))

    assert response.status >= 400
    assert not list((tmp_path / "uploads").glob("*"))
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_api_send_file_online_creates_durable_intent_before_send(
    tmp_path: Path, monkeypatch,
):
    """Browser uploads should never be a naked best-effort send.

    The server must stage bytes, create a durable transfer row, then run the
    live transfer against that row so a later network drop can resume instead
    of losing the user's upload.
    """
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="OnlineBox",
        trust_default="pinned",
    )
    queued: list[dict] = []
    sends: list[dict] = []

    class _Daemon:
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        def __init__(self):
            self.state = state

        async def resolve_for_send(self, needle):
            return SimpleNamespace(
                short_id="bbbbbbbb",
                ed_pub_hex=(b"\xbb" * 32).hex(),
            )

        def _peer_fp_from_peer(self, peer):
            return peer_fp

        def queue_file_transfer(
            self, *, peer_fp, path, reason="peer offline", schedule_resume=True,
        ):
            queued.append({
                "peer_fp": peer_fp,
                "path": Path(path),
                "reason": reason,
                "schedule_resume": schedule_resume,
            })
            return self.state.upsert_transfer(
                id="durable-online-1",
                direction="out",
                peer_fp=peer_fp,
                kind="file",
                name=Path(path).name,
                size=Path(path).stat().st_size,
                status="paused",
                progress_bytes=0,
                total_bytes=Path(path).stat().st_size,
                chunks_done=0,
                chunks_total=1,
                metadata={
                    "path": str(path),
                    "delivery_state": "waiting_for_device",
                    "transient": True,
                },
            )

        async def send_file(self, peer, path, *, transfer_id=None, rel_path=None, extra_metadata=None, **_kwargs):
            sends.append({
                "peer": peer.short_id,
                "path": Path(path),
                "transfer_id": transfer_id,
                "exists_during_send": Path(path).is_file(),
            })
            self.state.update_transfer(
                transfer_id,
                status="complete",
                progress_bytes=Path(path).stat().st_size,
            )
            return {"transfer_id": transfer_id}

    server = UIServer(_Daemon())
    resp = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"send me safely", filename="online.bin"),
    ]))
    body = json.loads(resp.text)

    assert resp.status == 200
    assert body["ok"] is True
    assert body["result"]["transfer_id"] == "durable-online-1"
    assert queued and queued[0]["schedule_resume"] is False
    assert sends == [{
        "peer": "bbbbbbbb",
        "path": sends[0]["path"],
        "transfer_id": "durable-online-1",
        "exists_during_send": True,
    }]
    assert queued and queued[0]["path"].is_file() is True
    assert queued[0]["path"].read_bytes() == b"send me safely"
    state.close()


@pytest.mark.asyncio
async def test_api_send_file_ledger_failure_is_503_and_never_calls_send(
    tmp_path: Path,
    monkeypatch,
):
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="LedgerFailBox",
        trust_default="pinned",
    )
    sends: list[Path] = []

    class _Daemon:
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        def __init__(self):
            self.state = state

        async def resolve_for_send(self, _needle):
            return SimpleNamespace(
                short_id="bbbbbbbb",
                ed_pub_hex=(b"\xbb" * 32).hex(),
            )

        def _peer_fp_from_peer(self, _peer):
            return peer_fp

        def queue_file_transfer(self, **_kwargs):
            raise OSError("injected sqlite outage")

        async def send_file(self, _peer, path, **_kwargs):
            sends.append(Path(path))
            raise AssertionError("send_file must not run without a durable row")

    server = UIServer(_Daemon())
    response = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"retain staged bytes", filename="ledger.bin"),
    ]))
    body = json.loads(response.text)

    assert response.status == 503
    assert body["code"] == "transfer_ledger_unavailable"
    assert sends == []
    # Staging names are random and never embed caller-controlled filenames
    # (prevents NTFS ADS/reserved-name/path-length attacks). The retained inode
    # still owns the exact bytes for ledger recovery/GC.
    staged = list(tmp_path.rglob("*.upload"))
    assert len(staged) == 1
    assert staged[0].read_bytes() == b"retain staged bytes"
    state.close()


def _durable_send_daemon(state, peer_fp, *, send_file, resumes):
    """Build a fake daemon that pre-queues a durable transfer row (like the
    real one) so the api_send_file failure paths can be exercised."""

    class _Daemon:
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        def __init__(self):
            self.state = state

        async def resolve_for_send(self, needle):
            return SimpleNamespace(
                short_id="bbbbbbbb", ed_pub_hex=(b"\xbb" * 32).hex(),
            )

        def _peer_fp_from_peer(self, peer):
            return peer_fp

        def _schedule_resume_paused(self, fp, *, force=False):
            resumes.append((fp, force))

        def queue_file_transfer(
            self, *, peer_fp, path, reason="peer offline", schedule_resume=True,
        ):
            return self.state.upsert_transfer(
                id="durable-online-1",
                direction="out",
                peer_fp=peer_fp,
                kind="file",
                name=Path(path).name,
                size=Path(path).stat().st_size,
                status="paused",
                progress_bytes=0,
                total_bytes=Path(path).stat().st_size,
                chunks_done=0,
                chunks_total=1,
                metadata={"path": str(path), "transient": True},
            )

        async def send_file(self, peer, path, *, transfer_id=None, **kwargs):
            return await send_file(peer, path, transfer_id=transfer_id, **kwargs)

    return _Daemon()


@pytest.mark.asyncio
async def test_api_send_file_transient_failure_without_transfer_id_queues(
    tmp_path: Path, monkeypatch,
):
    """REGRESSION: a flapping/unreachable peer makes send_file raise a plain
    transient error that does NOT carry a .transfer_id attribute. The durable
    row was already created, so this must become a 202 'paused; will resume'
    (One Link's offline-resilient promise) — not a hard error that dead-ends
    the user with the staged bytes thrown away."""
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id="bbbbbbbb", pubkey=b"\xbb" * 32,
        hostname="FlappyBox", trust_default="pinned",
    )
    resumes: list[tuple[str, bool]] = []

    async def send_file(peer, path, *, transfer_id=None, **_kwargs):
        # mirrors the daemon log's "Connection lost" — no transfer_id attr
        raise ConnectionError("connection lost")

    server = UIServer(
        _durable_send_daemon(state, peer_fp, send_file=send_file, resumes=resumes)
    )
    resp = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"queue me", filename="flap.bin"),
    ]))
    body = json.loads(resp.text)

    assert resp.status == 202
    assert body["paused"] is True
    assert body["queued"] is True
    assert body["transfer_id"] == "durable-online-1"
    # the durable row survives (not deleted) so resume can finish it
    assert state.get_transfer("durable-online-1") is not None
    # and a resume was scheduled for the peer
    assert resumes == [(peer_fp, True)]
    state.close()


@pytest.mark.asyncio
async def test_api_send_file_permanent_failure_drops_durable_row(
    tmp_path: Path, monkeypatch,
):
    """A permanent failure (sending disabled by policy) must surface a hard
    error AND drop the orphaned durable row so it doesn't retry forever."""
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    state.upsert_peer(
        fingerprint=peer_fp, short_id="bbbbbbbb", pubkey=b"\xbb" * 32,
        hostname="DeniedBox", trust_default="pinned",
    )
    resumes: list[tuple[str, bool]] = []

    async def send_file(peer, path, *, transfer_id=None, **_kwargs):
        raise RuntimeError("files capability is disabled for this peer")

    server = UIServer(
        _durable_send_daemon(state, peer_fp, send_file=send_file, resumes=resumes)
    )
    resp = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"nope", filename="denied.bin"),
    ]))
    body = json.loads(resp.text)

    assert resp.status == 403
    assert body["code"] == "capability_disabled"
    # orphaned durable row is cleaned up; no resume scheduled
    assert state.get_transfer("durable-online-1") is None
    assert resumes == []
    state.close()


@pytest.mark.asyncio
async def test_api_send_file_retries_wire_version_mismatch_once(tmp_path: Path, monkeypatch):
    """A stale secure session can surface as InvalidTag/wire mismatch.

    Browser uploads should retry once after a fresh resolve instead of making
    the user retry manually.
    """
    from cryptography.exceptions import InvalidTag

    from one_link.server import UIServer

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    sends: list[str] = []
    resolves: list[str] = []

    class _Daemon:
        state = None
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        async def resolve_for_send(self, needle):
            resolves.append(str(needle))
            return SimpleNamespace(short_id=str(needle))

        async def send_file(self, peer, path, *, transfer_id=None, rel_path=None, extra_metadata=None, **_kwargs):
            sends.append(peer.short_id)
            if len(sends) == 1:
                raise InvalidTag()
            return {"ok": True, "path_exists": Path(path).is_file()}

    server = UIServer(_Daemon())
    resp = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"retry me", filename="retry.bin"),
    ]))
    body = json.loads(resp.text)

    assert resp.status == 200
    assert body["ok"] is True
    assert body["result"]["path_exists"] is True
    assert sends == ["bbbbbbbb", "bbbbbbbb"]
    assert resolves == ["bbbbbbbb", "bbbbbbbb"]


@pytest.mark.asyncio
async def test_api_send_file_offline_paired_peer_queues_staged_upload(
    tmp_path: Path, monkeypatch,
):
    """Known paired peers should get a durable send intent even while
    offline. The upload bytes stay staged so the background queue can
    send them later without asking the user to try again.
    """
    from one_link.server import UIServer
    from one_link.state import State

    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    peer_fp = "bb" * 32
    state.upsert_peer(
        fingerprint=peer_fp,
        short_id="bbbbbbbb",
        pubkey=b"\xbb" * 32,
        hostname="OfflineBox",
        trust_default="pinned",
    )
    queued_paths: list[Path] = []

    class _Daemon:
        me = SimpleNamespace(fingerprint="aa" * 32, short_id="aaaaaaaa")

        def __init__(self):
            self.state = state

        async def resolve_for_send(self, needle):
            return None

        def queue_file_transfer(self, *, peer_fp, path, reason="peer offline"):
            queued_paths.append(Path(path))
            return self.state.upsert_transfer(
                id="queued-1",
                direction="out",
                peer_fp=peer_fp,
                kind="file",
                name=Path(path).name,
                size=Path(path).stat().st_size,
                status="paused",
                progress_bytes=0,
                total_bytes=Path(path).stat().st_size,
                chunks_done=0,
                chunks_total=1,
                metadata={
                    "path": str(path),
                    "delivery_state": "waiting_for_device",
                    "transient": True,
                },
            )

    server = UIServer(_Daemon())
    resp = await server.api_send_file(_FakeMultipartReq([
        _FakePart("peer", text="bbbbbbbb"),
        _FakePart("file", data=b"wait for me", filename="offline.bin"),
    ]))
    body = json.loads(resp.text)
    assert resp.status == 202
    assert body["queued"] is True
    assert body["transfer_id"] == "queued-1"
    assert queued_paths and queued_paths[0].is_file()
    assert queued_paths[0].read_bytes() == b"wait for me"
    state.close()


@pytest.mark.asyncio
async def test_api_files_lists_and_downloads():
    with daemon_pair(pin_trust=True) as p:
        # Send a file from A to B first so B has something in inbox
        from tests.harness import request as ctrl_request
        src = p.tmp / "for_listing.bin"
        src.write_bytes(b"hello world")
        ctrl_request(p.a.control_port, cmd="send_file", peer=p.b.short_id, path=str(src))
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base_b}/api/files", token=tok_b)
            assert status == 200
            names = [f["name"] for f in j["files"]]
            assert any("for_listing.bin" in n for n in names), names

            file_row = next(f for f in j["files"] if "for_listing.bin" in f["name"])
            assert file_row["risk"]["level"] == "low"
            assert file_row["risk"]["open_policy"] == "normal"
            target = file_row["name"]
            async with s.get(
                f"{base_b}/api/files/{target}",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                assert r.status == 200
                data = await r.read()
                assert data == b"hello world"


@pytest.mark.asyncio
async def test_api_file_download_resolves_unique_collision_prefix():
    with daemon_pair() as p:
        inbox = p.b.home / "data" / "inbox"
        inbox.mkdir(parents=True, exist_ok=True)
        stored = inbox / "8fcba10f_1779413794325_4efab5b0d8e5083e_image.png"
        stored.write_bytes(b"png-bytes")

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{base_b}/api/files/1779413794325_4efab5b0d8e5083e_image.png",
                headers={"Authorization": f"Bearer {tok_b}"},
            ) as r:
                assert r.status == 200
                assert await r.read() == b"png-bytes"


@pytest.mark.asyncio
async def test_api_file_download_blocks_path_traversal():
    """Defense in depth: even if a client crafts a URL that bypasses
    aiohttp's path normalization, the handler must refuse."""
    with daemon_pair() as p:
        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            # These get normalized client-side; they should at minimum NOT
            # return 200 with file content.
            for evil in ["../../etc/passwd", "..\\..\\foo", "../bar"]:
                status, _ = await _get(
                    s, f"{base_b}/api/files/{evil}", token=tok_b
                )
                assert status != 200, f"path-traversal returned 200: {evil!r}"

        # Send a raw HTTP request that DOESN'T normalize, to hit the handler.
        port = int(_read(p.b.home, "server.port"))
        for raw_evil in ["..%2F..%2Fetc%2Fpasswd", "..", "subdir/x", "x/../y"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", port))
            try:
                req = (
                    f"GET /api/files/{raw_evil} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1\r\n"
                    f"Authorization: Bearer {tok_b}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                sock.sendall(req)
                buf = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                first_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                # Must NOT be 200 OK
                assert "200" not in first_line, (
                    f"raw path-traversal got {first_line!r} for {raw_evil!r}"
                )
            finally:
                sock.close()


@pytest.mark.asyncio
async def test_api_messages_returns_list():
    with daemon_pair() as p:
        # Generate some traffic
        from tests.harness import request as ctrl_request
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="m1")
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="m2")
        await asyncio.sleep(0.6)

        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(
                s, f"{base_a}/api/messages?limit=50", token=tok_a
            )
            assert status == 200
            bodies = [m.get("body") for m in j["messages"] if m.get("t") == "TEXT"]
            assert "m1" in bodies and "m2" in bodies


@pytest.mark.asyncio
async def test_websocket_event_stream_pushes_messages():
    with daemon_pair(pin_trust=True) as p:
        base_b, tok_b = _server_addr(p.b.home)
        ws_url = base_b.replace("http://", "ws://") + "/api/events"
        async with aiohttp.ClientSession() as s:
            async with s.ws_connect(
                ws_url, headers={"Authorization": f"Bearer {tok_b}"}
            ) as ws:
                # First frame should be the hello with our identity
                msg = await asyncio.wait_for(ws.receive(), timeout=5)
                assert msg.type == aiohttp.WSMsgType.TEXT
                hello = json.loads(msg.data)
                assert hello["type"] == "hello"
                assert hello["me"]["short_id"] == p.b.short_id

                # Now have A send a message; B's WS should see it
                from tests.harness import request as ctrl_request
                ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="ws-test")

                # Drain events until we see the one we want, with a timeout.
                deadline = time.time() + 8.0
                got = False
                while time.time() < deadline:
                    msg = await asyncio.wait_for(ws.receive(), timeout=2.0)
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        continue
                    obj = json.loads(msg.data)
                    if obj.get("type") == "msg" and obj.get("msg", {}).get("body") == "ws-test":
                        got = True
                        break
                assert got, "WS never delivered the inbound TEXT"


@pytest.mark.asyncio
async def test_api_search_finds_message_by_word():
    with daemon_pair(pin_trust=True) as p:
        from tests.harness import request as ctrl_request
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="the quick brown fox")
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="lazy dog")
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(
                s, f"{base_b}/api/search?q=quick", token=tok_b
            )
            assert status == 200
            bodies = [m.get("body") for m in j["messages"]]
            assert "the quick brown fox" in bodies


@pytest.mark.asyncio
async def test_api_search_q_required():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, _ = await _get_json(s, f"{base_a}/api/search", token=tok_a)
            assert status == 400


@pytest.mark.asyncio
async def test_api_audit_describes_surface():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _get_json(s, f"{base_a}/api/audit", token=tok_a)
            assert status == 200
            assert j["ui_bind"].startswith("127.0.0.1")
            assert j["no_external_telemetry"] is True
            assert "TEXT" in j["peer_protocol"]["message_types"]
            assert "PAIR_REQUEST" in j["peer_protocol"]["message_types"]
            assert "FILE_WANTS" in j["peer_protocol"]["message_types"]
            assert "FILE_CDC_CHUNK" in j["peer_protocol"]["message_types"]
            assert "MANIFEST_PUSH" in j["peer_protocol"]["message_types"]
            assert "CAPS" in j["peer_protocol"]["message_types"]
            assert "CAPSULE_RECEIPT" in j["peer_protocol"]["message_types"]
            assert "FILE_COMMIT" in j["peer_protocol"]["message_types"]
            assert j["peer_protocol"]["handshake_policy"]["default_version"] == 3
            assert "ML-KEM-768" in j["peer_protocol"]["encryption"]
            assert j["peer_protocol"]["handshake_policy"]["browser_webrtc_pq_qualified"] is False
            assert j["peer_protocol"]["file_payload_routes"]["supported_requests"] == [
                "auto", "tcp", "relay",
            ]
            assert "CALL_SDP_ANSWER" in j["peer_protocol"]["message_types"]
            assert any(s["name"] == "file_cdc_transfer" for s in j["peer_protocol"]["sessions"])
            assert "file_cdc" in j["local_capabilities"]
            assert j["performance"]["cdc_cache"]["max_bytes"] > 0
            assert "adaptive zlib" in j["performance"]["file_transfer"]["compression"]
            assert "BDP-aware" in j["performance"]["file_transfer"]["autopilot"]
            assert "transfer_autopilot" in j["performance"]
            assert any("mdns" in d["kind"] for d in j["outbound_destinations"])
            destination_kinds = {d["kind"] for d in j["outbound_destinations"]}
            assert {
                "stun", "turn_relay", "rendezvous", "encrypted_relay",
                "update_check",
            }.issubset(destination_kinds)
            assert "not proof of calls made" in j["outbound_inventory_scope"]
            doctrine = j["sovereign_network"]
            assert doctrine["privacy_guarantees"]["mandatory_relay"] is False
            assert "open-source distribution" in doctrine["principles"]
            assert any(
                c["name"] == "merkle_drift_sync"
                for c in doctrine["capabilities"]
            )


@pytest.mark.asyncio
async def test_api_set_trust_round_trip():
    with daemon_pair() as p:
        # First, drive A to send to B so B records A in its peer DB
        from tests.harness import request as ctrl_request
        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="trust-test")
        await asyncio.sleep(0.6)

        # B's view: list peers, find A by short_id, get fingerprint.
        # Pre-trust-set the peer is unpaired, so use modal feed.
        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            _, j = await _get_json(
                s, f"{base_b}/api/peers?include_unpaired=1", token=tok_b
            )
            target = next(
                (pp for pp in j["peers"] if pp["short_id"] == p.a.short_id),
                None,
            )
            assert target is not None and target.get("fingerprint")
            fp = target["fingerprint"]
            assert target["trust"] in ("pending", "pinned")

            # Set rejected
            status, j2 = await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "rejected"}, token=tok_b,
            )
            assert status == 200
            assert j2["trust"] == "rejected"

            # Verify it stuck — rejected peers are hidden by default,
            # so opt-in with include_rejected=1.
            _, j3 = await _get_json(
                s, f"{base_b}/api/peers?include_rejected=1", token=tok_b
            )
            target3 = next(pp for pp in j3["peers"] if pp["fingerprint"] == fp)
            assert target3["trust"] == "rejected"

            # Bad trust value
            status_bad, _ = await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "yolo"}, token=tok_b,
            )
            assert status_bad == 400


@pytest.mark.asyncio
async def test_api_peer_capability_policy_round_trip():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            _, peers = await _get_json(
                s, f"{base_a}/api/peers?include_unpaired=1", token=tok_a
            )
            fp = next(
                (pp["fingerprint"] for pp in peers["peers"] if pp["short_id"] == p.b.short_id),
                None,
            )
            assert fp, f"peer {p.b.short_id} not visible: {peers['peers']!r}"

            status, out = await _post_json(
                s,
                f"{base_a}/api/peers/{fp}/capabilities",
                {"allowed": ["chat", "files", "not_real"]},
                token=tok_a,
            )
            assert status == 200
            assert out["allowed"] == ["chat", "files"]

            status, got = await _get_json(
                s, f"{base_a}/api/peers/{fp}/capabilities", token=tok_a
            )
            assert status == 200
            assert got["allowed"] == ["chat", "files"]

            status, cleared = await _post_json(
                s,
                f"{base_a}/api/peers/{fp}/capabilities",
                {"allowed": None},
                token=tok_a,
            )
            assert status == 200
            assert cleared["allowed"] is None

@pytest.mark.asyncio
async def test_set_trust_auto_seeds_from_mdns_for_unmessaged_peer():
    """User clicks Accept/Block on a peer they've only seen via mDNS, never
    actually messaged. The endpoint must auto-populate the peer DB from the
    discovery record rather than rejecting with 'unknown peer'."""
    with daemon_pair() as p:
        # B has seen A via mDNS but they have NOT exchanged messages yet,
        # so B's peer DB likely doesn't have an A record.
        # Find A in B's discovery view (modal feed since A is unpaired).
        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            _, j = await _get_json(
                s, f"{base_b}/api/peers?include_unpaired=1", token=tok_b
            )
            target = next(
                (pp for pp in j["peers"] if pp["short_id"] == p.a.short_id),
                None,
            )
            assert target, f"peer {p.a.short_id} not visible: {j['peers']!r}"
            fp = target["fingerprint"]

            # Pin them — should succeed even if state.get_peer(fp) returns None
            status, j2 = await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "pinned"}, token=tok_b,
            )
            assert status == 200, j2
            assert j2["trust"] == "pinned"

            # Now confirmed in DB — paired-only feed should now contain it.
            _, j3 = await _get_json(s, f"{base_b}/api/peers", token=tok_b)
            after = next(pp for pp in j3["peers"] if pp["fingerprint"] == fp)
            assert after["trust"] == "pinned"


@pytest.mark.asyncio
async def test_set_trust_for_truly_unknown_peer_returns_404():
    """If a fingerprint isn't in the DB and isn't visible via mDNS either,
    the endpoint should still 404 (genuine unknown)."""
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            status, j = await _post_json(
                s, f"{base_a}/api/peers/{'00' * 32}/trust",
                {"trust": "pinned"}, token=tok_a,
            )
            assert status == 404


@pytest.mark.asyncio
async def test_outbound_blocked_for_rejected_peer():
    """If we mark a peer 'rejected', outbound sends to them must error."""
    with daemon_pair() as p:
        # Seed: A sends to B so B has A's fingerprint pinned-trust.
        # Then B marks A rejected. Subsequent B → A sends must fail.
        from tests.harness import request as ctrl_request

        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="seed")
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            # The inbound TEXT didn't auto-pin A; A is still pending on B.
            _, j = await _get_json(
                s, f"{base_b}/api/peers?include_unpaired=1", token=tok_b
            )
            target = next(
                (pp for pp in j["peers"] if pp["short_id"] == p.a.short_id),
                None,
            )
            assert target, f"peer {p.a.short_id} not visible from B"
            fp = target["fingerprint"]

            # B rejects A
            await _post_json(
                s, f"{base_b}/api/peers/{fp}/trust",
                {"trust": "rejected"}, token=tok_b,
            )

            # B tries to send to A → must error
            status, j2 = await _post_json(
                s, f"{base_b}/api/send",
                {"peer": p.a.short_id, "body": "hi"},
                token=tok_b,
            )
            assert status >= 400
            # The user-facing error text was rewritten in v0.7.x; assert
            # on the stable `code` field (peer_rejected) rather than the
            # English wording.
            assert j2.get("code") == "peer_rejected", j2


@pytest.mark.asyncio
async def test_inbound_blocked_for_rejected_peer():
    """Rejecting a peer must stop their future inbound messages too."""
    with daemon_pair() as p:
        from tests.harness import message_log, request as ctrl_request

        ctrl_request(p.a.control_port, cmd="send", peer=p.b.short_id, body="seed")
        await asyncio.sleep(0.6)

        base_b, tok_b = _server_addr(p.b.home)
        async with aiohttp.ClientSession() as s:
            _, j = await _get_json(
                s, f"{base_b}/api/peers?include_unpaired=1", token=tok_b
            )
            target = next(
                (pp for pp in j["peers"] if pp["short_id"] == p.a.short_id),
                None,
            )
            assert target, f"peer {p.a.short_id} not visible from B"
            await _post_json(
                s, f"{base_b}/api/peers/{target['fingerprint']}/trust",
                {"trust": "rejected"}, token=tok_b,
            )

        res = ctrl_request(
            p.a.control_port, cmd="send", peer=p.b.short_id, body="blocked inbound"
        )
        assert not res["ok"]
        await asyncio.sleep(0.6)
        bodies = [
            m.get("body")
            for m in message_log(p.b.home)
            if m.get("t") == "TEXT" and m.get("dir") == "in"
        ]
        assert "blocked inbound" not in bodies


@pytest.mark.asyncio
async def test_websocket_unauthorized_closes():
    with daemon_pair() as p:
        base_b, _ = _server_addr(p.b.home)
        ws_url = base_b.replace("http://", "ws://") + "/api/events"  # no token
        async with aiohttp.ClientSession() as s:
            async with s.ws_connect(ws_url) as ws:
                # Server should close immediately. receive() returns CLOSE.
                msg = await asyncio.wait_for(ws.receive(), timeout=5)
                assert msg.type in (
                    aiohttp.WSMsgType.CLOSE,
                    aiohttp.WSMsgType.CLOSED,
                    aiohttp.WSMsgType.CLOSING,
                )


@pytest.mark.asyncio
async def test_settings_round_trip():
    with daemon_pair() as p:
        base_a, tok_a = _server_addr(p.a.home)
        async with aiohttp.ClientSession() as s:
            # Default
            status, j = await _get_json(s, f"{base_a}/api/settings", token=tok_a)
            assert status == 200
            assert j["display_name"] is None
            assert j["auto_accept_lan"] is False

            # Set
            status, _ = await _post_json(
                s, f"{base_a}/api/settings",
                {"display_name": "Alex's Studio", "auto_accept_lan": True},
                token=tok_a,
            )
            assert status == 200

            # Read back
            _, j2 = await _get_json(s, f"{base_a}/api/settings", token=tok_a)
            assert j2["display_name"] == "Alex's Studio"
            assert j2["auto_accept_lan"] is True

            # /api/me reflects the override
            _, me = await _get_json(s, f"{base_a}/api/me", token=tok_a)
            assert me["display_name"] == "Alex's Studio"

            # Clear display_name (empty / null)
            await _post_json(
                s, f"{base_a}/api/settings",
                {"display_name": None}, token=tok_a,
            )
            _, j3 = await _get_json(s, f"{base_a}/api/settings", token=tok_a)
            assert j3["display_name"] is None
            _, me2 = await _get_json(s, f"{base_a}/api/me", token=tok_a)
            assert me2["display_name"] == me2["hostname"]


@pytest.mark.asyncio
async def test_retry_complete_transfer_is_idempotent_noop():
    """A completed delivery must never emit a second FILE_OFFER."""
    from one_link.server import UIServer

    rec = SimpleNamespace(
        id="out:" + ("ab" * 32) + ":123456789abc",
        direction="out",
        status="complete",
        metadata={"commit_confirmed": True},
    )

    async def unexpected_network_call(*_args, **_kwargs):
        raise AssertionError("completed transfer attempted network I/O")

    server = object.__new__(UIServer)
    server.daemon = SimpleNamespace(
        state=SimpleNamespace(get_transfer=lambda _transfer_id: rec),
        resolve_for_send=unexpected_network_call,
        send_file=unexpected_network_call,
    )
    request = _FakeReq()
    request.match_info["transfer_id"] = rec.id

    response = await server.api_retry_transfer(request)
    body = json.loads(response.text)

    assert response.status == 200
    assert body["ok"] is True
    assert body["already_complete"] is True
    assert body["transfer_id"] == rec.id


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "metadata",
    [
        {
            "delivery_state": "sent_unconfirmed",
            "commit_confirmed": False,
            "error_class": "DeliveryUnconfirmed",
        },
        {
            "delivery_state": "outcome_unknown",
            "error_class": "SenderCommitAccountingError",
        },
    ],
)
async def test_retry_refuses_outcome_unknown_delivery(metadata):
    """Legacy/ambiguous commits are never blindly re-sent."""
    from one_link.server import UIServer

    rec = SimpleNamespace(
        id="out:" + ("cd" * 32) + ":123456789abc",
        direction="out",
        status="failed",
        metadata=metadata,
    )

    async def unexpected_network_call(*_args, **_kwargs):
        raise AssertionError("outcome-unknown transfer attempted network I/O")

    server = object.__new__(UIServer)
    server.daemon = SimpleNamespace(
        state=SimpleNamespace(get_transfer=lambda _transfer_id: rec),
        resolve_for_send=unexpected_network_call,
        send_file=unexpected_network_call,
    )
    request = _FakeReq()
    request.match_info["transfer_id"] = rec.id

    response = await server.api_retry_transfer(request)
    body = json.loads(response.text)

    assert response.status == 409
    assert body["ok"] is False
    assert body["code"] == "delivery_outcome_unknown"
    assert body["outcome_unknown"] is True


@pytest.mark.asyncio
async def test_retry_fails_closed_when_commit_marker_check_errors():
    """Unreadable durability evidence is not permission to duplicate."""
    from one_link.server import UIServer

    rec = SimpleNamespace(
        id="out:" + ("ef" * 32) + ":123456789abc",
        direction="out",
        status="failed",
        metadata={"error_class": "ConnectionError"},
    )

    def broken_failstop_check(_transfer_id):
        raise OSError("commit marker store unavailable")

    async def unexpected_network_call(*_args, **_kwargs):
        raise AssertionError("unresolved transfer attempted network I/O")

    server = object.__new__(UIServer)
    server.daemon = SimpleNamespace(
        state=SimpleNamespace(get_transfer=lambda _transfer_id: rec),
        _remote_commit_is_failstopped=broken_failstop_check,
        resolve_for_send=unexpected_network_call,
        send_file=unexpected_network_call,
    )
    request = _FakeReq()
    request.match_info["transfer_id"] = rec.id

    response = await server.api_retry_transfer(request)
    body = json.loads(response.text)

    assert response.status == 409
    assert body["code"] == "delivery_outcome_unknown"
