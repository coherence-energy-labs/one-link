"""v0.21.x persistent UI sessions: revocable browser authority that outlives daemon
token rotation. Tests cover:

  - state.ui_sessions table mechanics (create/touch/lookup/revoke/
    revoke_all/prune)
  - server auth path: _check_token accepts a valid session bearer even when
    the process owner token doesn't match
  - plaintext bootstrap path: ?t=<valid> injects a port-origin-scoped bearer,
    expires historical port-agnostic cookies, and never retains the owner token
  - revoke endpoints: single + all; clearing caller's cookie on
    own-session revoke
  - access-denied page self-heal: marker cookie triggers JS redirect
"""
from __future__ import annotations

import time
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import (
    COOKIE_NAME, OWNER_WS_BEARER_PROTOCOL_PREFIX, OWNER_WS_PROTOCOL,
    SESSION_COOKIE_NAME, SESSION_PRESENT_MARKER_COOKIE,
    UIServer,
)
from one_link.state import State


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="sess-host",
    )


@pytest_asyncio.fixture
async def ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[])
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield {
            "client": client, "server": server, "daemon": daemon,
            "state": state, "token": server.token,
        }
    finally:
        await client.close()
        state.close()


# ── state-layer mechanics ─────────────────────────────────────────


def test_create_returns_64hex_uuid(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session(user_agent="Mozilla/5.0 Firefox/120.0")
    sid = sess["session_uuid"]
    assert len(sid) == 64
    assert all(c in "0123456789abcdef" for c in sid)
    assert sess["label"] == "Firefox on Unknown OS"  # no OS substring
    s.close()


def test_database_never_stores_replayable_session_token(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session()
    stored = s._conn.execute(
        "SELECT session_uuid FROM ui_sessions WHERE id=1"
    ).fetchone()["session_uuid"]
    assert stored != sess["session_uuid"]
    assert stored == State.ui_session_token_id(sess["session_uuid"])
    assert s.touch_ui_session(stored) is False, (
        "the at-rest record key must not itself be replayable as a cookie"
    )
    s.close()


def test_v28_migration_hashes_legacy_tokens_without_logging_out(tmp_path: Path):
    db = tmp_path / "s.db"
    s = State(db_path=db)
    sess = s.create_ui_session()
    raw_token = sess["session_uuid"]
    s.close()

    # Recreate the exact v27 exposure: raw cookie in the credential index and
    # schema_version 28 absent. Reopen must transform it exactly once.
    conn = sqlite3.connect(db)
    conn.execute(
        "UPDATE ui_sessions SET session_uuid=? WHERE id=1", (raw_token,)
    )
    conn.execute("DELETE FROM schema_version WHERE version>=28")
    conn.commit()
    conn.close()

    migrated = State(db_path=db)
    assert migrated.schema_version() >= 29
    assert migrated.touch_ui_session(raw_token) is True
    stored = migrated._conn.execute(
        "SELECT session_uuid FROM ui_sessions WHERE id=1"
    ).fetchone()["session_uuid"]
    assert stored == State.ui_session_token_id(raw_token)
    assert stored != raw_token
    migrated.close()


def test_label_recognises_modern_edge_ua(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session(
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120.0"
        ),
    )
    assert sess["label"] == "Edge on Windows"
    s.close()


def test_touch_updates_last_seen(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session()
    initial = sess["last_seen_ms"]
    time.sleep(0.005)
    assert s.touch_ui_session(sess["session_uuid"]) is True
    after = s.lookup_ui_session(sess["session_uuid"])
    assert after["last_seen_ms"] > initial
    s.close()


def test_touch_rejects_bogus(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    assert s.touch_ui_session("") is False
    assert s.touch_ui_session("not-a-uuid") is False
    assert s.touch_ui_session(None) is False  # type: ignore[arg-type]
    s.close()


def test_revoked_session_no_longer_touches(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    sess = s.create_ui_session()
    assert s.revoke_ui_session(sess["session_uuid"]) is True
    assert s.touch_ui_session(sess["session_uuid"]) is False
    assert s.lookup_ui_session(sess["session_uuid"]) is None
    # Re-revoking a revoked session is a no-op (idempotent).
    assert s.revoke_ui_session(sess["session_uuid"]) is False
    s.close()


def test_revoke_all_counts_active(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    first = s.create_ui_session(user_agent="A")
    s.create_ui_session(user_agent="B")
    s.create_ui_session(user_agent="C")
    # Pre-revoke one — it shouldn't be re-counted.
    s.revoke_ui_session(first["session_uuid"])
    assert s.revoke_all_ui_sessions() == 2
    s.close()


def test_list_excludes_revoked_by_default(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    a = s.create_ui_session()
    b = s.create_ui_session()
    s.revoke_ui_session(a["session_uuid"])
    active = s.list_ui_sessions()
    assert len(active) == 1
    assert active[0]["session_uuid"] == State.ui_session_token_id(
        b["session_uuid"]
    )
    all_rows = s.list_ui_sessions(include_revoked=True)
    assert len(all_rows) == 2
    s.close()


def test_prune_drops_stale(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    s.create_ui_session()
    old_ts = int(time.time() * 1000) + 10_000  # all rows fall under this
    pruned = s.prune_expired_ui_sessions(older_than_ms=old_ts)
    assert pruned == 1
    s.close()


# ── server auth path: cookie acceptance ──────────────────────────


@pytest.mark.asyncio
async def test_session_bearer_accepted_when_token_rotates(ctx):
    """The whole point of this feature: a browser holding a revocable session
    keeps authing even after the daemon's UI token rotates to a new
    value (which would normally invalidate ol_ui)."""
    sess = ctx["state"].create_ui_session(user_agent="Mozilla/5.0")
    # Token rotation simulation: change the server token in-place.
    # The session cookie is unrelated and should still work.
    ctx["server"].token = "ROTATED-" + "x" * 50
    r = await ctx["client"].get(
        "/api/me",
        headers={"Authorization": f"Bearer {sess['session_uuid']}"},
    )
    assert r.status == 200, await r.text()


@pytest.mark.asyncio
async def test_bogus_session_cookie_is_rejected(ctx):
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: "not-a-real-uuid"},
    )
    assert r.status == 401


@pytest.mark.asyncio
async def test_revoked_session_cookie_rejected(ctx):
    sess = ctx["state"].create_ui_session(user_agent="Mozilla/5.0")
    assert ctx["state"].revoke_ui_session(sess["session_uuid"])
    ctx["server"].token = "ROTATED"
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: sess["session_uuid"]},
    )
    assert r.status == 401


@pytest.mark.asyncio
async def test_short_cookie_rejected_without_db_lookup(ctx):
    """Defense in depth: cookies under 32 chars short-circuit before
    hitting the SQL layer."""
    r = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: "tooshort"},
    )
    assert r.status == 401


# ── bootstrap path: cookie issuance ──────────────────────────────


@pytest.mark.asyncio
async def test_plaintext_bootstrap_injects_session_and_expires_cookies(ctx):
    """Plain HTTP uses origin storage and actively deletes legacy cookies."""
    r = await ctx["client"].get(f"/?t={ctx['token']}")
    assert r.status == 200
    # Aiohttp test client surfaces Set-Cookie headers.
    cookie_hdrs = r.headers.getall("Set-Cookie", [])
    joined = " ".join(cookie_hdrs)
    assert COOKIE_NAME in joined and SESSION_COOKIE_NAME in joined
    assert SESSION_PRESENT_MARKER_COOKIE in joined
    assert joined.count("Max-Age=0") == 3
    body = await r.text()
    assert "ol_persistent_session_token" in body
    assert ctx["token"] not in body


@pytest.mark.asyncio
async def test_bootstrap_reuses_explicit_origin_session_bearer(ctx):
    """A browser recovery fetch reuses its origin-scoped session."""
    r1 = await ctx["client"].get(f"/?t={ctx['token']}")
    assert r1.status == 200
    sessions_after_first = ctx["state"].list_ui_sessions()
    assert len(sessions_after_first) == 1
    import re

    match = re.search(r'const b="([0-9a-f]{64})"', await r1.text())
    assert match is not None
    session_token = match.group(1)
    r2 = await ctx["client"].get(
        f"/?t={ctx['token']}",
        headers={"Authorization": f"Bearer {session_token}"},
    )
    assert r2.status == 200
    sessions_after_second = ctx["state"].list_ui_sessions()
    assert len(sessions_after_second) == 1, (
        "re-hitting the bootstrap with the same browser should "
        "reuse the existing session, not mint another"
    )


# ── revoke endpoints ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_sessions_marks_own_browser(ctx):
    sess = ctx["state"].create_ui_session(user_agent="Mozilla/5.0")
    other = ctx["state"].create_ui_session(user_agent="Firefox")
    r = await ctx["client"].get(
        "/api/auth/sessions",
        headers={"Authorization": f"Bearer {sess['session_uuid']}"},
    )
    assert r.status == 200
    body = await r.json()
    by_prefix = {
        s["session_uuid_prefix"]: s for s in body["sessions"]
    }
    own_prefix = State.ui_session_token_id(sess["session_uuid"])[:8]
    other_prefix = State.ui_session_token_id(other["session_uuid"])[:8]
    assert by_prefix[own_prefix]["is_this_browser"] is True
    assert by_prefix[other_prefix]["is_this_browser"] is False
    assert sess["session_uuid"] not in await r.text()


def _csrf_origin_for(client) -> dict:
    """Browser POSTs MUST carry Origin equal to the daemon's own
    bind URL — that's the CSRF gate. Tests need to spoof it the
    same way a real same-origin fetch would."""
    return {"Origin": f"http://127.0.0.1:{client.port}"}


def _auth_headers(ctx, *, csrf_client=None) -> dict:
    """Bearer for auth + Origin for CSRF on POSTs."""
    h = {"Authorization": f"Bearer {ctx['token']}"}
    if csrf_client is not None:
        h["Origin"] = f"http://127.0.0.1:{csrf_client.port}"
    return h


def _session_headers(token: str, *, csrf_client=None) -> dict:
    h = {"Authorization": f"Bearer {token}"}
    if csrf_client is not None:
        h["Origin"] = f"http://127.0.0.1:{csrf_client.port}"
    return h


@pytest.mark.asyncio
async def test_cookie_auth_rejects_different_loopback_origin_port(ctx):
    session = ctx["state"].create_ui_session(user_agent="malicious-local-app")
    wrong_port = ctx["client"].port + 1

    response = await ctx["client"].post(
        "/api/auth/sessions/revoke-all",
        cookies={SESSION_COOKIE_NAME: session["session_uuid"]},
        headers={"Origin": f"http://127.0.0.1:{wrong_port}"},
    )

    assert response.status == 403
    assert ctx["state"].lookup_ui_session(session["session_uuid"]) is not None


@pytest.mark.asyncio
async def test_plaintext_cookie_auth_is_rejected_even_same_origin(ctx):
    session = ctx["state"].create_ui_session(user_agent="legacy-cookie")
    response = await ctx["client"].get(
        "/api/me",
        cookies={SESSION_COOKIE_NAME: session["session_uuid"]},
    )
    assert response.status == 401


@pytest.mark.asyncio
async def test_loopback_host_must_include_exact_listener_port(ctx):
    response = await ctx["client"].get(
        "/api/me",
        headers={
            "Authorization": f"Bearer {ctx['token']}",
            "Host": f"127.0.0.1:{ctx['client'].port + 1}",
        },
    )
    assert response.status == 421
    assert (await response.json())["error"] == "host header rejected"


@pytest.mark.asyncio
@pytest.mark.parametrize("site", ["same-site", "cross-site", "unknown"])
async def test_fetch_metadata_rejects_non_origin_loopback_site(ctx, site: str):
    response = await ctx["client"].get(
        "/api/me",
        headers={
            "Authorization": f"Bearer {ctx['token']}",
            "Sec-Fetch-Site": site,
        },
    )
    assert response.status == 403


@pytest.mark.asyncio
async def test_referer_from_different_loopback_port_is_rejected(ctx):
    response = await ctx["client"].get(
        "/api/me",
        headers={
            "Authorization": f"Bearer {ctx['token']}",
            "Referer": f"http://127.0.0.1:{ctx['client'].port + 1}/attack",
        },
    )
    assert response.status == 403


@pytest.mark.asyncio
async def test_websocket_bearer_uses_subprotocol_not_url(ctx):
    session = ctx["state"].create_ui_session(user_agent="ws-owner")
    websocket = await ctx["client"].ws_connect(
        "/api/events",
        protocols=(
            OWNER_WS_PROTOCOL,
            OWNER_WS_BEARER_PROTOCOL_PREFIX + session["session_uuid"],
        ),
    )
    try:
        hello = await websocket.receive_json(timeout=2)
        assert hello["type"] == "hello"
        assert websocket.protocol == OWNER_WS_PROTOCOL
    finally:
        await websocket.close()


@pytest.mark.parametrize(
    "authority",
    [
        "",
        " 127.0.0.1:7117",
        "127.0.0.1:7117:evil",
        "127.0.0.1:7117,evil.example",
        "user@127.0.0.1:7117",
        "[::1]suffix:7117",
        "localhost:",
        "[::1]:",
        "localhost.:7117",
        "localhost\\@evil:7117",
    ],
)
def test_host_authority_parser_rejects_ambiguous_forms(authority: str):
    assert UIServer._parse_host_authority(authority) is None


def test_ipv6_wildcard_is_not_loopback_bound():
    server = object.__new__(UIServer)
    server.bind_host = "::"
    assert server._is_loopback_bound() is False


def test_invalid_bearer_does_not_bypass_csrf_origin_gate():
    server = object.__new__(UIServer)
    server.token = "real-owner-token"
    server.daemon = SimpleNamespace(state=None)
    request = SimpleNamespace(headers={"Authorization": "Bearer invalid"})
    assert server._csrf_origin_ok(request) is False


@pytest.mark.asyncio
async def test_revoke_all_returns_count_and_clears_cookies(ctx):
    ctx["state"].create_ui_session(user_agent="A")
    ctx["state"].create_ui_session(user_agent="B")
    caller = ctx["state"].create_ui_session(user_agent="C")
    r = await ctx["client"].post(
        "/api/auth/sessions/revoke-all",
        headers=_session_headers(
            caller["session_uuid"],
            csrf_client=ctx["client"],
        ),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["revoked"] == 3
    # Cookies are cleared in the response.
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert SESSION_COOKIE_NAME in cookie_hdrs
    # del_cookie sets Max-Age=0 to clear.
    assert "Max-Age=0" in cookie_hdrs


@pytest.mark.asyncio
async def test_revoke_one_session(ctx):
    a = ctx["state"].create_ui_session(user_agent="A")
    b = ctx["state"].create_ui_session(user_agent="B")
    listed = ctx["state"].list_ui_sessions()
    a_id = next(
        row["id"]
        for row in listed
        if row["session_uuid"] == State.ui_session_token_id(a["session_uuid"])
    )
    r = await ctx["client"].post(
        f"/api/auth/sessions/id-{a_id}/revoke",
        headers=_session_headers(b["session_uuid"], csrf_client=ctx["client"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["revoked"] == 1
    # A is gone, B still active.
    active = ctx["state"].list_ui_sessions()
    assert len(active) == 1
    assert active[0]["session_uuid"] == State.ui_session_token_id(
        b["session_uuid"]
    )


@pytest.mark.asyncio
async def test_revoke_endpoint_rejects_display_prefix(ctx):
    caller = ctx["state"].create_ui_session(user_agent="A")
    prefix = State.ui_session_token_id(caller["session_uuid"])[:8]
    response = await ctx["client"].post(
        f"/api/auth/sessions/{prefix}/revoke",
        headers=_session_headers(
            caller["session_uuid"],
            csrf_client=ctx["client"],
        ),
    )
    assert response.status == 400
    assert ctx["state"].touch_ui_session(caller["session_uuid"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "session_ref",
    ["id-", "id-0", "id-01", "id-+1", "id-١", "id-１２", "id-9223372036854775808"],
)
async def test_revoke_endpoint_requires_canonical_ascii_int64_reference(
    ctx, session_ref: str,
):
    """Row references have one unambiguous, portable wire representation."""
    caller = ctx["state"].create_ui_session(user_agent="A")
    response = await ctx["client"].post(
        f"/api/auth/sessions/{session_ref}/revoke",
        headers=_session_headers(
            caller["session_uuid"],
            csrf_client=ctx["client"],
        ),
    )
    assert response.status == 400
    assert ctx["state"].touch_ui_session(caller["session_uuid"])


def test_session_management_ui_revokes_by_non_secret_row_id():
    html = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "one_link"
        / "web"
        / "index.html"
    ).read_text(encoding="utf-8")
    assert "id-${encodeURIComponent(String(s.id))}/revoke" in html
    assert "encodeURIComponent(s.session_uuid_prefix)}/revoke" not in html


# ── access-denied self-heal page ─────────────────────────────────


def test_access_denied_page_includes_self_heal_script():
    page = UIServer._auth_failed_help_page(reason="stale_token")
    # Marker name appears in the JS check.
    assert SESSION_PRESENT_MARKER_COOKIE in page
    # Heal logic strips the query + reloads.
    assert "location.replace" in page
    assert "location.pathname" in page
    # Still shows the static fallback help text for users WITHOUT
    # a marker cookie (private windows, first-time browsers).
    assert "tray" in page.lower()


@pytest.mark.asyncio
async def test_stale_token_localhost_browser_cannot_mint_session(ctx):
    """Loopback and navigation headers are not owner authentication."""
    r = await ctx["client"].get(
        "/?t=definitely-not-a-real-token",
        headers={"Accept": "text/html"},
    )
    assert r.status == 401, await r.text()
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert SESSION_COOKIE_NAME not in cookie_hdrs
    assert SESSION_PRESENT_MARKER_COOKIE not in cookie_hdrs
    assert "ol_ui" not in cookie_hdrs


@pytest.mark.asyncio
async def test_stale_query_with_valid_session_recovers_without_minting(ctx):
    session = ctx["state"].create_ui_session(user_agent="valid")
    r = await ctx["client"].get(
        "/?t=definitely-not-a-real-token",
        headers={
            "Accept": "text/html",
            "Authorization": f"Bearer {session['session_uuid']}",
        },
    )
    assert r.status == 200, await r.text()
    assert "location.replace(location.pathname)" in await r.text()
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert "ol_ui" not in cookie_hdrs or "Max-Age=0" in cookie_hdrs
    assert SESSION_COOKIE_NAME not in cookie_hdrs or "Max-Age=0" in cookie_hdrs


def test_help_page_references_marker_cookie():
    """The help page (used for non-localhost / non-document
    navigations that can't use the silent recovery) must include the
    marker-cookie self-heal script so saved-session browsers can
    still skip the dead-end."""
    page = UIServer._auth_failed_help_page(reason="stale_token")
    assert SESSION_PRESENT_MARKER_COOKIE in page
    assert "location.replace" in page


# ── privacy toggles + auto-prune ─────────────────────────────────


@pytest.mark.asyncio
async def test_persistence_toggle_off_stops_cookie_issuance(ctx):
    """Flipping persistence OFF must stop minting new ol_session
    cookies — every subsequent bootstrap should be cookie-free."""
    # Flip OFF.
    r = await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"persistence_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    assert r.status == 200, await r.text()
    body = await r.json()
    assert body["persistence_enabled"] is False
    # Fresh client (no inherited cookies) hits the bootstrap.
    fresh_client = TestClient(TestServer(ctx["server"].app))
    await fresh_client.start_server()
    try:
        r2 = await fresh_client.get(f"/?t={ctx['token']}")
        assert r2.status == 200
        cookie_hdrs = " ".join(r2.headers.getall("Set-Cookie", []))
        assert SESSION_COOKIE_NAME in cookie_hdrs
        assert SESSION_PRESENT_MARKER_COOKIE in cookie_hdrs
        assert COOKIE_NAME in cookie_hdrs
        assert cookie_hdrs.count("Max-Age=0") == 3
    finally:
        await fresh_client.close()


@pytest.mark.asyncio
async def test_persistence_toggle_off_wipes_table(ctx):
    """Flipping persistence OFF must hard-delete the ui_sessions
    table so historical session rows don't survive the choice."""
    ctx["state"].create_ui_session(user_agent="A")
    ctx["state"].create_ui_session(user_agent="B")
    assert len(ctx["state"].list_ui_sessions()) == 2
    r = await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"persistence_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    assert r.status == 200
    body = await r.json()
    assert body["wiped_sessions"] == 2
    assert len(ctx["state"].list_ui_sessions()) == 0
    # Response also clears the caller's cookies.
    cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
    assert SESSION_COOKIE_NAME in cookie_hdrs
    assert "Max-Age=0" in cookie_hdrs


@pytest.mark.asyncio
async def test_labels_toggle_off_strips_existing_fingerprints(ctx):
    """Flipping labels OFF must strip the label + UA hash columns
    from EVERY existing row so the historical fingerprints don't
    linger after the user changed their mind."""
    a = ctx["state"].create_ui_session(
        user_agent="Mozilla/5.0 (Windows) Edg/120.0",
    )
    b = ctx["state"].create_ui_session(user_agent="Firefox/120")
    assert ctx["state"].lookup_ui_session(a["session_uuid"])["label"]
    r = await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"labels_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    assert r.status == 200
    body = await r.json()
    assert body["stripped_labels"] == 2
    a_after = ctx["state"].lookup_ui_session(a["session_uuid"])
    b_after = ctx["state"].lookup_ui_session(b["session_uuid"])
    assert a_after["label"] is None
    assert a_after["user_agent_hash"] is None
    assert b_after["label"] is None
    assert b_after["user_agent_hash"] is None


@pytest.mark.asyncio
async def test_labels_toggle_off_skips_ua_on_future_sessions(ctx):
    """After flipping labels OFF, _set_ui_cookie must not pass
    User-Agent into create_ui_session for NEW sessions either."""
    await ctx["client"].post(
        "/api/auth/sessions/settings",
        json={"labels_enabled": False},
        headers=_auth_headers(ctx, csrf_client=ctx["client"]),
    )
    # Fresh bootstrap.
    fresh_client = TestClient(TestServer(ctx["server"].app))
    await fresh_client.start_server()
    try:
        r = await fresh_client.get(
            f"/?t={ctx['token']}",
            headers={"User-Agent": "Mozilla/5.0 (Windows) Edg/120.0"},
        )
        assert r.status == 200
    finally:
        await fresh_client.close()
    # The newest row should have no label / UA hash.
    rows = ctx["state"].list_ui_sessions()
    assert len(rows) == 1
    assert rows[0]["label"] is None
    assert rows[0]["user_agent_hash"] is None


@pytest.mark.asyncio
async def test_settings_get_returns_defaults_when_unset(ctx):
    """Out-of-the-box (no setting written), both toggles default ON
    so the just-works UX kicks in for first-time installs."""
    r = await ctx["client"].get(
        "/api/auth/sessions/settings",
        headers=_auth_headers(ctx),
    )
    assert r.status == 200
    body = await r.json()
    assert body["persistence_enabled"] is True
    assert body["labels_enabled"] is True


def test_wipe_ui_sessions_hard_deletes(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    s.create_ui_session()
    s.create_ui_session()
    assert s.wipe_ui_sessions() == 2
    assert s.list_ui_sessions(include_revoked=True) == []
    s.close()


def test_strip_labels_clears_columns_in_place(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    a = s.create_ui_session(user_agent="Mozilla/5.0 Edg/120")
    b = s.create_ui_session(user_agent="Firefox/120")
    affected = s.strip_ui_session_labels()
    assert affected == 2
    ra = s.lookup_ui_session(a["session_uuid"])
    rb = s.lookup_ui_session(b["session_uuid"])
    assert ra["label"] is None and ra["user_agent_hash"] is None
    assert rb["label"] is None and rb["user_agent_hash"] is None
    # Sessions themselves stay valid — the uuid still authenticates.
    assert s.touch_ui_session(a["session_uuid"]) is True
    s.close()


def test_prune_only_drops_old_rows(tmp_path: Path):
    s = State(db_path=tmp_path / "s.db")
    fresh = s.create_ui_session()
    # Backdate the second session's last_seen_ms past the cutoff.
    stale = s.create_ui_session()
    with s._write_lock:
        s._conn.execute(
            "UPDATE ui_sessions SET last_seen_ms=? WHERE session_uuid=?",
            (1, State.ui_session_token_id(stale["session_uuid"])),
        )
        s._conn.commit()
    pruned = s.prune_expired_ui_sessions(older_than_ms=1000)
    assert pruned == 1
    assert s.lookup_ui_session(fresh["session_uuid"]) is not None
    assert s.lookup_ui_session(stale["session_uuid"]) is None
    s.close()


# ── log audit: session uuid never appears in daemon logs ─────────


def test_create_ui_session_never_logs_uuid(tmp_path: Path, caplog):
    """Defense-in-depth: a session uuid is a bearer secret. It must
    NEVER show up in a daemon log line, or a stolen log file could
    be replayed against the live daemon."""
    import logging
    s = State(db_path=tmp_path / "s.db")
    with caplog.at_level(logging.DEBUG):
        sess = s.create_ui_session(user_agent="Mozilla/5.0")
        s.touch_ui_session(sess["session_uuid"])
        s.revoke_ui_session(sess["session_uuid"])

    # If NOTHING was logged, the loop below inspects zero lines and this
    # security claim -- "a bearer secret never reaches a log" -- would be
    # asserted against no evidence at all. Three session operations at DEBUG
    # must produce some output for the absence check to mean anything.
    assert caplog.records, (
        "no log records captured, so 'the uuid never appears in logs' was "
        "checked against nothing"
    )
    for rec in caplog.records:
        assert sess["session_uuid"] not in rec.getMessage(), (
            f"session uuid leaked into log at {rec.levelname}: "
            f"{rec.getMessage()!r}"
        )
    s.close()


# ── sovereignty preset wiring ────────────────────────────────────


def test_preset_definitions_have_session_flags():
    """All three presets must declare both ui_session_* flags so the
    resolver always has a defined preset_value to fall back on."""
    from one_link.sovereignty import ALL_PRESETS
    # The docstring says ALL THREE presets. An empty or shrunken registry would
    # satisfy the loop while leaving the resolver with no preset_value to fall
    # back on for whichever preset went missing.
    assert len(ALL_PRESETS) == 3, f"expected 3 presets, got {sorted(ALL_PRESETS)}"
    for name, p in ALL_PRESETS.items():
        assert isinstance(p.ui_session_persistence_enabled, bool), (
            f"preset {name!r} missing ui_session_persistence_enabled"
        )
        assert isinstance(p.ui_session_labels_enabled, bool), (
            f"preset {name!r} missing ui_session_labels_enabled"
        )


def test_just_works_preset_keeps_sessions_on():
    from one_link.sovereignty import get_preset
    p = get_preset("just_works")
    assert p.ui_session_persistence_enabled is True
    assert p.ui_session_labels_enabled is True


def test_quiet_preset_keeps_persistence_drops_labels():
    """quiet mode keeps the UX win (cookie survives restarts) but
    strips browser fingerprints."""
    from one_link.sovereignty import get_preset
    p = get_preset("quiet")
    assert p.ui_session_persistence_enabled is True
    assert p.ui_session_labels_enabled is False


def test_off_grid_preset_kills_all_session_state():
    """off_grid mode is true paranoia — no cookies at all, every
    restart sends the user back to the tray-open flow."""
    from one_link.sovereignty import get_preset
    p = get_preset("off_grid")
    assert p.ui_session_persistence_enabled is False
    assert p.ui_session_labels_enabled is False


def test_resolver_explicit_setting_can_only_tighten_preset():
    """Per-feature settings cannot loosen the preset's privacy ceiling."""
    from one_link.sovereignty import (
        resolve_ui_session_persistence_enabled,
        resolve_ui_session_labels_enabled,
    )
    # Off-grid forbids both even when stale settings still say true.
    assert resolve_ui_session_persistence_enabled(
        state_setting="true", preset_name="off_grid",
    ) is False
    assert resolve_ui_session_labels_enabled(
        state_setting="on", preset_name="off_grid",
    ) is False
    # just_works defaults to ON. Explicit 'false' must win.
    assert resolve_ui_session_persistence_enabled(
        state_setting="false", preset_name="just_works",
    ) is False


def test_resolver_empty_setting_falls_back_to_preset():
    from one_link.sovereignty import (
        resolve_ui_session_persistence_enabled,
    )
    for empty in (None, "", "   "):
        assert resolve_ui_session_persistence_enabled(
            state_setting=empty, preset_name="just_works",
        ) is True
        assert resolve_ui_session_persistence_enabled(
            state_setting=empty, preset_name="off_grid",
        ) is False


@pytest.mark.asyncio
async def test_off_grid_preset_blocks_cookie_issuance(ctx):
    """End-to-end: setting the off_grid preset stops the daemon
    from issuing any persistent-session cookies on bootstrap."""
    ctx["state"].set_setting("sovereignty_preset", "off_grid")
    fresh_client = TestClient(TestServer(ctx["server"].app))
    await fresh_client.start_server()
    try:
        r = await fresh_client.get(f"/?t={ctx['token']}")
        assert r.status == 200
        cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
        assert SESSION_COOKIE_NAME in cookie_hdrs
        assert SESSION_PRESENT_MARKER_COOKIE in cookie_hdrs
        assert cookie_hdrs.count("Max-Age=0") == 3
    finally:
        await fresh_client.close()


@pytest.mark.asyncio
async def test_quiet_preset_skips_ua_label(ctx):
    """End-to-end: quiet preset still mints cookies but doesn't
    store the User-Agent fingerprint."""
    ctx["state"].set_setting("sovereignty_preset", "quiet")
    fresh_client = TestClient(TestServer(ctx["server"].app))
    await fresh_client.start_server()
    try:
        r = await fresh_client.get(
            f"/?t={ctx['token']}",
            headers={"User-Agent": "Mozilla/5.0 (Windows) Edg/120"},
        )
        assert r.status == 200
        cookie_hdrs = " ".join(r.headers.getall("Set-Cookie", []))
        assert cookie_hdrs.count("Max-Age=0") == 3
        assert "ol_persistent_session_token" in await r.text()
    finally:
        await fresh_client.close()
    rows = ctx["state"].list_ui_sessions()
    assert len(rows) == 1
    assert rows[0]["label"] is None, (
        "quiet preset must skip UA label storage"
    )


@pytest.mark.asyncio
async def test_sovereignty_status_surfaces_session_flags(ctx):
    """The Privacy panel reads /api/sovereignty/status to render the
    'What's turned on right now' list. Both new session flags must
    appear there so users see them alongside update_check / mdns /
    rendezvous."""
    r = await ctx["client"].get(
        "/api/sovereignty/status",
        headers=_auth_headers(ctx),
    )
    assert r.status == 200
    body = await r.json()
    feat = body.get("features", {})
    assert "ui_session_persistence" in feat
    assert "ui_session_labels" in feat
    assert "enabled" in feat["ui_session_persistence"]
    assert "source" in feat["ui_session_persistence"]


@pytest.mark.asyncio
async def test_sovereignty_preset_list_includes_session_flags(ctx):
    """The preset list (used to render the 3 cards) must include the
    new session flags so the UI can describe what each preset does
    to sessions if it wants to surface that detail later."""
    r = await ctx["client"].get(
        "/api/sovereignty/preset",
        headers=_auth_headers(ctx),
    )
    assert r.status == 200
    body = await r.json()
    by_name = {p["name"]: p for p in body["presets"]}
    assert by_name["just_works"]["ui_session_persistence_enabled"] is True
    assert by_name["just_works"]["ui_session_labels_enabled"] is True
    assert by_name["quiet"]["ui_session_persistence_enabled"] is True
    assert by_name["quiet"]["ui_session_labels_enabled"] is False
    assert by_name["off_grid"]["ui_session_persistence_enabled"] is False
    assert by_name["off_grid"]["ui_session_labels_enabled"] is False


def test_privacy_panel_renders_session_rows():
    """Index.html must render the two session-flag rows in the
    Privacy panel's 'What's turned on right now' section so the
    user can see + audit session state from the same panel that
    holds update_check / mdns / etc."""
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert "ui_session_persistence" in src, (
        "Privacy panel must read feat.ui_session_persistence so "
        "the row renders with the resolved enabled state"
    )
    assert "ui_session_labels" in src
    assert "Stay signed in across daemon restarts" in src
    assert "Remember which browser is which" in src


def test_session_bearer_recovery_never_serializes_secret_into_url():
    """A revocable browser bearer is valid only as an explicit header.

    A retry path must never copy it into ``?t=`` where browser history,
    referrers, screenshots, or access logs could retain it.
    """
    src = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "index.html"
    ).read_text(encoding="utf-8")
    assert "encodeURIComponent(stashedToken)" not in src
    assert 'location.href = location.pathname + "?t="' not in src
    # Recovery validates the bearer by one header-authenticated request;
    # the probe's own source may not build a URL from anything.
    start = src.find("async function _probeOwnerSession()")
    assert start > 0
    probe = src[start:src.find("\n  }\n", start)]
    assert 'await fetch("/api/me", { cache: "no-store" });' in probe
    assert "?t=" not in probe and "encodeURIComponent" not in probe and "location" not in probe
    assert "probe: _probeOwnerSession," in src

    sw = (
        Path(__file__).resolve().parents[1]
        / "src" / "one_link" / "web" / "sw.js"
    ).read_text(encoding="utf-8")
    assert 'const CACHE_NAME = "one-link-shell-v4";' in sw
    assert 'const carriesBootstrapToken = url.searchParams.has("t");' in sw
    assert "? authenticatedApiFetch(event.request)" in sw
    assert "res.status === 200 && !carriesBootstrapToken" in sw
    assert 'caches.match("/")' in sw
