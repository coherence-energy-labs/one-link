"""v0.11.4 — SAS works offline + diagnostics resilience.

Two bug fixes that surfaced from real screenshots:

1. SAS shows "(unavailable)" for an offline paired peer, blocking
   in-person verification. SAS is purely deterministic from the two
   pubkeys, so requiring the peer to be live on mDNS was a leftover
   constraint. Fix: api_get_sas falls back to the stored pubkey
   when mDNS doesn't have the peer right now.

2. /api/debug/health returned 401 when the auth cookie expired,
   defeating the diagnostics modal's whole purpose ("open this
   when something feels broken"). The endpoint leaks no PII and
   the daemon binds to 127.0.0.1 only, so it's safe to skip the
   token guard.

Plus belt-and-suspenders: any other 401 from the api wrapper now
triggers a clear "Session expired — relaunch" banner instead of a
cryptic per-endpoint message.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State


def _identity(host: str = "host") -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname=host,
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    # Add a paired peer with a real pubkey but DON'T add it to mDNS —
    # this is the "offline paired peer" case.
    peer_sk = Ed25519PrivateKey.generate()
    peer_pub = peer_sk.public_key().public_bytes_raw()
    peer_fp = fingerprint_of(peer_pub)
    state.upsert_peer(
        fingerprint=peer_fp, short_id=peer_fp[:8],
        pubkey=peer_pub, hostname="bob",
    )
    state.set_peer_trust(peer_fp, "pinned")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None  # No mDNS — peer is offline.
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token, peer_fp, peer_pub
    finally:
        await client.close()
        state.close()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── SAS works for offline paired peers ───────────────────────

@pytest.mark.asyncio
async def test_sas_works_for_offline_paired_peer(http):
    """The whole point of v0.11.4 — paired peer offline, SAS still
    computes from the stored pubkey."""
    client, _, _, token, peer_fp, _ = http
    resp = await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )
    assert resp.status == 200, await resp.text()
    j = await resp.json()
    assert "sas" in j
    assert j["sas"]
    assert "formatted" in j


@pytest.mark.asyncio
async def test_sas_is_deterministic_from_pubkeys(http):
    """SAS must be the same value across calls — both ends of the
    in-person verification need to read the same digits/art."""
    client, _, _, token, peer_fp, _ = http
    r1 = await (await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )).json()
    r2 = await (await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )).json()
    assert r1["sas"] == r2["sas"]
    assert r1["formatted"] == r2["formatted"]


@pytest.mark.asyncio
async def test_sas_404_only_when_no_pubkey_at_all(http):
    """The 404 path should ONLY fire when truly nothing is on file —
    not for an offline-but-known paired peer."""
    client, _, _, token, _, _ = http
    # Random fingerprint that's neither on mDNS nor in the peer DB.
    resp = await client.get(
        f"/api/peers/{'00' * 32}/sas", headers=_h(token),
    )
    assert resp.status == 404


@pytest.mark.asyncio
async def test_sas_matches_compute_sas_directly(http):
    """The endpoint must return exactly what the underlying
    compute_sas helper returns from the SAME pubkeys. Pin so a
    refactor can't accidentally double-hash or swap argument order."""
    client, daemon, _, token, peer_fp, peer_pub = http
    from one_link.pairing import compute_sas
    expected = compute_sas(daemon.me.public_bytes, peer_pub)
    resp = await client.get(
        f"/api/peers/{peer_fp}/sas", headers=_h(token),
    )
    j = await resp.json()
    assert j["sas"] == expected


# ───────── /api/debug/health is auth-free ───────────────────────────

@pytest.mark.asyncio
async def test_debug_health_works_without_auth(http):
    """The diagnostics surface must work even when the session
    cookie expires — that's the whole point of the modal."""
    client, _, _, _, _, _ = http
    resp = await client.get("/api/debug/health")  # No headers.
    assert resp.status == 200
    j = await resp.json()
    assert "checks" in j or "ok" in j


@pytest.mark.asyncio
async def test_debug_health_works_with_auth(http):
    """Authed requests still pass — un-guarding shouldn't make the
    endpoint reject token-bearing callers."""
    client, _, _, token, _, _ = http
    resp = await client.get("/api/debug/health", headers=_h(token))
    assert resp.status == 200


@pytest.mark.asyncio
async def test_other_endpoints_still_guarded(http):
    """Belt-and-suspenders: only /api/debug/health is auth-free.
    Confirm that some adjacent endpoint still 401s without auth."""
    client, _, _, _, _, _ = http
    resp = await client.get("/api/peers")
    assert resp.status == 401


# ───────── Frontend: 401 banner ─────────────────────────────────────

def _function_body(page: str, signature: str) -> str:
    """Source of one top-level feature function in the shipped page."""
    start = page.find(signature)
    assert start > 0, f"{signature} is not in the shipped page"
    end = page.find("\n  }\n", start)
    assert end > start
    return page[start:end]


def _css_rule(page: str, selector: str) -> str:
    start = page.find(selector + " {")
    assert start > 0, f"no CSS rule for {selector}"
    return page[start:page.find("}", start)]


def test_global_401_handler_present(index_html: str):
    """Pin _maybe401 + the banner so a refactor can't quietly drop
    the global 401 handling.

    A 401 is handed to windowLink, which probes the credential, keeps
    retrying while the daemon cannot be reached, and renders the signed-out
    line only after the daemon has refused the credential twice
    (tests/js/test_window_link.cjs)."""
    handler = _function_body(index_html, "function _maybe401(status)")
    assert "if (status !== 401) return;" in handler
    assert "windowLink.unauthorized();" in handler
    assert "function showSessionExpiredBanner(text)" in index_html
    renderer = _function_body(index_html, "function _renderWindowStatus(kind)")
    assert "showSessionExpiredBanner(text);" in renderer


def test_session_expired_banner_class_styled(index_html: str):
    """The signed-out line needs its own visible styling, and it must take
    its place in the layout.

    This test used to assert ``position: fixed`` appeared somewhere in the
    page, which any rule satisfied. The fixed position was the defect: at
    ``top: 56px`` the banner sat on the grid row the status line occupies,
    so the two printed over each other (2026-11-25). The rule is now a
    modifier on that one in-flow element and may not position itself."""
    rule = _css_rule(index_html, ".offline-banner.session-expired-banner")
    assert "background:" in rule and "var(--bad)" in rule
    for declaration in ("position", "top:", "left:", "right:", "z-index"):
        assert declaration not in rule, f"the signed-out line positions itself ({declaration})"
    # No free-standing rule either: it would style a second element.
    assert "\n  .session-expired-banner {" not in index_html
    base = _css_rule(index_html, "  .offline-banner")
    assert "position" not in base


def test_api_wrappers_call_maybe401(index_html: str):
    """Every fetch path in the api object must invoke _maybe401 so
    a 401 from any endpoint surfaces the banner. Without this only
    /api/foo would trigger it; the global session-expired UX is
    the whole point. v0.21.x grew the per-verb bodies (AbortController
    + _apiError plumbing) so each verb now spans more chars; the
    search window needs to be wide enough to cover get + post + del
    + upload (the 4 verbs that actually hit the network)."""
    idx = index_html.find("const api = {")
    assert idx > 0
    # Bound the four network primitives structurally. A fixed character
    # window became a false negative as upload recovery/idempotency handling
    # grew, even though all four wrappers still invoked the guard.
    end = index_html.find("\n    folders()", idx)
    assert end > idx
    snippet = index_html[idx:end]
    # Each network-touching verb (get, post, del, upload) calls _maybe401.
    assert snippet.count("_maybe401(r.status)") >= 4


def test_session_expired_banner_has_relaunch_guidance(index_html: str):
    """The banner must tell the user WHAT to do, not just announce
    a problem."""
    body = _function_body(index_html, "function showSessionExpiredBanner(text)")
    # The actionable instruction is the load-bearing UX: without it
    # the user is stuck staring at a line that says "signed out".
    # This test used to look for the word "Reload" within 3200 characters
    # of the function, and a code comment supplied it. It now reads the
    # function's own body, comments removed.
    code = "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("//"))
    assert '"This window was signed out."' in code
    assert "desktop shortcut" in code and "tray icon" in code
    assert "Your data is safe." in code
    # Signed out is reached only after the daemon refused the credential
    # twice, and nothing on the page can mint a new one. A button here
    # could not work, so there is none; while the credential is merely
    # unverified the line says "Restoring One Link…" and offers Try now.
    assert "button" not in code.lower()
    # Engineer wording does not belong in front of a person.
    for jargon in ("access key", "address bar", "validate", "bearer", "token", "401"):
        assert jargon not in code.lower()
    restoring = _function_body(index_html, "function _renderWindowStatus(kind)")
    assert '"Try now"' in restoring
    assert "windowLink.retryNow();" in restoring
    assert "LiveRefresh.forceReconnectNow();" in restoring


def test_session_expired_banner_only_shows_once(index_html: str):
    """If five endpoints all 401 in quick succession, we should
    NOT stack five banners.

    The once-only flag this test used to pin is gone because there is no
    second element to stack: the signed-out status is written into the
    status line's own text node. A burst of 401s starting exactly one
    recovery is tested in tests/js/test_window_link.cjs."""
    assert 'id = "session-expired-banner"' not in index_html
    assert 'getElementById("session-expired-banner")' not in index_html
    body = _function_body(index_html, "function showSessionExpiredBanner(text)")
    assert "document.body.appendChild" not in body
    assert 'createElement("div")' not in body


# ───────── version pin ──────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
