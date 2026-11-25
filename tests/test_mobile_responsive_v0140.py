"""v0.14.0 — Mobile-responsive web UI + Markov prefetch + Service
Worker + frame-budget instrumentation.

Ship-spec gated by docs/PRINCIPLES.md:

  Reach:  iOS Safari and Android Chrome users can use One Link
          who couldn't before (sub-720px viewports were broken
          previously).
  Hide:   the desktop sidebar disappears into a slide-in drawer
          on mobile; users see one pane at a time instead of three.
  Async:  Service Worker queues sends to IDB when fetch fails;
          the browser's sync event drains when connectivity
          returns. Closing the tab no longer loses outbound msgs.
  Depth:  predictive peer-switch prefetch via a sparse Markov
          chain over recent transitions, persisted under 4KB,
          + frame-budget instrumentation (window.__oneLinkFrameBudget)
          for SLA regression in CI.

Tests cover the markup, helpers, server SW route, and the
correctness of the Markov persistence cap.
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


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="mobile-host",
    )


@pytest_asyncio.fixture
async def http(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    test_server = TestServer(server.app)
    client = TestClient(test_server)
    await client.start_server()
    try:
        yield client, daemon, state, server.token
    finally:
        await client.close()
        state.close()


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def sw_js() -> str:
    return Path("src/one_link/web/sw.js").read_text(encoding="utf-8")


def _mobile_media_blocks(index_html: str) -> list[str]:
    """Return every complete 720px media block without fixed-size slicing."""
    needle = "@media (max-width: 720px)"
    blocks: list[str] = []
    cursor = 0
    while True:
        start = index_html.find(needle, cursor)
        if start < 0:
            return blocks
        opening = index_html.find("{", start + len(needle))
        assert opening >= 0, "mobile media query has no opening brace"
        depth = 0
        for end in range(opening, len(index_html)):
            char = index_html[end]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(index_html[start:end + 1])
                    cursor = end + 1
                    break
        else:
            raise AssertionError("mobile media query has no closing brace")


# ───────── mobile layout markup ──────────────────────────────────────

def test_mobile_media_query_exists(index_html: str):
    """The 720px breakpoint MUST exist; without it the layout never
    collapses on phones and Reach is zero."""
    assert "@media (max-width: 720px)" in index_html


def test_mobile_breakpoint_overrides_main_grid(index_html: str):
    """Main grid must collapse to 1fr at <720px or the sidebar +
    chat overflow horizontally."""
    idx = index_html.find("@media (max-width: 720px)")
    # Find the SECOND media-query block (the new full-layout one).
    idx2 = index_html.find("@media (max-width: 720px)", idx + 1)
    assert idx2 > 0
    scope = index_html[idx2:idx2 + 9000]
    assert ".main {" in scope
    assert "grid-template-columns: 1fr !important;" in scope


def test_sidebar_becomes_drawer_overlay(index_html: str):
    """Sidebar must position fixed + translateX off-screen on mobile."""
    assert "transform: translateX(-100%);" in index_html
    assert ".app.mobile-side-open .side" in index_html


def test_mobile_scrim_present(index_html: str):
    """Scrim sits behind the open drawer; tap-out closes it."""
    assert 'id="mobile-scrim"' in index_html
    assert ".mobile-scrim {" in index_html


def test_hamburger_button_present(index_html: str):
    """Hamburger in conversation header AND top header so users
    without a peer selected can also open the drawer."""
    assert 'id="mobile-hamburger"' in index_html
    assert 'id="mobile-hamburger-top"' in index_html


def test_hamburger_hidden_on_desktop(index_html: str):
    """Default state must be display:none; CSS flips to grid in the
    mobile media query. Find the OUT-OF-MEDIA-QUERY `.mobile-hamburger`
    rule (the second occurrence, since the in-media-query one
    appears inside `@media (max-width: 720px)` first)."""
    first = index_html.find(".mobile-hamburger {")
    assert first > 0
    second = index_html.find(".mobile-hamburger {", first + 1)
    assert second > 0, "default (out-of-media) .mobile-hamburger rule not found"
    snippet = index_html[second:second + 500]
    assert "display: none;" in snippet


def test_touch_target_minimums(index_html: str):
    """44px is the iOS HIG minimum for tap targets. Buttons that
    are smaller on desktop MUST grow on mobile. We allow the
    rule to live in ANY @media (max-width: 720px) block (the
    file now has multiple as more responsive UI ships)."""
    blocks = _mobile_media_blocks(index_html)
    assert blocks, "no mobile media-query blocks found"
    has_44 = any("44px" in block for block in blocks)
    assert has_44, (
        "44px touch-target minimum must appear in at least one "
        "@media (max-width: 720px) block"
    )


def test_one_setup_is_phone_native_inside_mobile_query(index_html: str):
    """One Setup is often the first screen a phone user sees. It must
    behave like a mobile page, not a desktop modal squeezed onto glass."""
    markers = (
        ".onboarding-backdrop",
        ".onboarding-card",
        ".setup-device-line",
        "grid-template-columns: 1fr;",
        ".onboarding-actions button",
        "min-height: 44px",
        "env(safe-area-inset-top)",
        "env(safe-area-inset-bottom)",
    )
    assert any(
        all(marker in block for marker in markers)
        for block in _mobile_media_blocks(index_html)
    ), "One Setup mobile rules must remain in one 720px media block"


def test_one_setup_prevents_ios_input_zoom(index_html: str):
    assert any(
        '.onboarding-step input[type="text"]' in block
        and "font-size: 16px" in block
        and "min-height: 46px" in block
        for block in _mobile_media_blocks(index_html)
    )


def test_one_setup_receipts_stack_on_phone(index_html: str):
    assert any(
        ".setup-receipt-row," in block
        and ".setup-technical-list div" in block
        and "grid-template-columns: 1fr;" in block
        for block in _mobile_media_blocks(index_html)
    )


def test_ios_zoom_prevention_on_textarea(index_html: str):
    """iOS Safari zooms the page when an input has font-size < 16px.
    Composer textarea must bump to 16px on mobile."""
    assert any(
        ".composer textarea" in block and "font-size: 16px" in block
        for block in _mobile_media_blocks(index_html)
    )


# ───────── mobile sidebar JS ────────────────────────────────────────

def test_open_close_toggle_helpers_present(index_html: str):
    assert "function openMobileSidebar()" in index_html
    assert "function closeMobileSidebar()" in index_html
    assert "function toggleMobileSidebar()" in index_html


def test_select_peer_closes_sidebar(index_html: str):
    """Tapping a peer auto-closes the drawer on mobile (otherwise
    the user has to scrim-tap or hamburger-tap every time)."""
    idx = index_html.find("function selectPeer(shortId)")
    snippet = index_html[idx:idx + 500]
    assert "closeMobileSidebar()" in snippet


def test_select_group_closes_sidebar(index_html: str):
    idx = index_html.find("async function selectGroup(gidHex)")
    snippet = index_html[idx:idx + 500]
    assert "closeMobileSidebar()" in snippet


def test_scrim_tap_closes(index_html: str):
    assert '$("#mobile-scrim")' in index_html
    idx = index_html.find('$("#mobile-scrim")')
    snippet = index_html[idx:idx + 200]
    assert "closeMobileSidebar" in snippet


# ───────── Markov prefetch ──────────────────────────────────────────

def test_markov_module_present(index_html: str):
    assert "MARKOV_KEY" in index_html
    assert "function _recordSwitch(toShortId)" in index_html
    assert "function _predictNextPeerShort(currentShortId)" in index_html
    assert "function _prefetchPeerMessages(shortId)" in index_html


def test_markov_persistence_cap_under_4kb(index_html: str):
    """The 4KB persistence cap is the Frontier-discipline constraint.
    Pin so a refactor can't blow up localStorage usage."""
    idx = index_html.find("function _saveMarkov(m)")
    assert idx > 0
    snippet = index_html[idx:idx + 2000]
    assert "4096" in snippet
    # When the matrix exceeds 4KB, all counts halve. Pin the
    # decay step so it can't be removed.
    assert "Math.floor(out[from][to] / 2)" in snippet


def test_markov_capped_from_keys(index_html: str):
    """The from-keys are capped at MARKOV_MAX_FROM_KEYS so the
    matrix can't grow unbounded with peer count."""
    assert "MARKOV_MAX_FROM_KEYS = 32" in index_html


def test_markov_uses_laplace_smoothing(index_html: str):
    """Without smoothing, a brand-new peer would never win the
    argmax. Pin the prior."""
    assert "MARKOV_PRIOR" in index_html


def test_prefetch_uses_idle_callback(index_html: str):
    """Prefetch is idle-deferred so it never competes with the
    user's actual interaction."""
    idx = index_html.find("function _prefetchPeerMessages(shortId)")
    snippet = index_html[idx:idx + 1500]
    assert "requestIdleCallback" in snippet


def test_prefetch_cache_capped(index_html: str):
    """8-entry cap on the per-peer cache so memory can't grow
    without bound."""
    idx = index_html.find("function _prefetchPeerMessages(shortId)")
    snippet = index_html[idx:idx + 1500]
    assert "state.peerMessageCache.size >= 8" in snippet


def test_select_peer_records_switch_and_prefetches(index_html: str):
    idx = index_html.find("function selectPeer(shortId)")
    snippet = index_html[idx:idx + 800]
    assert "_recordSwitch(shortId)" in snippet
    assert "_maybePrefetchNext(shortId)" in snippet


# ───────── Frame-budget instrumentation ─────────────────────────────

def test_frame_budget_state_present(index_html: str):
    assert "state.frameBudget" in index_html


def test_measure_helpers_present(index_html: str):
    assert "function _measure(label, fn)" in index_html
    assert "async function _measureAsync(label, fn)" in index_html


def test_render_messages_wrapped_with_measure(index_html: str):
    """The render hot path must be measured or our SLA regression
    in CI has nothing to read."""
    idx = index_html.find("function renderMessages()")
    snippet = index_html[idx:idx + 200]
    assert '_measure("renderMessages"' in snippet


def test_chat_render_sticks_to_bottom_for_live_edge_and_own_sends(index_html: str):
    """Sending a message or staying at the live edge must keep the newest
    bubble visible after the virtualized DOM rebuild."""
    assert "function _forceNextMessagesToBottom" in index_html
    assert "function _forceMessagesBottomNowAndAfter" in index_html
    assert "function _isMessagesNearBottom" in index_html
    assert "function _scrollMessagesToVisualBottom" in index_html
    assert 'history.scrollRestoration = "manual"' in index_html
    assert "scroll-padding-bottom: calc(96px + env(safe-area-inset-bottom, 0px));" in index_html

    scheduler_idx = index_html.find("function scheduleRenderMessages()")
    scheduler = index_html[scheduler_idx:scheduler_idx + 500]
    assert "_isMessagesNearBottom(m)" in scheduler
    assert "_forceNextMessagesToBottom(350)" in scheduler

    send_idx = index_html.find("messageStore.appendDirect(optimistic);")
    send_path = index_html[send_idx:send_idx + 700]
    assert "_forceNextMessagesToBottom();" in send_path
    assert "renderMessages();" in send_path

    switch_idx = index_html.find("function selectPeer(shortId)")
    switch_path = index_html[switch_idx:switch_idx + 1100]
    assert "_resetRenderedMessageCount();" in switch_path
    assert "_forceMessagesBottomNowAndAfter();" in switch_path


def test_image_preview_load_preserves_bottom_scroll(index_html: str):
    """Large image thumbnails load after render; their load event must not
    push the newest bubble under the composer."""
    assert "function _keepMessagesBottomAfterMediaLoad(mediaEl)" in index_html
    helper_idx = index_html.find("function _keepMessagesBottomAfterMediaLoad")
    helper = index_html[helper_idx:helper_idx + 900]
    assert "addEventListener(\"load\", settle" in helper
    assert "mediaEl.decode()" in helper
    assert "_scrollMessagesToVisualBottom(container)" in helper
    assert index_html.count("_keepMessagesBottomAfterMediaLoad(img);") >= 2


def test_chat_colors_are_deterministic_across_devices(index_html: str):
    """Message colors and peer accents should not depend on browser-local
    cache unless the user explicitly saves a custom group color."""
    assert "--bubble-in:  linear-gradient(135deg, #263f74 0%, #0f6670 100%);" in index_html
    assert "--bubble-out: linear-gradient(135deg, #6a4dff 0%, #4ec1ff 100%);" in index_html
    assert index_html.count("--bubble-in: linear-gradient(135deg, #263f74 0%, #0f6670 100%);") >= 1
    assert index_html.count("--bubble-out: linear-gradient(135deg, #6a4dff 0%, #4ec1ff 100%);") >= 1
    assert "function deterministicAccentForId(id)" in index_html
    assert "function peerAccentColor(peer)" in index_html
    assert "linear-gradient(135deg, #7c5cff 0%, #4ec1ff 100%)" in index_html
    assert "av.style.background = peerAccentColor(p);" in index_html
    assert "|| deterministicAccentForId(gid)" in index_html


def test_clear_unread_rerenders_open_chat(index_html: str):
    """Unread dividers must disappear as soon as the open thread is read."""
    idx = index_html.find("function clearUnread(peerShortId)")
    snippet = index_html[idx:idx + 700]
    assert "delete state.unreadByPeer[peerShortId]" in snippet
    assert "state.selectedPeer === peerShortId" in snippet
    assert "scheduleRenderMessages()" in snippet


def test_conversation_header_status_uses_live_peer_refresh(index_html: str):
    """The sidebar and conversation header must use the same latency/reach
    dot state after peer health refreshes."""
    assert "function renderConversationPeerStatus(peer)" in index_html
    assert "const lc = latencyClass(peer);" in index_html
    helper_idx = index_html.find("function renderConversationPeerStatus(peer)")
    helper = index_html[helper_idx:helper_idx + 1600]
    assert "Device chat - " in helper
    assert "Device chat Â·" not in helper
    idx = index_html.find("async function refreshPeers()")
    snippet = index_html[idx:idx + 1200]
    assert "renderConversationPeerStatus(cur);" in snippet
    assert "renderConvHeaderTrust(cur);" in snippet


def test_jump_to_date_has_validation_and_nearest_fallback(index_html: str):
    """Jump-to-date must not silently fail on impossible or empty dates."""
    assert "function _messagesForJumpDate()" in index_html
    assert "function _localDateKeyFromMs(ms)" in index_html
    assert "function _jumpToMessageNode(target, note)" in index_html
    assert "class=\"jdp-hint\"" in index_html
    assert "input.min = firstKey" in index_html
    assert "input.max = lastKey" in index_html
    assert "chosenYear < 2000 || chosenYear > 2100" in index_html
    assert "Jumped to nearest message" in index_html


def test_file_image_previews_fail_cleanly(index_html: str):
    """Broken local image routes should show useful state, not a broken
    image icon or an empty Details pane."""
    assert "function renderImagePreviewFallback" in index_html
    assert "function attachImagePreviewFallback" in index_html
    assert "function renderFileBubbleDetails" in index_html
    assert "Preview unavailable" in index_html
    assert "Image preview unavailable" in index_html
    assert "file-lightbox-error" in index_html
    assert "file-bubble-details" in index_html
    assert "img.onerror = () =>" in index_html
    assert "body.appendChild(img);\n    img.src = ent.url;" in index_html
    assert "meta.appendChild(img);\n        img.src = previewUrl;" in index_html
    assert "meta.appendChild(img);\n        img.src = cachedUrl;" in index_html
    assert "Open in new tab or save a copy" in index_html


def test_global_frame_budget_accessor(index_html: str):
    """window.__oneLinkFrameBudget is the API CI / Playwright tests
    will read to assert SLAs (p50/p95/p99/max)."""
    assert "window.__oneLinkFrameBudget" in index_html
    idx = index_html.find("window.__oneLinkFrameBudget")
    snippet = index_html[idx:idx + 1500]
    for percentile in ("p50", "p95", "p99", "max"):
        assert percentile in snippet


# ───────── Service Worker + outbox ──────────────────────────────────

def test_sw_registered_from_page(index_html: str):
    assert 'navigator.serviceWorker.register("/sw.js"' in index_html


def test_sw_route_registered(index_html: str):
    """Server must serve /sw.js. The route is at top scope so the
    SW can control "/" — pin the route registration AND the
    Service-Worker-Allowed header."""
    server_py = Path("src/one_link/server.py").read_text(encoding="utf-8")
    assert 'r.add_get("/sw.js"' in server_py
    assert 'Service-Worker-Allowed' in server_py


@pytest.mark.asyncio
async def test_sw_endpoint_serves_javascript(http):
    """End-to-end: hit /sw.js without auth and confirm we get the
    SW source with the right headers."""
    client, _, _, _ = http
    resp = await client.get("/sw.js")
    assert resp.status == 200
    ct = resp.headers.get("Content-Type", "")
    assert "javascript" in ct
    assert resp.headers.get("Service-Worker-Allowed") == "/"
    body = await resp.text()
    # The SW must contain the outbox-drain logic.
    assert "ol-outbox" in body
    assert "drainOutbox" in body


def test_sw_skips_caching_api_paths(sw_js: str):
    """API paths must NEVER be cached (live state). Pin so a
    refactor doesn't accidentally cache /api/me and serve a stale
    version after an identity change. Find the actual fetch
    handler's early-return on /api/ paths, not a comment that
    happens to mention an API URL."""
    idx = sw_js.find('url.pathname.startsWith("/api/")')
    assert idx > 0
    # The next ~200 chars must contain `return;` (early exit so
    # the browser handles the request without SW intervention).
    snippet = sw_js[idx:idx + 200]
    assert "return;" in snippet


def test_sw_drains_via_message_too(sw_js: str):
    """Beyond the browser's `sync` event, the page can poke the SW
    via postMessage to force a flush. Pin both code paths."""
    assert 'event.tag === "ol-outbox"' in sw_js
    assert '"drain-now"' in sw_js


def test_outbox_idb_helpers_present(index_html: str):
    assert "function _outboxOpenDB()" in index_html
    assert "async function _outboxQueue(item)" in index_html
    assert "async function _outboxRequestSync()" in index_html


def test_send_with_outbox_used_for_send(index_html: str):
    """The composer's send path must go through _sendWithOutbox so a
    network-failed send queues instead of toasting and disappearing."""
    assert "_sendWithOutbox" in index_html
    # Pin that sendCurrent uses it. Window is generous because the
    # v0.21.x bulletproof-send rewrite added an optimistic-bubble
    # block before the API call — the pin still has to be in the
    # same function, not anywhere in the file.
    idx = index_html.find("async function sendCurrent()")
    snippet = index_html[idx:idx + 10000]
    assert "_sendWithOutbox(" in snippet


def test_online_event_pokes_drain(index_html: str):
    """When the network comes back, the page proactively asks the
    SW to drain — don't wait on the browser's sync scheduler."""
    assert 'window.addEventListener("online"' in index_html


# ───────── version pin ───────────────────────────────────────────────

def test_page_version_bumped(index_html: str):
    from one_link import __version__
    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html


# ───────── v0.14.1 last-selection persistence + restore ─────────────

def test_last_selection_helpers_present(index_html: str):
    """The persistence helpers + their localStorage key must exist."""
    assert "LAST_SELECTION_KEY" in index_html
    assert "function _saveLastSelection(scope, id)" in index_html
    assert "function _readLastSelection()" in index_html
    assert "function _restoreLastSelection()" in index_html


def test_select_peer_persists(index_html: str):
    idx = index_html.find("function selectPeer(shortId)")
    snippet = index_html[idx:idx + 1200]
    assert '_saveLastSelection("peer", shortId)' in snippet


def test_select_group_persists(index_html: str):
    idx = index_html.find("async function selectGroup(gidHex)")
    snippet = index_html[idx:idx + 800]
    assert '_saveLastSelection("group", gidHex)' in snippet


def test_init_restores_last_selection(index_html: str):
    """The restore step must run after refreshPeers + refreshGroups
    + loadChatPrefs (state needs to be populated first) but BEFORE
    connectWS (so the WS arrives into a fully restored UI)."""
    idx = index_html.find("async function init()")
    snippet = index_html[idx:idx + 6000]
    assert "_restoreLastSelection()" in snippet
    # Order check: restore must come after refreshGroups + loadChatPrefs.
    refresh_groups_idx = snippet.find("await refreshGroups()")
    load_prefs_idx = snippet.find("await loadChatPrefs()")
    restore_idx = snippet.find("_restoreLastSelection()")
    connect_ws_idx = snippet.find("connectWS()")
    assert refresh_groups_idx < restore_idx
    assert load_prefs_idx < restore_idx
    assert restore_idx < connect_ws_idx


def test_restore_silently_skips_missing_peer(index_html: str):
    """If the last-selected peer is no longer paired (unpair from
    another tab), the restore must not throw or toast."""
    idx = index_html.find("function _restoreLastSelection()")
    snippet = index_html[idx:idx + 1500]
    assert "state.peers.has(last.id)" in snippet
    assert "state.groups.has(last.id)" in snippet
