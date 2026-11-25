"""Markup smoke tests for the v0.7.x UX overhaul.

The web UI lives in a single 3k-line index.html. We don't have a JS test
harness, so these tests do two things:

1. Static structural checks — every new ID / class / JS helper added by
   the UX overhaul is present in the served HTML. Regressions where a
   merge accidentally drops a wired-up element will be caught here.

2. Live smoke check — boot a real daemon and assert the same checks
   against what the daemon actually serves (defends against a future
   refactor that splits index.html and forgets to wire it up).
"""

from __future__ import annotations

from pathlib import Path

import aiohttp
import pytest

from tests.harness import daemon_pair


pytestmark = pytest.mark.timeout(60)


WEB_INDEX = Path(__file__).resolve().parent.parent / "src" / "one_link" / "web" / "index.html"


# Element IDs that must exist for the v0.7.x UX overhaul to function.
# Each one is wired to a feature: dropping any breaks user-visible behavior.
EXPECTED_IDS = [
    # Attachment staging tray (replaces auto-send-on-paste)
    "attach-tray",
    # Composer buttons
    "btn-attach2",
    "btn-screenshot",
    "btn-send",
    # v0.7.x post-cleanup: notification permission lives in the
    # Settings modal now, not as a top banner. The button is the
    # only entry point.
    "set-notif",
    # Files panel: Received/Sent toggle + open-inbox button
    "btn-files-received",
    "btn-files-sent",
    "btn-open-inbox",
    # Keyboard shortcuts modal
    "shortcuts-backdrop",
    "shortcuts-close",
    # Existing surfaces we still rely on
    "messages",
    "input",
    "filelist",
    "transferlist",
    # Universal Comms Fabric truth in Activity panel
    "fabric-truth",
    "no-router-kit",
    "no-router-guide",
    "courier-kit",
    "courier-transfer-select",
    "courier-drop-select",
    "courier-outbox-select",
    "courier-removable-select",
    "courier-removable-file-select",
    "courier-chunks",
    "courier-key-token",
    "courier-file-input",
    "btn-courier-export",
    "btn-courier-stage",
    "btn-courier-import-file",
    "btn-courier-import-drop",
    "btn-courier-copy-key",
    "btn-courier-copy-removable",
    "btn-courier-pull-removable",
    "courier-wizard",
    "courier-wizard-steps",
    "btn-courier-guide-send",
    "btn-courier-guide-receive",
    "route-bootstrap-qr",
    "route-bootstrap-token",
    "btn-copy-route-bootstrap",
    "btn-import-route-bootstrap",
    "btn-launch-path-create",
]


# CSS classes whose styling drives the v0.7.x look.
EXPECTED_CLASSES = [
    "attach-tray",
    "chip",
    "img-preview",
    "progress-mini",
    "status-icon",
    "files-toggle",
    "shortcuts-list",
    "lat-dot",
    "copyable",
    "fabric-truth",
    "no-router-kit",
    "nr-guide",
    "courier-kit",
    "courier-wizard",
]


# JS helper functions that must be defined. The names are public-ish
# (the JS is one big IIFE), but their existence is a load-bearing
# contract because the rest of the file calls them.
EXPECTED_JS_HELPERS = [
    "function renderInlineText",
    "function renderInlineNonCode",
    "function renderInlineMarks",
    "function transferForMessage",
    "function statusLabel",
    "function statusKind",
    "function statusGlyph",
    "function renderFileBubble",
    "function renderStaging",
    "function stageFile",
    "function removeStaged",
    "function copyToClipboard",
    "function notifyIncoming",
    "function maybeShowNotifBanner",
    "function latencyClass",
    "function renderFilesPanel",
    "function readAllEntries",
    "function collectFromEntry",
    # Peer version drift stays diagnostic-only; it must not block chat.
    "function recordPeerCompatibility",
    # Structured-error helper used to surface error.code + error.hint
    "function _apiError",
    "function errorToastBody",
    "function renderFabricTruth",
    "function renderNoRouterKit",
    "function renderNoRouterGuide",
    "function renderCourierKit",
    "function _courierChunkHashesFromInput",
    "function _downloadCourierBundle",
    "function setCourierGuideMode",
    "function renderCourierWizard",
    "async function exportCourierBundle",
    "async function importCourierBundleFile",
    "async function refreshCourierStatus",
    "async function refreshFabricTruth",
    "async function copyRouteBootstrapToken",
    "async function importRouteBootstrapToken",
    "async function launchBestPathCreate",
    "/api/fabric/no-router",
    "/api/fabric/mobile-reach",
    "/api/fabric/path-create",
    "/api/fabric/path-create/launch",
    "/api/fabric/path-create/native",
    "/api/courier/status",
    "/api/courier/files",
    "/api/courier/outbox",
    "/api/courier/removable",
    "/api/courier/removable-files",
    "/api/courier/export",
    "/api/courier/export-file",
    "/api/courier/copy-to-removable",
    "/api/courier/copy-from-removable",
    "/api/courier/import",
    "/api/courier/import-file",
    "/api/courier/assemble",
    "/api/route-bootstrap/qr.svg",
    "kit.steps",
    "kit.path_options",
    "kit.creation",
    "operator_guide",
    "nr-paths",
    "nr-guide-step",
    "blocked",
    "route brain",
    "trusted paths",
    "label: \"sources\"",
    "label: \"healed\"",
    "noRouter()",
    "mobileReach()",
    "fabricPathCreate()",
    "launchFabricPathCreate(body)",
    "nativeFabricPathCreate(body)",
    "courierStatus()",
    "courierFiles()",
    "courierOutbox()",
    "courierRemovable()",
    "courierRemovableFiles(targetId)",
    "courierExport(body)",
    "courierExportFile(body)",
    "courierCopyToRemovable(body)",
    "courierCopyFromRemovable(body)",
    "courierImport(body)",
    "courierImportFile(body)",
    "courierAssemble(body)",
    "Offline file ready",
    "Offline bundle saved",
    "Copied offline bundle to",
    "USB copy failed",
    "Pulled offline bundle",
    "USB pull failed",
    "Import failed",
    "Offline delivery folder changed",
    "removable_media",
    "USB delivery",
    "phone bridge",
    "phone courier",
    "Choose or import an offline bundle",
    "Choose a cached transfer",
    "Duplicate protection remembers",
    "Download this transfer as an encrypted offline bundle.",
    "routeBootstrap()",
    "importRouteBootstrap(token)",
]


def _read_local_index() -> str:
    return WEB_INDEX.read_text(encoding="utf-8")


# ─── Static checks against the source file ────────────────────────────

def test_local_index_html_has_all_expected_ids():
    html = _read_local_index()
    missing = [i for i in EXPECTED_IDS if f'id="{i}"' not in html]
    assert not missing, f"missing element IDs in index.html: {missing}"


def test_local_index_html_has_all_expected_classes():
    html = _read_local_index()
    # Class can appear in CSS selectors and HTML class= attributes; check
    # for either form. We deliberately accept a loose substring match
    # because some classes are added dynamically via classList.add().
    missing = []
    for cls in EXPECTED_CLASSES:
        # CSS selector form: ".cls "  or ".cls{"  or ".cls:"  or ".cls."
        # Or as part of class="..." attr
        if (
            f".{cls} " not in html
            and f".{cls}{{" not in html
            and f".{cls}:" not in html
            and f".{cls}." not in html
            and f".{cls}\n" not in html
            and f'class="{cls}"' not in html
            and f'class="{cls} ' not in html
            and f' {cls}"' not in html
            and f' {cls} ' not in html
        ):
            missing.append(cls)
    assert not missing, f"missing classes in index.html: {missing}"


def test_local_index_html_has_all_expected_js_helpers():
    html = _read_local_index()
    missing = [h for h in EXPECTED_JS_HELPERS if h not in html]
    assert not missing, f"missing JS helpers in index.html: {missing}"


def test_inline_text_helper_uses_dom_not_innerhtml():
    """renderInlineText must not concatenate raw user text into innerHTML.
    The helper builds DOM via createElement / createTextNode — verify by
    checking the function body never writes to .innerHTML.
    """
    html = _read_local_index()
    # Find the renderInlineText function body.
    start = html.find("function renderInlineText")
    assert start >= 0, "renderInlineText not found"
    # Find the end of the related cluster (renderInlineMarks closes it).
    end = html.find("// Look up the transfer record matching", start)
    assert end > start, "could not find end of inline-text helpers"
    body = html[start:end]
    assert ".innerHTML" not in body, (
        "inline-text helpers must not assign innerHTML — XSS surface"
    )
    # Positive checks: it does use createTextNode + createElement.
    assert "createTextNode" in body
    assert 'createElement("a")' in body or "createElement('a')" in body


def test_keyboard_shortcuts_handler_present():
    """Verify the shortcuts handler binds to keydown and looks for the
    expected combinations. A regression that drops the handler (or one
    of the modifiers) would break power-user flow silently."""
    html = _read_local_index()
    # Handler shape — a single document-level keydown that branches on
    # ctrl combos and "Escape" + "?" .
    assert 'document.addEventListener("keydown"' in html
    for needle in [
        '"Escape"',
        '"k" || e.key === "K"',
        '"/"',
        '","',
        '"n" || e.key === "N"',
        '/^[1-9]$/',
        '"?"',
    ]:
        assert needle in html, f"shortcut binding missing: {needle}"


def test_paste_drop_attach_all_route_through_stagefile():
    """The whole point of the staging UI is that paste, drop, and the
    file picker no longer call uploadFile() directly — they all stage.
    This test guards against a refactor that re-introduces auto-send."""
    html = _read_local_index()
    # The paste handler must call stageFile.
    paste_idx = html.find("function handlePasteImage")
    assert paste_idx >= 0
    paste_body = html[paste_idx:paste_idx + 1500]
    assert "stageFile(" in paste_body, "paste no longer routes through stageFile"
    assert "uploadFile(" not in paste_body, (
        "paste auto-sends again — staging UX regression"
    )

    # The file picker change handler must stage, not upload. Slice
    # just the handler body — the next thing in the file is the
    # uploadFile definition, which is unrelated.
    picker_idx = html.find('fileInput.addEventListener("change"')
    assert picker_idx >= 0
    handler_close = html.find("});", picker_idx)
    assert handler_close > picker_idx
    picker_body = html[picker_idx:handler_close]
    assert "stageFile(" in picker_body
    assert "uploadFile(" not in picker_body, (
        "attach button auto-sends again — staging UX regression"
    )


def test_file_bubble_uses_transfer_record_for_status():
    """The fix for the 'Sending… forever' bug is that file bubbles look
    up their matching transfer by blob_hash and render real status from
    the ledger. Guard the lookup primitive."""
    html = _read_local_index()
    fn_idx = html.find("function transferForMessage")
    assert fn_idx >= 0
    end_idx = html.find("function statusLabel", fn_idx)
    assert end_idx > fn_idx
    body = html[fn_idx:end_idx]
    assert "msg.blob" in body
    assert "transferByDirBlob" in body
    assert "msg.dir" in body or "msg.dir ===" in body
    # And the renderer must consult it.
    assert "transferForMessage(msg)" in html


# ─── Live smoke check against a running daemon ─────────────────────────

@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_daemon_serves_v07x_ui():
    """Boot a real daemon and verify the served / contains the expected
    scaffolding — defends against a packaging regression where the
    daemon ships a stale index.html."""
    with daemon_pair() as p:
        port = int((p.a.home / "data" / "server.port").read_text().strip())
        async with aiohttp.ClientSession() as s:
            async with s.get(f"http://127.0.0.1:{port}/") as r:
                assert r.status == 200
                html = await r.text()

        # Spot-check each major surface so a regression is named.
        for needle in [
            'id="attach-tray"',
            'id="btn-screenshot"',
            'id="set-notif"',
            'id="btn-files-received"',
            'id="btn-files-sent"',
            'id="btn-open-inbox"',
            'id="shortcuts-backdrop"',
            "function renderInlineText",
            "function transferForMessage",
            "function stageFile",
            "function copyToClipboard",
        ]:
            assert needle in html, f"daemon serving stale UI — missing {needle!r}"
