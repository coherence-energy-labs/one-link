"""v0.8.8 — live transfer progress in chat (bytes/sec + ETA + aggregate pill).

Pure UI ship — no schema, no new endpoint. The transfer WS event
already carries progress_bytes / total_bytes / status; we add a
client-side EWMA rate tracker so the chat bubble shows live B/s
+ ETA, and a per-conversation aggregate pill in the header so the
user sees 'sending 3 files at 14 MB/s' at a glance.

These tests pin the surface contract.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def index_html() -> str:
    return Path("src/one_link/web/index.html").read_text(encoding="utf-8")


# ───────── helpers present ───────────────────────────────────────────

def test_rate_helper_present(index_html: str):
    assert "function updateTransferRate(" in index_html
    assert "function rateForTransfer(" in index_html
    assert "function aggregateActiveTransferStats(" in index_html


def test_format_helpers_present(index_html: str):
    assert "const fmtRate" in index_html
    assert "const fmtMbps" in index_html
    assert "const fmtEta" in index_html


def test_state_has_transfer_rates_map(index_html: str):
    assert "transferRates: transferStore.rates" in index_html


# ───────── EWMA semantics ────────────────────────────────────────────

def test_rate_tracker_uses_ewma(index_html: str):
    """The tracker must use an EWMA, not raw last-delta — bursty
    chunked transfers would jiggle wildly otherwise."""
    assert "_RATE_ALPHA" in index_html
    # alpha must be in (0, 1) and named-constant exposed at module top.
    m = re.search(r"const _RATE_ALPHA = ([\d.]+)", index_html)
    assert m is not None
    alpha = float(m.group(1))
    assert 0 < alpha < 1


def test_rate_tracker_resets_on_terminal_status(index_html: str):
    """complete / failed must drop the rate cache so the next
    transfer for the same id (retry after pause) starts fresh."""
    start = index_html.find("function updateTransferRate(")
    assert start > 0
    snippet = index_html[start:start + 1800]
    assert 'status === "complete"' in snippet
    assert 'status === "failed"' in snippet
    assert "transferStore.forgetRate(" in snippet


def test_rate_decays_after_inactivity(index_html: str):
    """If no event has arrived for >3s the bps must read as 0 —
    otherwise a frozen transfer would keep showing 14 MB/s forever."""
    start = index_html.find("function rateForTransfer(")
    assert start > 0
    snippet = index_html[start:start + 600]
    assert "age > 3" in snippet


# ───────── chat bubble surface ───────────────────────────────────────

def test_file_bubble_shows_rate_and_eta(index_html: str):
    """The in-flight file bubble must include live B/s + ETA when
    the rate is known."""
    start = index_html.find("function renderFileBubble(msg)")
    assert start > 0
    # Anchor on the in-flight progress block itself rather than a fixed
    # char window from the function start — the bubble's preamble grows
    # (direction-aware + old-message fallbacks) and kept shifting a
    # magic-number window. Bound the slice at the next function def so a
    # match can't bleed into unrelated code.
    nextfn = index_html.find("\n  function ", start + 1)
    snippet = index_html[start:(nextfn if nextfn > start else start + 6000)]
    assert "rateForTransfer(" in snippet
    assert "fmtRate(" in snippet
    assert "fmtMbps(" in snippet
    assert "fmtEta(" in snippet
    assert "transfer-detail" in snippet


def test_paused_bubble_shows_resume_hint(index_html: str):
    """Paused transfer bubble should explicitly mention the resume
    behaviour so the user doesn't think it's stuck. renderFileBubble
    grew with v0.21.x (image-preview + status pills + autopilot
    facts) so the paused-branch is further down; widen the slice."""
    start = index_html.find("function renderFileBubble(msg)")
    assert start > 0
    snippet = index_html[start:start + 6000]
    assert "One Link will keep trying automatically" in snippet


def test_file_bubble_surfaces_autopilot_truth(index_html: str):
    start = index_html.find("function transferAutopilotFacts(")
    assert start > 0
    snippet = index_html[start:start + 4200]
    assert "t.autopilot_truth" in snippet
    assert "truth.facts" in snippet
    assert "Sending at" in snippet
    assert "already known" in snippet
    assert "Only sent missing pieces" in snippet
    assert "Using fast binary path" in snippet
    assert "Resuming automatically" in snippet
    assert "trusted device" in snippet
    assert "Route:" in snippet
    assert "transfer-facts" in index_html
    assert "renderTransferFacts(t, kind)" in index_html


def test_transfer_panel_surfaces_autopilot_truth(index_html: str):
    start = index_html.find("function renderTransfers()")
    assert start > 0
    # v0.21.x: renderTransfers grew with folder-send-group row
    # grouping, pushing renderTransferFacts(...) ~2.3k chars past the
    # function start. Widen the window to keep covering it.
    snippet = index_html[start:start + 3500]
    assert "renderTransferFacts(t, statusKind(t))" in snippet
    assert "renderTransferCommandCenter(t)" in snippet
    assert ".file-row .transfer-facts" in index_html
    assert ".file-row .transfer-fact" in index_html


def test_transfer_command_center_shows_real_speed_and_savings(index_html: str):
    start = index_html.find("function transferCommandMetrics(")
    assert start > 0
    snippet = index_html[start:start + 3600]
    assert "autopilot_truth" in snippet
    assert "speed_mbps" in snippet
    assert "wire_mbps" in snippet
    assert "known_pct" in snippet
    assert "saved_bytes" in snippet
    assert "wire_bytes" in snippet
    assert "self_healing_action" in snippet
    assert "transfer-command" in index_html
    assert "tc-metric" in index_html


def test_sent_files_panel_uses_transfer_command_center(index_html: str):
    start = index_html.find("function renderFilesPanel()")
    assert start > 0
    snippet = index_html[start:start + 4200]
    assert "renderTransferCommandCenter(t)" in snippet
    assert "renderTransferFacts(t, statusKind(t))" in snippet


# ───────── aggregate pill surface ────────────────────────────────────

def test_header_has_transfer_pill(index_html: str):
    assert 'id="transfer-pill"' in index_html


def test_pill_renderer_present(index_html: str):
    assert "function renderTransferHeaderPill(" in index_html
    assert "function scheduleRenderTransferHeaderPill(" in index_html


def test_pill_decays_via_interval(index_html: str):
    """Need a setInterval so a stalled transfer's stale rate fades
    even when no new transfer events arrive."""
    # 2026-06-04: `renderTransferHeaderPill();` now appears at multiple
    # call sites (the periodic interval AND the X-cancel handler that
    # re-renders to drop the pill immediately). The naive find() landed
    # on the cancel-handler occurrence, so anchor on the setInterval
    # block itself and assert it re-renders the pill.
    idx = index_html.find("setInterval(() => {")
    while idx != -1:
        window = index_html[idx:idx + 400]
        if "renderTransferHeaderPill()" in window:
            return  # found the decay interval that re-renders the pill
        idx = index_html.find("setInterval(() => {", idx + 1)
    raise AssertionError(
        "no setInterval that re-renders the transfer pill — a stalled "
        "transfer's stale rate would never fade without new events"
    )


def test_pill_click_opens_files_pane(index_html: str):
    """Clicking the pill should switch to Files → Sent."""
    start = index_html.find("function renderTransferHeaderPill(")
    assert start > 0
    snippet = index_html[start:start + 1800]
    assert 'data-pane="files"' in snippet
    assert 'data-files-mode="sent"' in snippet


def test_ws_handler_calls_update_rate(index_html: str):
    """The transfer WS event handler must call updateTransferRate
    on every event, otherwise the EWMA never advances.

    2026-05-22 audit Batch AA: the by-id Map prune block grew the
    handler past the original 1200-char window. Read to the next
    ``else if (m.type ===`` or 2400 chars (whichever is shorter)
    so structural checks survive reasonable in-handler additions.
    """
    idx = index_html.find('m.type === "transfer"')
    assert idx > 0
    end_idx = index_html.find('else if (m.type ===', idx + 30)
    if end_idx == -1 or end_idx - idx > 2400:
        end_idx = idx + 2400
    snippet = index_html[idx:end_idx]
    assert "updateTransferRate(" in snippet
    assert "scheduleRenderTransferHeaderPill()" in snippet


def test_page_version_bumped(index_html: str):
    from one_link import __version__

    assert f'PAGE_BUILT_FOR = "{__version__}"' in index_html
