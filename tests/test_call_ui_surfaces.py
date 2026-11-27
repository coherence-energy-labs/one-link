"""Tests for the browser call UI surfaces.

Mirrors the test_voice_messages_v092 + test_reality_dot_ui pattern:
substring assertions over index.html pin the DOM + JS hooks the
call UI relies on. The actual rendering is exercised in a browser;
these tests catch unintended regressions to the contract.
"""

from __future__ import annotations

from pathlib import Path

import pytest


INDEX_HTML_PATH = (
    Path(__file__).resolve().parent.parent
    / "src" / "one_link" / "web" / "index.html"
)


@pytest.fixture(scope="module")
def index_html() -> str:
    return INDEX_HTML_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CSS — overlay + active-call surfaces present
# ---------------------------------------------------------------------------

def test_call_overlay_class_styled(index_html: str) -> None:
    assert ".call-overlay" in index_html
    assert ".call-overlay.show" in index_html


def test_call_active_class_styled(index_html: str) -> None:
    assert ".call-active" in index_html
    assert ".call-active.show" in index_html


def test_recording_badge_styled(index_html: str) -> None:
    assert ".call-recording-badge" in index_html
    assert ".call-recording-badge.show" in index_html


def test_sas_pane_styled(index_html: str) -> None:
    assert ".sas-pane" in index_html
    assert ".sas-pane.show" in index_html


# ---------------------------------------------------------------------------
# DOM — overlay divs exist
# ---------------------------------------------------------------------------

def test_outgoing_overlay_div(index_html: str) -> None:
    assert 'id="call-outgoing-overlay"' in index_html
    assert 'id="call-outgoing-peer"' in index_html


def test_incoming_overlay_div(index_html: str) -> None:
    assert 'id="call-incoming-overlay"' in index_html
    assert 'id="call-incoming-peer"' in index_html
    # Accept + Decline buttons
    assert 'id="btn-call-accept"' in index_html
    assert 'id="btn-call-decline"' in index_html


def test_active_call_surface_div(index_html: str) -> None:
    assert 'id="call-active-surface"' in index_html
    assert 'id="call-active-name"' in index_html
    assert 'id="btn-call-hangup"' in index_html
    assert 'id="btn-call-record"' in index_html


def test_recording_badge_dom(index_html: str) -> None:
    assert 'id="call-recording-badge"' in index_html
    # Doctrine §7.2: visible recording indicator with plain language
    # — must include "Recording" and "both sides agreed" so the
    # user never wonders whether silent recording is happening.
    assert "Recording (both sides agreed)" in index_html


def test_sas_pane_dom(index_html: str) -> None:
    assert 'id="call-sas-pane"' in index_html
    assert 'id="call-sas-words"' in index_html
    assert 'id="btn-sas-yes"' in index_html
    assert 'id="btn-sas-no"' in index_html


# ---------------------------------------------------------------------------
# Accessibility — every overlay has role=dialog + aria-label
# ---------------------------------------------------------------------------

def test_overlays_have_dialog_role_and_aria_label(index_html: str) -> None:
    # The three call overlays must be screen-reader navigable.
    snippets = [
        index_html.find('id="call-outgoing-overlay"'),
        index_html.find('id="call-incoming-overlay"'),
        index_html.find('id="call-active-surface"'),
    ]
    assert all(idx > 0 for idx in snippets)
    for idx in snippets:
        block = index_html[max(0, idx - 60):idx + 200]
        assert 'role="dialog"' in block
        assert "aria-label=" in block


def test_buttons_have_aria_labels(index_html: str) -> None:
    for btn_id, expected_label_word in [
        ("btn-call-cancel", "End"),
        ("btn-call-accept", "Accept"),
        ("btn-call-decline", "Decline"),
        ("btn-call-hangup", "End"),
        ("btn-call-record", "Save"),
        ("btn-call-export-trace", "Export"),
    ]:
        idx = index_html.find(f'id="{btn_id}"')
        assert idx > 0, f"missing button id {btn_id}"
        snippet = index_html[idx:idx + 200]
        assert 'aria-label=' in snippet


# ---------------------------------------------------------------------------
# JS — public entry points + WS handler hook
# ---------------------------------------------------------------------------

def test_start_call_function_exposed(index_html: str) -> None:
    """`window.startLivingPresenceCall(peerVk, peerLabel)` is the
    function a 'Call Mom' button calls. Pin its presence + signature."""
    assert "window.startLivingPresenceCall = async function" in index_html


def test_call_event_handler_exposed(index_html: str) -> None:
    """The driver exposes a forwarder for the WebSocket dispatcher."""
    assert "window.handleLivingPresenceCallEvent = function" in index_html


def test_ws_dispatch_forwards_call_event(index_html: str) -> None:
    """The existing ws.onmessage chain has a branch that forwards
    `call_event` to the driver."""
    idx = index_html.find('m.type === "call_event"')
    assert idx > 0
    snippet = index_html[idx:idx + 500]
    assert "handleLivingPresenceCallEvent(m)" in snippet


def test_call_driver_backfills_incoming_rings_from_call_list(index_html: str) -> None:
    idx = index_html.find("async function backfillLivingPresenceCalls")
    assert idx > 0
    snippet = index_html[idx:idx + 2500]
    assert 'fetch("/api/v1/calls"' in index_html
    assert 'phase === "ringing"' in snippet
    assert "call.local_role === \"recipient\"" in snippet
    assert "call.pending_sdp_offer" in snippet
    assert "call.pending_sdp_answer" in snippet
    assert "showIncomingRing" in snippet
    # WebSocket events are primary; the HTTP reconciliation backstop adapts
    # between active-call, visible-idle, and hidden-idle cadences and never
    # overlaps itself.
    assert "function callBackfillDelayMs()" in index_html
    assert "if (_callBackfillRunning) return" in index_html
    assert 'document.getElementById("peers-count")' in index_html
    assert "return peerCount > 0 ? 5000 : 10000" in index_html
    assert "? 5000 : 30000" in index_html


def test_call_driver_queues_ice_until_remote_description(index_html: str) -> None:
    idx = index_html.find("async function applyRemoteIceCandidate")
    assert idx > 0
    snippet = index_html[idx:idx + 1200]
    assert "pendingIceCandidates" in index_html
    assert "!media.pc.remoteDescription" in snippet
    assert "flushPendingIceCandidates" in index_html


def test_active_call_surface_is_polished_full_screen(index_html: str) -> None:
    idx = index_html.find(".call-active {")
    assert idx > 0
    snippet = index_html[idx:idx + 5200]
    assert "radial-gradient" in snippet
    assert "backdrop-filter: blur(18px)" in snippet
    assert "bottom: 34px" in snippet


def test_call_side_panels_are_hidden_until_details_open(index_html: str) -> None:
    idx = index_html.find(".call-history-strip")
    snippet = index_html[idx:idx + 1800]
    assert "top: 112px" in snippet
    assert "top: 278px" in snippet
    assert "display: none" in snippet
    assert ".call-active.details-open .call-history-strip" in index_html
    assert ".call-active.details-open .call-side-panel" in index_html
    mobile_idx = index_html.find("@media (max-width: 780px)", idx)
    mobile_snippet = index_html[mobile_idx:mobile_idx + 1400]
    assert ".call-history-strip" in mobile_snippet
    assert ".call-side-panel" in mobile_snippet
    assert "display: none" in mobile_snippet
    assert "min-width: 160px" in snippet
    assert "Connected privately over One Link" in index_html


def test_call_surface_hides_details_when_opening_or_closing(index_html: str) -> None:
    idx = index_html.find("function showActiveSurface")
    snippet = index_html[idx:idx + 1100]
    assert 'classList.remove("details-open")' in snippet
    close_idx = index_html.find("function hideActiveSurface")
    close_snippet = index_html[close_idx:close_idx + 500]
    assert 'classList.remove("show", "details-open", "reconnecting")' in close_snippet


def test_active_call_surface_has_one_assist_rail(index_html: str) -> None:
    assert 'id="call-one-rail"' in index_html
    assert 'id="call-one-route"' in index_html
    assert 'id="call-one-reality"' in index_html
    assert 'id="btn-call-send-file"' in index_html
    assert 'id="btn-call-use-best-path"' in index_html
    assert 'id="call-file-input"' in index_html


def test_call_driver_reports_metrics_to_immune_system(index_html: str) -> None:
    idx = index_html.find("async function reportCallMetricsOnce")
    assert idx > 0
    snippet = index_html[idx:idx + 15200]
    assert "media.pc.getStats()" in snippet
    assert 'action: "report_metrics"' in snippet
    assert "bandwidth_estimate_kbps" in snippet
    assert "raw_loss_rate" in snippet
    assert "smoothed_rtt_ms" in snippet
    assert "setInterval(reportCallMetricsOnce, 2000)" in index_html


def test_call_driver_auto_captures_trace_on_freeze_and_watchdog(index_html: str) -> None:
    assert "autoTraceBuffer: []" in index_html
    fn_idx = index_html.find("async function captureAutoCallTrace")
    assert fn_idx > 0
    fn_snippet = index_html[fn_idx:fn_idx + 2600]
    assert "/api/v1/calls/${encodeURIComponent(callId)}/trace" in fn_snippet
    assert "window._oneLinkCallDebug" in fn_snippet
    assert "localStorage.setItem" in fn_snippet
    assert "one_link_auto_call_traces" in fn_snippet
    assert "auto_call_trace_captured" in fn_snippet
    assert "auto_call_trace_failed" in fn_snippet

    metrics_idx = index_html.find("async function reportCallMetricsOnce")
    metrics_snippet = index_html[metrics_idx:metrics_idx + 20000]
    assert 'captureAutoCallTrace("sustained_media_freeze"' in metrics_snippet
    watchdog_idx = index_html.find("function startMediaWatchdog")
    watchdog_snippet = index_html[watchdog_idx:watchdog_idx + 1600]
    assert 'captureAutoCallTrace("watchdog_no_media_movement"' in watchdog_snippet
    debug_idx = index_html.find("window._oneLinkCallDebug = async function")
    debug_snippet = index_html[debug_idx:debug_idx + 3500]
    assert "auto_trace_buffer: callUI.autoTraceBuffer" in debug_snippet


def test_call_driver_backfills_pending_ice_candidates(index_html: str) -> None:
    idx = index_html.find("async function backfillLivingPresenceCalls")
    assert idx > 0
    snippet = index_html[idx:idx + 2200]
    assert "pending_ice_candidates" in snippet
    assert "await applyRemoteIceCandidate" in snippet
    assert "appliedIceKeys" in index_html


def test_call_driver_reconciles_stale_call_surfaces(index_html: str) -> None:
    """Regression: browser overlays must not keep ringing/calling when
    the daemon call registry no longer has that call."""
    idx = index_html.find("async function backfillLivingPresenceCalls")
    assert idx > 0
    snippet = index_html[idx:idx + 4200]
    assert "visibleCallIds" in snippet
    assert "hideOutgoingOverlay()" in snippet
    assert "hideIncomingRing()" in snippet
    assert "!visibleCallIds.has(callUI.activeCallId)" in snippet


def test_call_driver_suppresses_duplicate_rings_after_accept(index_html: str) -> None:
    assert "acceptedCallIds: new Set()" in index_html
    assert "lastAcceptRetryMs" in index_html
    accept_idx = index_html.find("async function acceptInboundCall")
    accept_snippet = index_html[accept_idx:accept_idx + 1800]
    assert "callState.acceptCall(inboundCallId)" in accept_snippet
    assert "accept_sent" in accept_snippet
    backfill_idx = index_html.find("async function backfillLivingPresenceCalls")
    backfill_snippet = index_html[backfill_idx:backfill_idx + 3600]
    assert "callUI.acceptedCallIds.has(call.call_id)" in backfill_snippet
    assert 'action: "accept", call_id: call.call_id' in backfill_snippet
    ring_idx = index_html.find('if (tail === "show_ring")')
    ring_snippet = index_html[ring_idx:ring_idx + 1200]
    assert "callUI.acceptedCallIds.has(callId)" in ring_snippet
    assert 'reason: "duplicate_ring"' in ring_snippet


def test_call_driver_rejoins_active_calls_after_browser_reload(index_html: str) -> None:
    assert "lastRejoinAttemptMs" in index_html
    rejoin_idx = index_html.find("async function rejoinActiveCallFromSnapshot")
    assert rejoin_idx > 0
    rejoin_snippet = index_html[rejoin_idx:rejoin_idx + 3600]
    assert 'action: "rejoin"' in rejoin_snippet
    assert "same call" not in rejoin_snippet.lower()
    assert "setupRtcPeerConnection()" in rejoin_snippet
    assert "startLocalMedia({ audio: true, video: wantsVideo })" in rejoin_snippet
    assert "client_rejoin_media_ready" in rejoin_snippet
    assert "applyRemoteSdpOffer(snapshot.pending_sdp_offer)" in rejoin_snippet
    assert "applyRemoteSdpAnswer(snapshot.pending_sdp_answer)" in rejoin_snippet
    assert "await applyRemoteIceCandidate" in rejoin_snippet
    assert 'ensureMediaNegotiation("rejoin")' in rejoin_snippet

    backfill_idx = index_html.find("async function backfillLivingPresenceCalls")
    backfill_snippet = index_html[backfill_idx:backfill_idx + 4200]
    assert "!media.pc || !media.localStream || !callUI.localMediaReady" in backfill_snippet
    assert 'rejoinActiveCallFromSnapshot(call, "backfill_active")' in backfill_snippet


def test_start_call_paints_overlay_before_daemon_roundtrip(index_html: str) -> None:
    idx = index_html.find("window.startLivingPresenceCall = async function")
    assert idx > 0
    snippet = index_html[idx:idx + 2200]
    overlay_idx = snippet.find("showOutgoingOverlay")
    api_idx = snippet.find("const result = await callApiPost")
    assert overlay_idx > 0
    assert api_idx > 0
    assert overlay_idx < api_idx
    assert "const mediaPromise = startLocalMedia" in snippet


def test_start_call_uses_window_scoped_preflight_and_ring_helpers(index_html: str) -> None:
    """Regression: the contact buttons live in one script scope and
    the call driver in another. Cross-scope helpers must be resolved
    through window or button clicks stop before dialing."""
    assert "window._callPermissionPreflight = _callPermissionPreflight" in index_html
    assert "window.startCallRingback = startCallRingback" in index_html
    assert "window.startCallRingtone = startCallRingtone" in index_html
    assert "window.stopCallRing = stopCallRing" in index_html
    idx = index_html.find("window.startLivingPresenceCall = async function")
    snippet = index_html[idx:idx + 4200]
    assert 'typeof window._callPermissionPreflight === "function"' in snippet
    assert "const proceed = await preflight" in snippet
    assert "window.startCallRingback" in index_html


def test_inbound_sdp_waits_for_local_media_before_answer(index_html: str) -> None:
    accept_idx = index_html.find("async function acceptInboundCall")
    assert accept_idx > 0
    accept_snippet = index_html[accept_idx:accept_idx + 2200]
    assert 'callState.set("localMediaReady", false)' in accept_snippet
    assert accept_snippet.find("media.pc.addTrack") < accept_snippet.find('callState.set("localMediaReady", true)')
    assert accept_snippet.find('callState.set("localMediaReady", true)') < accept_snippet.find("await applyRemoteSdpOffer")

    handler_idx = index_html.find('if (tail === "sdp_offer")')
    assert handler_idx > 0
    handler_snippet = index_html[handler_idx:handler_idx + 700]
    assert "callUI.localMediaReady" in handler_snippet
    assert 'callState.set("pendingRemoteOffer", null)' in handler_snippet


def test_call_buttons_clear_surfaces_before_network_wait(index_html: str) -> None:
    accept_idx = index_html.find("async function acceptInboundCall")
    assert accept_idx > 0
    accept_snippet = index_html[accept_idx:accept_idx + 1200]
    assert accept_snippet.find("hideIncomingRing()") < accept_snippet.find("const result = await callApiPost")
    assert accept_snippet.find("showActiveSurface") < accept_snippet.find("const result = await callApiPost")

    buttons_idx = index_html.find('const cancelBtn = $$("#btn-call-cancel")')
    assert buttons_idx > 0
    buttons_snippet = index_html[buttons_idx:buttons_idx + 1800]
    assert buttons_snippet.find("hideOutgoingOverlay()") < buttons_snippet.find('await callApiPost({ action: "hangup"')
    assert buttons_snippet.find("hideIncomingRing()") < buttons_snippet.find('await callApiPost({ action: "decline"')
    assert buttons_snippet.find("hideActiveSurface()") < buttons_snippet.rfind('await callApiPost({ action: "hangup"')


def test_call_driver_resolves_simultaneous_calls(index_html: str) -> None:
    idx = index_html.find("async function resolveSimultaneousCallIfNeeded")
    assert idx > 0
    snippet = index_html[idx:idx + 1800]
    assert 'action: "hangup"' in snippet
    assert 'action: "decline"' in snippet
    assert "String(inboundCallId) < String(callUI.activeCallId)" in snippet
    assert "await acceptInboundCall()" in snippet


def test_call_driver_can_send_files_inside_call(index_html: str) -> None:
    idx = index_html.find('const callFileInput = $$("#call-file-input")')
    assert idx > 0
    snippet = index_html[idx:idx + 2200]
    assert "async function _sendCallFileIntents(intents)" in snippet
    assert "api.upload(peerId, file, {clientDeliveryId})" in snippet
    assert "_callFileSendInFlight" in snippet
    assert "Sending ${file.name} without leaving the call." in snippet
    assert "trusted file fabric" in snippet


def test_call_driver_surfaces_immune_actions_in_one_assist(index_html: str) -> None:
    idx = index_html.find('if (tail === "immune_lower_fidelity")')
    assert idx > 0
    snippet = index_html[idx:idx + 3500]
    assert "One Link lowered video bitrate" in snippet
    assert "Camera paused automatically" in snippet
    assert "resumable voice capsule" in snippet
    assert "warming a stronger path" in snippet
    assert "Secure connection refreshed" in snippet


# ---------------------------------------------------------------------------
# All four overlay states the driver handles
# ---------------------------------------------------------------------------

def test_driver_handles_show_ring(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"show_ring"' in snippet


def test_driver_handles_phase_changed(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"phase_changed"' in snippet
    assert '"active"' in snippet
    assert '"ended"' in snippet


def test_driver_handles_recording_state_changed(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"recording_state_changed"' in snippet


def test_driver_handles_resume_offer(index_html: str) -> None:
    idx = index_html.find("window.handleLivingPresenceCallEvent = function")
    snippet = index_html[idx:idx + 4000]
    assert '"resume_offer_available"' in snippet


# ---------------------------------------------------------------------------
# Doctrine — no forbidden surfaces in the call UI
# ---------------------------------------------------------------------------

def test_no_forbidden_call_strings_in_driver_block(index_html: str) -> None:
    """The call-UI driver block must not contain any
    doctrine-forbidden user-facing strings. The doctrine lint also
    checks the whole file; here we pin the local guarantee."""
    idx = index_html.find("Living Presence Tier α-pre — call UI driver")
    end = index_html.find("</script>", idx)
    block = index_html[idx:end]
    forbidden = [
        "reconnecting",
        "call failed",
        "please try again",
        "your connection is unstable",
    ]
    low = block.lower()
    for tok in forbidden:
        assert tok not in low, f"call UI driver leaks forbidden token: {tok}"
