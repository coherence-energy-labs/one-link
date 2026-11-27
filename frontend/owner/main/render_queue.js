  function errorToastBody(e) {
    let headline = (e && e.message) ? e.message : String(e);
    const hint = e?.hint;
    // v0.7.x: append the error_detail (server-side exception text)
    // for catch-all "Send didn't work." errors. Without this the user
    // just sees "Send didn't work." and the actual cause is invisible.
    const detail = e?.error_detail;
    // v0.21.x: strip internal error codes / API-shaped fragments that
    // sometimes show up in headlines from upstream catches. Users
    // shouldn't see 'send_failed' / 'capability_disabled' / a raw
    // 'request failed (500)' as the lead - the hint + detail carry
    // the actionable info.
    const internalCodePattern = /^(send_failed|capability_disabled|peer_rejected|handshake_failed|wire_version_mismatch|request failed \(\d+\)|fetch failed|TypeError|NetworkError)[:\s]*/i;
    if (typeof headline === "string" && internalCodePattern.test(headline)) {
      headline = headline.replace(internalCodePattern, "").trim()
        || "Something went wrong";
    }
    // v0.21.x: ' - ' separator produces awkward double-punctuation
    // ('Took too long. - The other device...'). Use a single space
    // so the headline + hint read as two consecutive sentences -
    // assumes both end in a period, which our server-side
    // translations all do.
    let body = hint ? `${headline} ${hint}` : headline;
    // v0.21.x: surface the underlying exception text on EVERY 5xx
    // (not just send_failed) so opaque catch-alls like "could not
    // create folder" carry the actual cause the user can act on.
    const status = e?.status;
    if (detail && (
        e?.code === "send_failed"
        || !e?.code
        || (status && status >= 500 && status < 600)
    )) {
      body += ` (${detail})`;
    }
    return body;
  }

  // ── rAF-throttled schedulers ───────────────────────────────────────
  // A stuck or retrying transfer can fire many "transfer" WS events per
  // second; rebuilding the chat DOM each time makes the page visibly
  // flicker. These schedulers coalesce all the rebuilds into a single
  // animation-frame callback so the UI updates smoothly.
  const _scheduled = { msgs: false, transfers: false, files: false, status: false };
  function scheduleRenderMessages() {
    const m = document.querySelector("#messages");
    if (m && _isMessagesNearBottom(m)) _forceNextMessagesToBottom(350);
    if (_scheduled.msgs) return;
    _scheduled.msgs = true;
    requestAnimationFrame(() => { _scheduled.msgs = false; renderMessages(); });
  }
  function scheduleRenderTransfers() {
    if (_scheduled.transfers) return;
    _scheduled.transfers = true;
    requestAnimationFrame(() => { _scheduled.transfers = false; renderTransfers(); });
  }
  function scheduleRenderFilesPanel() {
    if (_scheduled.files) return;
    _scheduled.files = true;
    requestAnimationFrame(() => { _scheduled.files = false; renderFilesPanel(); });
  }
  // refreshStatus does a network call; throttle to at most once per
  // 500 ms so a flurry of transfer events doesn't hammer the daemon.
  let _statusPending = null;
  function scheduleRefreshStatus() {
    if (_statusPending) return;
    _statusPending = setTimeout(() => { _statusPending = null; refreshStatus(); }, 500);
  }

