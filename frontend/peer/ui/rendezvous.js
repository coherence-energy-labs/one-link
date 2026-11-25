  // ── rendezvous UI wiring ────────────────────────────────────────────
  const RDZ_URL_KEY = "ol_peer.rdz_url";

  function _showRdzCard() {
    show($("#rdz-card"));
    // Restore last-used URL.
    try {
      const saved = localStorage.getItem(RDZ_URL_KEY);
      if (saved) $("#rdz-url").value = saved;
    } catch {}
  }

  let _rdzRefreshTimer = null;
  let _rdzRefreshState = null;

  function _cancelRdzRefresh() {
    if (_rdzRefreshTimer !== null) clearTimeout(_rdzRefreshTimer);
    _rdzRefreshTimer = null;
    _rdzRefreshState = null;
  }

  function _pauseRdzRefresh() {
    if (_rdzRefreshTimer !== null) clearTimeout(_rdzRefreshTimer);
    _rdzRefreshTimer = null;
  }

  function _scheduleRdzRefresh() {
    if (!_rdzRefreshState) return;
    if (_rdzRefreshTimer !== null) clearTimeout(_rdzRefreshTimer);
    const current = _rdzRefreshState;
    const remainingMs = Math.max(0, current.localExpiresAtMs - Date.now());
    const refreshDelay = Math.max(1_000, remainingMs - RDZ_REFRESH_MARGIN_MS);
    const retryDelay = Math.min(60_000, 2_000 * (2 ** current.retryAttempt));
    const delay = current.retryAttempt === 0
      ? refreshDelay
      : Math.max(1_000, Math.min(retryDelay, remainingMs > 1_000 ? remainingMs - 1_000 : retryDelay));
    _rdzRefreshTimer = setTimeout(async () => {
      if (_rdzRefreshState !== current) return;
      _rdzRefreshTimer = null;
      try {
        const ack = await registerWith(current.url);
        if (_rdzRefreshState !== current) return;
        const lifetimeMs = Math.max(1_000, ack.expires_at_ms - ack.server_time_ms);
        current.localExpiresAtMs = Date.now() + lifetimeMs;
        current.retryAttempt = 0;
        text($("#rdz-status"), `Signed presence refreshed (${new Date().toLocaleTimeString()})`);
      } catch (e) {
        if (_rdzRefreshState !== current) return;
        current.retryAttempt = Math.min(current.retryAttempt + 1, 10);
        text($("#rdz-status"),
          `Presence refresh failed; retrying: ${e && e.message ? e.message : e}`);
      }
      _scheduleRdzRefresh();
    }, delay);
  }

  function _startRdzRefresh(ack, rdzUrl) {
    _cancelRdzRefresh();
    const lifetimeMs = Math.max(1_000, ack.expires_at_ms - ack.server_time_ms);
    _rdzRefreshState = {
      url: _normalizeRdzUrl(rdzUrl),
      localExpiresAtMs: Date.now() + lifetimeMs,
      retryAttempt: 0,
    };
    _scheduleRdzRefresh();
  }

  window.addEventListener("pagehide", (event) => {
    if (event.persisted) _pauseRdzRefresh();
    else _cancelRdzRefresh();
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted && _rdzRefreshState) _scheduleRdzRefresh();
  });

  $("#btn-rdz-register")?.addEventListener("click", async () => {
    const url = $("#rdz-url").value;
    if (!url) {
      text($("#rdz-status"), "Enter a rendezvous URL first.");
      return;
    }
    const btn = $("#btn-rdz-register");
    if (btn) btn.disabled = true;
    text($("#rdz-status"), "Signing + posting register…");
    hide($("#rdz-ack-wrap"));
    let ack;
    try {
      _cancelRdzRefresh();
      ack = await registerWith(url);
      try { localStorage.setItem(RDZ_URL_KEY, _normalizeRdzUrl(url)); } catch {}
    } catch (e) {
      text($("#rdz-status"),
        `Register failed: ${e && e.message ? e.message : e}`);
      if (btn) btn.disabled = false;
      return;
    }
    text($("#rdz-status"), "Signed presence published. Manual signaling is still required.");
    if (ack && typeof ack.observed_host === "string" &&
        Number.isInteger(ack.observed_port)) {
      text($("#rdz-ack-endpoint"),
        `${ack.observed_host}:${ack.observed_port}`);
      show($("#rdz-ack-wrap"));
    }
    if (btn) btn.disabled = false;
    // Start auto-refresh.
    _startRdzRefresh(ack, url);
  });

