  // ── API client ─────────────────────────────────────────────────────
  // v0.11.4: every fetch goes through _maybe401 so a global session-
  // expired banner can surface ONCE instead of every page being
  // littered with cryptic per-endpoint "401" messages.
  //
  // Auto-recovery validates the current origin-scoped bearer directly against
  // /api/me. It never serializes a browser-session bearer into a URL.

  // The server's bootstrap script snapshots the URL token in <head> before it
  // scrubs the address bar. This body-side capture is a defensive fallback for
  // static/dev serving paths and still runs before any API fetch.
  //
  // 2026-05-21 audit T3-C: previously the token survived in
  // ``location.href`` after page load — landing in browser history,
  // referrer headers, and any browser-sync the user had enabled.
  // We now strip ``?t=...`` from the URL via ``history.replaceState``
  // immediately after stashing the token in sessionStorage, shrinking
  // the leak window to the few ms between page-load and this script.
  // The token remains in the daemon's HTTP access log of the initial
  // page-load request — the only place we can't help.
  (function _captureUrlToken() {
    try {
      const params = new URLSearchParams(location.search || "");
      const t = params.get("t");
      if (t) {
        sessionStorage.setItem("ol_session_token", t);
        // The owner bearer deliberately stays tab-scoped. Persistent
        // cross-restart access uses a revocable, origin-scoped session bearer;
        // writing this higher-privilege daemon token to localStorage would
        // leave it readable by any future same-origin script compromise.
        // Strip the token from the visible URL without triggering a
        // navigation. After this line, ``location.href`` no longer
        // contains the token so a subsequent click into history,
        // a screen-capture, or a referrer-leaking navigation
        // cannot expose it.
        params.delete("t");
        const cleanQs = params.toString();
        const cleanUrl = location.pathname + (cleanQs ? "?" + cleanQs : "") + location.hash;
        try { history.replaceState(null, "", cleanUrl); } catch (_) {}
      }
    } catch (_) {}
  })();

  // Plain loopback HTTP cannot safely use bearer cookies: cookie scope does
  // not include the port, so an unrelated server on another 127.0.0.1 port
  // would receive them. The bootstrap head stores a revocable browser-session
  // bearer in origin-scoped storage instead. Every same-origin API fetch adds
  // it explicitly; plaintext requests omit cookies even if an older release
  // left one behind. HTTPS keeps its HttpOnly-cookie compatibility layer, but
  // the explicit bearer also gives one auth path to fetch and WebSocket code.
  const _PERSISTENT_OWNER_SESSION_KEY = "ol_persistent_session_token";
  function _ownerBearerToken() {
    let token = "";
    try { token = sessionStorage.getItem("ol_session_token") || ""; } catch (_) {}
    if (!token) {
      try { token = localStorage.getItem(_PERSISTENT_OWNER_SESSION_KEY) || ""; } catch (_) {}
      if (token) {
        try { sessionStorage.setItem("ol_session_token", token); } catch (_) {}
      }
    }
    return token;
  }
  function _clearBrowserOwnerSession() {
    try { sessionStorage.removeItem("ol_session_token"); } catch (_) {}
    try { localStorage.removeItem(_PERSISTENT_OWNER_SESSION_KEY); } catch (_) {}
    try {
      navigator.serviceWorker?.controller?.postMessage({ type: "owner-auth-clear-v1" });
    } catch (_) {}
  }

  const _nativeWindowFetch = window.fetch.bind(window);
  window.fetch = function oneLinkAuthenticatedFetch(input, init) {
    const next = Object.assign({}, init || {});
    try {
      const rawUrl = (typeof input === "string" || input instanceof URL)
        ? String(input)
        : String(input && input.url || "");
      const url = new URL(rawUrl, location.href);
      if (url.origin === location.origin && url.pathname.startsWith("/api/")) {
        const headers = new Headers(
          input instanceof Request ? input.headers : undefined,
        );
        if (next.headers) {
          new Headers(next.headers).forEach((value, name) => headers.set(name, value));
        }
        const token = _ownerBearerToken();
        if (token && !headers.has("authorization")) {
          headers.set("Authorization", `Bearer ${token}`);
        }
        next.headers = headers;
        if (location.protocol === "http:") next.credentials = "omit";
      }
    } catch (_) {
      // Preserve native fetch behavior for malformed or non-URL inputs. The
      // server still fails closed if a protected request lacks a bearer.
    }
    return _nativeWindowFetch(input, next);
  };

  let _sessionExpiredBannerShown = false;
  let _autoRecoveryInFlight = false;
  let _autoRecoveryAttempts = 0;
  const _AUTO_RECOVERY_MAX_ATTEMPTS = 2;

  async function _attemptAutoRecovery() {
    if (_autoRecoveryInFlight) return false;
    if (_autoRecoveryAttempts >= _AUTO_RECOVERY_MAX_ATTEMPTS) return false;
    // The bootstrap head script captures the URL token into tab-scoped
    // sessionStorage before scrubbing the address bar. Long-lived access is
    // handled by the revocable origin-scoped browser-session credential.
    let token = "";
    token = _ownerBearerToken();
    if (!token) return false;
    _autoRecoveryInFlight = true;
    _autoRecoveryAttempts += 1;
    try {
      // Validate the origin-scoped bearer directly. It may be a revocable
      // browser session that intentionally is not accepted in a URL.
      const r = await fetch("/api/me", {
        cache: "no-store",
      });
      if (r.ok) {
        // Keep the current-tab credential hot; the bootstrap decides whether
        // a revocable copy is also retained in origin-persistent storage.
        try { sessionStorage.setItem("ol_session_token", token); } catch (_) {}
        return true;
      }
      // 401 from the recovery fetch itself means the stashed
      // token is no longer an active owner/session credential.
      // That stash is dead — flush it so we don't keep retrying
      // a known-bad value on every poll.
      if (r.status === 401 || r.status === 403) {
        try { sessionStorage.removeItem("ol_session_token"); } catch (_) {}
        try { localStorage.removeItem(_PERSISTENT_OWNER_SESSION_KEY); } catch (_) {}
      }
      return false;
    } catch (_) {
      return false;
    } finally {
      _autoRecoveryInFlight = false;
    }
  }

  function _maybe401(status) {
    if (status !== 401) return;
    if (_sessionExpiredBannerShown) return;
    // 2026-05-21 audit T3-P: pause the polling cluster while we
    // try to recover so we don't fire six concurrent _maybe401
    // → _attemptAutoRecovery chains. Recovery itself is guarded
    // by ``_autoRecoveryInFlight`` but the polling timers still
    // bombard the daemon with retries that immediately bounce. Pause once;
    // resume on success.
    _pauseMainPollTimers();
    // Try silent auto-recovery FIRST. If it succeeds, the next
    // fetch should succeed too - no banner. If it fails (token
    // mismatch with new daemon), fall through to the banner.
    _attemptAutoRecovery().then((ok) => {
      if (ok) {
        // Bearer validated. Reload the data without a full page refresh.
        _resumeMainPollTimers();
        // 2026-05-22 audit T2-M: the prior code called
        // ``refreshAll()`` here behind a ``typeof === "function"``
        // guard, but no such function exists anywhere in the
        // file — the guard hid the dead reference. The intent
        // was an immediate post-recovery refresh; without it
        // recovery would succeed but the user waited up to 30 s
        // for the next polling tick. Call the real refresh
        // functions directly. Each tolerates network errors so
        // we don't need to chain catches.
        try { refreshPeers(); } catch (_) {}
        try { refreshTransfers(); } catch (_) {}
        try { refreshStatus(); } catch (_) {}
        try { refreshGroups(); } catch (_) {}
        return;
      }
      // Token also rejected → the daemon really minted a new
      // token (rare; only happens if the user explicitly
      // resets via tray "forget credentials"). Show the banner.
      // Timers stay paused; the banner's "Sign in" button (or a
      // page reload after authorize) resumes them.
      if (_sessionExpiredBannerShown) return;
      _sessionExpiredBannerShown = true;
      showSessionExpiredBanner();
    });
  }

  // The background polling cluster: [refresh, period ms]. Boot starts
  // it; a 401 burst pauses it; explicit recovery resumes it.
  function _mainPollTasks() {
    return [
      [refreshPeers, 5000],
      [refreshTransfers, 4000],
      [refreshStatus, 8000],
      [refreshOneHealth, 15000],
      [refreshFabricTruth, 30000],
      [refreshGroups, 12000],
    ];
  }
  function _pauseMainPollTimers() {
    // pollingCluster empties its timers; ``_resumeMainPollTimers``
    // re-schedules fresh intervals so we don't accidentally
    // double-fire after a partial pause/resume cycle.
    pollingCluster.pause();
  }
  function _resumeMainPollTimers() {
    pollingCluster.resume(_mainPollTasks());
  }

  function showSessionExpiredBanner() {
    let banner = document.getElementById("session-expired-banner");
    if (banner) return;
    banner = document.createElement("div");
    banner.id = "session-expired-banner";
    banner.className = "session-expired-banner";
    // 2026-06-04: distinguish the two real dead-end cases and speak
    // honestly about which one the user is in. A Reload button that
    // re-lands on the same banner is worse than no button at all.
    //
    //   Case A — we still have a tab-scoped bearer because validation failed
    //     with a transient network error. Offer a direct retry; never place the
    //     bearer in a URL, history entry, referrer, or access log.
    //
    //   Case B — this tab has no token. We genuinely cannot
    //     recover from JS. The only way forward is for the user to
    //     re-open One Link from the desktop shortcut or tray, which
    //     re-mints a fresh URL with ?t= via the launcher. A Reload
    //     button here just reloads the bare URL → 401 → same banner
    //     again. So we omit it and tell the user exactly what to do.
    let stashedToken = "";
    try { stashedToken = sessionStorage.getItem("ol_session_token") || ""; } catch (_) {}
    if (stashedToken) {
      banner.innerHTML = `
        <strong>This tab's access key expired.</strong>
        Click Retry to validate it again without exposing it in the address bar.
        <button class="btn-ghost" id="session-expired-reload">Retry</button>
      `;
    } else {
      banner.innerHTML = `
        <strong>This tab's access key expired.</strong>
        Open One Link from the desktop shortcut (or its tray icon)
        to refresh this window with a fresh key. Your data is safe.
      `;
    }
    document.body.appendChild(banner);
    document.getElementById("session-expired-reload")
      ?.addEventListener("click", async (event) => {
        const button = event.currentTarget;
        if (button) button.disabled = true;
        const recovered = await _attemptAutoRecovery();
        if (recovered) {
          banner.remove();
          _sessionExpiredBannerShown = false;
          _resumeMainPollTimers();
          try { refreshPeers(); } catch (_) {}
          try { refreshTransfers(); } catch (_) {}
          try { refreshStatus(); } catch (_) {}
          try { refreshGroups(); } catch (_) {}
          return;
        }
        if (button) button.disabled = false;
      });
  }
