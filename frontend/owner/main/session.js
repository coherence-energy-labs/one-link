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

  // ── This window's link to the daemon ──────────────────────────────
  // windowLink (services/window_link.js) owns the session state, its
  // recovery and the one status line. This module supplies what that
  // service cannot reach by itself: the probe, the credential stores, the
  // polling cluster and the DOM element.

  // Ask the daemon whether this window's credential still works. The
  // origin-scoped bearer goes in the Authorization header (the fetch wrapper
  // above adds it); it is never serialized into a URL.
  //
  //   "ok"           the daemon accepted it
  //   "rejected"     the daemon answered and refused it (401/403)
  //   "unavailable"  no answer about the credential: unreachable, a 5xx, or
  //                  a rate limit. This says nothing about the credential.
  async function _probeOwnerSession() {
    try {
      const r = await fetch("/api/me", { cache: "no-store" });
      if (r.ok) return "ok";
      if (r.status === 401 || r.status === 403) return "rejected";
      return "unavailable";
    } catch (_) {
      return "unavailable";
    }
  }

  // The credential was refused twice in a row: it is dead. Flush it so a
  // reload does not present a known-bad value again.
  function _forgetRejectedOwnerSession() {
    try { sessionStorage.removeItem("ol_session_token"); } catch (_) {}
    try { localStorage.removeItem(_PERSISTENT_OWNER_SESSION_KEY); } catch (_) {}
  }

  let _offlineStatusCopy = null;
  function _renderWindowStatus(kind) {
    const b = document.querySelector("#offline-banner");
    if (!b) return;
    const text = b.querySelector("span:not(.offline-dot)");
    if (!text) return;
    // The markup carries the offline copy; keep it so the line can return
    // to it after showing something else.
    if (_offlineStatusCopy === null) _offlineStatusCopy = text.textContent;
    b.querySelector(".status-action")?.remove();
    b.classList.toggle("session-expired-banner", kind === "signed_out");
    b.dataset.status = kind || "";
    if (!kind) {
      b.classList.remove("show");
      text.textContent = _offlineStatusCopy;
      return;
    }
    if (kind === "signed_out") {
      showSessionExpiredBanner(text);
    } else if (kind === "restoring") {
      // doctrine-ok: §3.2.a grandfathered legacy surface (ADR-PENDING-doctrine-sweep-v0.21); reconnect banner is on the v0.21 cleanup list. Replace with silent prewarm + capsule-mode fallback per LIVING_PRESENCE_ARCHITECTURE §3.
      text.textContent = "Restoring One Link…";
      // Recovery retries by itself. The button only skips the wait.
      const now = document.createElement("button");
      now.type = "button";
      now.className = "btn-ghost status-action";
      now.textContent = "Try now";
      now.addEventListener("click", () => {
        windowLink.retryNow();
        LiveRefresh.forceReconnectNow();
      });
      b.appendChild(now);
    } else {
      text.textContent = _offlineStatusCopy;
    }
    b.classList.add("show");
  }

  const windowLink = createWindowLink({
    probe: _probeOwnerSession,
    forgetCredential: _forgetRejectedOwnerSession,
    // Six polls answering 401 in a burst would each start a recovery;
    // stop them while the link is being restored.
    suspend: () => _pauseMainPollTimers(),
    resume: () => {
      _resumeMainPollTimers();
      // Refresh now instead of leaving the page stale until each poll's
      // next tick. Each refresh tolerates a failed request.
      try { refreshPeers(); } catch (_) {}
      try { refreshTransfers(); } catch (_) {}
      try { refreshStatus(); } catch (_) {}
      try { refreshGroups(); } catch (_) {}
    },
    render: _renderWindowStatus,
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (id) => clearTimeout(id),
    random: () => Math.random(),
  });

  // Every API call reports its status here (services/api_client.js). A 401
  // starts recovery; anything else is the caller's business.
  function _maybe401(status) {
    if (status !== 401) return;
    windowLink.unauthorized();
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

  // The daemon refused this window's credential twice. Nothing on this page
  // can obtain a new one: the launcher mints it. So the line says exactly
  // that, in the person's terms, and offers no button that cannot work.
  // It is written into the status line's own text node, so it cannot be
  // shown twice or on top of another status.
  function showSessionExpiredBanner(text) {
    text.textContent = "";
    const lead = document.createElement("strong");
    lead.textContent = "This window was signed out.";
    text.appendChild(lead);
    text.appendChild(document.createTextNode(
      " Open One Link from its desktop shortcut or tray icon to continue. Your data is safe.",
    ));
  }
