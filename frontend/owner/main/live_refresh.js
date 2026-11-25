  // ── LiveRefresh: smart auto-reconnect + auto-update controller ────
  //
  // Goals (in priority order):
  //   1. Just work. Recover automatically from network blips, daemon
  //      restarts, laptop sleep/wake, tab dormancy, OS-level offline,
  //      and version upgrades. The user should never have to hit
  //      reload or restart One Link manually for a routine event.
  //   2. Don't disrupt the user. Never auto-reload while the user has
  //      draft text in a composer, is mid-pair, has a modal open, or
  //      typed in the last few seconds. If they're busy, defer the
  //      reload until they're idle - there is no hurry.
  //   3. Stay silent when normal. A brief WS reconnect (< 4s) should
  //      pass without surfacing anything. Only when reconnect drags
  //      do we light up the existing offline banner with a calm
  //      link-repair message - same channel users already know
  //      from the OS-offline path, so it reads as familiar, not new.
  //   4. Never reload-loop. We persist "already refreshed for version
  //      X" in sessionStorage so a misbehaving daemon can't flap us
  //      into a refresh cycle.
  // v0.21.x: "Update ready" banner surfaced from inside LiveRefresh's
  // scheduleSoftReload. Module-scoped so the function lives outside
  // the IIFE and can be referenced without hoisting concerns.
  function _showUpdateReadyBanner(targetVersion, doReloadNow) {
    if (document.getElementById("update-ready-banner")) return;
    const bar = document.createElement("div");
    bar.id = "update-ready-banner";
    bar.className = "update-ready-banner";
    bar.setAttribute("role", "status");
    bar.innerHTML = `
      <span class="urb-text">An update is ready for One Link.</span>
      <button type="button" class="urb-reload">Reload now</button>
      <button type="button" class="urb-dismiss" aria-label="Dismiss">✕</button>
    `;
    document.body.appendChild(bar);
    const reload = bar.querySelector(".urb-reload");
    const dismiss = bar.querySelector(".urb-dismiss");
    function remove() { try { bar.remove(); } catch {} }
    reload.onclick = (ev) => {
      ev.stopPropagation();
      remove();
      try { doReloadNow && doReloadNow(); }
      catch { try { location.reload(); } catch {} }
    };
    dismiss.onclick = (ev) => { ev.stopPropagation(); remove(); };
  }

  const LiveRefresh = (() => {
    let reconnectAttempts = 0;
    let reconnectTimer = null;
    let bannerTimer = null;
    let bannerShown = false;
    let pendingReloadTimer = null;
    let lastInputActivity = 0;
    let lastConnectedAt = 0;
    let wsHadOpen = false;

    // Track any keystroke / pointer activity so we can tell whether
    // the user is currently driving the UI vs idle. Used to avoid
    // mid-action reloads. Capture-phase so we see events regardless
    // of which handler stops propagation.
    document.addEventListener("input",   () => { lastInputActivity = Date.now(); }, true);
    document.addEventListener("keydown", () => { lastInputActivity = Date.now(); }, true);
    document.addEventListener("pointerdown", () => { lastInputActivity = Date.now(); }, true);

    function isUserBusy() {
      // Composer has draft text → user is mid-message.
      const inp = document.querySelector("#input");
      if (inp && inp.value && inp.value.trim().length > 0) return true;
      const gInp = document.querySelector("#group-input");
      if (gInp && gInp.value && gInp.value.trim().length > 0) return true;
      // Any modal / backdrop currently open → defer.
      if (document.querySelector(".modal-backdrop.show, .backdrop.show")) return true;
      if (document.querySelector(".pair-modal.show, .pair-backdrop.show")) return true;
      // Recent activity → defer (5s grace).
      if (Date.now() - lastInputActivity < 5000) return true;
      // Tab not visible → safe-but-not-now: don't reload a hidden
      // tab (next visible focus will re-check and reload then).
      if (document.visibilityState === "hidden") return true;
      return false;
    }

    function backoffMs() {
      // Exponential: 1s, 2s, 4s, 8s, 16s, 30s cap. ±25% jitter so
      // many tabs restoring after a daemon restart don't pile in
      // lock-step.
      const base = Math.min(30000, 1000 * Math.pow(2, reconnectAttempts));
      const jitter = (Math.random() - 0.5) * 0.5 * base;
      return Math.floor(base + jitter);
    }

    function showReconnectBanner() {
      if (bannerShown) return;
      bannerShown = true;
      const b = document.querySelector("#offline-banner");
      if (!b) return;
      const txt = b.querySelector("span:not(.offline-dot)");
      if (txt && b._savedText == null) {
        b._savedText = txt.textContent;
        // doctrine-ok: §3.2.a grandfathered legacy surface (ADR-PENDING-doctrine-sweep-v0.21); reconnect banner is on the v0.21 cleanup list. Replace with silent prewarm + capsule-mode fallback per LIVING_PRESENCE_ARCHITECTURE §3.
        txt.textContent = "Restoring One Link…";
      }
      b.classList.add("show");
    }

    function hideReconnectBanner() {
      if (!bannerShown && navigator.onLine !== false) return;
      bannerShown = false;
      const b = document.querySelector("#offline-banner");
      if (!b) return;
      const txt = b.querySelector("span:not(.offline-dot)");
      if (txt && b._savedText != null) {
        txt.textContent = b._savedText;
        b._savedText = null;
      }
      // Only fully clear if the OS reports online. If the OS still
      // says offline, the offline handler's "You're offline" copy
      // belongs there.
      if (navigator.onLine !== false) {
        b.classList.remove("show");
      } else {
        // Restore the OS-offline copy (saved above already).
      }
    }

    function onOpen() {
      reconnectAttempts = 0;
      lastConnectedAt = Date.now();
      const wasReconnect = wsHadOpen;
      wsHadOpen = true;
      if (bannerTimer) { clearTimeout(bannerTimer); bannerTimer = null; }
      hideReconnectBanner();
      // After a reconnect (not the very first open), the daemon may
      // have upgraded. Check now so any version drift triggers a
      // soft reload instead of stale-page mystery errors.
      if (wasReconnect) {
        checkVersionDrift();
        // Best-effort refresh of UI surfaces that may have missed
        // events during the gap.
        try { refreshPeers && refreshPeers(); } catch {}
        try { refreshTransfers && refreshTransfers(); } catch {}
        try { refreshStatus && refreshStatus(); } catch {}
      }
    }

    function onClose() {
      if (!bannerTimer) {
        // Don't flash the banner for sub-4s reconnects. Most daemon
        // restarts during dev / upgrade complete inside this window.
        bannerTimer = setTimeout(showReconnectBanner, 4000);
      }
      scheduleReconnect();
    }

    function scheduleReconnect() {
      if (reconnectTimer) return;
      const delay = backoffMs();
      reconnectAttempts++;
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        try { connectWS(); }
        catch (e) {
          // connectWS itself blew up (e.g. invalid host). Treat as
          // a close; the next backoff slot will try again.
          onClose();
        }
      }, delay);
    }

    function forceReconnectNow() {
      // Used by visibilitychange / network-restored. Cancel pending
      // backoff, reset attempt counter, fire immediately.
      if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
      reconnectAttempts = 0;
      try { connectWS(); } catch { scheduleReconnect(); }
    }

    async function checkVersionDrift() {
      try {
        const me = await api.get("/api/me");
        const v = me && me.app_version;
        const fp = me && me.source_fingerprint;
        if (v && v !== PAGE_BUILT_FOR) {
          scheduleSoftReload(v, "reconnect");
          return;
        }
        if (
          fp
          && PAGE_SOURCE_FINGERPRINT !== "__ONE_LINK_SOURCE_FINGERPRINT__"
          && fp !== PAGE_SOURCE_FINGERPRINT
        ) {
          scheduleSoftReload(`${v || PAGE_BUILT_FOR}:${fp}`, "source");
        }
      } catch {
        // Ignore - we'll get another shot on the next reconnect.
      }
    }

    function scheduleSoftReload(targetVersion, reason) {
      // Loop guard: never refresh twice for the same daemon version
      // in one tab session.
      const key = `ol_refreshed_for_version:${targetVersion}`;
      if (sessionStorage.getItem(key) === "1") return;
      if (pendingReloadTimer) return;
      console.info(`LiveRefresh: daemon version drift (${PAGE_BUILT_FOR} → ${targetVersion}); reason=${reason}; scheduling soft reload when idle.`);

      let waitedMs = 0;
      function attempt() {
        pendingReloadTimer = null;
        if (isUserBusy()) {
          // Defer up to 5 minutes; after that, just reload - the
          // user might have walked away leaving draft text behind,
          // and a stale page is more dangerous than a lost draft.
          if (waitedMs >= 5 * 60 * 1000) {
            doReload();
            return;
          }
          waitedMs += 10000;
          pendingReloadTimer = setTimeout(attempt, 10000);
          return;
        }
        doReload();
      }
      function doReload() {
        sessionStorage.setItem(key, "1");
        toast("Updating One Link…", "info", 2500);
        // Give the toast ~1 frame to render before reload yanks the
        // page out from under it. Use a short delay (not setImmediate)
        // so the user actually sees the reassuring copy.
        setTimeout(() => {
          try { location.reload(); }
          catch { location.href = location.href; }
        }, 800);
      }
      // Initial 2s settle window so a noisy reconnect (multiple
      // open/close handshakes during a daemon restart) doesn't
      // race us to reload before the daemon stabilizes.
      pendingReloadTimer = setTimeout(attempt, 2000);
      // v0.21.x: also surface a sticky "Update ready" banner so a
      // user mid-conversation can opt to reload now instead of
      // waiting for the idle-wait timer to fire. Banner is a
      // single 28px strip at the top of the chat surface; clicking
      // "Reload now" runs the same doReload() path the timer would
      // run, so the loop-guard sessionStorage key is honored
      // uniformly. Ignoring the banner falls through to the
      // existing idle-wait behaviour with no behaviour change.
      try { _showUpdateReadyBanner(targetVersion, doReload); } catch (_) {}
    }

    function attachWindowHandlers() {
      // Tab returns to foreground → daemon may have restarted while
      // we were dormant. Force a reconnect and re-check version.
      document.addEventListener("visibilitychange", () => {
        if (document.visibilityState !== "visible") return;
        if (!ws || ws.readyState >= 2 /* CLOSING|CLOSED */) {
          forceReconnectNow();
        } else if (ws.readyState === 1 /* OPEN */) {
          // Long-dormant tab: WS might be a half-open zombie, and
          // the daemon may have upgraded. Probe + check.
          checkVersionDrift();
        }
      });
      // OS reports network-up → reconnect immediately, don't wait
      // for the backoff window.
      window.addEventListener("online", () => {
        forceReconnectNow();
      });
    }

    return {
      onOpen, onClose,
      forceReconnectNow,
      scheduleSoftReload,
      checkVersionDrift,
      attachWindowHandlers,
      isUserBusy,
    };
  })();

