  // ── Global keyboard shortcuts ─────────────────────────────────────
  function isTypingTarget(t) {
    if (!t) return false;
    if (t.isContentEditable) return true;
    const tag = t.tagName;
    return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
  }
  function anyModalOpen() {
    return document.querySelector(".modal-backdrop.show, .discover-overlay.show") != null;
  }
  function closeAnyModal() {
    document.querySelectorAll(".modal-backdrop.show, .discover-overlay.show")
      .forEach(b => b.classList.remove("show"));
    if (state.discoverOpen) state.discoverOpen = false;
  }
  document.addEventListener("keydown", (e) => {
    // Esc - universal close (search input, modals)
    if (e.key === "Escape") {
      if (searchWrap.classList.contains("open")) {
        searchInput.value = ""; finishSearch();
        searchWrap.classList.remove("open");
        return;
      }
      if (anyModalOpen()) {
        closeAnyModal();
        return;
      }
    }
    // Bypass keyboard shortcuts while typing, except for the special
    // Ctrl-combos that users expect to work everywhere.
    const typing = isTypingTarget(e.target);
    const ctrl = e.ctrlKey || e.metaKey;
    // v0.9.3: Ctrl+K is now the GLOBAL command palette (handled in
    // its own listener earlier in the file). Ctrl+F replaces it as
    // the per-conversation search trigger - matches Slack / VS Code
    // / Notion conventions. Without this remap the two handlers
    // would race + the palette would steal focus mid-search.
    if (ctrl && (e.key === "f" || e.key === "F") && !e.shiftKey) {
      // Skip if browser-native find is desirable (no conversation
      // open).
      if (!state.selectedPeer && !state.selectedGroup) return;
      e.preventDefault();
      searchWrap.classList.add("open");
      searchInput.focus();
      return;
    }
    if (ctrl && e.key === "/") {
      e.preventDefault();
      input.focus();
      return;
    }
    // v0.8.1.1: hidden diagnostics - Ctrl+Shift+D.
    if (ctrl && e.shiftKey && (e.key === "d" || e.key === "D")) {
      e.preventDefault();
      openDebugOverlay();
      return;
    }
    if (ctrl && e.key === ",") {
      e.preventDefault();
      $("#btn-settings").click();
      return;
    }
    if (ctrl && (e.key === "n" || e.key === "N")) {
      e.preventDefault();
      $("#open-discover-modal").click();
      return;
    }
    if (ctrl && /^[1-9]$/.test(e.key)) {
      e.preventDefault();
      const peers = [...state.peers.values()];
      const idx = parseInt(e.key, 10) - 1;
      if (peers[idx]) selectPeer(peers[idx].short_id);
      return;
    }
    if (!typing && e.key === "?") {
      e.preventDefault();
      $("#shortcuts-backdrop").classList.add("show");
      return;
    }
  });

  init();

  // 2026-05-22 UX: tray "Connect a device" + first-launch onboarding
  // both deep-link to ``/?setup=add-device``. Detect that here and
  // auto-open the Add Device flow (mint a fresh QR + show the
  // setup pane) so the user lands directly on the QR instead of
  // having to navigate Settings → Setup → Add Device.
  try {
    const _setupParam = new URLSearchParams(location.search).get("setup");
    if (_setupParam === "add-device") {
      // Wait for init's async work to finish populating state.
      const _tryOpen = () => {
        const btn = document.getElementById("one-setup-add-device")
          || document.getElementById("one-setup-add-device-panel")
          || document.getElementById("settings-one-setup-add-device");
        if (btn) {
          // Open the panel + click the button to mint a fresh invite.
          const panel = document.getElementById("setup-pane")
            || document.querySelector('[data-pane="setup"]');
          if (panel && typeof panel.scrollIntoView === "function") {
            panel.scrollIntoView({ behavior: "smooth", block: "start" });
          }
          btn.click();
          // Strip the query param so a refresh doesn't re-mint a new
          // QR on every page reload.
          try {
            const url = new URL(location.href);
            url.searchParams.delete("setup");
            history.replaceState({}, "", url.toString());
          } catch (_) { /* best-effort */ }
        } else {
          setTimeout(_tryOpen, 250);
        }
      };
      // Give init() a beat to finish first.
      setTimeout(_tryOpen, 100);
    }
  } catch (_) { /* ignore — deep-link is best-effort */ }

  // MAY 15 2026 - removed the diagnostic title-bar overlay that
  // previously surfaced viewport measurements like
  // "One Link [vp 1707x996] [win 1707x1019] [chrome-px 23]
  // [.top y=56 h=34]" into the visible title bar. That string was
  // temporary instrumentation for a 2026-05 layout investigation;
  // the gap it was measuring was Edge's reserved chrome height
  // (now known + handled). The title now reads simply "One Link".
  document.title = "One Link";
