  // ── v0.21.1 mobile-feel polish: gesture + viewport handlers ─────
  //
  // Three behaviours layer onto the existing CSS responsive shell:
  //
  //   1. Edge-swipe-right from the left edge opens the sidebar
  //      drawer. Swipe-left while the drawer is open closes it.
  //      Mimics iOS / Android system back gestures so the drawer
  //      feels native, not "tap the tiny hamburger".
  //
  //   2. visualViewport tracking keeps `.app` height matched to
  //      the visible-after-keyboard area. Without this, when the
  //      soft keyboard slides up, our 100dvh-sized `.app` stays
  //      tall and the composer ends up BEHIND the keyboard. Modern
  //      browsers also honour viewport meta `interactive-widget=
  //      resizes-content`, but the JS belt-and-suspenders catches
  //      iOS Safari, which still hasn't fully implemented it as
  //      of 2026-05.
  //
  //   3. Haptic feedback hook: tiny vibration on send + reaction
  //      so the user knows the gesture took. Browser API is
  //      navigator.vibrate; iOS Safari ignores it (no haptics on
  //      web yet), but Android Chrome / Edge / Firefox all honour
  //      a 10ms tick.
  //
  // The handlers all no-op on desktop form-factor so a hover-only
  // accidental cursor drag doesn't fire phantom gestures.
  (() => {
    function _isPhone() {
      return document.documentElement.getAttribute("data-form-factor") === "phone";
    }

    // ---- Edge-swipe drawer gesture ----
    // Touch starts on the left 24px of the screen → open drawer
    // (or close if already open and swiping the other way).
    let touchStartX = 0;
    let touchStartY = 0;
    let touchStartTime = 0;
    let touchActive = false;
    const EDGE_ZONE_PX = 24;
    const MIN_SWIPE_PX = 60;
    const MAX_VERTICAL_DRIFT_PX = 50;
    const MAX_SWIPE_DURATION_MS = 500;

    function onTouchStart(ev) {
      if (!_isPhone()) return;
      // Don't compete with any open modal / backdrop.
      if (document.querySelector(
        ".modal-backdrop.show, .backdrop.show, .discover-overlay.show",
      )) return;
      const t = ev.touches[0];
      const drawerOpen = document.querySelector(".app")?.classList.contains("mobile-side-open");
      // To open: must start in the left edge zone.
      // To close: drawer is open and finger started anywhere right of
      // the drawer's right edge (~320px) - closes via swipe-left from
      // the conversation area.
      if (!drawerOpen && t.clientX > EDGE_ZONE_PX) return;
      if (drawerOpen && t.clientX < 100) return;  // ignore drag from inside drawer
      touchStartX = t.clientX;
      touchStartY = t.clientY;
      touchStartTime = Date.now();
      touchActive = true;
    }
    function onTouchEnd(ev) {
      if (!touchActive) return;
      touchActive = false;
      const t = ev.changedTouches[0];
      const dx = t.clientX - touchStartX;
      const dy = Math.abs(t.clientY - touchStartY);
      const dt = Date.now() - touchStartTime;
      if (dt > MAX_SWIPE_DURATION_MS) return;
      if (dy > MAX_VERTICAL_DRIFT_PX) return;
      const drawerOpen = document.querySelector(".app")?.classList.contains("mobile-side-open");
      if (!drawerOpen && dx > MIN_SWIPE_PX) {
        openMobileSidebar();
        _haptic(8);
      } else if (drawerOpen && dx < -MIN_SWIPE_PX) {
        closeMobileSidebar();
        _haptic(8);
      }
    }
    document.addEventListener("touchstart", onTouchStart, { passive: true });
    document.addEventListener("touchend", onTouchEnd, { passive: true });

    // ---- visualViewport keyboard-aware sizing ----
    // When the soft keyboard slides up, visualViewport.height shrinks
    // by the keyboard height. We mirror that into a CSS custom prop
    // --ol-vh that the composer + chat list consume so the composer
    // stays just above the keyboard instead of being hidden behind it.
    const _vv = window.visualViewport;
    function _syncViewportHeight() {
      const h = (_vv && _vv.height) ? _vv.height : window.innerHeight;
      document.documentElement.style.setProperty("--ol-vh", `${h}px`);
    }
    if (_vv) {
      _vv.addEventListener("resize", _syncViewportHeight);
      _vv.addEventListener("scroll", _syncViewportHeight);
    }
    window.addEventListener("orientationchange", _syncViewportHeight);
    _syncViewportHeight();

    // ---- Haptic feedback hook ----
    // Tiny tick on send / reaction. iOS Safari ignores (no Web Vibration
    // API support); Android browsers honour. Wrap in try/catch because
    // some browsers (Firefox in iframe) throw on .vibrate().
    function _haptic(ms) {
      try { navigator.vibrate && navigator.vibrate(ms); } catch {}
    }
    // Expose globally so existing send / reaction handlers can use it.
    window._olHaptic = _haptic;

    // Wire haptic to message-send: when the send button is tapped, fire
    // an 8ms tick before the network call. Coordinated through the
    // existing send button click handler so we don't double-bind.
    const sendBtn = document.querySelector("#btn-send");
    if (sendBtn) {
      sendBtn.addEventListener("click", () => _haptic(8), { passive: true });
    }
  })();

  async function setCapability(cap, enabled, opts = {}) {
    // v0.7.3: drawer can pass an explicit `fingerprint`; otherwise
    // we fall back to the currently-selected peer (legacy callers).
    let fp = opts.fingerprint || null;
    let peer = null;
    if (fp) {
      peer = [...state.peers.values()].find(p => p.fingerprint === fp) || null;
    } else {
      peer = state.selectedPeer ? state.peers.get(state.selectedPeer) : null;
      fp = peer?.fingerprint || null;
    }
    if (!fp) return;
    const current = peer && peer.allowed_capabilities != null
      ? new Set(peer.allowed_capabilities)
      : new Set(["chat", "files", "folder_sync"]);
    if (enabled) current.add(cap); else current.delete(cap);
    try {
      const res = await api.post(
        `/api/peers/${fp}/capabilities`, { allowed: [...current] }
      );
      if (peer) peer.allowed_capabilities = res.allowed;
      toast("Peer policy updated", "good");
      return res;
    } catch (e) {
      toast(`Policy update failed: ${e.message || e}`, "bad");
      throw e;
    }
  }

  // v0.21.x: first-send celebration. Tracks per-peer in
  // localStorage so the moment fires exactly once per peer. Renders
  // a brief ✨ glow on the just-painted bubble. Skips when the
  // celebration is disabled or the bubble can't be found.
