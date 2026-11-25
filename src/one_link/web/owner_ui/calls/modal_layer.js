  // May 16 2026 - UNIVERSAL MODAL CLOSE LAYER (UX audit P0-1, P0-2,
  // P1-9). Replaces 18+ ad-hoc bindings with one document-level
  // pair of handlers that close ANY visible modal via:
  //   - click on the backdrop element itself (not its children)
  //   - Escape key (closes the topmost visible modal)
  //
  // Recognized overlay shapes:
  //   .modal-backdrop.show          (most modals)
  //   .modal-backdrop[style*=flex]  (onboarding uses inline style)
  //   .discover-overlay.show
  //   .privacy-panel-overlay.show
  //   .call-overlay.show            (call ringing / active)
  //   .voice-overlay[style*=flex]   (voice recording)
  //
  // _closeOverlay(el) does the right thing for each shape +
  // emits a synthetic event so any per-modal cleanup (e.g.
  // stopping a recording, releasing a camera) can listen.
  function _isOverlayVisible(el) {
    if (!el) return false;
    if (el.classList.contains("show")) return true;
    // Onboarding + voice overlay use inline style.display.
    const cs = el.style && el.style.display;
    if (cs && cs !== "none" && cs !== "") return true;
    // Fall back to computed style for anything else.
    try {
      return getComputedStyle(el).display !== "none";
    } catch (_) { return false; }
  }
  function _closeOverlay(el) {
    if (!el) return;
    // Special closers - let the existing code path run if it
    // exposes a documented close function. This preserves
    // side-effects (stop recording, release camera, restore focus
    // to the trigger, etc.).
    if (el.id === "privacy-panel-overlay"
        && typeof _hidePrivacyPanel === "function") {
      _hidePrivacyPanel();
      return;
    }
    if (el.id === "voice-overlay"
        && typeof window.cancelVoiceRecord === "function") {
      window.cancelVoiceRecord();
      return;
    }
    if (el.id === "onboarding-backdrop") {
      el.style.display = "none";
      returnToOneHealthGuideIfPending();
      return;
    }
    // Default: strip the .show class. Works for every other modal.
    el.classList.remove("show");
    // Dispatch a synthetic close event so per-modal cleanup that
    // wants to listen (e.g., stopping a media-gallery slideshow)
    // can do so without rewriting its close button handler.
    try { el.dispatchEvent(new CustomEvent("ol-modal-closed", { bubbles: true })); }
    catch (_) {}
  }
  // Backdrop-click delegation - close when the user clicks the
  // dark area outside the inner panel.
  document.addEventListener("click", (ev) => {
    const t = ev.target;
    if (!t || !(t instanceof Element)) return;
    // Close-X delegation: any element with id ending in "-close"
    // (settings-cancel, device-cancel, conflicts-close, shortcuts-
    // close, debug-close, rdz-help-close, palette-close, privacy-
    // panel-close, etc.) should close its containing overlay. The
    // existing per-button handlers already do this; this is a
    // safety net so a forgotten binding doesn't trap the user.
    const closeBtn = t.closest("[data-modal-close], #privacy-panel-close, "
      + "#palette-close, #shortcuts-close, #rdz-help-close, #debug-close, "
      + "#conflicts-close");
    if (closeBtn) {
      const overlay = closeBtn.closest(
        ".modal-backdrop, .privacy-panel-overlay, .discover-overlay, "
        + ".onboarding-backdrop, .voice-overlay, .call-overlay"
      );
      if (overlay) {
        _closeOverlay(overlay);
        return;
      }
    }
    // Backdrop click: target IS the backdrop element itself.
    if (
      t.classList.contains("modal-backdrop")
      || t.classList.contains("privacy-panel-overlay")
      || t.classList.contains("discover-overlay")
      || t.classList.contains("onboarding-backdrop")
    ) {
      if (_isOverlayVisible(t)) {
        _closeOverlay(t);
        return;
      }
    }
  });

  // Single Esc handler closes the TOPMOST visible overlay.
  // "Topmost" = last visible one in DOM order (highest z-index
  // stacking-context for our use; we always append overlays at
  // body level). This makes Esc work everywhere - pair modal,
  // settings, device drawer, call overlays, every menu -
  // without each modal needing its own listener. Doctrine of
  // invisibility honored: the keyboard-shortcuts modal at
  // L5961 explicitly promises "Esc - close current modal";
  // before this commit that promise was a lie.
  function _topmostVisibleOverlay() {
    const candidates = document.querySelectorAll(
      ".modal-backdrop, .privacy-panel-overlay, .discover-overlay, "
      + ".onboarding-backdrop, .voice-overlay, .call-overlay"
    );
    let last = null;
    for (const el of candidates) {
      if (_isOverlayVisible(el)) last = el;
    }
    return last;
  }
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    const top = _topmostVisibleOverlay();
    if (top) {
      ev.preventDefault();
      _closeOverlay(top);
    }
  });

  document.addEventListener("keydown", (ev) => {
    const overlayEl = document.getElementById("privacy-panel-overlay");
    const isOpen = overlayEl && overlayEl.classList.contains("show");
    if (ev.key === "Escape" && isOpen) {
      _hidePrivacyPanel();
      return;
    }
    // Ctrl+Shift+P opens the panel (no menu-bar takeover risk).
    if (ev.ctrlKey && ev.shiftKey && (ev.key === "P" || ev.key === "p")) {
      ev.preventDefault();
      if (typeof window.openPrivacyPanel === "function") {
        window.openPrivacyPanel();
      }
    }
  });

