  function _ensureRecoveryWizard() {
    if (document.getElementById("recovery-wizard")) return;
    const m = document.createElement("div");
    m.id = "recovery-wizard";
    m.className = "recwiz-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-label", "Set up recovery");
    m.innerHTML = `
      <div class="recwiz-backdrop" data-recwiz-close></div>
      <div class="recwiz-pane">
        <h2 class="recwiz-title">Set up recovery</h2>
        <p class="recwiz-lead">
          If you lose every device with One Link, this is how you get
          back in. There is no cloud reset, no password recovery, no
          support email. Pick one path now. We recommend the recovery
          phrase plus at least one of the others.
        </p>
        <div id="recwiz-track-phrase" class="recwiz-card" data-track="phrase"></div>
        <div id="recwiz-track-social" class="recwiz-card" data-track="social"></div>
        <div id="recwiz-track-backup" class="recwiz-card" data-track="backup"></div>
        <div id="recwiz-track-restore" class="recwiz-card" data-track="restore">
          <div class="recwiz-card-head">
            <div class="recwiz-card-name">Restore an existing identity</div>
          </div>
          <p class="recwiz-card-desc">
            Coming from another install with a recovery phrase? Type
            the 24 words here to replace this identity with the one
            you had before.
          </p>
          <details class="recwiz-help">
            <summary>How does this work?</summary>
            <p>
              Your identity and .olbak bundle key are derived from the
              24-word phrase. Application data keys are either derived
              from it or stored in the backup under an authenticated
              seed-recovery wrap. Typing the phrase restores your
              identity; bringing the matching .olbak file restores the
              saved data inside it. The phrase never leaves this device.
            </p>
          </details>
          <div class="recwiz-card-actions">
            <button type="button" class="recwiz-btn" data-recwiz-action="open-restore">
              Restore from phrase
            </button>
          </div>
        </div>
        <div id="recwiz-track-rotate" class="recwiz-card" data-track="rotate"></div>
        <div id="recwiz-track-held-shares" class="recwiz-card" data-track="held-shares"></div>
        <div class="recwiz-close-bar" style="justify-content:space-between;">
          <button type="button" class="recwiz-btn recwiz-btn-danger" data-recwiz-action="reset"
                  title="Clear the wizard's setup flags so each track can be re-run. Does not touch the master seed or peer state.">
            Reset recovery setup
          </button>
          <button type="button" class="recwiz-btn" data-recwiz-action="close">Done</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
    m.addEventListener("click", (ev) => {
      const t = ev.target;
      if (!(t instanceof Element)) return;
      if (t.hasAttribute("data-recwiz-close")) _recwizClose();
      const action = t.getAttribute("data-recwiz-action");
      if (action === "close") _recwizClose();
      if (action === "open-restore") {
        // Close the setup wizard first so the two modals don't
        // stack. The restore modal handles its own open/close.
        _recwizClose();
        openRecoveryRestoreModal();
      }
      if (action === "open-rotate") {
        _recwizClose();
        openRotationModal();
      }
      if (action === "reset") {
        _recwizConfirmReset();
      }
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && m.classList.contains("show")) _recwizClose();
    });
  }

  function _recwizClose() {
    const modal = document.getElementById("recovery-wizard");
    if (modal) modal.classList.remove("show");
    document.body.classList.remove("recwiz-open");
    _recwizReturnFocus(modal);
  }

  // ── recovery-modal focus management (Phase G a11y) ────────────────
  // Two helpers shared by every recovery modal (wizard + restore +
  // rotate + share-unwrap):
  //   1. _recwizCaptureFocus stores the element that opened the
  //      modal so we can return focus there on close.
  //   2. _recwizSetInitialFocus moves keyboard focus to the first
  //      interactive element inside the modal pane so the user
  //      does not lose their place.
  //   3. _recwizReturnFocus moves focus back to the captured
  //      trigger element when the modal closes.
  // Without these, keyboard + screen-reader users hit Tab into
  // the page background after the modal opens, and after it
  // closes they have to re-find their entry point. With them,
  // focus flows naturally through the modal and back out.
  function _recwizCaptureFocus(modal) {
    if (!modal) return;
    const trigger = document.activeElement;
    if (trigger && trigger !== document.body) {
      modal._recwizFocusReturn = trigger;
    }
  }
  function _recwizSetInitialFocus(modal) {
    if (!modal) return;
    // setTimeout so the modal is paint-stable before focus moves
    // (avoids a single-tick race where the focus call lands on
    // an element that's still display:none).
    setTimeout(() => {
      const target = modal.querySelector(
        ".recwiz-pane input:not([type='hidden']):not([disabled])," +
        " .recwiz-pane textarea:not([disabled])," +
        " .recwiz-pane select:not([disabled])," +
        " .recwiz-pane button:not([disabled]):not([data-recwiz-close])"
      );
      if (target && typeof target.focus === "function") {
        try { target.focus(); } catch (_) { /* defensive */ }
      }
    }, 40);
  }
  function _recwizReturnFocus(modal) {
    if (!modal) return;
    const trigger = modal._recwizFocusReturn;
    modal._recwizFocusReturn = null;
    if (
      trigger
      && trigger.isConnected
      && typeof trigger.focus === "function"
      && !trigger.disabled
    ) {
      try { trigger.focus(); } catch (_) { /* defensive */ }
    }
  }

  // Shared 'Shut down One Link now' helper used by the rotation +
  // restore success cards. window.confirm before the destructive
  // call so an accidental click is recoverable. After shutdown the
  // user is told to restart via launcher / re-run command - the
  // daemon does NOT auto-restart (no supervisor assumption).
  async function _recwizShutdownDaemon(reason) {
    const ok = window.confirm(
      "Shut down One Link now?\n\n" +
      "This stops the daemon so the new identity loads on next " +
      "start. If you launched One Link from a system tray, click " +
      "the tray icon to start it again; otherwise re-run the " +
      "daemon command. Your browser tab will reconnect once the " +
      "fresh daemon is up."
    );
    if (!ok) return;
    try {
      await api.daemonShutdown(reason || "recovery_restart");
      toast("Daemon shutting down. Restart One Link to come back.", "info", 8000);
    } catch (e) {
      toast(`Shutdown failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  // 'Reset recovery setup' clears only per-track setup flags so the wizard can
  // be re-run with real intent. It never touches rotation delivery state.
  // Native
  // window.confirm keeps the modal stack from getting too deep
  // (the wizard is already a modal) and matches OS-level
  // 'are you sure?' UX users already know.
  async function _recwizConfirmReset() {
    const ok = window.confirm(
      "Reset recovery setup?\n\n" +
      "This clears the wizard's setup flags so each track shows " +
      "as 'not configured' and can be re-run. It does NOT touch " +
      "the master seed, your identity, or any peer state."
    );
    if (!ok) return;
    try {
      await api.recoveryReset();
      toast("Recovery setup reset. Re-run any track when ready.", "good", 5000);
      await _recwizRefreshStatus();
      await refreshOneSetup();
    } catch (e) {
      toast(`Reset failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function _showRecoveryWizard() {
    _ensureRecoveryWizard();
    const modal = document.getElementById("recovery-wizard");
    _recwizCaptureFocus(modal);
    modal.classList.add("show");
    document.body.classList.add("recwiz-open");
    _recwizSetInitialFocus(modal);
    await _recwizRefreshStatus();
  }

  async function _recwizRefreshStatus() {
    let status;
    try {
      status = await api.recoveryStatus();
    } catch (e) {
      toast(`Could not load recovery status: ${errorToastBody(e)}`, "bad", 5000);
      return;
    }
    _recwizRenderPhraseCard(status.phrase || {});
    _recwizRenderSocialCard(status.social || {});
    _recwizRenderBackupCard(status.backup || {});
    // Rotation card pulls its own status because it isn't part of
    // the recovery-status snapshot - it's about queue state, not
    // backup/restore configuration.
    _recwizRenderRotateCard().catch(() => {});
    // Held-shares card (guardian side of social-share recovery).
    // Also pulls its own status from the dedicated endpoint.
    _recwizRenderHeldSharesCard().catch(() => {});
  }

  function _recwizFormatRelative(ms) {
    const v = Number(ms) || 0;
    if (v <= 0) return "never";
    const delta = Date.now() - v;
    if (delta < 60000) return "just now";
    if (delta < 3600000) return `${Math.floor(delta / 60000)} min ago`;
    if (delta < 86400000) return `${Math.floor(delta / 3600000)} hr ago`;
    return `${Math.floor(delta / 86400000)} d ago`;
  }

  function _recwizHumanSize(bytes) {
    const b = Number(bytes) || 0;
    if (!b) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
    let v = b; let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
  }

