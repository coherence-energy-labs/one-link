  // Samsung Internet, Brave) fire `beforeinstallprompt` once
  // installability criteria are met (manifest valid + SW registered
  // + served over HTTPS or localhost). We capture the event, prevent
  // the browser's own banner, and show our own button in About.
  // On click, we call .prompt() on the deferred event so the user
  // gets the OS-native install dialog. Firefox + iOS Safari don't
  // fire this event; on those platforms users follow the OS
  // add-to-home-screen path instead.
  state.installPromptEvent = null;
  function _showInstallAffordance() {
    const row = document.querySelector("#install-pwa-row");
    const help = document.querySelector("#install-pwa-help");
    if (row) row.style.display = "";
    if (help) help.style.display = "";
  }
  function _hideInstallAffordance() {
    const row = document.querySelector("#install-pwa-row");
    const help = document.querySelector("#install-pwa-help");
    if (row) row.style.display = "none";
    if (help) help.style.display = "none";
  }
  window.addEventListener("beforeinstallprompt", (e) => {
    // Stop the browser's own banner so we control when + where the
    // prompt appears (in our About pane, not as a top-of-page bar
    // that competes with the chat surface).
    e.preventDefault();
    state.installPromptEvent = e;
    _showInstallAffordance();
  });
  window.addEventListener("appinstalled", () => {
    state.installPromptEvent = null;
    _hideInstallAffordance();
    toast("One Link installed. Open it from your home screen any time.", "good", 5000);
  });
  document.querySelector("#btn-install-pwa")?.addEventListener("click", async () => {
    const ev = state.installPromptEvent;
    if (!ev) {
      toast("Install isn't available in this browser. Try Chrome or Edge, or use your browser's 'Add to home screen' option.", "info", 6000);
      return;
    }
    try {
      ev.prompt();
      const choice = await ev.userChoice;
      // Either way, the deferred prompt is single-use; clear it.
      state.installPromptEvent = null;
      if (choice && choice.outcome === "accepted") {
        // appinstalled will fire and hide the affordance. No-op here.
      } else {
        // User dismissed; keep the affordance hidden until a future
        // beforeinstallprompt fires (browser may re-fire after a
        // few page loads).
        _hideInstallAffordance();
      }
    } catch (err) {
      toast(`Install prompt failed: ${err && err.message ? err.message : err}`, "bad");
    }
  });

  // Detect "already running as installed PWA" - Chrome sets the
  // display-mode media query to "standalone" inside the installed
  // shell. Suppress the install affordance so the user isn't told
  // to "install" the thing they're already inside.
  if (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches) {
    _hideInstallAffordance();
  }

  // v0.14.8 - Phone diagnostics escape hatch. The Advanced settings
  // pane carries the desktop-only "Open diagnostics" button + the
  // page-wide Ctrl+Shift+D shortcut. Phones have neither (no
  // keyboard, Advanced pane is hidden). Long-pressing the version
  // string in About is the in-app fallback so a phone user can
  // still reach diagnostics if a maintainer asks "open the debug
  // overlay and tell me what you see." 800ms threshold matches
  // platform conventions.
  (function _wirePhoneDiagnosticsLongPress() {
    const target = $("#settings-about-version");
    if (!target) return;
    let timer = null;
    const start = (e) => {
      // Skip non-phone form-factors - desktop has Ctrl+Shift+D and
      // the Advanced pane button. Avoid surprising desktop users
      // who linger on the version string.
      const ff = document.documentElement.getAttribute("data-form-factor");
      if (ff !== "phone") return;
      timer = setTimeout(() => {
        timer = null;
        $("#settings-backdrop")?.classList.remove("show");
        openDebugOverlay();
      }, 800);
    };
    const cancel = () => { if (timer) { clearTimeout(timer); timer = null; } };
    target.addEventListener("touchstart", start, { passive: true });
    target.addEventListener("touchend", cancel);
    target.addEventListener("touchmove", cancel);
    target.addEventListener("touchcancel", cancel);
    // Mouse fallback so a tablet on a hybrid form-factor still works.
    target.addEventListener("mousedown", start);
    target.addEventListener("mouseup", cancel);
    target.addEventListener("mouseleave", cancel);
  })();

