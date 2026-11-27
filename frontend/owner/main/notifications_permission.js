  // ── Click-to-copy helper ───────────────────────────────────────────
  async function copyToClipboard(text, label) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${label || "to clipboard"}`, "good", 1800);
    } catch (e) {
      // Fallback for older browsers / non-secure contexts.
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        toast(`Copied ${label || "to clipboard"}`, "good", 1800);
      } catch {
        toast("Copy refused. Clipboard's busy.", "bad");
      }
      document.body.removeChild(ta);
    }
  }

  // ── Desktop notifications ──────────────────────────────────────────
  function notifySupported() {
    return typeof Notification !== "undefined";
  }
  function maybeShowNotifBanner() {
    // v0.7.x: notification opt-in moved into Settings. This helper
    // is kept as a no-op so existing call sites stay valid; the
    // status now renders in the settings modal's "Desktop
    // notifications" row, populated by populateNotifSettings().
  }

  // v0.21.x: read /api/update/check and surface the "update available"
  // affordance — both the top banner and the inline header chip — when
  // the latest GitHub Release is newer than this build. Per-version
  // dismiss in localStorage so a user who dismissed v0.22.1 still
  // sees both surfaces when v0.23.0 ships.
  //
