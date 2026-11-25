  // ── Discovery modal bindings (v0.4) ───────────────────────────────
  $("#open-discover-modal").addEventListener("click", openDiscoverModal);
  $("#discover-close").addEventListener("click", closeDiscoverModal);
  $("#discover-refresh").addEventListener("click", () =>
    loadDiscoverable({ prune: true })
  );
  // Close on overlay click (outside the modal box) or Esc.
  $("#discover-overlay").addEventListener("click", (e) => {
    if (e.target.id === "discover-overlay") closeDiscoverModal();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && state.discoverOpen) closeDiscoverModal();
  });

  // ── Invite sub-modal bindings ─────────────────────────────────────
  const _inviteBtn = $("#discover-invite-btn");
  if (_inviteBtn) {
    _inviteBtn.addEventListener("click", () => openInviteModal(null));
  }
  const _inviteClose = $("#invite-close");
  if (_inviteClose) {
    _inviteClose.addEventListener("click", closeInviteModal);
  }
  const _inviteCopy = $("#invite-copy");
  if (_inviteCopy) {
    _inviteCopy.addEventListener("click", async () => {
      const url = ($("#invite-url").textContent || "").trim();
      if (!url) return;
      try {
        await navigator.clipboard.writeText(url);
        toast("Invite link copied", "ok");
      } catch (e) {
        toast("Couldn't copy. Long-press to copy manually.", "bad");
      }
    });
  }
  // Tap-to-copy on the pair-code card. The whole big code is a
  // button - single tap copies + flashes feedback.
  const _inviteCodeCard = $("#invite-code-card");
  if (_inviteCodeCard) {
    _inviteCodeCard.addEventListener("click", async () => {
      const code = ($("#invite-code").textContent || "").trim();
      if (!code || code === "------") return;
      try {
        await navigator.clipboard.writeText(code);
        // Visual flash
        _inviteCodeCard.style.background = "rgba(126,96,255,0.28)";
        setTimeout(() => {
          _inviteCodeCard.style.background = "rgba(126,96,255,0.10)";
        }, 280);
        toast("Pair code copied", "ok");
      } catch (e) {
        toast("Couldn't copy code.", "bad");
      }
    });
  }
  // Native share sheet (mobile / touch only - on Windows desktop
  // this routes to Microsoft Phone Link which is corp-tied and not
  // what the user wants). The Share button is hidden on desktop.
  const _inviteShare = $("#invite-share");
  if (_inviteShare) {
    _inviteShare.addEventListener("click", async () => {
      const url = ($("#invite-url").textContent || "").trim();
      const code = ($("#invite-code").textContent || "").trim();
      if (!url || !navigator.share) return;
      try {
        await navigator.share({
          title: "One Link invite",
          text: `Join me on One Link. Pair code: ${code}`,
          url,
        });
      } catch (e) {
        if (e && e.name !== "AbortError") {
          toast(`Couldn't share. ${e.message || e}`, "bad");
        }
      }
    });
  }
  // Email - opens the user's default mail client with a
  // pre-filled subject + body. No corp routing, no Phone Link.
  const _inviteEmail = $("#invite-email");
  if (_inviteEmail) {
    _inviteEmail.addEventListener("click", () => {
      const url = ($("#invite-url").textContent || "").trim();
      const code = ($("#invite-code").textContent || "").trim();
      if (!url) return;
      const subject = encodeURIComponent("One Link invite");
      const body = encodeURIComponent(
        `Open this link on your device to join me on One Link:\n\n${url}\n\nPair code: ${code}\n\nIt works whether or not you already have One Link installed.`
      );
      const href = `mailto:?subject=${subject}&body=${body}`;
      // Use window.location so the OS opens the default mail
      // handler. No new tab needed.
      try {
        window.location.href = href;
      } catch (e) {
        toast("Couldn't open mail client.", "bad");
      }
    });
  }
  // Show big - display the QR fullscreen so a device across the
  // room can scan it. Great for showing on a TV / external monitor.
  const _inviteFullscreen = $("#invite-fullscreen");
  if (_inviteFullscreen) {
    _inviteFullscreen.addEventListener("click", () => {
      const code = ($("#invite-code").textContent || "").trim();
      if (!code || code === "------") return;
      const qrUrl = `/api/discover/invite/qr.svg?code=${encodeURIComponent(code)}`;
      const stage = $("#invite-fullscreen-qr");
      const codeEl = $("#invite-fullscreen-code");
      const backdrop = $("#invite-fullscreen-backdrop");
      if (stage) {
        stage.innerHTML = `<img src="${qrUrl}" alt="Pair QR" `
          + `style="width:100%; height:100%; object-fit:contain;" />`;
      }
      if (codeEl) codeEl.textContent = code;
      if (backdrop) backdrop.classList.add("show");
    });
  }
  // Save QR image (download SVG).
  const _inviteSaveQr = $("#invite-save-qr");
  if (_inviteSaveQr) {
    _inviteSaveQr.addEventListener("click", () => {
      const a = $("#invite-qr-download");
      if (a && a.dataset.ready === "1" && a.href && a.href !== "#") {
        a.click();
      }
    });
  }
  // Fullscreen QR - tap anywhere to close.
  const _fsBackdrop = $("#invite-fullscreen-backdrop");
  if (_fsBackdrop) {
    _fsBackdrop.addEventListener("click", () => {
      _fsBackdrop.classList.remove("show");
    });
  }
  const _inviteBackdrop = $("#invite-backdrop");
  if (_inviteBackdrop) {
    _inviteBackdrop.addEventListener("click", (e) => {
      if (e.target.id === "invite-backdrop") {
        closeInviteModal();
      }
    });
  }

