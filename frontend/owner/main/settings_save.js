  // May 15 2026 - Privacy panel trigger. Opens the sovereignty-
  // preset + outbound-audit overlay. Clicking the lock icon does
  // exactly one thing: surface the privacy picture.
  const _privacyBtn = $("#btn-privacy");
  if (_privacyBtn) {
    _privacyBtn.onclick = () => {
      if (typeof window.openPrivacyPanel === "function") {
        window.openPrivacyPanel();
      }
    };
  }

  $("#btn-settings").onclick = async () => {
    _settingsHydrating = true;
    markSettingsClean("Loading settings...");
    try {
      const r = await api.get("/api/settings");
      $("#set-name").value = r.display_name || "";
      $("#set-autoaccept").checked = !!r.auto_accept_lan;
      // Accept-first: default ON when the server omits it.
      {
        const ra = $("#set-require-accept");
        if (ra) ra.checked = (r.incoming_files_require_accept !== false);
      }
      // v0.7.3: default-allow-all on pair (true by default).
      $("#set-pair-allow-all").checked =
        r.pair_default_allow_all !== false;
      // v0.10.0 settings polish.
      $("#set-theme").value = r.theme || "dark";
      $("#set-ui-density").value = r.ui_density || "comfortable";
      $("#set-message-bubble-style").value = r.message_bubble_style || "gradient";
      $("#set-font-scale").value = r.font_scale || "normal";
      $("#set-motion-level").value = r.motion_level || "full";
      $("#set-chat-wallpaper").value = r.chat_wallpaper || "soft";
      $("#set-accent-color").value = r.accent_color || "#7c5cff";
      renderSettingsAccentSwatches(r.accent_color || "#7c5cff");
      applyAppearanceSettings(r);
      $("#set-download-folder").value = r.download_folder || "";
      $("#set-dnd-enabled").checked = !!r.dnd_enabled;
      $("#set-dnd-start").value = r.dnd_start || "22:00";
      $("#set-dnd-end").value = r.dnd_end || "07:00";
      $("#set-sound").checked = r.notification_sound !== false;
      $("#set-log-level").value = r.log_level || "info";
      // v0.11.1 Profile fields.
      const bioEl = $("#set-bio");
      if (bioEl) bioEl.value = r.bio || "";
      _renderBioCounter();
      _renderColorSwatches(
        r.avatar_color_presets || [],
        r.avatar_color || (r.avatar_color_presets || [])[0] || "#7c4dff",
      );
      _refreshProfileAvatarPreview();
      // v0.11.2 notification fine-tuning toggles.
      const np = $("#set-notif-preview");
      const nr = $("#set-notif-reactions");
      if (np) np.checked = r.notification_preview !== false;
      if (nr) nr.checked = r.notify_on_reactions !== false;
      // v0.12.2 read-receipt privacy toggles.
      const sr = $("#set-send-receipts");
      const dr = $("#set-display-receipts");
      if (sr) sr.checked = r.send_read_receipts !== false;
      if (dr) dr.checked = r.display_read_receipts !== false;
      // v0.12.3 typing-indicator privacy toggles.
      const st = $("#set-send-typing");
      const dt = $("#set-display-typing");
      if (st) st.checked = r.send_typing_indicators !== false;
      if (dt) dt.checked = r.display_typing_indicators !== false;
      $("#set-enter-to-send").checked = r.enter_to_send !== false;
      $("#set-auto-scroll").checked = r.auto_scroll_new_messages !== false;
      $("#set-compact-message-list").checked = r.compact_message_list === true;
      $("#set-show-message-seconds").checked = r.show_message_seconds === true;
      $("#set-link-previews").checked = r.send_link_previews !== false;
      // v0.11.6 storage + data settings.
      const ddt = $("#set-default-dm-ttl");
      if (ddt) ddt.value = r.default_dm_ttl_ms ? String(r.default_dm_ttl_ms) : "";
      const bw = $("#set-bandwidth-cap");
      if (bw) bw.value = String(r.bandwidth_cap_kbps || 0);
      const aas = $("#set-auto-accept-size");
      if (aas) aas.value = String(r.auto_accept_max_size_mb || 0);
      const aax = $("#set-auto-accept-exts");
      if (aax) aax.value = (r.auto_accept_extensions || []).join(", ");
      // Cache for runtime checks (DND + sound + theme).
      state.runtimeSettings = {
        theme: r.theme || "dark",
        ui_density: r.ui_density || "comfortable",
        message_bubble_style: r.message_bubble_style || "gradient",
        font_scale: r.font_scale || "normal",
        motion_level: r.motion_level || "full",
        accent_color: r.accent_color || "#7c5cff",
        chat_wallpaper: r.chat_wallpaper || "soft",
        enter_to_send: r.enter_to_send !== false,
        compact_message_list: r.compact_message_list === true,
        show_message_seconds: r.show_message_seconds === true,
        auto_scroll_new_messages: r.auto_scroll_new_messages !== false,
        send_link_previews: r.send_link_previews !== false,
        dnd_enabled: !!r.dnd_enabled,
        dnd_start: r.dnd_start || "22:00",
        dnd_end: r.dnd_end || "07:00",
        notification_sound: r.notification_sound !== false,
        bio: r.bio || "",
        avatar_color: r.avatar_color || "#7c4dff",
        send_read_receipts: r.send_read_receipts !== false,
        display_read_receipts: r.display_read_receipts !== false,
        send_typing_indicators: r.send_typing_indicators !== false,
        display_typing_indicators: r.display_typing_indicators !== false,
      };
    } catch (e) {
      $("#set-name").value = "";
      $("#set-autoaccept").checked = false;
      $("#set-pair-allow-all").checked = true;
    }
    // v0.5.3: load current rendezvous URLs + status
    try {
      const r = await api.get("/api/rendezvous");
      state.rendezvousUrls = r.urls || [];
      $("#set-rendezvous").value = (r.urls || []).join("\n");
      renderRendezvousStatus(r);
    } catch (e) {
      state.rendezvousUrls = [];
      $("#set-rendezvous").value = "";
      renderRendezvousStatus({});
    }
    // v0.7.x: populate the moved-from-the-top-banner notification status.
    populateNotifSettings();
    // v0.11.0: fill the new Profile + About panes + reset nav to
    // Profile each open so the user always lands on a predictable
    // pane regardless of where they last navigated.
    switchSettingsPane("profile");
    refreshSettingsAbout();
    renderSettingsDevices();
    renderSettingsNetwork();
    renderSettingsOverview();
    refreshSettingsNetwork().catch((e) => console.warn("settings network refresh:", e));
    refreshBlockedDevicesList();
    refreshUiSessionsList();
    refreshSessionSettings();
    refreshSettingsPrivacyPresets();
    refreshSettingsSecurityAudit();
    _settingsHydrating = false;
    markSettingsClean("No changes yet.");
    settingsBackdrop.classList.add("show");
  };
  $("#settings-cancel").onclick = () => {
    settingsBackdrop.classList.remove("show");
    returnToOneHealthGuideIfPending();
  };
  // v0.10.0: live-preview the chime so the user knows what it
  // sounds like before committing.
  $("#set-sound-test")?.addEventListener("click", () => {
    // Bypass the master toggle so test-sound works even when the
    // user has it disabled - they're explicitly asking to hear it.
    playNotificationChime();
  });
  // v0.10.0: live theme preview as the user changes the dropdown.
  $("#set-theme")?.addEventListener("change", (e) => {
    applyTheme(e.target.value);
  });
  function collectAppearanceSettingsDraft() {
    return {
      ui_density: $("#set-ui-density")?.value || "comfortable",
      message_bubble_style: $("#set-message-bubble-style")?.value || "gradient",
      font_scale: $("#set-font-scale")?.value || "normal",
      motion_level: $("#set-motion-level")?.value || "full",
      accent_color: $("#set-accent-color")?.value || "#7c5cff",
      chat_wallpaper: $("#set-chat-wallpaper")?.value || "soft",
    };
  }
  function renderSettingsAccentSwatches(activeColor = "#7c5cff") {
    const active = String(activeColor || "#7c5cff").toLowerCase();
    $("#settings-accent-swatches")?.querySelectorAll(".settings-accent-swatch")
      .forEach((btn) => {
        btn.classList.toggle(
          "active",
          String(btn.dataset.color || "").toLowerCase() === active,
        );
      });
  }
  [
    "set-ui-density",
    "set-message-bubble-style",
    "set-font-scale",
    "set-motion-level",
    "set-chat-wallpaper",
  ].forEach((id) => {
    $(`#${id}`)?.addEventListener("change", () => {
      applyAppearanceSettings(collectAppearanceSettingsDraft());
    });
  });
  $("#settings-accent-swatches")?.addEventListener("click", (e) => {
    const btn = e.target.closest(".settings-accent-swatch");
    if (!btn) return;
    const color = btn.dataset.color || "#7c5cff";
    $("#set-accent-color").value = color;
    renderSettingsAccentSwatches(color);
    applyAppearanceSettings(collectAppearanceSettingsDraft());
    markSettingsDirty();
  });
  document.querySelectorAll("[data-settings-pane-jump]").forEach((btn) => {
    btn.addEventListener("click", () => switchSettingsPane(btn.dataset.settingsPaneJump));
  });
  $("#settings-copy-shortcuts")?.addEventListener("click", async () => {
    const shortcuts = [
      "Ctrl K - Open search",
      "Enter - Send message",
      "Shift Enter - New line",
      "Ctrl Enter - Send from multiline composer",
      "Ctrl Shift D - Open diagnostics",
      "Esc - Close modal or overlay",
      "? - Show shortcut overlay",
      "Ctrl / - Focus message composer",
    ].join("\n");
    try {
      await navigator.clipboard.writeText(shortcuts);
      toast("Shortcut list copied.", "good", 3500);
    } catch {
      toast("Shortcut copy failed. Clipboard access was denied.", "bad", 4500);
    }
  });
  $("#settings-open-shortcuts")?.addEventListener("click", () => {
    $("#shortcuts-backdrop")?.classList.add("show");
  });
  $("#settings-save").onclick = async () => {
    setSettingsSaveStatus("Saving...", "dirty");
    // v0.11.1 - pull avatar_color from the active swatch, bio from
    // the input. Both are optional; nullish skips the field on the
    // backend.
    const activeSwatch = $(".profile-color-swatch.active");
    const appearanceDraft = collectAppearanceSettingsDraft();
    const payload = {
      display_name: $("#set-name").value.trim() || null,
      auto_accept_lan: $("#set-autoaccept").checked,
      incoming_files_require_accept: !!($("#set-require-accept") && $("#set-require-accept").checked),
      pair_default_allow_all: $("#set-pair-allow-all").checked,
      // v0.10.0 settings polish.
      theme: $("#set-theme").value || "dark",
      ui_density: appearanceDraft.ui_density,
      message_bubble_style: appearanceDraft.message_bubble_style,
      font_scale: appearanceDraft.font_scale,
      motion_level: appearanceDraft.motion_level,
      accent_color: appearanceDraft.accent_color,
      chat_wallpaper: appearanceDraft.chat_wallpaper,
      download_folder: $("#set-download-folder").value.trim(),
      dnd_enabled: $("#set-dnd-enabled").checked,
      dnd_start: $("#set-dnd-start").value || "22:00",
      dnd_end: $("#set-dnd-end").value || "07:00",
      notification_sound: $("#set-sound").checked,
      log_level: $("#set-log-level").value || "info",
      // v0.11.1 Profile fields.
      bio: ($("#set-bio")?.value || "").trim(),
      avatar_color: activeSwatch?.dataset?.color || undefined,
      // v0.11.2 notification fine-tuning.
      notification_preview: !!$("#set-notif-preview")?.checked,
      notify_on_reactions: !!$("#set-notif-reactions")?.checked,
      // v0.12.2 read-receipt privacy.
      send_read_receipts: !!$("#set-send-receipts")?.checked,
      display_read_receipts: !!$("#set-display-receipts")?.checked,
      // v0.12.3 typing-indicator privacy.
      send_typing_indicators: !!$("#set-send-typing")?.checked,
      display_typing_indicators: !!$("#set-display-typing")?.checked,
      enter_to_send: !!$("#set-enter-to-send")?.checked,
      auto_scroll_new_messages: !!$("#set-auto-scroll")?.checked,
      compact_message_list: !!$("#set-compact-message-list")?.checked,
      show_message_seconds: !!$("#set-show-message-seconds")?.checked,
      send_link_previews: !!$("#set-link-previews")?.checked,
      // v0.11.6 storage + data settings. The four selects/inputs
      // map directly to setting keys; null + 0 + "" all clear.
      default_dm_ttl_ms: (() => {
        const v = $("#set-default-dm-ttl")?.value || "";
        return v ? parseInt(v, 10) : null;
      })(),
      bandwidth_cap_kbps: (() => {
        const v = $("#set-bandwidth-cap")?.value || "0";
        return parseInt(v, 10) || 0;
      })(),
      auto_accept_max_size_mb: (() => {
        const v = $("#set-auto-accept-size")?.value || "0";
        const n = parseInt(v, 10);
        return Number.isFinite(n) && n >= 0 ? n : 0;
      })(),
      auto_accept_extensions: ($("#set-auto-accept-exts")?.value || "").trim(),
    };
    let savedSettings = false;
    try {
      await api.post("/api/settings", payload);
      savedSettings = true;
      // Apply changes that don't need a server roundtrip:
      // - theme: flip the data-theme attribute live
      // - runtime cache: keep DND / sound checks in sync
      applyTheme(payload.theme);
      applyAppearanceSettings(payload);
      if (payload.avatar_color) applyMyAvatarColor(payload.avatar_color);
      state.runtimeSettings = {
        theme: payload.theme,
        ui_density: payload.ui_density,
        message_bubble_style: payload.message_bubble_style,
        font_scale: payload.font_scale,
        motion_level: payload.motion_level,
        accent_color: payload.accent_color,
        chat_wallpaper: payload.chat_wallpaper,
        enter_to_send: payload.enter_to_send,
        compact_message_list: payload.compact_message_list,
        show_message_seconds: payload.show_message_seconds,
        auto_scroll_new_messages: payload.auto_scroll_new_messages,
        send_link_previews: payload.send_link_previews,
        dnd_enabled: payload.dnd_enabled,
        dnd_start: payload.dnd_start,
        dnd_end: payload.dnd_end,
        notification_sound: payload.notification_sound,
        bio: payload.bio,
        avatar_color: payload.avatar_color || state.runtimeSettings?.avatar_color,
        send_read_receipts: payload.send_read_receipts,
        display_read_receipts: payload.display_read_receipts,
        send_typing_indicators: payload.send_typing_indicators,
        display_typing_indicators: payload.display_typing_indicators,
      };
      if (!payload.display_typing_indicators) {
        state.peerTyping = {};
        state.groupTyping = {};
        renderTypingBanner();
      }
    } catch (e) {
      setSettingsSaveStatus("Save failed.", "bad");
      toast(`Save didn't work: ${errorToastBody(e)}`, "bad");
      return;
    }

    // v0.5.3: rendezvous URL list - only POST if value actually changed
    // (avoids needlessly tearing down a working client).
    const newUrls = $("#set-rendezvous").value
      .split(/[\s,]+/)
      .map(s => s.trim())
      .filter(Boolean);
    const oldUrls = (state.rendezvousUrls || []).slice().sort();
    const newSorted = newUrls.slice().sort();
    const changed = oldUrls.length !== newSorted.length ||
      oldUrls.some((u, i) => u !== newSorted[i]);
    if (changed) {
      try {
        const res = await api.post("/api/rendezvous", { urls: newUrls });
        state.rendezvousUrls = res.urls || [];
        renderRendezvousStatus({ active: res.active, urls: res.urls });
        toast(
          res.urls.length === 0
            ? "Saved - Wi-Fi-only mode"
            : `Saved - connected to ${res.urls.length} rendezvous`,
          "good",
        );
      } catch (e) {
        setSettingsSaveStatus("Rendezvous save failed.", "bad");
        toast(`Rendezvous save failed: ${e.message || e}`, "bad");
        return;
      }
    } else if (savedSettings) {
      toast("Settings saved. Smart move.", "good");
    }
    markSettingsClean("Saved.");

    settingsBackdrop.classList.remove("show");
    returnToOneHealthGuideIfPending();
    refreshPeers();
    // refresh own identity in case display name changed
    try {
      const me = await api.get("/api/me");
      $("#me-host").textContent = me.display_name || me.hostname;
    } catch {}
  };

  // v0.5.3: render rendezvous status (active/configured) inside the
  // settings modal, plus the dot indicator.
  function renderRendezvousStatus({ active, urls, observed_self } = {}) {
    const dot = $("#rdz-status-dot");
    const pane = $("#rdz-status-pane");
    if (!dot || !pane) return;
    if (urls && urls.length === 0) {
      dot.classList.remove("active", "error");
      dot.title = "Wi-Fi-only mode";
      pane.innerHTML = "";
      return;
    }
    if (active) {
      dot.classList.remove("error");
      dot.classList.add("active");
      dot.title = "Connected";
    } else {
      dot.classList.remove("active");
      dot.classList.add("error");
      dot.title = "Configured but not connected";
    }
    pane.innerHTML = "";
    if (observed_self && Object.keys(observed_self).length > 0) {
      for (const [url, obs] of Object.entries(observed_self)) {
        const line = el("div", "ok",
          `✓ ${url} → ${obs.observed_host}:${obs.observed_port}`);
        pane.appendChild(line);
      }
    } else if (urls && urls.length > 0) {
      pane.appendChild(el("div", "warn",
        "configured; waiting for first registration..."));
    }
  }

  // v0.5.3: rendezvous-help inline modal
  const rdzHelpBackdrop = $("#rdz-help-backdrop");
  $("#rdz-help-link").onclick = (e) => {
    e.preventDefault();
    rdzHelpBackdrop.classList.add("show");
  };
  $("#rdz-help-close").onclick = () => rdzHelpBackdrop.classList.remove("show");
  // v0.10.3 - convo-empty pane CTAs.
  $("#convo-empty-pair")?.addEventListener("click", () => {
    $("#open-discover-modal")?.click();
  });
  $("#convo-empty-help")?.addEventListener("click", () => {
    rdzHelpBackdrop.classList.add("show");
  });
  // v0.9.7: shortcut from the help modal straight to the settings
  // page where rendezvous URLs are actually pasted, so the user
  // who DOES want to set one up doesn't have to hunt for it.
  $("#rdz-help-settings")?.addEventListener("click", () => {
    rdzHelpBackdrop.classList.remove("show");
    $("#btn-settings")?.click();
  });

  // Click outside modal closes
  [pairBackdrop, settingsBackdrop, rdzHelpBackdrop, $("#shortcuts-backdrop")].forEach(b => {
    if (!b) return;
    b.addEventListener("click", (e) => { if (e.target === b) b.classList.remove("show"); });
  });
  $("#shortcuts-close")?.addEventListener("click", () => $("#shortcuts-backdrop").classList.remove("show"));

