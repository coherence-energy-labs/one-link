  // ── Settings modal ─────────────────────────────────────────────────
  const settingsBackdrop = $("#settings-backdrop");
  // settingsStore owns the editor's hydration and unsaved-changes flags.

  function setSettingsSaveStatus(text, kind = "") {
    const status = $("#settings-save-status");
    if (!status) return;
    status.textContent = text;
    status.classList.remove("dirty", "good", "bad");
    if (kind) status.classList.add(kind);
  }

  function markSettingsDirty() {
    if (!settingsStore.markDirty()) return;
    setSettingsSaveStatus("Unsaved changes.", "dirty");
  }

  function markSettingsClean(text = "No changes yet.") {
    settingsStore.markClean();
    setSettingsSaveStatus(text);
  }

  // v0.11.0: settings nav-rail dispatcher. Click a nav button → show
  // the matching pane, hide the rest. Entirely DOM-local - no router,
  // no state outside the modal - so a refresh just lands you back
  // on Profile (the default active pane).
  function switchSettingsPane(name) {
    document.querySelectorAll('[data-settings-pane]').forEach((el) => {
      const m = el.dataset.settingsPane === name;
      if (el.classList.contains("settings-nav-item")) {
        el.classList.toggle("active", m);
      } else if (el.classList.contains("settings-pane")) {
        el.classList.toggle("active", m);
      }
    });
    // v0.11.6: lazy-load storage usage when the user switches to it.
    if (name === "storage") {
      refreshStorageUsage();
    }
    if (name === "profile") {
      renderSettingsOverview();
    }
    if (name === "devices") {
      renderSettingsDevices();
    }
    if (name === "network") {
      refreshSettingsNetwork();
    }
    if (name === "privacy") {
      renderSettingsPrivacySummary();
    }
    if (name === "about") {
      refreshSettingsAbout();
    }
  }
  // v0.21.x: the 'Recovery' nav item is special - it doesn't switch
  // panes (no recovery pane exists; the wizard is a full modal).
  // Close Settings + open the wizard instead. Wired directly by ID
  // so the static UI-wiring contract recognizes it.
  $("#settings-nav-open-recovery")?.addEventListener("click", () => {
    settingsBackdrop?.classList.remove("show");
    if (typeof _showRecoveryWizard === "function") {
      _showRecoveryWizard().catch(() => {});
    }
  });
  document.querySelectorAll(".settings-nav-item").forEach((btn) => {
    btn.addEventListener("click", () => {
      // Recovery is handled above; skip the pane-switch path so
      // we don't try to swap to a nonexistent 'recovery' pane.
      if (btn.id === "settings-nav-open-recovery") return;
      switchSettingsPane(btn.dataset.settingsPane);
    });
  });
  settingsBackdrop?.querySelectorAll("input, select, textarea").forEach((ctl) => {
    if (ctl.dataset.settingsTransient === "true") return;
    ctl.addEventListener("input", markSettingsDirty);
    ctl.addEventListener("change", markSettingsDirty);
  });

  // v0.21.x: search-as-you-type across all settings panes. Empty
  // query restores the full nav + all rows. Non-empty hides any
  // settings-row whose text doesn't include the query (case-fold),
  // hides any pane that has zero matching rows, and hides nav
  // buttons for hidden panes. If the active pane becomes hidden,
  // jump to the first pane that still has matches.
  const _settingsSearchInput = $("#settings-search");
  function _applySettingsSearch(q) {
    const needle = (q || "").trim().toLowerCase();
    const navButtons = document.querySelectorAll(".settings-nav-item");
    const panes = document.querySelectorAll(".settings-pane[data-settings-pane]");
    if (needle === "") {
      // Reset: every row visible, every nav button visible.
      navButtons.forEach((b) => b.classList.remove("nav-hidden"));
      panes.forEach((p) => {
        p.classList.remove("pane-empty");
        p.querySelectorAll(".settings-row, .settings-help, .settings-section-h, .settings-row-block, .profile-avatar-row")
          .forEach((el) => el.classList.remove("row-hidden"));
      });
      _settingsEmptyState(false);
      return;
    }
    const visiblePanes = new Set();
    panes.forEach((pane) => {
      let visibleInPane = 0;
      // Treat each child element as a row group; if its text matches,
      // keep it. Two passes — first include matching elements + their
      // immediate label cluster, then hide the rest.
      const groups = pane.querySelectorAll(":scope > *");
      groups.forEach((group) => {
        const text = (group.textContent || "").toLowerCase();
        if (text.includes(needle)) {
          group.classList.remove("row-hidden");
          visibleInPane++;
        } else {
          group.classList.add("row-hidden");
        }
      });
      // Pane title (h3) almost always matches the pane name; keep it
      // visible when any descendant matched so users don't lose context.
      const h3 = pane.querySelector(":scope > h3");
      if (h3 && visibleInPane > 0) h3.classList.remove("row-hidden");
      if (visibleInPane > 0) {
        pane.classList.remove("pane-empty");
        visiblePanes.add(pane.dataset.settingsPane);
      } else {
        pane.classList.add("pane-empty");
      }
    });
    navButtons.forEach((btn) => {
      const k = btn.dataset.settingsPane;
      // Also keep the nav button visible if the pane name itself
      // matches the query, even when no row inside matched.
      const labelMatches = (btn.textContent || "").toLowerCase().includes(needle);
      if (visiblePanes.has(k) || labelMatches) btn.classList.remove("nav-hidden");
      else btn.classList.add("nav-hidden");
    });
    // If the current active pane is now empty, switch to the first pane
    // that has matches.
    const activePane = document.querySelector(".settings-pane.active");
    if (activePane && activePane.classList.contains("pane-empty")) {
      const firstVisible = [...navButtons].find((b) => !b.classList.contains("nav-hidden"));
      if (firstVisible) switchSettingsPane(firstVisible.dataset.settingsPane);
    }
    _settingsEmptyState(visiblePanes.size === 0);
  }
  function _settingsEmptyState(show) {
    const host = document.querySelector(".settings-pane-host");
    if (!host) return;
    let banner = host.querySelector(".settings-search-empty");
    if (show) {
      if (!banner) {
        banner = document.createElement("div");
        banner.className = "settings-search-empty";
        banner.textContent = "Nothing matches that. Try fewer words.";
        host.appendChild(banner);
      }
      banner.style.display = "";
    } else if (banner) {
      banner.style.display = "none";
    }
  }
  if (_settingsSearchInput) {
    _settingsSearchInput.addEventListener("input", (ev) => {
      _applySettingsSearch(ev.target.value);
    });
    _settingsSearchInput.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        ev.target.value = "";
        _applySettingsSearch("");
      }
    });
    // Reset search whenever the settings modal opens fresh.
    const settingsBackdrop = document.getElementById("settings-backdrop");
    if (settingsBackdrop) {
      const obs = new MutationObserver(() => {
        if (settingsBackdrop.classList.contains("show")) {
          // Don't clear text; let users return to their query. Just
          // re-apply so newly-rendered content (e.g. lazy-loaded
          // storage pane) honors the current filter.
          _applySettingsSearch(_settingsSearchInput.value);
        }
      });
      obs.observe(settingsBackdrop, { attributes: true, attributeFilter: ["class"] });
    }
  }

  // v0.11.6 - fetch + render the per-chat storage breakdown.
