  // ── Initial load ───────────────────────────────────────────────────
  async function init() {
    loadLocalCollections();
    try {
      const me = await _bootApiGetWithRetry("/api/me");
      identityStore.replaceMe(me);
      $("#me-host").textContent = me.display_name || me.hostname;
      // v0.10.4: apply persisted presence on load so the dot
      // matches the user's last choice.
      applyPresenceUI(me.presence || "online");
      // v0.10.6: replace the hardcoded folder example with a real
      // path under THIS user's home directory.
      if (me.suggested_folder) {
        const ex = $("#folder-path-example");
        if (ex) ex.textContent = me.suggested_folder;
        const pathInput = $("#folder-path");
        if (pathInput) {
          pathInput.placeholder = `e.g. ${me.suggested_folder}`;
        }
      }
      // Detect daemon-page mismatch quietly. The launcher should replace stale
      // daemons automatically; if a browser tab survives that handoff, keep the
      // chat surface usable and log the drift instead of blocking the user.
      if (me.app_version && me.app_version !== PAGE_BUILT_FOR) {
        handleLocalVersionDrift(me.app_version, PAGE_BUILT_FOR, "boot");
      } else if (
        me.source_fingerprint
        && PAGE_SOURCE_FINGERPRINT !== "__ONE_LINK_SOURCE_FINGERPRINT__"
        && me.source_fingerprint !== PAGE_SOURCE_FINGERPRINT
      ) {
        handleLocalVersionDrift(
          `${me.app_version || PAGE_BUILT_FOR}:${me.source_fingerprint}`,
          `${PAGE_BUILT_FOR}:${PAGE_SOURCE_FINGERPRINT}`,
          "source",
        );
      }
      // v0.21.x: "What's new" modal on first launch after a daemon
      // version bump. localStorage stores the last-seen version; if
      // it differs from me.app_version we show a small bottom-sheet
      // with the headline changes for the new version. Skipped on
      // very first launch (the welcome wizard handles that user).
      _maybeShowWhatsNew(me.app_version);
    } catch (e) {
      toast("Can't reach One Link. Is it running?", "bad", 8000);
      console.error(e);
    }
    // These snapshots are independent once /api/me has authenticated the
    // page. Fetch them concurrently so first-use readiness is bounded by the
    // slowest endpoint, not the sum of fifteen local round trips. allSettled
    // keeps an optional subsystem failure from cancelling the rest of boot.
    const bootTasks = [
      ["peers", refreshPeers()],
      ["history", loadHistory()],
      ["folders", refreshFolders()],
      ["folder offers", refreshFolderOffers()],
      ["transfers", refreshTransfers()],
      ["pending file offers", refreshPendingFileOffers()],
      ["attention", refreshAttention()],
      ["status", refreshStatus()],
      ["fabric", refreshFabricTruth()],
      ["health", refreshOneHealth()],
      ["courier", refreshCourierStatus()],
      ["groups", refreshGroups()],
      ["settings", loadAndApplySettings()],
      ["chat preferences", loadChatPrefs()],
      ["setup", refreshOneSetup()],
    ];
    const bootResults = await Promise.allSettled(bootTasks.map(([, task]) => task));
    bootResults.forEach((result, index) => {
      if (result.status === "rejected") {
        console.warn(`Boot snapshot failed: ${bootTasks[index][0]}`, result.reason);
      }
    });
    // maybeShowOnboarding() runs only after peers + persisted settings have
    // settled, so a returning paired user never sees the first-run wizard.
    await maybeShowOnboarding();
    // v0.14.1: restore last-selected conversation. After all the
    // peer + group state is loaded but BEFORE WS connects, jump
    // back to wherever the user was last. The selectPeer /
    // selectGroup calls render the conversation; if the bulk
    // message load already completed, the chat is fully populated
    // instantly.
    _restoreLastSelection();
    connectWS();
    // Wire visibilitychange + window 'online' so a tab returning to
    // the foreground (or the OS reporting network-up) triggers an
    // immediate reconnect + daemon-version-drift check. Idempotent;
    // call once.
    LiveRefresh.attachWindowHandlers();
    // 2026-05-21 audit T3-P: track the polling cluster so we can
    // pause it on a 401 burst and resume on recovery. Without
    // this, six concurrent timers keep firing through the
    // session-expired banner — each one re-firing _maybe401.
    // windowLink suspends the cluster on the first 401 and resumes
    // it by itself when the link to the daemon is restored.
    // pollingCluster owns the timers.
    pollingCluster.start(_mainPollTasks());
    // T3-O: free in-tab File-cache blob URLs on page hide so a
    // long-lived tab that sent 200+ photos doesn't accumulate
    // 200+ retained Blob references. The daemon's
    // /api/outbound_files/<id> endpoint makes the in-memory cache
    // redundant for post-refresh use; on tab close we have no
    // further need for these URLs.
    window.addEventListener?.("pagehide", () => {
      try {
        for (const ent of state.outboundFileCache.values()) {
          if (ent?.objectUrl) {
            try { URL.revokeObjectURL(ent.objectUrl); } catch (_) {}
          }
        }
      } catch (_) {}
    });
    maybeShowNotifBanner();
    // v0.21.x: check GitHub Releases for a newer version and surface
    // the update banner if one's out. Fire-and-forget - the banner
    // stays hidden if the check fails (offline, rate-limited, etc.).
    checkForUpdate().catch(() => {});
    // v0.8.0: group buttons.
    $("#open-create-group")?.addEventListener("click", openCreateGroupModal);
    $("#cg-cancel")?.addEventListener("click", closeCreateGroupModal);
    $("#cg-create")?.addEventListener("click", submitCreateGroup);
    $("#btn-group-settings")?.addEventListener("click", openGroupSettings);
    $("#group-settings-close")?.addEventListener("click", closeGroupSettings);
    $("#group-rename-save")?.addEventListener("click", renameCurrentGroup);
    $("#group-add-member")?.addEventListener("click", addGroupMember);
    $("#group-copy-invite")?.addEventListener("click", copyGroupInviteLink);
    $("#group-leave")?.addEventListener("click", leaveCurrentGroup);
    // v0.11.3 - new group-settings actions.
    $("#group-mute-apply")?.addEventListener("click", applyGroupMute);
    $("#group-archive-toggle")?.addEventListener("click", toggleArchiveCurrentGroup);
    // v0.11.5 - group chat tools.
    $("#group-clear-history")?.addEventListener("click", async () => {
      const gid = state.selectedGroup;
      if (!gid) return;
      if (!confirm(
        "Clear local chat history for this group?\n\n" +
        "Only YOUR copy is deleted. Other members keep their messages."
      )) return;
      try {
        const r = await api.del(`/api/groups/${gid}/history`);
        toast(`Cleared ${r.deleted || 0} message${r.deleted === 1 ? "" : "s"}`, "good");
        if (state.selectedGroup === gid) {
          messageStore.clearGroup();
          if (typeof renderGroupConversation === "function") {
            renderGroupConversation();
          }
        }
      } catch (e) {
        toast(`Clear didn't work: ${errorToastBody(e)}`, "bad");
      }
    });
    $("#group-export-md")?.addEventListener("click", () => {
      const gid = state.selectedGroup;
      if (!gid) return;
      _downloadConvoExport(`/api/groups/${gid}/export?format=md`);
    });
    $("#group-export-json")?.addEventListener("click", () => {
      const gid = state.selectedGroup;
      if (!gid) return;
      _downloadConvoExport(`/api/groups/${gid}/export?format=json`);
    });
  }

  // v0.7.x: notification toggle in Settings modal.
  $("#set-notif")?.addEventListener("click", async () => {
    if (!notifySupported()) {
      toast("This browser doesn't support notifications.", "bad");
      return;
    }
    if (Notification.permission === "granted") {
      toast(
        "Notifications are already enabled. To turn them off, use your browser's site settings.",
        "info", 5000,
      );
      return;
    }
    if (Notification.permission === "denied") {
      toast(
        "Browser is blocking notifications for this site. Open browser site settings to allow.",
        "bad", 5000,
      );
      return;
    }
    try {
      const res = await Notification.requestPermission();
      if (res === "granted") toast("Notifications enabled", "good");
      else toast("Notifications declined", "info");
      populateNotifSettings();
    } catch (e) {
      toast(`Permission request failed: ${e.message || e}`, "bad");
    }
  });

  async function refreshPeers() {
    try {
      const { peers } = await api.get("/api/peers");
      state.peers.clear();
      for (const p of peers) state.peers.set(p.short_id, p);
      renderPeers();
      renderPeerControls();
      updateNearbyMetric();
      if ($("#activity-nearby-panel")?.classList.contains("show")) {
        renderActivityNearby();
      }
      renderSettingsDevices();
      recordPeerCompatibility();
      // v0.7.7/v0.7.8: re-render trust + key-change surfaces for the
      // currently selected peer so a freshly-recorded event flips the
      // banner without needing a click. Drawer also refreshes if open.
      if (state.selectedPeer) {
        const cur = state.peers.get(state.selectedPeer);
        if (cur) {
          renderConversationPeerStatus(cur);
          renderConvHeaderTrust(cur);
          renderConvKeyChangeBanner(cur);
        }
      }
      if (state.deviceDrawerFp) {
        const drawerPeer = drawerPeerByFp(state.deviceDrawerFp);
        if (drawerPeer) {
          renderDrawerVerification(drawerPeer);
          renderDrawerKeyChange(drawerPeer);
        }
      }
    } catch (e) { console.warn(e); }
  }

  // Keep version metadata available for diagnostics without interrupting chat.
  // Cross-version operation is handled by capability negotiation and per-send
  // fallbacks; the user should only see an error if an action truly fails.
  function recordPeerCompatibility() {
    const myV = state.me?.app_version;
    if (!myV) return;
    const drifted = [];
    for (const p of state.peers.values()) {
      if (p.trust !== "pinned") continue;
      const pv = p.app_version;
      if (pv && pv !== myV) {
        drifted.push(`${p.hostname || p.short_id}@${pv}`);
      }
    }
    if (drifted.length) {
      console.info(`One Link peer version drift observed: local=${myV}; peers=${drifted.join(", ")}`);
    }
  }

  async function loadHistory() {
    try {
      const { messages } = await api.get("/api/messages?limit=300");
      messageStore.replaceDirect(messages);
      renderMessages();
    } catch (e) { console.warn(e); }
  }

