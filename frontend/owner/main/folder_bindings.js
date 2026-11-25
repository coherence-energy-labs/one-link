  // ── v0.8.1: Debug pane wiring ─────────────────────────────────────
  state.debugLastId = 0;
  state.debugEntries = [];

  async function refreshDebugLog() {
    try {
      const sevSel = $("#debug-severity");
      const sev = sevSel ? sevSel.value : "";
      // Plain string concat (not template literal) so the markup
      // smoke test's URL extractor doesn't capture `${qs}` as a
      // path segment.
      const qs = sev ? "?severity=" + encodeURIComponent(sev) : "";
      const r = await api.get("/api/debug/log" + qs);
      state.debugEntries = r.entries || [];
      // Track highest id we've seen so live WS updates can prepend
      // only the new ones without re-fetching.
      for (const e of state.debugEntries) {
        if (e.id > state.debugLastId) state.debugLastId = e.id;
      }
      renderDebugLog();
      $("#debug-error-count").textContent = state.debugEntries
        .filter(e => e.severity === "error").length;
    } catch (e) {
      console.warn("debug log fetch failed", e);
    }
  }

  function renderDebugLog() {
    const host = $("#debug-log-list");
    if (!host) return;
    host.innerHTML = "";
    if (state.debugEntries.length === 0) {
      host.appendChild(el("div", "empty", "No errors recorded."));
      return;
    }
    for (const e of state.debugEntries) {
      const row = el("div", `debug-row sev-${e.severity}`);
      const head = el("div", "debug-head");
      const sev = el("span", `debug-sev sev-${e.severity}`, e.severity);
      const src = el("span", "debug-src", e.source);
      const code = el("span", "debug-code", e.code);
      const ts = el("span", "debug-ts", new Date(e.ts_ms).toLocaleTimeString());
      head.appendChild(sev);
      head.appendChild(src);
      head.appendChild(code);
      head.appendChild(ts);
      row.appendChild(head);
      row.appendChild(el("div", "debug-msg", e.message));
      if (e.suggestion) {
        const tip = el("div", "debug-fix");
        tip.appendChild(el("span", "debug-fix-label", "How to fix: "));
        tip.appendChild(document.createTextNode(e.suggestion));
        row.appendChild(tip);
      }
      if (e.context && Object.keys(e.context).length) {
        const ctx = el("div", "debug-ctx");
        ctx.textContent = "context: " + JSON.stringify(e.context);
        row.appendChild(ctx);
      }
      host.appendChild(row);
    }
  }

  $("#btn-debug-clear")?.addEventListener("click", async () => {
    try {
      await api.post("/api/debug/log/clear", {});
      state.debugEntries = [];
      state.debugLastId = 0;
      renderDebugLog();
      $("#debug-error-count").textContent = "0";
      toast("Debug log wiped. Pretend it never happened.", "good", 2000);
    } catch (e) {
      toast(`Clear didn't work: ${errorToastBody(e)}`, "bad");
    }
  });

  $("#btn-debug-copy-report")?.addEventListener("click", async () => {
    try {
      let installInfo = {};
      try {
        const me = await api.get("/api/me");
        installInfo = {
          version: me.app_version,
          source_fingerprint: me.source_fingerprint,
          protocol_version: me.protocol_version,
          schema_version: me.schema_version,
        };
      } catch (_) { /* defensive */ }
      const eventSummary = _diagnosticEventSummary(state.debugEntries || []);
      const report = {
        kind: "one_link_error_report_v2",
        install: installInfo,
        event_summary: eventSummary,
      };
      const text = JSON.stringify(report, null, 2);
      await navigator.clipboard.writeText(text);
      toast(
        `Aggregate report copied (${eventSummary.total} event${eventSummary.total === 1 ? "" : "s"}). `
        + "Paste it wherever you're reporting the bug.",
        "good", 4000,
      );
    } catch (e) {
      toast(`Could not copy report: ${errorToastBody(e)}`, "bad");
    }
  });

  $("#btn-debug-health")?.addEventListener("click", async () => {
    const out = $("#debug-health-result");
    out.innerHTML = "Running…";
    try {
      const r = await api.get("/api/debug/health");
      out.innerHTML = "";
      const banner = el("div", `debug-health-banner ${r.ok ? "good" : "bad"}`,
        r.ok ? `All checks passed (v${r.version}). Don't get cocky.` : "Some checks failed. Read on.");
      out.appendChild(banner);
      for (const c of r.checks || []) {
        const row = el("div", `debug-health-row ${c.ok ? "ok" : "bad"}`);
        row.appendChild(el("span", "debug-health-icon", c.ok ? "✓" : "✗"));
        row.appendChild(el("span", "debug-health-name", c.name));
        row.appendChild(el("span", "debug-health-detail", c.detail || ""));
        out.appendChild(row);
      }
    } catch (e) {
      out.textContent = `Health check failed: ${errorToastBody(e)}`;
    }
  });

  $("#debug-severity")?.addEventListener("change", refreshDebugLog);

  // v0.10.6: spin the refresh icon while the fetch is in flight so
  // the user gets feedback on a button that's now icon-only.
  $("#btn-refresh-folders").onclick = async () => {
    const btn = $("#btn-refresh-folders");
    if (btn) btn.classList.add("spinning");
    try {
      await refreshFolders();
    } finally {
      if (btn) setTimeout(() => btn.classList.remove("spinning"), 600);
    }
  };
  // v0.10.6: native folder picker. POSTs to /api/fs/pick-folder which
  // pops a tk dialog on the daemon's desktop and returns the picked
  // path. If unavailable (headless) we silently keep the manual path
  // input as the fallback.
  $("#btn-browse-folder")?.addEventListener("click", async () => {
    try {
      const r = await api.post("/api/fs/pick-folder", {});
      if (r && r.path) {
        $("#folder-path").value = r.path;
        // If name is still blank, suggest the leaf folder name.
        const nameEl = $("#folder-name");
        if (nameEl && !nameEl.value.trim()) {
          const leaf = r.path.split(/[\\/]/).filter(Boolean).pop();
          if (leaf) nameEl.value = leaf;
        }
      } else if (r && r.cancelled) {
        // User cancelled - no toast, no noise.
      }
    } catch (e) {
      toast(`Browse unavailable on this device: ${errorToastBody(e)}`, "info", 4000);
    }
  });
  // v0.8.9: conflicts modal close button.
  $("#conflicts-close")?.addEventListener("click", closeConflictsModal);
  // Esc closes too - match other modals.
  $("#conflicts-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeConflictsModal();
  });
  // v0.21.x folder browser modal handlers — backdrop click + Esc.
  $("#folder-browser-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeFolderBrowser();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if ($("#folder-browser-backdrop")?.classList.contains("show")) {
      closeFolderBrowser();
    }
    if ($("#folder-settings-backdrop")?.classList.contains("show")) {
      closeFolderSettings();
    }
  });
  // v0.21.x Ship 4: folder settings modal handlers.
  $("#folder-settings-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeFolderSettings();
  });
  // v0.21.x: folder Send confirmation modal + in-flight progress.
  $("#folder-send-confirm-cancel")?.addEventListener("click", closeFolderSendConfirm);
  $("#folder-send-confirm-go")?.addEventListener("click", _confirmFolderSendGo);
  $("#folder-send-confirm-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeFolderSendConfirm();
  });
  $("#fsp-cancel")?.addEventListener("click", _cancelInflightFolderSend);

  $("#folder-settings-close")?.addEventListener("click", closeFolderSettings);
  $("#folder-settings-save")?.addEventListener("click", saveFolderSettings);
  // v0.21.x: Folder location section — Browse picks an OS folder,
  // Move-to-this-location calls /api/folders/{name}/relocate.
  $("#folder-settings-browse-path")?.addEventListener("click", async () => {
    try {
      const r = await api.post("/api/fs/pick-folder", {});
      if (r && r.path) {
        $("#folder-settings-path").value = r.path;
      }
    } catch (e) {
      toast(
        `Browse unavailable on this device: ${errorToastBody(e)}`,
        "info", 4000,
      );
    }
  });
  $("#folder-settings-relocate")?.addEventListener("click", async () => {
    const name = state.folderSettingsTarget;
    const newPath = ($("#folder-settings-path").value || "").trim();
    const status = $("#folder-settings-relocate-status");
    if (!name) return;
    if (!newPath) {
      if (status) {
        status.textContent = "Pick a folder first.";
        status.className = "settings-help-inline bad";
      }
      return;
    }
    if (status) {
      status.textContent = "Moving…";
      status.className = "settings-help-inline";
    }
    try {
      const r = await api.post(
        `/api/folders/${encodeURIComponent(name)}/relocate`,
        { local_path: newPath },
      );
      if (status) {
        status.textContent = `Moved to ${r.folder?.local_path || newPath}. Re-scanning in the background.`;
        status.className = "settings-help-inline good";
      }
      await refreshFolders();
    } catch (e) {
      if (status) {
        status.textContent = `Move failed: ${errorToastBody(e) || e}`;
        status.className = "settings-help-inline bad";
      }
    }
  });
  // Preset buttons: append to current ignored list, de-duped.
  document.querySelectorAll("#folder-settings-backdrop [data-preset]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const preset = btn.dataset.preset;
      const patterns = _IGNORE_PRESETS[preset] || [];
      const ta = $("#folder-settings-ignored");
      const current = new Set(
        (ta.value || "").split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
      );
      for (const p of patterns) current.add(p);
      ta.value = [...current].join("\n");
    });
  });
  $("#btn-refresh-mesh").onclick = async () => {
    await refreshTransfers();
    await refreshStatus();
    await refreshFabricTruth();
    if ($("#activity-nearby-panel")?.classList.contains("show")) {
      await loadActivityNearby({ force: true });
    }
  };
  $("#btn-clear-activity-traces")?.addEventListener("click", () => {
    clearTraceScope("activity", "activity traces");
  });
  $("#btn-copy-route-bootstrap")?.addEventListener("click", copyRouteBootstrapToken);
  $("#btn-import-route-bootstrap")?.addEventListener("click", importRouteBootstrapToken);
  $("#btn-launch-path-create")?.addEventListener("click", launchBestPathCreate);
  $("#btn-self-mesh-root")?.addEventListener("click", createSelfMeshRoot);
  $("#btn-self-mesh-mint")?.addEventListener("click", mintSelfMeshDeviceCert);
  $("#btn-self-mesh-enroll")?.addEventListener("click", enrollSelfMeshCert);
  $("#btn-self-mesh-invite")?.addEventListener("click", createSelfMeshInvite);
  $("#btn-self-mesh-claim")?.addEventListener("click", claimSelfMeshInvite);
  $("#btn-self-mesh-best")?.addEventListener("click", chooseBestSelfMeshDevice);
  $("#btn-self-mesh-revoke")?.addEventListener("click", revokeSelfMeshDevice);
  $("#btn-self-mesh-freeze")?.addEventListener("click", freezeSelfMeshDevice);
  $("#btn-self-mesh-recover")?.addEventListener("click", recoverSelfMeshDevice);
  $("#btn-self-mesh-trust-root")?.addEventListener("click", trustSelfMeshFolder);
  $("#btn-self-mesh-manifest")?.addEventListener("click", () => sendSelfMeshInstruction("pull_file_manifest"));
  $("#btn-self-mesh-send")?.addEventListener("click", () => sendSelfMeshInstruction("send_file_from_device"));
  $("#one-health-actions")?.addEventListener("click", (e) => {
    const btn = e.target?.closest?.("[data-one-health-action]");
    if (btn) {
      e.stopPropagation();
      runOneHealthAction(btn.dataset.oneHealthAction || "");
    }
  });
  $("#one-health")?.addEventListener("click", (e) => {
    if (e.target?.closest?.("button, a, details, summary, input, textarea, select")) return;
    openOneHealthGuide();
  });
  $("#one-health")?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    e.preventDefault();
    openOneHealthGuide();
  });
  $("#one-health-guide-close")?.addEventListener("click", closeOneHealthGuide);
  $("#one-health-guide-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closeOneHealthGuide();
  });
  $("#one-health-guide-actions")?.addEventListener("click", (e) => {
    const btn = e.target?.closest?.("[data-one-health-action]");
    if (!btn) return;
    openOneHealthGuideDestination(btn.dataset.oneHealthAction || "");
  });
  $("#one-health-guide-grid")?.addEventListener("click", (e) => {
    const card = e.target?.closest?.("[data-one-health-focus]");
    if (!card) return;
    setOneHealthGuideFocus(card.dataset.oneHealthFocus || "");
  });
  $("#one-health-guide-grid")?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const card = e.target?.closest?.("[data-one-health-focus]");
    if (!card) return;
    e.preventDefault();
    setOneHealthGuideFocus(card.dataset.oneHealthFocus || "");
  });
  $("#one-health-guide-autopilot-button")?.addEventListener("click", (e) => {
    const action = e.currentTarget?.dataset?.oneHealthAction || bestOneHealthActionId();
    openOneHealthGuideDestination(action);
  });
  $("#one-health-guide-setup")?.addEventListener("click", () => {
    openOneHealthGuideDestination("finish_setup");
  });
  $("#btn-courier-export")?.addEventListener("click", exportCourierBundle);
  $("#btn-courier-stage")?.addEventListener("click", stageCourierBundle);
  $("#btn-courier-copy-removable")?.addEventListener("click", copyCourierToRemovable);
  $("#btn-courier-pull-removable")?.addEventListener("click", pullCourierFromRemovable);
  $("#btn-courier-guide-send")?.addEventListener("click", () => setCourierGuideMode("send"));
  $("#btn-courier-guide-receive")?.addEventListener("click", () => setCourierGuideMode("receive"));
  $("#courier-transfer-select")?.addEventListener("change", renderCourierWizard);
  $("#courier-drop-select")?.addEventListener("change", renderCourierWizard);
  $("#courier-outbox-select")?.addEventListener("change", renderCourierWizard);
  $("#courier-removable-select")?.addEventListener("change", refreshRemovableCourierFiles);
  $("#courier-removable-file-select")?.addEventListener("change", renderCourierWizard);
  $("#courier-chunks")?.addEventListener("input", renderCourierWizard);
  $("#courier-key-token")?.addEventListener("input", renderCourierWizard);
  $("#btn-courier-copy-key")?.addEventListener("click", () => {
    copyToClipboard(($("#courier-key-token")?.value || "").trim(), "unlock code");
  });
  $("#btn-courier-import-file")?.addEventListener("click", () => $("#courier-file-input")?.click());
  $("#btn-courier-import-drop")?.addEventListener("click", importDroppedCourierFile);
  $("#courier-file-input")?.addEventListener("change", async (e) => {
    const file = e.currentTarget?.files?.[0];
    await importCourierBundleFile(file);
    if (e.currentTarget) e.currentTarget.value = "";
  });
  $("#btn-clear-transfers").onclick = async () => {
    try {
      const r = await api.post("/api/transfers/prune", { keep_latest: 0 });
      toast(`Cleared ${r.removed || 0} transfer${r.removed === 1 ? "" : "s"}`, "good");
      await refreshTransfers();
    } catch (e) {
      toast(`Clear didn't work: ${e.message || e}`, "bad");
    }
  };
  $("#btn-clear-file-traces")?.addEventListener("click", () => {
    clearTraceScope("files", "file traces");
  });
  $("#btn-add-folder").onclick = async () => {
    const name = $("#folder-name").value.trim();
    const local_path = $("#folder-path").value.trim();
    if (!name || !local_path) {
      toast("Folder name and path are required", "info");
      return;
    }
    const peer = state.selectedPeer ? state.peers.get(state.selectedPeer) : null;
    const shared_with = peer?.fingerprint && peer.trust === "pinned" ? [peer.fingerprint] : [];
    try {
      await api.post("/api/folders", { name, local_path, shared_with });
      $("#folder-name").value = "";
      $("#folder-path").value = "";
      toast("Folder added. Hope it's the right one.", "good");
      await refreshFolders();
    } catch (e) {
      toast(`Folder add failed: ${e.message || e}`, "bad", 6000);
    }
  };
  $("#btn-clear-folder-traces")?.addEventListener("click", () => {
    clearTraceScope("folders", "folder traces");
  });

