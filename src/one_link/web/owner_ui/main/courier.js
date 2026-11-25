  function renderNoRouterKit(noRouter) {
    const host = $("#no-router-kit");
    if (!host) return;
    const kit = noRouter || {};
    const stateLabel = {
      trusted_path_ready: "Trusted local path ready",
      checking_path: "Checking local path",
      route_check_failed: "Route check failed",
      cable_ready: "Cable path visible",
      local_network_ready: "Local path ready",
      token_ready: "Setup code ready",
      waiting_for_local_path: "Waiting for local path",
      peer_listener_unavailable: "Peer listener starting",
    }[kit.state] || "Local path";
    const message = kit.message || "Checking local route readiness.";
    const chips = Array.isArray(kit.steps) && kit.steps.length
      ? kit.steps.map((s) => ({
          label: s.label || s.id || "step",
          ready: s.status === "ready",
          current: s.status === "current",
          blocked: s.status === "blocked",
        }))
      : [
          { label: "listener", ready: !!kit.token_ready },
          { label: "QR", ready: !!kit.qr_ready },
          { label: "cable", ready: !!kit.ethernet_ready },
          { label: "trusted", ready: Number(kit.trusted_local_paths || 0) > 0 },
        ];
    host.replaceChildren();
    host.appendChild(el("div", "nr-state", stateLabel));
    host.appendChild(el("div", "nr-message", message));
    const row = el("div", "nr-row");
    for (const c of chips) {
      row.appendChild(el("div", `nr-chip${c.ready ? " ready" : ""}${c.current ? " current" : ""}${c.blocked ? " blocked" : ""}`, c.label));
    }
    host.appendChild(row);
    const pathOptions = Array.isArray(kit.path_options) ? kit.path_options : [];
    const creation = kit.creation || {};
    const creationPlans = Array.isArray(creation.plans) ? creation.plans : [];
    if (pathOptions.length) {
      const paths = el("div", "nr-paths");
      for (const p of pathOptions.slice(0, 3)) {
        const status = String(p.status || "");
        const card = el("div", `nr-path ${status}`);
        const label = String(p.label || p.id || "path");
        const detail = String(p.reason || p.next_step || "");
        card.appendChild(el("b", "", label));
        card.appendChild(el("span", "", detail));
        paths.appendChild(card);
      }
      host.appendChild(paths);
    }
    if (creationPlans.length) {
      const best = creationPlans.find(p => p.state === "ready" || p.state === "needs_user") || creationPlans[0];
      const status = String(best.state || "");
      const card = el("div", `nr-path ${status === "needs_user" ? "current" : status}`);
      card.appendChild(el("b", "", `Create path: ${String(best.label || best.path_id || "local path")}`));
      card.appendChild(el("span", "", String(best.reason || best.action || "Path creation plan ready.")));
      host.appendChild(card);
      const launch = $("#btn-launch-path-create");
      if (launch) {
        const canLaunch = !!best.path_id && (Array.isArray(best.command) && best.command.length || !!best.settings_uri);
        launch.style.display = canLaunch ? "block" : "none";
        launch.dataset.pathId = canLaunch ? String(best.path_id) : "";
        launch.textContent = best.settings_uri ? "Open path settings" : "Open path ceremony";
      }
    } else {
      const launch = $("#btn-launch-path-create");
      if (launch) {
        launch.style.display = "none";
        launch.dataset.pathId = "";
      }
    }
    renderNoRouterGuide(kit.operator_guide || kit.guide || null);
    host.title = kit.next_action ? `Next: ${String(kit.next_action).replaceAll("_", " ")}` : "";
  }
  async function launchBestPathCreate() {
    const btn = $("#btn-launch-path-create");
    const pathId = btn?.dataset?.pathId || "";
    if (!pathId) return;
    try {
      const result = await api.launchFabricPathCreate({ path_id: pathId });
      toast(result.disabled ? "Path settings launch disabled here" : "Opening path settings");
      await refreshFabricTruth();
    } catch (e) {
      toast(errorToastBody(e, "Path settings launch failed"), "err");
    }
  }
  function renderNoRouterGuide(operatorGuide) {
    const host = $("#no-router-guide");
    if (!host) return;
    const guide = operatorGuide || {};
    host.replaceChildren();
    const modes = [
      ["send", "Send"],
      ["receive", "Receive"],
    ];
    for (const [mode, title] of modes) {
      const steps = Array.isArray(guide[mode]) ? guide[mode] : [];
      if (!steps.length) continue;
      const wrap = el("div", "nr-guide-mode");
      wrap.appendChild(el("div", "nr-guide-title", title));
      const list = el("div", "nr-guide-steps");
      for (const step of steps.slice(0, 4)) {
        const status = String(step.status || "pending");
        const row = el("div", `nr-guide-step ${status}`);
        const dot = el("div", "nr-guide-dot", status === "ready" ? "✓" : status === "current" ? "·" : status === "blocked" ? "!" : "");
        const body = el("div");
        body.appendChild(el("b", "", String(step.label || step.id || "step")));
        body.appendChild(el("span", "", String(step.detail || "")));
        row.appendChild(dot);
        row.appendChild(body);
        list.appendChild(row);
      }
      wrap.appendChild(list);
      host.appendChild(wrap);
    }
  }
  function renderCourierKit() {
    const host = $("#courier-kit");
    if (!host) return;
    const courier = state.courier || {};
    const ledger = courier.ledger || {};
    const copy = host.querySelector(".ck-copy");
    if (copy) {
      const seen = Number(ledger.seen_bundle_ids || 0);
      const recent = Array.isArray(ledger.recent) ? ledger.recent[ledger.recent.length - 1] : null;
      const outboxCount = Array.isArray(courier.outbox_files_list) ? courier.outbox_files_list.length : Number(courier.outbox_files || 0);
      const removableEvents = Array.isArray(courier.removable_events) ? courier.removable_events : [];
      const removableEvent = removableEvents[0] || null;
      const removableLabel = removableEvent?.target?.label || removableEvent?.target?.path || "";
      copy.textContent = removableEvent
        ? `USB delivery ${String(removableEvent.kind || "changed").replace(/_/g, " ")}${removableLabel ? `: ${removableLabel}` : ""}. Duplicate protection remembers ${seen}.`
        : recent
          ? `Last offline delivery ${recent.kind || "event"}: ${recent.chunk_count || 0} chunk${recent.chunk_count === 1 ? "" : "s"}. Duplicate protection remembers ${seen}.`
          : (outboxCount > 0 ? `${outboxCount} saved offline bundle${outboxCount === 1 ? "" : "s"} ready.` : "Move a file when the internet, router, or other device is not reachable.");
    }
    const select = $("#courier-transfer-select");
    if (select) {
      const current = select.value;
      const rows = (state.transfers || []).filter(t =>
        t && t.blob_hash && (t.chunks_total || t.status === "complete")
      );
      select.innerHTML = "";
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = rows.length ? "Choose cached transfer" : "No cached transfers yet";
      select.appendChild(blank);
      for (const t of rows.slice(0, 80)) {
        const opt = document.createElement("option");
        opt.value = t.id || "";
        opt.dataset.blobHash = t.blob_hash || "";
        const chunkText = t.chunks_total ? `${t.chunks_total} chunks` : "cached chunks";
        opt.textContent = `${t.name || "file"} - ${fmtBytes(t.total_bytes || 0)} - ${chunkText}`;
        select.appendChild(opt);
      }
      if ([...select.options].some(o => o.value === current)) select.value = current;
    }
    const drop = $("#courier-drop-select");
    if (drop) {
      const current = drop.value;
      const files = Array.isArray(courier.files) ? courier.files : [];
      drop.innerHTML = "";
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = files.length ? "Choose received bundle" : "No received bundles";
      drop.appendChild(blank);
      for (const f of files.slice(0, 64)) {
        const opt = document.createElement("option");
        opt.value = f.id || "";
        opt.textContent = `${f.name || "offline bundle"} - ${fmtBytes(f.bytes || 0)}`;
        drop.appendChild(opt);
      }
      if ([...drop.options].some(o => o.value === current)) drop.value = current;
    }
    const outbox = $("#courier-outbox-select");
    if (outbox) {
      const current = outbox.value;
      const files = Array.isArray(courier.outbox_files_list) ? courier.outbox_files_list : [];
      outbox.innerHTML = "";
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = files.length ? "Choose saved bundle" : "No saved bundles";
      outbox.appendChild(blank);
      for (const f of files.slice(0, 64)) {
        const opt = document.createElement("option");
        opt.value = f.id || "";
        opt.textContent = `${f.name || "saved bundle"} - ${fmtBytes(f.bytes || 0)}`;
        outbox.appendChild(opt);
      }
      if ([...outbox.options].some(o => o.value === current)) outbox.value = current;
    }
    const removable = $("#courier-removable-select");
    if (removable) {
      const current = removable.value;
      const targets = Array.isArray(courier.removable_targets) ? courier.removable_targets : [];
      removable.innerHTML = "";
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = targets.length ? "Choose USB drive" : "No USB drive found";
      removable.appendChild(blank);
      for (const t of targets) {
        const opt = document.createElement("option");
        opt.value = t.id || "";
        opt.textContent = t.label || t.path || "USB drive";
        removable.appendChild(opt);
      }
      if ([...removable.options].some(o => o.value === current)) removable.value = current;
    }
    const removableFile = $("#courier-removable-file-select");
    if (removableFile) {
      const current = removableFile.value;
      const files = Array.isArray(courier.removable_files) ? courier.removable_files : [];
      removableFile.innerHTML = "";
      const blank = document.createElement("option");
      blank.value = "";
      blank.textContent = files.length ? "Choose USB bundle" : "No USB bundles";
      removableFile.appendChild(blank);
      for (const f of files.slice(0, 64)) {
        const opt = document.createElement("option");
        opt.value = f.id || "";
        opt.textContent = `${f.name || "offline bundle"} - ${fmtBytes(f.bytes || 0)}`;
        removableFile.appendChild(opt);
      }
      if ([...removableFile.options].some(o => o.value === current)) removableFile.value = current;
    }
    renderCourierWizard();
  }
  function setCourierGuideMode(mode) {
    state.courierGuideMode = mode === "receive" ? "receive" : "send";
    renderCourierWizard();
  }
  function renderCourierWizard() {
    const stepsHost = $("#courier-wizard-steps");
    if (!stepsHost) return;
    const sendBtn = $("#btn-courier-guide-send");
    const receiveBtn = $("#btn-courier-guide-receive");
    sendBtn?.classList.toggle("active", state.courierGuideMode !== "receive");
    receiveBtn?.classList.toggle("active", state.courierGuideMode === "receive");
    const courier = state.courier || {};
    const hasTransfer = !!($("#courier-transfer-select")?.value || _courierChunkHashesFromInput().length);
    const keyReady = !!($("#courier-key-token")?.value || "").trim();
    const outboxReady = Number(courier.outbox_files || 0) > 0 || (courier.outbox_files_list || []).length > 0;
    const removableReady = Number(courier.removable_targets?.length || 0) > 0;
    const dropReady = Number(courier.drop_files || 0) > 0 || (courier.files || []).length > 0;
    const receiveSelected = !!$("#courier-drop-select")?.value;
    const removableFileSelected = !!$("#courier-removable-file-select")?.value;
    const steps = state.courierGuideMode === "receive"
      ? [
          ["Choose or import an offline bundle", dropReady || removableFileSelected],
          ["Paste the unlock code", keyReady],
          ["Pick the received bundle", receiveSelected],
          ["Import it and let One Link verify it", false],
        ]
      : [
          ["Choose a cached transfer", hasTransfer],
          ["Download or save the offline bundle", outboxReady],
          ["Share the unlock code separately", keyReady],
          ["Carry the bundle by USB, cloud drive, or any safe handoff", (outboxReady && keyReady) || removableReady],
        ];
    stepsHost.replaceChildren();
    steps.forEach(([label, ready], idx) => {
      const row = el("div", `cw-step${ready ? " ready" : ""}`);
      row.appendChild(el("span", "cw-dot", ready ? "✓" : String(idx + 1)));
      row.appendChild(el("span", "", label));
      stepsHost.appendChild(row);
    });
  }
  function _courierChunkHashesFromInput() {
    const raw = ($("#courier-chunks")?.value || "").trim();
    if (!raw) return [];
    return raw.split(/[\s,;]+/).map(x => x.trim().toLowerCase()).filter(Boolean);
  }
  function _downloadCourierBundle(bundleB64, manifest) {
    const body = JSON.stringify({
      type: "one-link-courier-bundle",
      version: 1,
      bundle_b64: bundleB64,
      manifest,
    }, null, 2);
    const blob = new Blob([body], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    a.href = url;
    a.download = `one-link-courier-${stamp}.olcb.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function _courierExportBodyFromUI() {
    const select = $("#courier-transfer-select");
    const selected = select?.selectedOptions?.[0];
    const chunks = _courierChunkHashesFromInput();
    const body = {};
    if (chunks.length) body.chunks = chunks;
    else if (select?.value) body.transfer_id = select.value;
    else if (selected?.dataset?.blobHash) body.blob_hash = selected.dataset.blobHash;
    const peer = state.selectedPeer ? state.peers.get(state.selectedPeer) : null;
    if (peer?.fingerprint) body.recipient_fp = peer.fingerprint;
    return body;
  }
  async function exportCourierBundle() {
    const body = _courierExportBodyFromUI();
    try {
      const r = await api.courierExport(body);
      _downloadCourierBundle(r.bundle_b64, r.manifest);
      const keyEl = $("#courier-key-token");
      if (keyEl) keyEl.value = r.key_token || "";
      await copyToClipboard(r.key_token || "", "unlock code");
      await refreshCourierStatus();
      toast(`Offline bundle ready: ${r.chunk_count || 0} chunk${r.chunk_count === 1 ? "" : "s"}`, "good", 4500);
    } catch (e) {
      toast(`Offline bundle failed: ${errorToastBody(e)}`, "bad", 8000);
    }
  }
  async function stageCourierBundle() {
    const body = _courierExportBodyFromUI();
    try {
      const r = await api.courierExportFile(body);
      const keyEl = $("#courier-key-token");
      if (keyEl) keyEl.value = r.key_token || "";
      await copyToClipboard(r.key_token || "", "unlock code");
      await refreshCourierStatus();
      toast(`Offline bundle saved: ${r.name || "ready"}`, "good", 5500);
    } catch (e) {
      toast(`Save didn't work: ${errorToastBody(e)}`, "bad", 8000);
    }
  }
  async function copyCourierToRemovable() {
    const fileId = $("#courier-outbox-select")?.value || "";
    const targetId = $("#courier-removable-select")?.value || "";
    if (!fileId) {
      toast("Choose a saved bundle first.", "info", 3500);
      return;
    }
    if (!targetId) {
      toast("Choose a USB drive first.", "info", 3500);
      return;
    }
    try {
      const r = await api.courierCopyToRemovable({ file_id: fileId, target_id: targetId });
      toast(`Copied offline bundle to ${r.target_label || "USB drive"}`, "good", 5500);
      await refreshCourierStatus();
    } catch (e) {
      toast(`USB copy failed: ${errorToastBody(e)}`, "bad", 8000);
    }
  }
  async function refreshRemovableCourierFiles() {
    const targetId = $("#courier-removable-select")?.value || "";
    state.courier = state.courier || {};
    if (!targetId) {
      state.courier.removable_files = [];
      renderCourierKit();
      renderOneNow();
      return;
    }
    try {
      const r = await api.courierRemovableFiles(targetId);
      state.courier.removable_files = r.files || [];
      renderCourierKit();
    } catch (_e) {
      state.courier.removable_files = [];
      renderCourierKit();
    }
  }
  async function pullCourierFromRemovable() {
    const targetId = $("#courier-removable-select")?.value || "";
    const fileId = $("#courier-removable-file-select")?.value || "";
    if (!targetId) {
      toast("Choose a USB drive first.", "info", 3500);
      return;
    }
    if (!fileId) {
      toast("Choose a USB bundle first.", "info", 3500);
      return;
    }
    try {
      const r = await api.courierCopyFromRemovable({ target_id: targetId, file_id: fileId });
      toast(`Pulled offline bundle: ${r.name || "ready"}`, "good", 5500);
      await refreshCourierStatus();
    } catch (e) {
      toast(`USB pull failed: ${errorToastBody(e)}`, "bad", 8000);
    }
  }
  async function importCourierBundleFile(file) {
    if (!file) return;
    const keyToken = ($("#courier-key-token")?.value || "").trim();
    if (!keyToken) {
      toast("Paste the unlock code first.", "info", 3500);
      $("#courier-key-token")?.focus();
      return;
    }
    try {
      const text = await file.text();
      let bundleB64 = "";
      try {
        const parsed = JSON.parse(text);
        bundleB64 = parsed.bundle_b64 || parsed.bundle || "";
      } catch {
        bundleB64 = text.trim();
      }
      if (!bundleB64) throw new Error("Offline bundle file did not contain bundle data");
      const r = await api.courierImport({ bundle_b64: bundleB64, key_token: keyToken });
      if (r.manifest?.blob_hash) {
        const assembled = await api.courierAssemble({
          blob_hash: r.manifest.blob_hash,
          name: r.manifest.name || "offline-file.bin",
        });
        toast(`Offline file ready: ${assembled.name || "ready"}`, "good", 6000);
      } else {
        toast(`Imported ${r.stored_chunks || 0} file chunk${r.stored_chunks === 1 ? "" : "s"}`, "good", 4500);
      }
      await refreshCourierStatus();
      await refreshStatus();
      await refreshTransfers();
      renderCourierKit();
    } catch (e) {
      toast(`Import failed: ${errorToastBody(e)}`, "bad", 8000);
    }
  }
  async function importDroppedCourierFile() {
    const drop = $("#courier-drop-select");
    const fileId = drop?.value || "";
    const keyToken = ($("#courier-key-token")?.value || "").trim();
    if (!fileId) {
      toast("Choose a received bundle first.", "info", 3500);
      return;
    }
    if (!keyToken) {
      toast("Paste the unlock code first.", "info", 3500);
      $("#courier-key-token")?.focus();
      return;
    }
    try {
      const r = await api.courierImportFile({ file_id: fileId, key_token: keyToken });
      if (r.manifest?.blob_hash) {
        const assembled = await api.courierAssemble({
          blob_hash: r.manifest.blob_hash,
          name: r.manifest.name || "offline-file.bin",
        });
        toast(`Offline file ready: ${assembled.name || "ready"}`, "good", 6000);
      } else {
        toast(`Imported ${r.stored_chunks || 0} file chunk${r.stored_chunks === 1 ? "" : "s"}`, "good", 4500);
      }
      await refreshCourierStatus();
      await refreshStatus();
      await refreshTransfers();
      renderCourierKit();
    } catch (e) {
      toast(`Import failed: ${errorToastBody(e)}`, "bad", 8000);
    }
  }
  async function refreshCourierStatus() {
    const [status, files, outbox, removable] = await Promise.allSettled([
      api.courierStatus(),
      api.courierFiles(),
      api.courierOutbox(),
      api.courierRemovable(),
    ]);
    state.courier = status.status === "fulfilled"
      ? status.value
      : (state.courier || {});
    if (files.status === "fulfilled") {
      state.courier.files = files.value.files || [];
      state.courier.drop_dir = files.value.drop_dir || state.courier.drop_dir;
    }
    if (outbox.status === "fulfilled") {
      state.courier.outbox_files_list = outbox.value.files || [];
      state.courier.outbox_dir = outbox.value.outbox_dir || state.courier.outbox_dir;
    }
    if (removable.status === "fulfilled") {
      state.courier.removable_targets = removable.value.targets || [];
    }
    await refreshRemovableCourierFiles();
    renderCourierKit();
  }
