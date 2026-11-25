  // ─── v0.21.x folder Send confirmation + in-flight overlay ────
  // openFolderSendConfirm() is called from BOTH the folder-card Send
  // button (scope=folder) and the chat composer's Folder attach
  // option (scope=adhoc). The pre-flight check + send + cancel flow
  // is identical; only the endpoint URLs change.
  state.folderSendInflight = null;  // {scope, ident, peer_fp, peer_hostname}

  function _fmtFiles(n) {
    return `${n} file${n === 1 ? "" : "s"}`;
  }

  function _folderSendUrls(scope, ident) {
    // ident is the folder NAME for scope=folder, or the local_path
    // for scope=adhoc. Encode appropriately.
    if (scope === "folder") {
      const base = `/api/folders/${encodeURIComponent(ident)}/send-to`;
      return { send: base, preview: `${base}/preview`, cancel: `${base}/cancel` };
    }
    return {
      send: "/api/fs/send-folder",
      preview: "/api/fs/send-folder/preview",
      cancel: "/api/fs/send-folder/cancel",
    };
  }

  async function openFolderSendConfirm({ scope, ident, peerFp, peerHostname, displayName, displayPath }) {
    state.folderSendConfirmCtx = { scope, ident, peerFp, peerHostname, displayName, displayPath };
    const targetEl = $("#folder-send-confirm-target");
    targetEl.innerHTML = "";
    const head = document.createElement("div");
    // 2026-06-16 (external-audit XSS fix): escape ALL interpolated
    // values. displayName/displayPath are user-chosen folder name +
    // local path; peerHostname is PEER-CONTROLLED (a malicious peer
    // could advertise a hostname like "<img src=x onerror=...>"). All
    // three previously went into innerHTML raw — a real stored-XSS
    // vector in this confirm modal.
    head.innerHTML = `<strong>${_escapeHtml(displayName)}</strong>`
      + (displayPath ? ` · ${_escapeHtml(displayPath)}` : "")
      + `<br>To ${_escapeHtml(peerHostname || (peerFp || "").slice(0, 8))}`;
    targetEl.appendChild(head);
    const statsEl = $("#folder-send-confirm-stats");
    statsEl.innerHTML = `
      <div class="fss-row fss-row-loading">
        <span class="fss-spinner"></span>
        <span>Checking what's already on the other device…</span>
      </div>
    `;
    const goBtn = $("#folder-send-confirm-go");
    goBtn.disabled = true;
    $("#folder-send-confirm-backdrop").classList.add("show");
    document.body.classList.add("modal-open");
    // Pre-flight call.
    const urls = _folderSendUrls(scope, ident);
    const body = scope === "folder"
      ? { peer_fp: peerFp }
      : { peer_fp: peerFp, local_path: ident };
    try {
      const stats = await api.post(urls.preview, body);
      _renderFolderSendStats(stats);
      goBtn.disabled = false;
    } catch (e) {
      const status = e?.status;
      const errMsg = errorToastBody(e) || (e?.message ?? "Pre-check failed.");
      // 2026-06-16 (external-audit XSS fix): errMsg can carry
      // server/peer-supplied text (error_detail / hint); escape it
      // before it enters innerHTML.
      statsEl.innerHTML = `<div class="fss-row" style="color: var(--bad, #e85c5c)"><span>${_escapeHtml(errMsg)}</span></div>`;
      // For peer_offline / folder_path_missing / etc the user can't
      // proceed; keep Send disabled. For other failures (e.g. the
      // peer's daemon doesn't speak BLOB_INVENTORY_QUERY) we allow
      // the user to send anyway — dedup still works at FILE_OFFER
      // time, they just don't get a pre-flight estimate.
      if (status === 503 || status === 404 || status === 409) {
        goBtn.disabled = true;
      } else {
        goBtn.disabled = false;
        statsEl.insertAdjacentHTML("beforeend",
          `<div class="fss-row fss-row-loading"><span>The send will still try to dedup automatically.</span></div>`,
        );
      }
    }
  }

  function _renderFolderSendStats(stats) {
    const statsEl = $("#folder-send-confirm-stats");
    statsEl.innerHTML = "";
    const total = document.createElement("div");
    total.className = "fss-row";
    total.innerHTML = `<span class="fss-label">Total</span><span class="fss-value">${_fmtFiles(stats.file_count || 0)} · ${_humanBytes(stats.total_bytes || 0)}</span>`;
    statsEl.appendChild(total);
    if (stats.pre_check_complete) {
      if ((stats.already_on_peer_count || 0) > 0) {
        const dedup = document.createElement("div");
        dedup.className = "fss-row fss-row-dedup";
        dedup.innerHTML = `<span class="fss-label">Already on the other device</span><span class="fss-value">${_fmtFiles(stats.already_on_peer_count)} · ${_humanBytes(stats.already_on_peer_bytes || 0)} skipped</span>`;
        statsEl.appendChild(dedup);
      }
      const transfer = document.createElement("div");
      transfer.className = "fss-row fss-row-transfer";
      transfer.innerHTML = `<span class="fss-label">Will transfer</span><span class="fss-value">${_fmtFiles(stats.will_transfer_count || 0)} · ${_humanBytes(stats.will_transfer_bytes || 0)}</span>`;
      statsEl.appendChild(transfer);
    } else {
      const hint = document.createElement("div");
      hint.className = "fss-row fss-row-loading";
      hint.innerHTML = `<span>The other device couldn't answer the dedup pre-check; sending will still skip files they already have at the FILE_OFFER step.</span>`;
      statsEl.appendChild(hint);
    }
    // v0.21.x: smart auto-router recommendation. Shows the user
    // WHICH mode the daemon would pick if they don't override +
    // WHY (e.g. "78% compressible → archive (60% smaller)").
    if (stats.recommended_mode) {
      const rec = document.createElement("div");
      rec.className = "fss-row fss-row-recommendation";
      const modeLabel = {
        archive: "Compressed archive",
        manifest_push: "Live folder sync (chunk dedup)",
        per_file: "Per-file (FILE_OFFER batched)",
      }[stats.recommended_mode] || stats.recommended_mode;
      const compRatio = stats.recommended_compressible_ratio;
      const compHint = compRatio !== undefined && compRatio !== null
        ? ` · ${Math.round((compRatio || 0) * 100)}% compressible`
        : "";
      rec.innerHTML = (
        `<span class="fss-label">Recommended</span>`
        + `<span class="fss-value">${modeLabel}${compHint}</span>`
      );
      rec.title = stats.recommended_reason || "";
      statsEl.appendChild(rec);
    }
  }

  function closeFolderSendConfirm() {
    $("#folder-send-confirm-backdrop").classList.remove("show");
    document.body.classList.remove("modal-open");
    state.folderSendConfirmCtx = null;
  }

  function showFolderSendProgress({ scope, ident, peerFp, peerHostname, displayName, fileCount, totalBytes }) {
    state.folderSendInflight = { scope, ident, peerFp, peerHostname, displayName };
    $("#fsp-title").textContent = `Sending ${displayName}`;
    $("#fsp-detail").textContent = `${_fmtFiles(fileCount)} · ${_humanBytes(totalBytes || 0)} → ${peerHostname || peerFp.slice(0, 8)}`;
    $("#folder-send-progress").style.display = "block";
  }

  function hideFolderSendProgress() {
    $("#folder-send-progress").style.display = "none";
    state.folderSendInflight = null;
  }

  async function _cancelInflightFolderSend() {
    const cur = state.folderSendInflight;
    if (!cur) return;
    const urls = _folderSendUrls(cur.scope, cur.ident);
    const body = cur.scope === "folder"
      ? { peer_fp: cur.peerFp }
      : { peer_fp: cur.peerFp, local_path: cur.ident };
    try {
      await api.post(urls.cancel, body);
      toast(`Cancelled send of ${cur.displayName}.`, "info", 4000);
    } catch (e) {
      // 404 = task already finished. Just hide the overlay.
      if (e?.status !== 404) {
        toast(`Cancel failed: ${errorToastBody(e) || e}`, "bad", 5000);
      }
    } finally {
      hideFolderSendProgress();
    }
  }

  async function _confirmFolderSendGo() {
    const ctx = state.folderSendConfirmCtx;
    if (!ctx) return;
    const urls = _folderSendUrls(ctx.scope, ctx.ident);
    const body = ctx.scope === "folder"
      ? { peer_fp: ctx.peerFp }
      : { peer_fp: ctx.peerFp, local_path: ctx.ident };
    closeFolderSendConfirm();
    try {
      const r = await api.post(urls.send, body);
      showFolderSendProgress({
        scope: ctx.scope, ident: ctx.ident,
        peerFp: ctx.peerFp, peerHostname: ctx.peerHostname,
        displayName: ctx.displayName,
        fileCount: r.file_count || 0,
        totalBytes: r.total_bytes || 0,
      });
    } catch (e) {
      toast(`Send didn't start: ${errorToastBody(e) || e}`, "bad", 6000);
    }
  }

  function openFolderSettings(folder) {
    state.folderSettingsTarget = folder.name;
    const targetEl = $("#folder-settings-target");
    targetEl.innerHTML = "";
    const head = document.createElement("div");
    head.style.fontSize = "12px";
    head.style.color = "var(--text-dim)";
    head.style.marginBottom = "12px";
    head.textContent = `${folder.name} · ${folder.local_path}`;
    targetEl.appendChild(head);
    const patterns = Array.isArray(folder.ignored_patterns) ? folder.ignored_patterns : [];
    $("#folder-settings-ignored").value = patterns.join("\n");
    // v0.21.x: max_file_bytes section removed from the UI entirely.
    // One Link does not impose a file size limit. Any existing
    // max_file_bytes value on the folder gets cleared on save.
    // v0.21.x: Folder location section — current path pre-filled so
    // the user can edit OR pick a new one via Browse. Save is a
    // separate button from the main Save (it's a heavier operation:
    // stops + restarts the watcher + kicks a re-scan).
    $("#folder-settings-path").value = folder.local_path || "";
    const relocateStatus = $("#folder-settings-relocate-status");
    if (relocateStatus) {
      relocateStatus.textContent = "";
      relocateStatus.className = "settings-help-inline";
    }
    const policy = folder.conflict_policy || "latest-wins";
    const radio = document.querySelector(`input[name="conflict-policy"][value="${policy}"]`);
    if (radio) radio.checked = true;
    $("#folder-settings-backdrop").classList.add("show");
    document.body.classList.add("modal-open");
  }

  function closeFolderSettings() {
    $("#folder-settings-backdrop").classList.remove("show");
    document.body.classList.remove("modal-open");
    state.folderSettingsTarget = null;
  }

  async function saveFolderSettings() {
    const name = state.folderSettingsTarget;
    if (!name) return;
    const ignored = ($("#folder-settings-ignored").value || "")
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const policyEl = document.querySelector('input[name="conflict-policy"]:checked');
    const policy = policyEl ? policyEl.value : "latest-wins";
    // v0.21.x: always send max_file_bytes: null so any pre-existing
    // size cap on the folder (set on an older client) gets cleared.
    // One Link does not impose a file size limit.
    const body = {
      ignored_patterns: ignored,
      max_file_bytes: null,
      conflict_policy: policy,
    };
    try {
      await api.post(`/api/folders/${encodeURIComponent(name)}/policy`, body);
      toast("Sync settings saved.", "good", 3500);
      closeFolderSettings();
      await refreshFolders();
    } catch (e) {
      toast(`Couldn't save: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  // v0.8.9: folder-sync divergent-edit conflict UI.

  // Cache of unresolved-conflict count + freshest list. Banner derives
  // from this; modal pulls a fresh list on open.
  state.folderConflicts = { unresolved_total: 0, conflicts: [] };

