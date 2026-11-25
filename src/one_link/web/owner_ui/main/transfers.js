  async function refreshTransfers() {
    try {
      const { transfers } = await api.transfers();
      state.transfers = transfers || [];
      state.transfersById = new Map();
      for (const t of state.transfers) state.transfersById.set(t.id, t);
      // T3-Z: rebuild the O(1) (dir|blob) → transfer lookup index.
      _rebuildTransferByDirBlob();
      renderTransfers();
      renderCourierKit();
      // Status of file bubbles is driven by transfersById - re-render
      // the active conversation so progress reflects the fresh data.
      renderMessages();
      // /api/status has an independent 8s cadence and is refreshed by live
      // WebSocket events. Do not turn every 4s transfer tick into a second
      // status -> self-mesh -> health cascade.
    } catch (e) { console.warn(e); }
  }

  function _renderTransferGroup(grpKey, members) {
    // v0.21.x Wave D: render a folder-send group as ONE row +
    // collapsible per-file rows underneath. Aggregates progress
    // across all member transfers.
    const wrap = el("div", "transfer-group");
    // Extract the folder name from the group key:
    //   "folder:papers:aabbccdd" → "papers"
    //   "adhoc:/path/to/papers:aabbccdd" → "papers" (leaf)
    let folderName = "folder";
    const parts = grpKey.split(":");
    if (parts.length >= 3) {
      const ident = parts.slice(1, -1).join(":");
      const leaf = ident.split(/[\\/]/).filter(Boolean).pop();
      folderName = leaf || ident;
    }
    const total = members.length;
    const done = members.filter(t => t.status === "complete").length;
    const failed = members.filter(t => t.status === "failed").length;
    const active = members.filter(t => t.status === "active" || t.status === "offered").length;
    const totalBytes = members.reduce((s, t) => s + (t.total_bytes || 0), 0);
    const progressBytes = members.reduce((s, t) => s + (t.progress_bytes || 0), 0);
    const pct = totalBytes > 0
      ? Math.round((progressBytes / totalBytes) * 100) : 0;
    // Header row.
    const header = el("div", "file-row transfer-group-header");
    header.appendChild(el("div", "icon", "Folder"));
    const meta = el("div", "meta");
    meta.appendChild(el("div", "name", folderName));
    const statusLine = (
      `${done}/${total} done`
      + (active > 0 ? ` · ${active} active` : "")
      + (failed > 0 ? ` · ${failed} failed` : "")
      + ` · ${fmtBytes(progressBytes)} / ${fmtBytes(totalBytes)}`
    );
    meta.appendChild(el("div", "size", statusLine));
    const bar = el("div", "bar");
    const fill = el("span");
    fill.style.width = `${pct}%`;
    bar.appendChild(fill);
    meta.appendChild(bar);
    const toggle = document.createElement("a");
    toggle.href = "#";
    toggle.className = "transfer-group-toggle";
    toggle.textContent = `▸ Show files (${total})`;
    meta.appendChild(toggle);
    header.appendChild(meta);
    wrap.appendChild(header);
    // Children container (hidden by default).
    const children = el("div", "transfer-group-children");
    children.style.display = "none";
    for (const t of members) {
      const childRow = el("div", "file-row transfer-group-child");
      childRow.appendChild(el("div", "icon", t.direction === "in" ? "In" : "Out"));
      const childMeta = el("div", "meta");
      childMeta.appendChild(el("div", "name", t.name || "file"));
      const childLabel = statusLabel(t, t.status || "Queued");
      childMeta.appendChild(el(
        "div", "size",
        `${childLabel} - ${fmtBytes(t.progress_bytes)} / ${fmtBytes(t.total_bytes)}`,
      ));
      childRow.appendChild(childMeta);
      children.appendChild(childRow);
    }
    wrap.appendChild(children);
    toggle.onclick = (ev) => {
      ev.preventDefault();
      const open = children.style.display !== "none";
      children.style.display = open ? "none" : "block";
      toggle.textContent = (open ? "▸" : "▾") + ` Show files (${total})`;
    };
    return wrap;
  }

  function renderTransfers() {
    const list = $("#transferlist");
    if (!list) return;
    list.innerHTML = "";
    $("#transfers-count").textContent = state.transfers.length;
    if (state.transfers.length === 0) {
      list.appendChild(el("div", "empty", "No activity yet. Sent files and folder sync will appear here."));
      return;
    }
    // v0.21.x Wave D: group per-file transfers from the same
    // folder-send operation. Each transfer tagged with
    // metadata.folder_send_group ("folder:papers:aabbccdd") gets
    // collapsed into ONE group row + a "▸ Show files (N)" toggle.
    // Ungrouped transfers render as individual rows like before.
    const grouped = new Map();  // group_key → [transfers]
    const ungrouped = [];
    for (const t of state.transfers) {
      const grp = t?.metadata?.folder_send_group;
      if (grp) {
        if (!grouped.has(grp)) grouped.set(grp, []);
        grouped.get(grp).push(t);
      } else {
        ungrouped.push(t);
      }
    }
    // Render grouped folder-sends first (more important).
    for (const [grpKey, members] of grouped.entries()) {
      list.appendChild(_renderTransferGroup(grpKey, members));
    }
    for (const t of ungrouped) {
      const row = el("div", "file-row");
      row.appendChild(el("div", "icon", t.direction === "in" ? "In" : "Out"));
      const meta = el("div", "meta");
      meta.appendChild(el("div", "name", t.name || "file"));
      const label = statusLabel(t, t.status || "Queued");
      const rate = (t.status === "active" || t.status === "offered") ? rateForTransfer(t) : 0;
      const parts = [
        label,
        `${fmtBytes(t.progress_bytes)} / ${fmtBytes(t.total_bytes)}`,
      ];
      if (rate > 0) {
        parts.push(fmtRate(rate));
        const remaining = Math.max(0, (t.total_bytes || 0) - (t.progress_bytes || 0));
        if (remaining > 0) parts.push(`ETA ${fmtEta(remaining, rate)}`);
      }
      meta.appendChild(el("div", "size", parts.join(" - ")));
      const bar = el("div", "bar");
      const fill = el("span");
      fill.style.width = `${Math.max(0, Math.min(100, t.progress_pct || 0))}%`;
      bar.appendChild(fill);
      meta.appendChild(bar);
      const command = renderTransferCommandCenter(t);
      if (command) meta.appendChild(command);
      // renderTransferFacts(t, statusKind(t)) is invoked inside the
      // collapsed wrapper so the transfer panel surfaces the same
      // autopilot truth as file bubbles without adding constant clutter.
      const facts = renderTransferFactsCollapsed(t, statusKind(t));
      if (facts) meta.appendChild(facts);
      row.appendChild(meta);
      // v0.7.x: Retry button for failed outbound transfers. The
      // server reads the original local path off the ledger row's
      // metadata.path and re-runs send_file. Inbound failures
      // can't be retried from the receiver side (the sender owns
      // the source file), so it's out-only.
      if (t.status === "failed" && !((t.metadata || {}).transient) && t.direction === "out") {
        const retry = el("button", null, "Retry");
        retry.onclick = async () => {
          retry.disabled = true;
          retry.textContent = "Retrying…";
          try {
            await api.post(
              `/api/transfers/${encodeURIComponent(t.id)}/retry`, {}
            );
            toast(`Retrying ${t.name || "transfer"}`, "info", 3000);
            await refreshTransfers();
          } catch (e) {
            toast(`Retry didn't work: ${errorToastBody(e)}`, "bad", 8000);
            retry.disabled = false;
            retry.textContent = "Retry";
          }
        };
        row.appendChild(retry);
      }
      // v0.7.4: paused outbound transfers auto-resume on next
      // session-up. Show a Cancel button for the user to give up.
      if ((t.status === "paused" || t.status === "queued") && t.direction === "out") {
        const cancel = el("button", null, "Cancel");
        cancel.onclick = async () => {
          cancel.disabled = true;
          try {
            await api.post(
              `/api/transfers/${encodeURIComponent(t.id)}/cancel`, {}
            );
            await refreshTransfers();
          } catch (e) {
            toast(`Cancel didn't work: ${errorToastBody(e)}`, "bad");
            cancel.disabled = false;
          }
        };
        row.appendChild(cancel);
      }
      if (t.blob_hash && (t.chunks_total || t.status === "complete")) {
        const courier = el("button", null, "Offline");
        courier.title = "Download this transfer as an encrypted offline bundle.";
        courier.onclick = async () => {
          const select = $("#courier-transfer-select");
          if (select) select.value = t.id || "";
          await exportCourierBundle();
        };
        row.appendChild(courier);
      }
      if (["complete", "failed"].includes(t.status)) {
        const del = el("button", null, "Clear");
        del.onclick = async () => {
          try {
            await api.del(`/api/transfers/${encodeURIComponent(t.id)}`);
            state.transfers = state.transfers.filter(x => x.id !== t.id);
            renderTransfers();
            await refreshStatus();
          } catch (e) {
            toast(`Clear didn't work: ${e.message || e}`, "bad");
          }
        };
        row.appendChild(del);
      }
      list.appendChild(row);
    }
  }

