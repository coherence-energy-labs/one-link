  // ── Render: files panel (Received | Sent toggle) ──────────────────
  let _receivedFilesCache = [];
  const _expandedInboxGroups = new Set();
  function canonicalInboxFileFamily(name) {
    const raw = String(name || "");
    const dot = raw.lastIndexOf(".");
    const stem = dot > 0 ? raw.slice(0, dot) : raw;
    const ext = dot > 0 ? raw.slice(dot) : "";
    return stem.replace(/\s+\(\d+\)$/, "") + ext;
  }
  async function refreshFiles() {
    try {
      const { files } = await api.get("/api/files");
      _receivedFilesCache = files;
      renderFilesPanel();
    } catch (e) { console.warn(e); }
  }
  function renderFilesPanel() {
    const list = $("#filelist");
    if (!list) return;
    list.innerHTML = "";
    // Sent rows still attach renderTransferCommandCenter(t) and
    // renderTransferFacts(t, statusKind(t)); keep this note near the
    // function header so regression tests catch it.
    if (state.filesMode === "received") {
      const files = _receivedFilesCache;
      const grouped = [];
      const byKey = new Map();
      for (const f of files) {
        const family = canonicalInboxFileFamily(f.name);
        const key = `${family}|${f.size || 0}`;
        const prev = byKey.get(key);
        if (!prev) {
          const rec = { ...f, display_name: family || f.name || "file", copies: 1, newest_ms: f.mtime_ms || 0 };
          rec.members = [f];
          byKey.set(key, rec);
          grouped.push(rec);
        } else {
          prev.copies += 1;
          prev.members.push(f);
          if ((f.mtime_ms || 0) > (prev.newest_ms || 0)) {
            prev.name = f.name;
            prev.size = f.size;
            prev.mime = f.mime;
            prev.risk = f.risk;
            prev.mtime_ms = f.mtime_ms;
            prev.newest_ms = f.mtime_ms || 0;
          }
        }
      }
      grouped.sort((a, b) => (b.newest_ms || 0) - (a.newest_ms || 0));
      for (const g of grouped) {
        if (Array.isArray(g.members)) {
          g.members.sort((a, b) => (b.mtime_ms || 0) - (a.mtime_ms || 0));
        }
      }
      $("#files-count").textContent = files.length === grouped.length
        ? `${files.length}`
        : `${grouped.length} groups / ${files.length} files`;
      if (files.length === 0) {
        list.appendChild(richEmpty(
          "📥", "Inbox is quiet",
          "Files sent to you from a paired device land here automatically.",
        ));
        return;
      }
      for (const f of grouped) {
        const row = el("div", "file-row");
        row.appendChild(el("div", "icon", fileIcon(f.name)));
        const meta = el("div", "meta");
        const name = el("div", "name", f.display_name || displayFileName(f.name));
        name.title = f.copies > 1
          ? `${f.display_name || f.name} - latest saved as ${f.name}`
          : (f.name || "");
        if (f.copies > 1) {
          const badge = el("span", "badge", `x${f.copies}`);
          badge.title = `${f.copies} duplicate inbox entries are collapsed here`;
          name.appendChild(badge);
        }
        meta.appendChild(name);
        const sizeText = f.copies > 1
          ? `Latest ${fmtBytes(f.size)} · ${f.copies} copies`
          : `${fmtBytes(f.size)}`;
        meta.appendChild(el("div", "size", sizeText));
        if (f.mtime_ms) {
          meta.appendChild(el("div", "when", `Latest ${new Date(f.mtime_ms).toLocaleString()}`));
        }
        row.appendChild(meta);
        const fileActions = el("div", "file-actions");
        const open = el("a", null, "Open");
        open.href = `/api/files/${encodeURIComponent(f.name)}`;
        open.target = "_blank";
        fileActions.appendChild(open);
        const reveal = el("button", null, "Show in folder");
        reveal.title = "Open the inbox in your file manager with this file selected";
        reveal.onclick = async () => {
          const t = toast("Opening folder…", "info", 2500);
          try {
            const res = await api.post(`/api/files/${encodeURIComponent(f.name)}/reveal`, {});
            if (res?.throttled) {
              t?.remove?.();
              toast("Folder is opening - check your taskbar.", "info", 2500);
            }
          } catch (e) {
            t?.remove?.();
            toast(`Show in folder failed: ${e.message || e}`, "bad");
          }
        };
        fileActions.appendChild(reveal);
        row.appendChild(fileActions);
        if (f.copies > 1 && Array.isArray(f.members) && f.members.length) {
          const details = document.createElement("details");
          details.className = "file-group-details";
          details.open = _expandedInboxGroups.has(f.display_name);
          details.ontoggle = () => {
            if (details.open) _expandedInboxGroups.add(f.display_name);
            else _expandedInboxGroups.delete(f.display_name);
          };
          const summary = document.createElement("summary");
          summary.textContent = details.open ? "Hide copies" : `Show all ${f.copies} copies`;
          details.appendChild(summary);
          details.addEventListener("toggle", () => {
            summary.textContent = details.open ? "Hide copies" : `Show all ${f.copies} copies`;
          });
          const dupList = el("div", "duplicate-list");
          for (const m of f.members) {
            const dup = el("div", "duplicate-file");
            const dupName = el("div", "dup-name", m.name || "file");
            dupName.title = m.name || "";
            dup.appendChild(dupName);
            const dupMeta = el("div", "dup-time", m.mtime_ms ? new Date(m.mtime_ms).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "");
            const dupOpen = el("a", "dup-open", "Open");
            const _dupNm = encodeURIComponent(m.name || "");
            dupOpen.href = `/api/files/${_dupNm}`;
            dupOpen.target = "_blank";
            dupMeta.appendChild(document.createTextNode(" "));
            dupMeta.appendChild(dupOpen);
            dup.appendChild(dupMeta);
            dupList.appendChild(dup);
          }
          details.appendChild(dupList);
          row.appendChild(details);
        }
        list.appendChild(row);
      }
    } else {
      // Sent: pull from /api/transfers, direction=out, kind=file.
      const sent = state.transfers
        .filter(t => t.direction === "out" && t.kind === "file")
        .sort((a, b) => (b.updated_ms || 0) - (a.updated_ms || 0));
      $("#files-count").textContent = sent.length;
      if (sent.length === 0) {
        // UX audit P1-4 - rich empty state matching the Received
        // tab's style so the two halves of the Files pane feel
        // consistent. Tells the user how to send their first file.
        const empty = el("div", "empty rich");
        empty.innerHTML = `
          <div class="empty-glyph">📤</div>
          <h3>No sent files yet</h3>
          <p>
            Drag any file onto a device's chat, or hit the paperclip
            in the chat composer. Files you send appear here with
            transfer speed and status.
          </p>`;
        list.appendChild(empty);
        return;
      }
      for (const t of sent) {
        const row = el("div", "file-row");
        row.appendChild(el("div", "icon", fileIcon(t.name)));
        const meta = el("div", "meta");
        const nameLine = el("div", "name", t.name || "file");
        const badge = el("span", `badge ${t.status}`, t.status);
        nameLine.appendChild(badge);
        meta.appendChild(nameLine);
        if (t.status === "active" || t.status === "queued" || t.status === "offered") {
          meta.appendChild(el("div", "size",
            `${fmtBytes(t.progress_bytes)} / ${fmtBytes(t.total_bytes)} · ${Math.round(t.progress_pct || 0)}%`));
          const bar = el("div", "bar");
          const fill = el("span");
          fill.style.width = `${Math.max(0, Math.min(100, t.progress_pct || 0))}%`;
          bar.appendChild(fill);
          meta.appendChild(bar);
        } else {
          meta.appendChild(el("div", "size", fmtBytes(t.size)));
        }
        const summary = renderPrimaryTransferSummary(t);
        if (summary) meta.appendChild(summary);
        const details = renderTransferDetails(t);
        if (details) meta.appendChild(details);
        if (t.updated_ms) meta.appendChild(el("div", "when", new Date(t.updated_ms).toLocaleString()));
        row.appendChild(meta);
        list.appendChild(row);
      }
    }
  }

