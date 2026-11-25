  async function refreshFolderConflictsBanner() {
    try {
      const r = await api.get("/api/folder-conflicts?unresolved=1&limit=200");
      state.folderConflicts.unresolved_total = r.unresolved_total || 0;
      state.folderConflicts.conflicts = r.conflicts || [];
    } catch (e) {
      // 404 means a pre-v0.8.9 daemon - banner stays hidden.
      state.folderConflicts.unresolved_total = 0;
      state.folderConflicts.conflicts = [];
    }
    const banner = $("#folder-conflicts-banner");
    if (!banner) return;
    const n = state.folderConflicts.unresolved_total || 0;
    if (n === 0) {
      banner.style.display = "none";
      banner.innerHTML = "";
      return;
    }
    banner.style.display = "flex";
    banner.innerHTML = "";
    banner.appendChild(el("span", "cb-icon", "⚠"));
    const text = el("div", "cb-text");
    const strong = el("strong", null, `${n} divergent-edit conflict${n === 1 ? "" : "s"}`);
    text.appendChild(strong);
    text.appendChild(document.createTextNode(
      ` - two devices changed the same file at the same time. Click to choose which version wins.`
    ));
    banner.appendChild(text);
    banner.appendChild(el("span", "cb-cta", "Review →"));
    banner.onclick = () => openConflictsModal();
  }

  async function openConflictsModal() {
    $("#conflicts-backdrop").classList.add("show");
    await renderConflictsModal();
  }
  function closeConflictsModal() {
    $("#conflicts-backdrop").classList.remove("show");
  }

  async function renderConflictsModal() {
    let conflicts = [];
    let total = 0;
    try {
      const r = await api.get("/api/folder-conflicts?unresolved=1&limit=200");
      conflicts = r.conflicts || [];
      total = r.unresolved_total || 0;
    } catch (e) {
      // 2026-05-21 audit T3-A: e.message originates from server JSON
      // and was injected raw — a hostile error string could XSS the
      // dashboard. Escape before rendering.
      const reason = _escapeHtml(String(e?.message || e || ""));
      $("#conflicts-list").innerHTML =
        `<div class="empty">Failed to load conflicts: ${reason}</div>`;
      $("#conflicts-sub").textContent = "";
      return;
    }
    $("#conflicts-sub").textContent =
      total > 0 ? `${total} unresolved` : "All clear";
    const list = $("#conflicts-list");
    list.innerHTML = "";
    if (conflicts.length === 0) {
      list.appendChild(el("div", "empty", "No conflicts. ✓"));
      return;
    }
    for (const c of conflicts) {
      list.appendChild(renderConflictRow(c));
    }
  }

  function renderConflictRow(c) {
    const row = el("div", "conflict-row");
    row.dataset.id = c.id;
    const head = el("div", "conflict-h");
    head.appendChild(el("span", "folder", c.folder_name + ":"));
    head.appendChild(document.createTextNode(c.file_path));
    row.appendChild(head);

    const versions = el("div", "versions");
    versions.appendChild(renderConflictVersion(
      "Mine", c, "local", c.applied_choice === "local",
    ));
    versions.appendChild(renderConflictVersion(
      "Theirs", c, "remote", c.applied_choice === "remote",
    ));
    row.appendChild(versions);

    const actions = el("div", "resolve-actions");
    const mine = el("button", null, "Keep mine");
    mine.onclick = () => resolveConflict(c.id, "mine", row);
    const theirs = el("button", null, "Keep theirs");
    theirs.onclick = () => resolveConflict(c.id, "theirs", row);
    const both = el("button", "keep-both", "Keep both");
    both.onclick = () => resolveConflict(c.id, "both", row);
    actions.appendChild(mine);
    actions.appendChild(theirs);
    actions.appendChild(both);
    // v0.21.x Ship 9: Show diff. For text files this expands an
    // inline panel with a coloured line-diff between the two
    // versions, so the user can SEE exactly which lines each side
    // changed before picking. Auto-merge hint when one is a strict
    // extension of the other.
    if (c.local_blob_hash && c.remote_blob_hash) {
      const diffBtn = el("button", "show-diff-btn", "Show diff");
      diffBtn.type = "button";
      diffBtn.title = "Show a line-by-line comparison of the two versions.";
      const diffSlot = el("div", "conflict-diff-slot");
      diffSlot.style.display = "none";
      diffSlot.style.marginTop = "8px";
      diffBtn.onclick = async () => {
        if (diffSlot.style.display !== "none") {
          diffSlot.style.display = "none";
          diffBtn.textContent = "Show diff";
          return;
        }
        diffBtn.textContent = "Loading…";
        diffBtn.disabled = true;
        try {
          const r = await api.get(
            `/api/blobs/${c.local_blob_hash}/diff?against=${c.remote_blob_hash}`,
          );
          diffSlot.replaceChildren();
          // Auto-merge hint banner.
          if (r.auto_merge) {
            const banner = document.createElement("div");
            banner.style.padding = "8px 10px";
            banner.style.borderRadius = "6px";
            banner.style.fontSize = "11px";
            banner.style.marginBottom = "8px";
            if (r.auto_merge.kind === "identical") {
              banner.style.background = "rgba(110,231,183,.15)";
              banner.style.color = "#6ee7b7";
              banner.textContent = "✓ Both versions are identical — safe to Keep mine.";
            } else if (r.auto_merge.kind === "b_extends_a") {
              banner.style.background = "rgba(124,92,255,.15)";
              banner.style.color = "var(--accent)";
              banner.textContent = "💡 Peer's version contains everything yours has plus more. Keep theirs picks up their additions without losing anything.";
            } else if (r.auto_merge.kind === "a_extends_b") {
              banner.style.background = "rgba(124,92,255,.15)";
              banner.style.color = "var(--accent)";
              banner.textContent = "💡 Your version contains everything theirs has plus more. Keep mine picks up your additions without losing anything.";
            }
            diffSlot.appendChild(banner);
          }
          // Summary line.
          const summary = document.createElement("div");
          summary.style.fontSize = "11px";
          summary.style.color = "var(--text-dim)";
          summary.style.marginBottom = "6px";
          summary.textContent = (
            `${r.lines_added} line${r.lines_added === 1 ? "" : "s"} added, `
            + `${r.lines_removed} removed`
            + (r.a_truncated || r.b_truncated ? " (preview truncated)" : "")
          );
          diffSlot.appendChild(summary);
          // Coloured diff: green +lines, red -lines, dim @@ hunks.
          const pre = document.createElement("pre");
          pre.style.background = "var(--bg)";
          pre.style.padding = "8px";
          pre.style.borderRadius = "6px";
          pre.style.fontSize = "11px";
          pre.style.fontFamily = "var(--font-mono, ui-monospace, Menlo, monospace)";
          pre.style.maxHeight = "300px";
          pre.style.overflow = "auto";
          pre.style.whiteSpace = "pre";
          for (const rawLine of (r.unified_diff || "").split("\n")) {
            const span = document.createElement("span");
            span.textContent = rawLine + "\n";
            if (rawLine.startsWith("+") && !rawLine.startsWith("+++")) {
              span.style.color = "#6ee7b7"; // green
              span.style.background = "rgba(110,231,183,.08)";
            } else if (rawLine.startsWith("-") && !rawLine.startsWith("---")) {
              span.style.color = "#f87171"; // red
              span.style.background = "rgba(248,113,113,.08)";
            } else if (rawLine.startsWith("@@")) {
              span.style.color = "var(--accent)";
              span.style.fontWeight = "600";
            } else {
              span.style.color = "var(--text-dim)";
            }
            pre.appendChild(span);
          }
          diffSlot.appendChild(pre);
          diffSlot.style.display = "block";
          diffBtn.textContent = "Hide diff";
        } catch (e) {
          toast(`Diff failed: ${errorToastBody(e)}`, "bad", 5000);
          diffBtn.textContent = "Show diff";
        } finally {
          diffBtn.disabled = false;
        }
      };
      actions.appendChild(diffBtn);
      row.appendChild(actions);
      row.appendChild(diffSlot);
    } else {
      row.appendChild(actions);
    }
    return row;
  }

  function renderConflictVersion(label, c, side, isApplied) {
    const v = el("div", "ver" + (isApplied ? " applied" : ""));
    const h = el("div", "ver-h");
    h.appendChild(document.createTextNode(label));
    if (isApplied) {
      h.appendChild(el("span", "applied-tag", "Auto-applied"));
    }
    v.appendChild(h);
    const blob = c[side + "_blob_hash"] || "(deleted)";
    const size = c[side + "_size"];
    const mtime = c[side + "_mtime_ms"];
    const peer = side === "remote" ? (c.peer_fp || "?") : "this device";
    v.appendChild(makeMetaLine("blob", (blob || "?").slice(0, 16) + "…"));
    v.appendChild(makeMetaLine("size", size != null ? fmtBytes(size) : "-"));
    v.appendChild(makeMetaLine(
      "modified", mtime ? new Date(mtime).toLocaleString() : "-"
    ));
    v.appendChild(makeMetaLine(
      "from", peer === "this device" ? peer : peer.slice(0, 12) + "…"
    ));
    // v0.21.x Ship 3: inline preview button. Lets the user SEE
    // what's actually in each version before picking Keep mine /
    // theirs / both. Text-y files render inline; binary files
    // get a download link via the raw blob endpoint.
    const blobHash = c[side + "_blob_hash"];
    if (blobHash) {
      const previewBtn = el("button", "ver-preview-btn", "Preview");
      previewBtn.type = "button";
      previewBtn.title = (
        side === "local"
          ? "Show what YOUR version of this file contains."
          : "Show what the OTHER device's version contains."
      );
      const previewSlot = el("div", "ver-preview-slot");
      previewSlot.style.display = "none";
      previewBtn.onclick = async () => {
        if (previewSlot.style.display !== "none") {
          previewSlot.style.display = "none";
          previewBtn.textContent = "Preview";
          return;
        }
        previewBtn.textContent = "Loading…";
        previewBtn.disabled = true;
        try {
          const ext = (c.file_path || "").split(".").pop() || "";
          const url = `/api/blobs/${blobHash}/preview` + (ext ? `?as=${encodeURIComponent(ext)}` : "");
          const r = await api.get(url);
          previewSlot.replaceChildren();
          if (r.stream_url && r.kind === "image") {
            const img = document.createElement("img");
            img.src = r.stream_url + (ext ? `&as=${encodeURIComponent(ext)}` : `?as=${encodeURIComponent(ext)}`);
            img.alt = `${side} version`;
            img.style.maxWidth = "100%";
            img.style.maxHeight = "300px";
            previewSlot.appendChild(img);
          } else if (r.content !== undefined) {
            const pre = document.createElement("pre");
            pre.textContent = r.content;
            pre.style.maxHeight = "300px";
            pre.style.overflow = "auto";
            pre.style.fontFamily = "var(--font-mono, ui-monospace, Menlo, monospace)";
            pre.style.fontSize = "11px";
            pre.style.background = "var(--bg)";
            pre.style.padding = "8px";
            pre.style.borderRadius = "4px";
            pre.style.whiteSpace = "pre-wrap";
            pre.style.wordBreak = "break-word";
            previewSlot.appendChild(pre);
            if (r.truncated) {
              const note = document.createElement("div");
              note.style.fontSize = "10px";
              note.style.color = "var(--text-dim)";
              note.style.marginTop = "4px";
              note.textContent = `Showing first ${fmtBytes(r.preview_bytes || 0)} of ${fmtBytes(r.size || 0)}.`;
              previewSlot.appendChild(note);
            }
          } else {
            const note = document.createElement("div");
            note.style.fontSize = "11px";
            note.style.color = "var(--text-dim)";
            note.textContent = "No inline preview for this file type.";
            previewSlot.appendChild(note);
          }
          previewSlot.style.display = "block";
          previewBtn.textContent = "Hide preview";
        } catch (e) {
          toast(`Couldn't load preview: ${errorToastBody(e)}`, "bad", 5000);
          previewBtn.textContent = "Preview";
        } finally {
          previewBtn.disabled = false;
        }
      };
      v.appendChild(previewBtn);
      v.appendChild(previewSlot);
    }
    return v;
  }
  function makeMetaLine(label, val) {
    const line = el("div", "meta-line");
    const lbl = el("span");
    lbl.style.color = "var(--text-dimmer)";
    lbl.textContent = label + ": ";
    line.appendChild(lbl);
    line.appendChild(document.createTextNode(val));
    return line;
  }

  async function resolveConflict(id, choice, row) {
    if (!id) return;
    if (row) row.classList.add("resolving");
    try {
      const res = await api.post(
        `/api/folder-conflicts/${id}/resolve`, { choice },
      );
      if (res.already_resolved) {
        toast("Conflict already resolved.", "info");
      } else if (choice === "both") {
        toast(`Kept both - saved peer's version as ${res.suffixed_path || "*.conflict-…"}`, "good", 6000);
      } else if (choice === "mine") {
        toast("Kept your version.", "good");
      } else {
        toast("Switched to peer's version.", "good");
      }
      await renderConflictsModal();
      await refreshFolderConflictsBanner();
    } catch (e) {
      if (row) row.classList.remove("resolving");
      toast(`Resolve didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

