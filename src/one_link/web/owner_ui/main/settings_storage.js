  async function refreshStorageUsage() {
    const totalsHost = $("#storage-totals");
    const tableHost = $("#storage-table");
    if (!totalsHost || !tableHost) return;
    totalsHost.innerHTML = `<span class="settings-help">Counting your files…</span>`;
    let r;
    try {
      r = await api.get("/api/storage/usage");
    } catch (e) {
      // 2026-05-21 audit T3-A: escape server-controlled errorToastBody.
      totalsHost.innerHTML = `<span class="settings-help">Failed to load: ${_escapeHtml(errorToastBody(e))}</span>`;
      tableHost.innerHTML = "";
      return;
    }
    const totals = r.totals || {};
    totalsHost.innerHTML = "";
    const stat = (n, lbl) => {
      const wrap = el("div", "stat");
      wrap.appendChild(el("div", "stat-num", n));
      wrap.appendChild(el("div", "stat-lbl", lbl));
      return wrap;
    };
    totalsHost.appendChild(stat(String(totals.chat_count || 0), "chats"));
    totalsHost.appendChild(stat(String(totals.msg_count || 0), "messages"));
    totalsHost.appendChild(stat(fmtBytes(totals.file_bytes || 0), "files"));

    tableHost.innerHTML = "";
    const peers = r.peers || [];
    const groups = r.groups || [];
    if (peers.length === 0 && groups.length === 0) {
      tableHost.innerHTML = `<p class="settings-help">No conversations yet.</p>`;
      return;
    }
    const renderRow = (kind, name, msgs, bytes, clearFn) => {
      const row = el("div", `storage-row scope-${kind}`);
      row.appendChild(el("div", "name", name));
      const num = el("div", "stat-num", String(msgs));
      num.appendChild(el("span", "stat-lbl-inline", " msgs"));
      row.appendChild(num);
      const sz = el("div", "stat-num", bytes != null ? fmtBytes(bytes) : "-");
      row.appendChild(sz);
      const btn = el("button", "btn-ghost", "Clear");
      btn.onclick = clearFn;
      row.appendChild(btn);
      tableHost.appendChild(row);
    };
    for (const p of peers) {
      renderRow("peer", p.display_name || p.fingerprint.slice(0, 8),
        p.msg_count, p.file_bytes,
        async () => {
          if (!confirm(
            `Clear local chat history with "${p.display_name}"?\n\n` +
            "Only YOUR copy is deleted."
          )) return;
          try {
            await api.del(`/api/peers/${p.fingerprint}/history`);
            toast("Cleared", "good");
            refreshStorageUsage();
          } catch (e) {
            toast(`Clear didn't work: ${errorToastBody(e)}`, "bad");
          }
        });
    }
    for (const g of groups) {
      renderRow("group", g.name, g.msg_count, null,
        async () => {
          if (!confirm(
            `Clear local chat history for group "${g.name}"?\n\n` +
            "Only YOUR copy is deleted; other members are unaffected."
          )) return;
          try {
            await api.del(`/api/groups/${g.group_id}/history`);
            toast("Cleared", "good");
            refreshStorageUsage();
          } catch (e) {
            toast(`Clear didn't work: ${errorToastBody(e)}`, "bad");
          }
        });
    }
  }

  async function clearTraceScope(scope, label) {
    if (!confirm(
      `Clear ${label} from One Link?\n\n` +
      "This removes local app records only. It will not delete files or folders from your computer."
    )) return;
    try {
      const traceEndpoints = {
        chat: "/api/traces/chat",
        files: "/api/traces/files",
        folders: "/api/traces/folders",
        activity: "/api/traces/activity",
      };
      const endpoint = traceEndpoints[scope];
      if (!endpoint) throw new Error(`unknown trace scope: ${scope}`);
      await api.del(endpoint);
      toast(`${label} cleared`, "good");
      if (scope === "chat") {
        state.messages = [];
        state.groupMessages = [];
        await loadHistory();
      }
      if (scope === "files") {
        state.transfers = [];
        state.transfersById = new Map();
        await refreshFiles();
        await refreshTransfers();
      }
      if (scope === "folders") {
        await refreshFolders();
      }
      if (scope === "activity") {
        state.activityEvents = [];
        await refreshActivityFeed();
        await refreshTransfers();
      }
      refreshStorageUsage();
    } catch (e) {
      toast(`Clear didn't work: ${errorToastBody(e)}`, "bad", 8000);
    }
  }

  async function wipeLocalAppTraces() {
    const typed = prompt(
      "This clears One Link's local app traces: chats, file-transfer records, folder metadata, activity/audit rows, route memory, and local UI trace settings.\n\n" +
      "It will NOT delete files or folders from your computer, and it will NOT revoke your identity or paired devices.\n\n" +
      "Type: wipe local traces"
    );
    if (typed == null) return;
    try {
      await api.post("/api/traces/wipe", { confirm: typed });
      toast("Local app traces wiped", "good", 5000);
      state.messages = [];
      state.groupMessages = [];
      state.transfers = [];
      state.transfersById = new Map();
      state.activityEvents = [];
      await Promise.allSettled([
        loadHistory(),
        refreshFiles(),
        refreshFolders(),
        refreshActivityFeed(),
        refreshTransfers(),
        refreshStorageUsage(),
      ]);
    } catch (e) {
      toast(`Wipe didn't work: ${errorToastBody(e)}`, "bad", 9000);
    }
  }

  $("#storage-refresh")?.addEventListener("click", refreshStorageUsage);
  $("#storage-clear-chat")?.addEventListener("click", () => clearTraceScope("chat", "chat traces"));
  $("#storage-clear-files")?.addEventListener("click", () => clearTraceScope("files", "file traces"));
  $("#storage-clear-folders")?.addEventListener("click", () => clearTraceScope("folders", "folder traces"));
  $("#storage-clear-activity")?.addEventListener("click", () => clearTraceScope("activity", "activity traces"));
  $("#storage-wipe-local")?.addEventListener("click", wipeLocalAppTraces);

  // v0.11.1 Profile helpers - avatar preview + bio counter + color
  // swatches. Local DOM only; persistence is via /api/settings.
  function _initialsFor(name) {
    if (!name) return "?";
    const parts = name.trim().split(/\s+/).filter(Boolean);
    if (parts.length === 0) return "?";
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }
  function _refreshProfileAvatarPreview() {
    const preview = $("#profile-avatar-preview");
    if (!preview) return;
    const nameInput = $("#set-name");
    const name = (nameInput?.value || "").trim() ||
                 (state.me?.display_name || state.me?.hostname || "");
    preview.textContent = _initialsFor(name);
    const active = $(".profile-color-swatch.active");
    if (active) preview.style.background = active.dataset.color;
  }
  function _renderColorSwatches(presets, current) {
    const host = $("#profile-color-swatches");
    if (!host) return;
    host.innerHTML = "";
    for (const c of presets) {
      const sw = document.createElement("button");
      sw.className = "profile-color-swatch" + (c === current ? " active" : "");
      sw.style.background = c;
      sw.dataset.color = c;
      sw.title = c;
      sw.setAttribute("aria-label", `Avatar color ${c}`);
      sw.onclick = (ev) => {
        ev.preventDefault();
        host.querySelectorAll(".profile-color-swatch").forEach(
          (b) => b.classList.toggle("active", b === sw),
        );
        _refreshProfileAvatarPreview();
        // Live-apply to my own avatar everywhere it's rendered.
        applyMyAvatarColor(c);
      };
      host.appendChild(sw);
    }
  }
  function _renderBioCounter() {
    const bio = $("#set-bio");
    const counter = $("#set-bio-counter");
    if (!bio || !counter) return;
    counter.textContent = `${bio.value.length} / 140`;
  }
  // Live update preview on name/bio edits.
  $("#set-name")?.addEventListener("input", _refreshProfileAvatarPreview);
  $("#set-bio")?.addEventListener("input", _renderBioCounter);

  // v0.11.1 - apply chosen avatar color to the user's own avatar
  // tiles across the UI. Cheap CSS variable propagation; no DOM
  // re-render needed.
  function applyMyAvatarColor(hex) {
    document.documentElement.style.setProperty("--my-avatar", hex);
  }

  // v0.11.2 mute-status text. Renders into a target node:
  //   "Muted forever"     when muted_until_ms === 0
  //   "Muted until …"     when muted_until_ms > now
  //   "" (cleared)        when not muted
  // Falls back to the legacy boolean if muted_until_ms is null but
  // legacyMuted is true (v0.7.3-era state).
  function _renderMuteStatus(target, mutedUntilMs, legacyMuted) {
    if (!target) return;
    const now = Date.now();
    if (mutedUntilMs == null) {
      target.textContent = legacyMuted ? "Muted (legacy toggle)." : "";
      return;
    }
    if (mutedUntilMs === 0) {
      target.textContent = "Muted until you unmute.";
      return;
    }
    if (mutedUntilMs <= now) {
      target.textContent = "Mute expired.";
      return;
    }
    const d = new Date(mutedUntilMs);
    target.textContent = `Muted until ${d.toLocaleString()}`;
  }

  // v0.11.1 - render blocked devices in Privacy pane. Uses the
  // existing /api/peers endpoint with ?include=rejected so we don't
  // need a new backend route.
