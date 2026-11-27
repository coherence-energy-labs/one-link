  async function refreshFolders() {
    try {
      const { folders } = await api.folders();
      state.folders = folders || [];
      // v0.8.9: refresh the conflicts banner whenever the folders
      // pane refreshes - they're tightly coupled.
      refreshFolderConflictsBanner();
      const list = $("#folderlist");
      list.innerHTML = "";
      $("#folders-count").textContent = state.folders.length;
      // v0.21.x: hide the secondary actions (Clear traces + Refresh)
      // when there's nothing to act on. Keeps the empty state focused
      // on the single primary path: fill in the form, click Add.
      const clearBtn = document.getElementById("btn-clear-folder-traces");
      const refreshBtn = document.getElementById("btn-refresh-folders");
      const isEmpty = state.folders.length === 0;
      if (clearBtn) clearBtn.style.display = isEmpty ? "none" : "";
      if (refreshBtn) refreshBtn.style.display = isEmpty ? "none" : "";

      if (isEmpty) {
        list.appendChild(richEmpty(
          "📂", "No folders synced yet",
          "A synced folder updates both ways. Name it, pick where it lives on this computer, then click Add in the form just below.",
        ));
        return;
      }
      for (const f of state.folders) {
        const row = el("div", "file-row");
        row.appendChild(el("div", "icon", "📁"));
        // v0.21.x: icon + content layout. content stacks meta + actions
        // vertically, giving each row the full panel width instead of
        // squeezing them into competing flex slots.
        const content = el("div", "content");
        const meta = el("div", "meta");
        // v0.21.x: folder name opens the INLINE file browser modal;
        // path opens the OS file manager. Two distinct affordances:
        // browse files inside One Link (most users want) vs leave
        // the app for OS-native context (power users).
        const openInExplorer = async () => {
          try {
            await api.post(
              `/api/folders/${encodeURIComponent(f.name)}/reveal`, {},
            );
          } catch (e) {
            // v0.21.x: when the folder's local_path is missing on
            // disk (renamed user account / deleted directory /
            // synced from a different machine) the daemon returns
            // a 404 with "folder no longer exists on disk". Surface
            // a concrete actionable message rather than a generic
            // "couldn't open" so the user knows the path itself is
            // the problem and can re-locate via Settings.
            const status = e && e.status;
            const body = errorToastBody(e) || "";
            if (status === 404 && /no longer exists on disk/i.test(body)) {
              toast(
                `Folder location missing on this device: ${f.local_path}. `
                + "Re-locate it in Settings → folder path.",
                "bad", 9000,
              );
            } else {
              toast(`Couldn't open folder: ${body || e}`, "bad", 6000);
            }
          }
        };
        const openInline = () => openFolderBrowser(f.name);
        const nameEl = el("div", "name folder-name-clickable", f.name);
        nameEl.title = (
            `Browse the files inside ${f.name} without leaving One Link. `
            + "(Use the Open button to launch your OS file manager.)"
        );
        nameEl.style.cursor = "pointer";
        nameEl.onclick = openInline;
        meta.appendChild(nameEl);
        meta.appendChild(el("div", "size", `${f.files || 0} files · ${f.in_store || 0} local blobs · ${f.shared_with?.length || 0} peers`));
        // v0.21.x Wave 6 UI render: if any peer in shared_with is
        // currently streaming us blobs (folder_recv_blob_done event
        // landed in the last 15s), show a live "Receiving N blobs"
        // line right under the meta. Stale events (>15s) drop off.
        const progressMap = state.folderRecvProgress || {};
        const liveRecv = (f.shared_with || []).map(fp =>
          progressMap[String(fp).slice(0, 16)]
        ).filter(p => p && (Date.now() - (p.lastSeen || 0)) < 15000);
        if (liveRecv.length > 0) {
          const totalBlobs = liveRecv.reduce((s, p) => s + (p.blobsDone || 0), 0);
          const totalBytes = liveRecv.reduce((s, p) => s + (p.bytesDone || 0), 0);
          const remaining = liveRecv.reduce((s, p) => s + (p.remaining || 0), 0);
          const recvEl = el(
              "div", "folder-recv-progress",
              `Receiving · ${totalBlobs} blob${totalBlobs === 1 ? "" : "s"} in `
              + `(${_humanBytes(totalBytes)})`
              + (remaining > 0 ? ` · ${remaining} to go` : ""),
          );
          meta.appendChild(recvEl);
        }
        // Middle-truncate the path: keep the start (C:\Users\...) and
        // the meaningful end (the actual folder name) visible, elide
        // the middle. Full path in the tooltip so nothing is hidden
        // permanently. Clicking the path also opens in Explorer.
        const pathEl = el("div", "size folder-path", _middleTruncatePath(f.local_path, 44));
        pathEl.title = `${f.local_path}\n\nClick to open in your file manager.`;
        pathEl.onclick = openInExplorer;
        meta.appendChild(pathEl);
        content.appendChild(meta);
        row.appendChild(content);
        const actions = el("div", "file-actions");
        // v0.21.x: explicit Open button so the click-to-open
        // affordance is discoverable even without hovering. Sits
        // BEFORE Share/Sync/Remove so the most common action
        // (look at the files) is the leftmost option.
        const openBtn = el("button", null, "Open");
        openBtn.title = (
            "Open this folder in your computer's file manager. "
            + "Lets you SEE and EDIT the synced files. Edits get "
            + "picked up automatically by the watcher and synced "
            + "back to every paired device."
        );
        openBtn.setAttribute("aria-label", `Open ${f.name} folder in file manager`);
        openBtn.onclick = openInExplorer;
        actions.appendChild(openBtn);
        const share = el("button", null, "Share");
        // v0.21.x: native hover tooltips so users know what each
        // button does without having to be told. Same pattern for
        // every action button on this row.
        share.title = (
            "Start a LIVE two-way sync of this folder with the "
            + "selected device. Future edits on either side propagate "
            + "to the other. (Pick a peer in the sidebar first.) "
            + "For a one-shot copy with NO sync, use Send instead."
        );
        share.setAttribute("aria-label", "Live-sync folder with selected peer");
        share.onclick = async () => {
          const peer = state.selectedPeer ? state.peers.get(state.selectedPeer) : null;
          if (!peer?.fingerprint || peer.trust !== "pinned") {
            toast("Pick a paired peer first", "info");
            return;
          }
          try {
            await api.post(`/api/folders/${encodeURIComponent(f.name)}/share`, { peer_fp: peer.fingerprint });
            toast("Folder shared", "good");
            await refreshFolders();
          } catch (e) {
            toast(`Share didn't work: ${e.message || e}`, "bad", 6000);
          }
        };
        // v0.21.x: one-shot Send. Mirrors a file send — the recipient
        // gets the folder contents in their inbox with the directory
        // tree preserved, and there's NO ongoing sync. Sits next to
        // Share so users see both options together and the tooltips
        // make the distinction explicit.
        const send = el("button", null, "Send");
        send.title = (
            "Send a ONE-SHOT copy of this folder to the selected "
            + "device. Recipient gets the folder tree in their inbox; "
            + "there is NO ongoing sync. (Pick a peer in the sidebar "
            + "first.) For a live two-way sync, use Share instead."
        );
        send.setAttribute("aria-label", "Send one-shot folder copy");
        send.onclick = () => {
          const peer = state.selectedPeer ? state.peers.get(state.selectedPeer) : null;
          if (!peer?.fingerprint || peer.trust !== "pinned") {
            toast("Pick a paired peer first", "info");
            return;
          }
          // v0.21.x: open the confirmation modal with pre-flight
          // dedup info instead of firing immediately. Bytes don't
          // move until the user clicks Send in the modal.
          openFolderSendConfirm({
            scope: "folder", ident: f.name,
            peerFp: peer.fingerprint,
            peerHostname: peer.hostname || peer.short_id,
            displayName: f.name, displayPath: f.local_path,
          });
        };
        const sync = el("button", null, "Sync");
        sync.title = (
            "Push this folder's current contents to every paired device "
            + "you've already shared it with. Useful right after edits; "
            + "the daemon also syncs in the background on its own."
        );
        sync.setAttribute("aria-label", "Push folder contents now");
        sync.onclick = async () => {
          try {
            const r = await api.post(`/api/folders/${encodeURIComponent(f.name)}/sync`, {});
            const pushed = (r.results || []).filter(x => x.status === "pushed").length;
            toast(`Folder sync queued for ${pushed} peer${pushed === 1 ? "" : "s"}`, "good");
            await refreshFolders();
          } catch (e) {
            toast(`Folder sync failed: ${e.message || e}`, "bad", 6000);
          }
        };
        const remove = el("button", null, "Remove");
        remove.title = (
            "Stop tracking this folder. Your files on disk are NOT "
            + "deleted; only the One Link sync record goes away."
        );
        remove.setAttribute("aria-label", "Stop tracking this folder");
        remove.onclick = async () => {
          try {
            await api.del(`/api/folders/${encodeURIComponent(f.name)}`);
            toast("Folder removed", "good");
            await refreshFolders();
          } catch (e) {
            toast(`Remove didn't work: ${e.message || e}`, "bad", 6000);
          }
        };
        // v0.21.x Ship 4: per-folder settings (ignored patterns,
        // max file size, conflict policy). Sits between Sync and
        // Remove because it's tuning, not a primary action.
        const settings = el("button", null, "Settings");
        settings.title = (
          "Sync settings: which subfolders / files to skip "
          + "(selective sync), max file size, and how to break "
          + "concurrent-edit ties."
        );
        settings.setAttribute("aria-label", `Sync settings for ${f.name}`);
        settings.onclick = () => openFolderSettings(f);
        actions.appendChild(share);
        actions.appendChild(send);
        actions.appendChild(sync);
        actions.appendChild(settings);
        actions.appendChild(remove);
        // v0.21.x: actions live INSIDE .content (stacked below the
        // meta) instead of in a third grid column. Gives the meta
        // and the buttons the full row width respectively.
        content.appendChild(actions);
        list.appendChild(row);
      }
    } catch (e) { console.warn(e); }
  }

  // v0.21.x folder-share ceremony: incoming offers from paired peers
  // that want to share a folder we haven't accepted yet.
  state.folderOffers = [];

  function _humanBytes(n) {
    const x = Number(n) || 0;
    if (x < 1024) return `${x} B`;
    if (x < 1024 ** 2) return `${(x / 1024).toFixed(1)} KB`;
    if (x < 1024 ** 3) return `${(x / 1024 ** 2).toFixed(1)} MB`;
    return `${(x / 1024 ** 3).toFixed(2)} GB`;
  }

  function _defaultLocalPathForOffer(folderName) {
    // Suggest <suggested_folder>/<folder_name> where suggested_folder
    // is already pulled by /api/me (e.g. C:\Users\you\Documents\One Link).
    const base = state.me?.suggested_folder || "";
    if (!base) return folderName || "";
    const sep = base.includes("\\") ? "\\" : "/";
    return base + sep + (folderName || "");
  }

  function _renderFolderOffer(o) {
    const card = el("div", "folder-offer-card");
    const fromName = o.peer_hostname || o.peer_short_id || (o.peer_fp || "").slice(0, 12);
    const fromEl = el("div", "offer-from", `From ${fromName} wants to share`);
    card.appendChild(fromEl);
    const nameEl = el("div", "offer-name", o.folder_name);
    nameEl.title = o.folder_name;
    card.appendChild(nameEl);
    card.appendChild(el(
      "div", "offer-meta",
      `${o.entry_count || 0} file${o.entry_count === 1 ? "" : "s"} · ${_humanBytes(o.total_bytes)}`,
    ));
    // v0.21.x: collapsible file-list preview. Shows the user what's
    // actually IN the folder before they click Accept. Entries are
    // already in the offer (sender shipped them in MANIFEST_PUSH);
    // we just render them on demand. Hidden by default to keep the
    // card compact.
    const entries = Array.isArray(o.entries) ? o.entries : [];
    if (entries.length > 0) {
      const previewToggle = document.createElement("a");
      previewToggle.href = "#";
      previewToggle.className = "offer-preview-toggle";
      previewToggle.textContent = `▸ Preview file list (${entries.length})`;
      const previewBody = document.createElement("div");
      previewBody.className = "offer-preview-body";
      previewBody.style.display = "none";
      // Show up to 200 entries; rest are summarized.
      const SHOW_LIMIT = 200;
      const shown = entries.slice(0, SHOW_LIMIT);
      const overflow = entries.length - shown.length;
      const ul = document.createElement("ul");
      for (const e of shown) {
        const li = document.createElement("li");
        const sz = _humanBytes(e.size || 0);
        const path = String(e.file_path || e.path || "?");
        li.title = path;
        li.textContent = `${path} · ${sz}`;
        ul.appendChild(li);
      }
      previewBody.appendChild(ul);
      if (overflow > 0) {
        const more = document.createElement("div");
        more.className = "offer-preview-overflow";
        more.textContent = `…and ${overflow} more`;
        previewBody.appendChild(more);
      }
      previewToggle.onclick = (ev) => {
        ev.preventDefault();
        const open = previewBody.style.display !== "none";
        previewBody.style.display = open ? "none" : "block";
        previewToggle.textContent = (
          (open ? "▸" : "▾") + ` Preview file list (${entries.length})`
        );
      };
      card.appendChild(previewToggle);
      card.appendChild(previewBody);
    }
    // Path picker row.
    const pathRow = el("div", "offer-path-row");
    const pathInput = document.createElement("input");
    pathInput.type = "text";
    pathInput.value = _defaultLocalPathForOffer(o.folder_name);
    pathInput.setAttribute("aria-label", "Where to save this folder on your computer");
    pathInput.title = "Where this folder will live on your computer. You can edit it before clicking Accept.";
    pathRow.appendChild(pathInput);
    const browseBtn = document.createElement("button");
    browseBtn.type = "button";
    browseBtn.textContent = "Browse…";
    browseBtn.title = "Pick the parent folder via the OS folder picker.";
    browseBtn.onclick = async () => {
      try {
        const r = await api.post("/api/fs/pick-folder", {});
        if (r && r.path) {
          const sep = r.path.includes("\\") ? "\\" : "/";
          pathInput.value = r.path + sep + o.folder_name;
        }
      } catch (_e) { /* user cancelled or picker unavailable */ }
    };
    pathRow.appendChild(browseBtn);
    card.appendChild(pathRow);
    // Accept / Decline row.
    const actions = el("div", "offer-actions");
    const acceptBtn = document.createElement("button");
    acceptBtn.type = "button";
    acceptBtn.className = "btn-accept";
    acceptBtn.textContent = "Accept";
    acceptBtn.title = "Create the folder at the path above + start receiving the files.";
    acceptBtn.onclick = async () => {
      const local_path = (pathInput.value || "").trim();
      if (!local_path) {
        toast("Pick where to save the folder first", "info", 4000);
        return;
      }
      acceptBtn.disabled = true;
      acceptBtn.textContent = "Accepting…";
      try {
        const r = await api.post(
          `/api/folder-offers/${o.id}/accept`, { local_path },
        );
        // v0.21.x: if the user-chosen path wasn't writable, the
        // daemon auto-fell-back to a working location. Surface that
        // in the toast so the user knows WHERE the folder actually
        // landed instead of looking for it at their typed path.
        if (r && r.used_fallback_path) {
          toast(
            `Accepted "${o.folder_name}". Saved to ${r.local_path} `
              + `(your path wasn't writable).`,
            "good", 7000,
          );
        } else {
          toast(
            `Accepted "${o.folder_name}". Files will arrive shortly.`,
            "good", 4500,
          );
        }
        await refreshFolderOffers();
        await refreshFolders();
      } catch (e) {
        acceptBtn.disabled = false;
        acceptBtn.textContent = "Accept";
        toast(`Couldn't accept: ${errorToastBody(e)}`, "bad", 7000);
      }
    };
    const declineBtn = document.createElement("button");
    declineBtn.type = "button";
    declineBtn.className = "btn-decline";
    declineBtn.textContent = "Decline";
    declineBtn.title = "Reject this folder offer. The other device won't sync files for it.";
    declineBtn.onclick = async () => {
      declineBtn.disabled = true;
      try {
        await api.post(`/api/folder-offers/${o.id}/decline`, {});
        toast(`Declined "${o.folder_name}".`, "info", 3500);
        await refreshFolderOffers();
      } catch (e) {
        declineBtn.disabled = false;
        toast(`Couldn't decline: ${errorToastBody(e)}`, "bad", 6000);
      }
    };
    actions.appendChild(acceptBtn);
    actions.appendChild(declineBtn);
    card.appendChild(actions);
    return card;
  }

  async function refreshFolderOffers() {
    try {
      const r = await api.get("/api/folder-offers");
      state.folderOffers = r.offers || [];
    } catch (_e) {
      state.folderOffers = [];
    }
    const section = $("#folder-offers-section");
    const list = $("#folder-offers-list");
    const count = $("#folder-offers-count");
    if (!section || !list || !count) return;
    list.replaceChildren();
    if (state.folderOffers.length === 0) {
      section.style.display = "none";
      count.textContent = "0";
      return;
    }
    section.style.display = "";
    count.textContent = String(state.folderOffers.length);
    for (const o of state.folderOffers) {
      list.appendChild(_renderFolderOffer(o));
    }
  }

  // v0.21.x folder file browser. Modal that shows the file tree
  // inside a synced folder, with per-file sync status, click-to-
  // preview for text/image/audio/video/pdf, and per-file actions
  // (show in file manager, download). Foundation for the per-file
  // status, version-history, and selective-sync features that
  // hang off the same UI.
  state.folderBrowser = {
    folderName: null,
    entries: [],
    conflicts: {},     // rel_path -> true if has unresolved conflict
    transfers: {},     // rel_path -> "uploading" | "downloading"
    filter: "",
    selectedPath: null,
  };

  function _fileGlyphForName(name) {
    const ext = (name.split(".").pop() || "").toLowerCase();
    if (["png","jpg","jpeg","gif","webp","bmp","svg"].includes(ext)) return "🖼";
    if (["mp4","mov","mkv","webm","avi"].includes(ext)) return "🎬";
    if (["mp3","wav","flac","ogg","m4a"].includes(ext)) return "🎵";
    if (["pdf"].includes(ext)) return "📄";
    if (["zip","tar","gz","7z","rar"].includes(ext)) return "🗜";
    if (["doc","docx","odt","rtf"].includes(ext)) return "📝";
    if (["xls","xlsx","ods","csv"].includes(ext)) return "📊";
    if (["md","txt","log","json","yml","yaml","toml","ini","conf","cfg"].includes(ext)) return "📝";
    if (["py","js","ts","go","rs","c","h","cpp","java","sh","ps1","html","css"].includes(ext)) return "🧩";
    return "📎";
  }

  function _statusForEntry(e) {
    // ⚠ conflict overrides everything else.
    if (state.folderBrowser.conflicts[e.path]) {
      return { glyph: "⚠", cls: "conflict", title: "Conflict: both devices changed this file. Open the Conflicts banner to resolve." };
    }
    const transfer = state.folderBrowser.transfers[e.path];
    if (transfer === "uploading") {
      return { glyph: "↑", cls: "uploading", title: "Uploading to a paired device right now." };
    }
    if (transfer === "downloading") {
      return { glyph: "↓", cls: "downloading", title: "Downloading from a paired device right now." };
    }
    // Manifest entry: do we have the local blob?
    if (e.blob_hash && e.local) {
      return { glyph: "✓", cls: "synced", title: "Synced. Local copy matches what every paired device has." };
    }
    if (e.blob_hash && !e.local) {
      return { glyph: "☁", cls: "cloud", title: "On a paired device but not yet on this one. Sync to pull it." };
    }
    if (!e.blob_hash) {
      return { glyph: "•", cls: "missing", title: "On disk but not yet indexed. Will be picked up by the next scan." };
    }
    return { glyph: "?", cls: "", title: "Unknown status." };
  }

  function _renderFolderFileRow(e) {
    const row = document.createElement("div");
    row.className = "folder-file-row";
    row.dataset.path = e.path;
    if (state.folderBrowser.selectedPath === e.path) {
      row.classList.add("selected");
    }
    const icon = document.createElement("span");
    icon.className = "ff-icon";
    icon.textContent = _fileGlyphForName(e.path);
    row.appendChild(icon);
    const stat = _statusForEntry(e);
    const sEl = document.createElement("span");
    sEl.className = `ff-status ${stat.cls}`;
    sEl.textContent = stat.glyph;
    sEl.title = stat.title;
    row.appendChild(sEl);
    const nameEl = document.createElement("span");
    nameEl.className = "ff-name";
    nameEl.textContent = e.path;
    nameEl.title = e.path;
    row.appendChild(nameEl);
    const metaEl = document.createElement("span");
    metaEl.className = "ff-meta";
    metaEl.textContent = `${_humanBytes(e.size)} · ${_humanAgo(e.mtime_ms)}`;
    row.appendChild(metaEl);
    row.onclick = () => _previewFolderFile(state.folderBrowser.folderName, e);
    return row;
  }

  function _humanAgo(ms) {
    if (!ms) return "?";
    const delta = Date.now() - Number(ms);
    if (delta < 60_000) return "just now";
    if (delta < 3_600_000) return `${Math.round(delta / 60_000)}m ago`;
    if (delta < 86_400_000) return `${Math.round(delta / 3_600_000)}h ago`;
    return `${Math.round(delta / 86_400_000)}d ago`;
  }

  async function openFolderBrowser(folderName) {
    const folder = (state.folders || []).find((x) => x.name === folderName);
    if (!folder) {
      toast("That folder isn't in the list anymore.", "info", 3500);
      return;
    }
    state.folderBrowser.folderName = folderName;
    state.folderBrowser.filter = "";
    state.folderBrowser.selectedPath = null;
    state.folderBrowser.transfers = {};
    $("#folder-browser-title").textContent = folder.name;
    const pathEl = $("#folder-browser-path");
    pathEl.textContent = folder.local_path;
    pathEl.title = `${folder.local_path}\n\nClick to open in your file manager.`;
    pathEl.onclick = async () => {
      try {
        await api.post(`/api/folders/${encodeURIComponent(folderName)}/reveal`, {});
      } catch (e) {
        toast(`Couldn't open folder: ${errorToastBody(e)}`, "bad", 5000);
      }
    };
    $("#folder-browser-meta").textContent = "Loading…";
    const searchEl = $("#folder-browser-search");
    searchEl.value = "";
    searchEl.oninput = () => {
      state.folderBrowser.filter = (searchEl.value || "").toLowerCase();
      _renderFolderBrowserList();
    };
    const previewEl = $("#folder-browser-preview");
    previewEl.replaceChildren();
    const empty = document.createElement("div");
    empty.className = "folder-browser-preview-empty";
    empty.textContent = "Pick a file to preview it here.";
    previewEl.appendChild(empty);
    $("#folder-browser-backdrop").classList.add("show");
    document.body.classList.add("modal-open");
    // Wire toolbar handlers (idempotent — replace onclick each open).
    $("#folder-browser-open-explorer").onclick = async () => {
      try {
        await api.post(`/api/folders/${encodeURIComponent(folderName)}/reveal`, {});
      } catch (e) {
        toast(`Couldn't open folder: ${errorToastBody(e)}`, "bad", 5000);
      }
    };
    $("#folder-browser-sync").onclick = async () => {
      try {
        const r = await api.post(`/api/folders/${encodeURIComponent(folderName)}/sync`, {});
        const pushed = (r.results || []).filter((x) => x.status === "pushed").length;
        toast(`Sync queued for ${pushed} device${pushed === 1 ? "" : "s"}`, "good", 4000);
      } catch (e) {
        toast(`Sync failed: ${errorToastBody(e)}`, "bad", 6000);
      }
    };
    $("#folder-browser-close").onclick = closeFolderBrowser;
    // Load tree + conflicts in parallel.
    await Promise.all([
      _loadFolderBrowserTree(folderName),
      _loadFolderBrowserConflicts(folderName),
      _loadFolderBrowserTransfers(folderName),
    ]);
    _renderFolderBrowserList();
  }

  function closeFolderBrowser() {
    $("#folder-browser-backdrop").classList.remove("show");
    document.body.classList.remove("modal-open");
    state.folderBrowser.folderName = null;
  }

  async function _loadFolderBrowserTree(folderName) {
    try {
      const r = await api.get(`/api/folders/${encodeURIComponent(folderName)}/tree`);
      state.folderBrowser.entries = r.entries || [];
      $("#folder-browser-meta").textContent =
        `${r.total_entries || 0} files · ${_humanBytes(r.total_bytes || 0)}`;
    } catch (e) {
      state.folderBrowser.entries = [];
      $("#folder-browser-meta").textContent = "—";
      toast(`Couldn't read folder tree: ${errorToastBody(e)}`, "bad", 5000);
    }
  }

  async function _loadFolderBrowserConflicts(folderName) {
    try {
      const r = await api.get(`/api/folder-conflicts?unresolved=1&limit=500`);
      const map = {};
      for (const c of r.conflicts || []) {
        if (c.folder_name === folderName && c.file_path) {
          map[c.file_path] = true;
        }
      }
      state.folderBrowser.conflicts = map;
    } catch (_e) {
      state.folderBrowser.conflicts = {};
    }
  }

  async function _loadFolderBrowserTransfers(folderName) {
    // Map in-flight folder transfers to per-file status. Folder
    // transfers are tracked as kind=folder; per-file is approximated
    // by the wanted_blobs metadata.
    try {
      const r = await api.transfers();
      const map = {};
      const transfers = r.transfers || r || [];
      for (const t of transfers) {
        if (t.kind !== "folder") continue;
        if ((t.name || t.metadata?.folder) !== folderName) continue;
        if (t.status !== "active" && t.status !== "queued") continue;
        // No per-file granularity here yet; mark all currently-cloud
        // files as downloading if direction=in, uploading if =out.
        for (const e of state.folderBrowser.entries) {
          if (e.blob_hash && !e.local && t.direction === "in") {
            map[e.path] = "downloading";
          }
          if (e.blob_hash && e.local && t.direction === "out") {
            map[e.path] = "uploading";
          }
        }
      }
      state.folderBrowser.transfers = map;
    } catch (_e) {
      state.folderBrowser.transfers = {};
    }
  }

  function _renderFolderBrowserList() {
    const list = $("#folder-browser-list");
    list.replaceChildren();
    const filter = state.folderBrowser.filter;
    const matches = (state.folderBrowser.entries || []).filter((e) => {
      if (!filter) return true;
      return (e.path || "").toLowerCase().includes(filter);
    });
    if (matches.length === 0) {
      const em = document.createElement("div");
      em.className = "empty";
      em.textContent = filter
        ? "No files match your filter."
        : "This folder is empty. Drop files into it on disk and they'll appear here.";
      list.appendChild(em);
      return;
    }
    for (const e of matches) {
      list.appendChild(_renderFolderFileRow(e));
    }
  }

  async function _previewFolderFile(folderName, entry) {
    state.folderBrowser.selectedPath = entry.path;
    _renderFolderBrowserList();
    const previewEl = $("#folder-browser-preview");
    previewEl.replaceChildren();
    const head = document.createElement("div");
    head.className = "preview-head";
    const nameEl = document.createElement("div");
    nameEl.className = "preview-name";
    nameEl.textContent = entry.path;
    nameEl.title = entry.path;
    head.appendChild(nameEl);
    const actions = document.createElement("div");
    actions.className = "preview-actions";
    // v0.21.x Ship 3: if this file has an unresolved conflict, the
    // single most useful action is to OPEN the resolver right
    // here. Surface it as the leading primary action.
    if (state.folderBrowser.conflicts[entry.path]) {
      const resolveBtn = document.createElement("button");
      resolveBtn.type = "button";
      resolveBtn.textContent = "Resolve conflict…";
      resolveBtn.title = (
        "This file was changed on both devices at the same time. "
        + "Open the conflict resolver to see both versions and pick."
      );
      resolveBtn.style.background = "#fbbf24";
      resolveBtn.style.color = "#0a0a0a";
      resolveBtn.onclick = () => {
        closeFolderBrowser();
        $("#conflicts-backdrop").classList.add("show");
        renderConflictsModal();
      };
      actions.appendChild(resolveBtn);
    }
    const showBtn = document.createElement("button");
    showBtn.type = "button";
    showBtn.textContent = "Show in folder";
    showBtn.title = "Highlight this file in your OS file manager.";
    showBtn.onclick = async () => {
      try {
        await api.post(
          `/api/folders/${encodeURIComponent(folderName)}/file/${encodeURIComponent(entry.path)}/reveal`, {},
        );
      } catch (err) {
        toast(`Couldn't reveal: ${errorToastBody(err)}`, "bad", 5000);
      }
    };
    actions.appendChild(showBtn);
    const dlBtn = document.createElement("button");
    dlBtn.type = "button";
    dlBtn.textContent = "Download a copy";
    dlBtn.title = "Save a copy of this file outside the synced folder.";
    dlBtn.onclick = () => {
      const u = `/api/folders/${encodeURIComponent(folderName)}/file/${encodeURIComponent(entry.path)}/raw`;
      const a = document.createElement("a");
      a.href = u;
      a.download = entry.path.split(/[\\/]/).pop() || "file";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    };
    actions.appendChild(dlBtn);
    // v0.21.x Ship 5: per-file version history. Opens an inline
    // list of past blob hashes recorded in the audit log; each
    // historical version can be previewed or restored in place.
    const histBtn = document.createElement("button");
    histBtn.type = "button";
    histBtn.textContent = "History";
    histBtn.title = "Previous versions of this file recorded in the audit log.";
    histBtn.onclick = () => _showFolderFileHistory(folderName, entry);
    actions.appendChild(histBtn);
    head.appendChild(actions);
    previewEl.appendChild(head);
    const body = document.createElement("div");
    body.className = "preview-body";
    previewEl.appendChild(body);
    body.textContent = "Loading…";
    try {
      const r = await api.get(
        `/api/folders/${encodeURIComponent(folderName)}/file/${encodeURIComponent(entry.path)}/preview`,
      );
      body.replaceChildren();
      if (r.previewable === false) {
        const ne = document.createElement("div");
        ne.className = "folder-browser-preview-empty";
        ne.textContent = `Preview not supported for .${r.extension || "?"} files. Use Download a copy to fetch it.`;
        body.appendChild(ne);
        return;
      }
      if (r.stream_url) {
        // Image / video / audio / pdf / html-sandboxed
        if (r.kind === "image") {
          const img = document.createElement("img");
          img.src = r.stream_url;
          img.alt = entry.path;
          body.appendChild(img);
        } else if (r.kind === "video") {
          const v = document.createElement("video");
          v.src = r.stream_url;
          v.controls = true;
          body.appendChild(v);
        } else if (r.kind === "audio") {
          const a = document.createElement("audio");
          a.src = r.stream_url;
          a.controls = true;
          body.appendChild(a);
        } else if (r.kind === "pdf" || r.kind === "html-sandboxed") {
          const f = document.createElement("iframe");
          f.src = r.stream_url;
          if (r.kind === "html-sandboxed") {
            f.sandbox = "";  // empty = max isolation
          }
          body.appendChild(f);
        }
        return;
      }
      // Text-y kinds: inline content.
      const pre = document.createElement("pre");
      pre.textContent = r.content || "";
      body.appendChild(pre);
      if (r.truncated) {
        const trunc = document.createElement("div");
        trunc.className = "preview-truncated";
        trunc.textContent = `Showing the first ${_humanBytes(r.preview_bytes || 0)} of ${_humanBytes(r.size || 0)}. Use Download a copy for the full file.`;
        body.appendChild(trunc);
      }
    } catch (e) {
      body.replaceChildren();
      const err = document.createElement("div");
      err.className = "folder-browser-preview-empty";
      err.textContent = `Couldn't preview: ${errorToastBody(e)}`;
      body.appendChild(err);
    }
  }

  // v0.21.x Ship 5: per-file version history viewer. Lists past
  // blob_hash values from the folder audit log; each historical
  // version can be previewed (text inline / image / download) or
  // restored in place (writes the blob's bytes back to the file
  // path on disk → watcher reconciles → vclock bumps → propagates
  // to peers as a normal edit).
  async function _showFolderFileHistory(folderName, entry) {
    const body = $("#folder-browser-preview").querySelector(".preview-body");
    if (!body) return;
    body.replaceChildren();
    const wrap = document.createElement("div");
    wrap.style.display = "flex";
    wrap.style.flexDirection = "column";
    wrap.style.gap = "8px";
    const heading = document.createElement("div");
    heading.style.fontSize = "12px";
    heading.style.color = "var(--text-dim)";
    heading.style.marginBottom = "4px";
    heading.textContent = `Past versions of ${entry.path}`;
    wrap.appendChild(heading);
    body.appendChild(wrap);
    const loading = document.createElement("div");
    loading.textContent = "Loading history…";
    loading.style.color = "var(--text-dim)";
    loading.style.fontSize = "12px";
    wrap.appendChild(loading);
    let versions = [];
    try {
      const r = await api.get(
        `/api/folders/${encodeURIComponent(folderName)}/file/${encodeURIComponent(entry.path)}/history`,
      );
      versions = r.versions || [];
    } catch (e) {
      loading.textContent = `Couldn't load history: ${errorToastBody(e)}`;
      return;
    }
    loading.remove();
    if (versions.length === 0) {
      const em = document.createElement("div");
      em.style.color = "var(--text-dim)";
      em.style.fontSize = "12px";
      em.textContent = "No prior versions recorded.";
      wrap.appendChild(em);
      return;
    }
    for (const v of versions) {
      const row = document.createElement("div");
      row.style.background = "var(--bg)";
      row.style.borderRadius = "8px";
      row.style.padding = "10px 12px";
      const head = document.createElement("div");
      head.style.display = "flex";
      head.style.justifyContent = "space-between";
      head.style.alignItems = "center";
      head.style.gap = "8px";
      head.style.marginBottom = "6px";
      const label = document.createElement("div");
      label.style.fontSize = "12px";
      const peer = v.peer_fp ? v.peer_fp.slice(0, 8) : "?";
      const action = document.createElement("strong");
      action.textContent = String(v.action || "");
      const by = document.createElement("code");
      by.textContent = peer;
      label.replaceChildren(
        action,
        ` · ${_humanAgo(v.ts_ms)} · by `,
        by,
        ` · ${v.size != null ? _humanBytes(v.size) : "—"}`,
      );
      head.appendChild(label);
      const hash = document.createElement("code");
      hash.style.fontSize = "10px";
      hash.style.color = "var(--text-dim)";
      hash.textContent = v.blob_hash ? v.blob_hash.slice(0, 16) + "…" : "(deleted)";
      hash.title = v.blob_hash || "";
      head.appendChild(hash);
      row.appendChild(head);
      if (!v.blob_hash) {
        const note = document.createElement("div");
        note.style.fontSize = "11px";
        note.style.color = "var(--text-dim)";
        note.textContent = "Tombstone (the file was deleted at this point).";
        row.appendChild(note);
      } else {
        const actions = document.createElement("div");
        actions.style.display = "flex";
        actions.style.gap = "6px";
        const prev = document.createElement("button");
        prev.type = "button";
        prev.textContent = "Preview";
        prev.style.fontSize = "11px";
        prev.style.padding = "5px 9px";
        prev.disabled = !v.local_available;
        prev.title = v.local_available
          ? "Show this past version's content."
          : "Not previewable — the blob was garbage-collected from this device.";
        const previewSlot = document.createElement("div");
        previewSlot.style.display = "none";
        previewSlot.style.marginTop = "6px";
        prev.onclick = async () => {
          if (previewSlot.style.display !== "none") {
            previewSlot.style.display = "none";
            prev.textContent = "Preview";
            return;
          }
          prev.textContent = "Loading…";
          prev.disabled = true;
          try {
            const ext = (entry.path || "").split(".").pop() || "";
            const r2 = await api.get(
              `/api/blobs/${v.blob_hash}/preview` + (ext ? `?as=${encodeURIComponent(ext)}` : ""),
            );
            previewSlot.replaceChildren();
            if (r2.kind === "image" && r2.stream_url) {
              const img = document.createElement("img");
              img.src = r2.stream_url + (ext ? `&as=${encodeURIComponent(ext)}` : `?as=${encodeURIComponent(ext)}`);
              img.style.maxWidth = "100%";
              img.style.maxHeight = "200px";
              previewSlot.appendChild(img);
            } else if (r2.content !== undefined) {
              const pre = document.createElement("pre");
              pre.textContent = r2.content;
              pre.style.maxHeight = "200px";
              pre.style.overflow = "auto";
              pre.style.fontFamily = "var(--font-mono, ui-monospace, Menlo, monospace)";
              pre.style.fontSize = "11px";
              pre.style.background = "var(--bg-2)";
              pre.style.padding = "8px";
              pre.style.borderRadius = "4px";
              pre.style.whiteSpace = "pre-wrap";
              pre.style.wordBreak = "break-word";
              previewSlot.appendChild(pre);
            } else {
              const note = document.createElement("div");
              note.style.fontSize = "11px";
              note.style.color = "var(--text-dim)";
              note.textContent = "No inline preview for this file type.";
              previewSlot.appendChild(note);
            }
            previewSlot.style.display = "block";
            prev.textContent = "Hide preview";
          } catch (err) {
            toast(`Preview failed: ${errorToastBody(err)}`, "bad", 5000);
            prev.textContent = "Preview";
          } finally {
            prev.disabled = false;
          }
        };
        actions.appendChild(prev);
        const restoreBtn = document.createElement("button");
        restoreBtn.type = "button";
        restoreBtn.textContent = "Restore this version";
        restoreBtn.style.fontSize = "11px";
        restoreBtn.style.padding = "5px 9px";
        restoreBtn.style.background = "var(--accent)";
        restoreBtn.style.color = "white";
        restoreBtn.disabled = !v.local_available;
        restoreBtn.title = v.local_available
          ? "Overwrite the current file with these bytes. Peers will pick up the restore as a normal edit."
          : "Not restorable — the blob was garbage-collected from this device.";
        restoreBtn.onclick = async () => {
          if (!confirm(
            `Overwrite "${entry.path}" with the version from ${_humanAgo(v.ts_ms)}? `
            + "The current contents will be replaced; the change will sync to every paired device."
          )) return;
          restoreBtn.disabled = true;
          restoreBtn.textContent = "Restoring…";
          try {
            await api.post(
              `/api/folders/${encodeURIComponent(folderName)}/file/${encodeURIComponent(entry.path)}/restore`,
              { blob_hash: v.blob_hash },
            );
            toast(`Restored "${entry.path}".`, "good", 4500);
            // Re-open the file preview so the user sees the restored content.
            setTimeout(() => _previewFolderFile(folderName, entry), 600);
          } catch (err) {
            toast(`Restore failed: ${errorToastBody(err)}`, "bad", 6000);
            restoreBtn.disabled = false;
            restoreBtn.textContent = "Restore this version";
          }
        };
        actions.appendChild(restoreBtn);
        row.appendChild(actions);
        row.appendChild(previewSlot);
      }
      wrap.appendChild(row);
    }
  }

  // v0.21.x Ship 4: per-folder sync settings (selective sync via
  // ignored_patterns + max_file_bytes + conflict_policy).
  const _IGNORE_PRESETS = {
    dev: [
      "node_modules/", ".git/", "__pycache__/", "dist/", "build/",
      "target/", ".venv/", "venv/", ".tox/", ".mypy_cache/",
      ".pytest_cache/", ".next/", ".cache/",
    ],
    osjunk: [
      ".DS_Store", "Thumbs.db", "desktop.ini", "$RECYCLE.BIN/",
    ],
    logs: ["*.log", "*.tmp", "*.swp", "*.swo", "*.bak", "*~"],
  };

