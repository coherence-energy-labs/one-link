  // ── v0.8.0: groups ────────────────────────────────────────────────
  async function refreshGroups() {
    try {
      const r = await api.get("/api/groups");
      state.groups.clear();
      for (const g of r.groups || []) {
        state.groups.set(g.group_id, g);
      }
      renderGroups();
    } catch (e) { console.warn(e); }
  }

  function renderGroups() {
    const list = $("#grouplist");
    if (!list) return;
    $("#groups-count").textContent = state.groups.size;
    list.innerHTML = "";
    if (state.groups.size === 0) {
      // No empty-state needed; the + button sits above this.
      return;
    }
    // v0.11.3: split into active vs archived. Archived rows render
    // under an "Archived" expand toggle so they don't clutter the
    // sidebar but stay one click away.
    const activeGroups = [];
    const archivedGroups = [];
    for (const g of state.groups.values()) {
      if (isGroupArchived(g.group_id)) archivedGroups.push(g);
      else activeGroups.push(g);
    }
    const renderRow = (g) => {
      const row = el("div", "peer group-row");
      if (state.selectedGroup === g.group_id) row.classList.add("active");
      // v0.11.3: per-group avatar tint.
      const av = el("div", "avatar group-avatar", "G");
      av.style.background = getGroupColor(g.group_id);
      const txt = el("div", "text");
      const nameEl = el("div", "name", g.name || "(unnamed group)");
      // v0.11.3: 🔕 indicator when group is currently muted.
      if (g.muted_until_ms != null) {
        const now = Date.now();
        if (g.muted_until_ms === 0 || g.muted_until_ms > now) {
          const muteIcon = el("span", "mute-indicator", " 🔕");
          muteIcon.title = "Notifications muted";
          nameEl.appendChild(muteIcon);
        }
      }
      txt.appendChild(nameEl);
      txt.appendChild(el("div", "sub",
        `${g.member_count} member${g.member_count === 1 ? "" : "s"}`
      ));
      row.appendChild(av);
      row.appendChild(txt);
      const gear = el("button", "gear-btn", "⚙");
      gear.title = `${g.name || "Group"} settings`;
      gear.onclick = async (ev) => {
        ev.stopPropagation();
        if (state.selectedGroup !== g.group_id) {
          await selectGroup(g.group_id);
        }
        openGroupSettings();
      };
      row.appendChild(gear);
      row.onclick = () => selectGroup(g.group_id);
      list.appendChild(row);
    };
    for (const g of activeGroups) renderRow(g);
    if (archivedGroups.length > 0) {
      const header = el("div", "archived-header");
      const expanded = state._archivedExpanded;
      header.textContent =
        `${expanded ? "▾" : "▸"} Archived (${archivedGroups.length})`;
      header.onclick = () => {
        state._archivedExpanded = !state._archivedExpanded;
        renderGroups();
      };
      list.appendChild(header);
      if (expanded) {
        for (const g of archivedGroups) renderRow(g);
      }
    }
  }

  async function selectGroup(gidHex) {
    saveActiveDraft();
    // v0.10.1: switching conversations exits multi-select.
    if (state.selecting) exitSelection();
    // v0.14.0 mobile: tapping a group auto-closes the drawer.
    closeMobileSidebar();
    // v0.21.1: reset the new-message pill on conversation switch.
    _hideNewMessagePill();
    _lastRenderedLen = 0;
    _forceMessagesBottomNowAndAfter();
    // v0.14.1 persist for boot-time restore.
    _saveLastSelection("group", gidHex);
    state.selectedGroup = gidHex;
    state.selectedPeer = null;  // mutually exclusive
    try {
      state.groupDetail = await api.get(`/api/groups/${gidHex}`);
    } catch (e) {
      toast(`Couldn\'t load group: ${errorToastBody(e)}`, "bad");
      return;
    }
    try {
      const r = await api.get(`/api/groups/${gidHex}/messages?limit=200`);
      state.groupMessages = r.messages || [];
    } catch (e) {
      state.groupMessages = [];
    }
    renderGroups();
    renderGroupConversation();
    renderPins();
    restoreDraft();
    // v0.11.5 - apply this group's wallpaper accent.
    applyActiveChatWallpaper();
    $("#input").focus();
  }

  function closeGroupSettings() {
    $("#group-settings-backdrop").classList.remove("show");
  }

  function memberLabel(member) {
    if (member.is_me) return "You";
    return member.display_name || member.fingerprint?.slice(0, 8) || "Unknown";
  }

  function openGroupSettings() {
    const g = state.groupDetail;
    if (!state.selectedGroup || !g) return;
    $("#group-settings-name").textContent = g.name || "(unnamed group)";
    $("#group-settings-sub").textContent =
      `${g.member_count} member${g.member_count === 1 ? "" : "s"}`;
    $("#group-rename-input").value = g.name || "";
    const canManage = g.my_role === "owner" || g.my_role === "admin";
    const isOwner = g.my_role === "owner";
    $("#group-rename-input").disabled = !canManage;
    $("#group-rename-save").disabled = !canManage;

    const memberHost = $("#group-settings-members");
    memberHost.innerHTML = "";
    for (const m of g.members || []) {
      const row = el("div", "file-row");
      row.appendChild(el("div", "icon", m.is_me ? "You" : "User"));
      const meta = el("div", "meta");
      meta.appendChild(el("div", "name", memberLabel(m)));
      meta.appendChild(el("div", "size", m.role || "member"));
      row.appendChild(meta);
      // v0.11.3: owner-only role picker. Drop-in dropdown (no
      // confirm) since the action is reversible. Owners can
      // promote/demote anyone but themselves; reducer enforces
      // server-side.
      if (isOwner && !m.is_me) {
        const roleSel = document.createElement("select");
        roleSel.className = "group-role-picker";
        for (const r of ["owner", "admin", "member"]) {
          const opt = document.createElement("option");
          opt.value = r;
          opt.textContent = r;
          if ((m.role || "member") === r) opt.selected = true;
          roleSel.appendChild(opt);
        }
        roleSel.onchange = () =>
          changeGroupMemberRole(m.fingerprint, roleSel.value);
        row.appendChild(roleSel);
      }
      if (canManage && !m.is_me) {
        const remove = el("button", null, "Remove");
        remove.onclick = () => removeGroupMember(m.fingerprint);
        row.appendChild(remove);
      }
      memberHost.appendChild(row);
    }

    const memberFps = new Set((g.members || []).map(m => m.fingerprint));
    const candidates = [...state.peers.values()]
      .filter(p => p.fingerprint && p.trust === "pinned" && !memberFps.has(p.fingerprint));
    const addSelect = $("#group-add-peer");
    addSelect.innerHTML = "";
    for (const p of candidates) {
      const opt = document.createElement("option");
      opt.value = p.fingerprint;
      opt.textContent = p.display_name || p.hostname || p.short_id;
      addSelect.appendChild(opt);
    }
    $("#group-settings-add-section").style.display =
      canManage ? "block" : "none";
    $("#group-add-member").disabled = candidates.length === 0;
    if (candidates.length === 0) {
      const opt = document.createElement("option");
      opt.textContent = "No paired devices to add";
      opt.value = "";
      addSelect.appendChild(opt);
    }

    // v0.11.3: avatar color swatches keyed by group_id.
    _renderGroupColorSwatches(state.selectedGroup);

    // v0.11.3: mute status + reset duration picker.
    const groupRow = state.groups.get(state.selectedGroup);
    _renderMuteStatus(
      $("#group-mute-status"),
      groupRow ? groupRow.muted_until_ms : null,
      false,
    );
    const muteSel = $("#group-mute-duration");
    if (muteSel) muteSel.value = "";

    // v0.11.3: archive button label reflects current state.
    const archiveBtn = $("#group-archive-toggle");
    if (archiveBtn) {
      const isArchived = isGroupArchived(state.selectedGroup);
      archiveBtn.textContent = isArchived ? "Unarchive group" : "Archive group";
    }

    $("#group-settings-backdrop").classList.add("show");
  }

  async function renameCurrentGroup() {
    const gid = state.selectedGroup;
    const name = $("#group-rename-input").value.trim();
    if (!gid || !name) return;
    try {
      const r = await api.post(`/api/groups/${gid}/rename`, { name });
      if (state.groupDetail) state.groupDetail.name = r.name || name;
      const g = state.groups.get(gid);
      if (g) g.name = r.name || name;
      toast("Group renamed", "good");
      await refreshGroups();
      await refreshSelectedGroup();
    } catch (e) {
      toast(`Rename didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function refreshSelectedGroup() {
    if (!state.selectedGroup) return;
    await selectGroup(state.selectedGroup);
    if ($("#group-settings-backdrop").classList.contains("show")) {
      openGroupSettings();
    }
  }

  async function addGroupMember() {
    const gid = state.selectedGroup;
    const fp = $("#group-add-peer").value;
    if (!gid || !fp) return;
    try {
      await api.post(`/api/groups/${gid}/members`, { fp });
      toast("Member added. Be nice.", "good");
      await refreshGroups();
      await refreshSelectedGroup();
    } catch (e) {
      toast(`Add didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function removeGroupMember(fp) {
    const gid = state.selectedGroup;
    if (!gid || !fp) return;
    if (!confirm("Remove this member from the group?")) return;
    try {
      await api.del(`/api/groups/${gid}/members/${encodeURIComponent(fp)}`);
      toast("Member removed", "good");
      await refreshGroups();
      await refreshSelectedGroup();
    } catch (e) {
      toast(`Remove didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  // v0.11.3: change a group member's role. Owner-only on the
  // server side; the UI also gates the dropdown to owners.
  async function changeGroupMemberRole(fp, newRole) {
    const gid = state.selectedGroup;
    if (!gid || !fp || !newRole) return;
    try {
      await api.post(
        `/api/groups/${gid}/members/${encodeURIComponent(fp)}/role`,
        { role: newRole },
      );
      toast(`Role changed to ${newRole}`, "good");
      await refreshGroups();
      await refreshSelectedGroup();
    } catch (e) {
      toast(`Role change failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  // v0.11.3: per-group avatar color. Settings-keyed by gid_hex so
  // each group keeps its own tint independent of the user's
  // global avatar color.
  const _GROUP_COLOR_PRESETS = [
    "#7c4dff", "#3b82f6", "#06b6d4", "#10b981",
    "#facc15", "#f97316", "#ef4444", "#ec4899",
  ];
  function _hashStringForAccent(input) {
    let h = 2166136261;
    const s = String(input || "");
    for (let i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 16777619) >>> 0;
    }
    return h >>> 0;
  }
  function deterministicAccentForId(id) {
    const h = _hashStringForAccent(id);
    return _GROUP_COLOR_PRESETS[h % _GROUP_COLOR_PRESETS.length];
  }
  function peerAccentColor(peer) {
    // Keep device avatars in the One Link brand family. Earlier
    // fingerprint hashing could make the same peer deterministically
    // red/orange/etc., which was technically stable but visually
    // surprising beside the purple-blue chat language.
    return "linear-gradient(135deg, #7c5cff 0%, #4ec1ff 100%)";
  }
  // v0.12.1 - chat-prefs cache. Source-of-truth for per-chat
  // cosmetic state (color, wallpaper, archived). Populated from
  // /api/chat-prefs at boot + kept in sync by chat_pref WS events.
  // localStorage is still written so the FIRST paint after a
  // reload is instant (we don't have to wait for the GET).
  state.chatPrefs = state.chatPrefs || { peer: {}, group: {} };
  function _readChatPref(scope, id, kind) {
    const cached = state.chatPrefs?.[scope]?.[id]?.[kind];
    if (cached !== undefined) return cached;
    // Fall back to legacy localStorage keys so users upgrading
    // from v0.11.x don't lose their picks on the first session.
    if (kind === "color") {
      return localStorage.getItem(`one_link.${scope}_color.${id}`) || undefined;
    }
    if (kind === "wallpaper") {
      return localStorage.getItem(`one_link.chat_wallpaper.${scope}.${id}`) || undefined;
    }
    if (kind === "archived") {
      return localStorage.getItem(`one_link.${scope}_archived.${id}`) === "1"
        ? true : undefined;
    }
    return undefined;
  }
  function _writeChatPref(scope, id, kind, value) {
    if (!state.chatPrefs[scope]) state.chatPrefs[scope] = {};
    if (!state.chatPrefs[scope][id]) state.chatPrefs[scope][id] = {};
    if (value === null || value === undefined || value === "") {
      delete state.chatPrefs[scope][id][kind];
    } else {
      state.chatPrefs[scope][id][kind] = value;
    }
    // Mirror to localStorage for instant first-paint on reload.
    if (kind === "color") {
      const k = `one_link.${scope}_color.${id}`;
      if (value) localStorage.setItem(k, value);
      else localStorage.removeItem(k);
    } else if (kind === "wallpaper") {
      const k = `one_link.chat_wallpaper.${scope}.${id}`;
      if (value) localStorage.setItem(k, value);
      else localStorage.removeItem(k);
    } else if (kind === "archived") {
      const k = `one_link.${scope}_archived.${id}`;
      if (value) localStorage.setItem(k, "1");
      else localStorage.removeItem(k);
    }
    // Persist server-side so the user's other devices see it.
    api.post("/api/chat-prefs", {
      scope, id, kind, value: value === undefined ? null : value,
    }).catch((e) => console.warn("chat-prefs save failed:", e));
  }
  async function loadChatPrefs() {
    try {
      const r = await api.get("/api/chat-prefs");
      // Server is the authority; replace any cached state.
      state.chatPrefs = { peer: r.peer || {}, group: r.group || {} };
      // Re-render anything that consumed the prefs.
      renderGroups();
      renderPeers();
      applyActiveChatWallpaper();
    } catch (e) {
      console.warn("loadChatPrefs failed:", e);
    }
  }

  function getGroupColor(gid) {
    return _readChatPref("group", gid, "color")
        || deterministicAccentForId(gid);
  }
  function setGroupColor(gid, hex) {
    _writeChatPref("group", gid, "color", hex);
    // Live-reflect in the sidebar.
    renderGroups();
  }
  function _renderGroupColorSwatches(gid) {
    const host = $("#group-color-swatches");
    if (!host) return;
    host.innerHTML = "";
    const current = getGroupColor(gid);
    for (const c of _GROUP_COLOR_PRESETS) {
      const sw = document.createElement("button");
      sw.className = "profile-color-swatch" + (c === current ? " active" : "");
      sw.style.background = c;
      sw.dataset.color = c;
      sw.title = c;
      sw.onclick = (ev) => {
        ev.preventDefault();
        host.querySelectorAll(".profile-color-swatch").forEach(
          (b) => b.classList.toggle("active", b === sw),
        );
        setGroupColor(gid, c);
      };
      host.appendChild(sw);
    }
  }

  // v0.12.1 archive - server-synced "hide from sidebar". Other
  // members aren't affected; this is local to the user's account
  // but does sync across the user's own devices.
  function isGroupArchived(gid) {
    return _readChatPref("group", gid, "archived") === true;
  }
  function setGroupArchived(gid, archived) {
    _writeChatPref("group", gid, "archived", archived ? true : null);
    renderGroups();
  }
  // v0.21.x: per-peer pin + archive. Mirrors the group helpers
  // above using the same chat-prefs machinery (localStorage-backed,
  // scope-agnostic key/value). Pinned peers float to the top of the
  // sidebar; archived peers move under an expandable "Archived"
  // header at the bottom (or out of view entirely when collapsed).
  // v0.21.x: right-click context menu on a peer row. Surfaces
  // Pin / Unpin, Archive / Unarchive, plus a Settings shortcut.
  // Single instance — opening a new one dismisses any existing.
  function _openPeerContextMenu(x, y, peer) {
    document.querySelectorAll(".peer-context-menu").forEach((m) => m.remove());
    const menu = el("div", "peer-context-menu");
    menu.setAttribute("role", "menu");
    function item(label, fn) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "pcm-item";
      b.textContent = label;
      b.onclick = (ev) => { ev.stopPropagation(); fn(); menu.remove(); };
      menu.appendChild(b);
    }
    const pinned = isPeerPinned(peer.short_id);
    const archived = isPeerArchived(peer.short_id);
    item(pinned ? "📌 Unpin from top" : "📌 Pin to top", () => {
      setPeerPinned(peer.short_id, !pinned);
      toast(pinned ? "Unpinned." : "Pinned to top.", "good", 2500);
    });
    item(archived ? "📁 Unarchive" : "📁 Archive", () => {
      setPeerArchived(peer.short_id, !archived);
      toast(archived ? "Brought back from the archive." : "Filed away in archive.", "good", 2500);
    });
    item("⚙ Device settings", () => openDeviceDrawer(peer.short_id));
    document.body.appendChild(menu);
    // Clamp inside viewport.
    const rect = menu.getBoundingClientRect();
    const left = Math.min(x, window.innerWidth - rect.width - 8);
    const top = Math.min(y, window.innerHeight - rect.height - 8);
    menu.style.left = `${Math.max(8, left)}px`;
    menu.style.top = `${Math.max(8, top)}px`;
    const close = (ev) => {
      if (!menu.contains(ev.target)) {
        menu.remove();
        document.removeEventListener("click", close, true);
        document.removeEventListener("contextmenu", close, true);
      }
    };
    setTimeout(() => {
      document.addEventListener("click", close, true);
      document.addEventListener("contextmenu", close, true);
    }, 0);
  }

  function isPeerPinned(shortId) {
    return _readChatPref("peer", shortId, "pinned") === true;
  }
  function setPeerPinned(shortId, pinned) {
    _writeChatPref("peer", shortId, "pinned", pinned ? true : null);
    renderPeers();
  }
  function isPeerArchived(shortId) {
    return _readChatPref("peer", shortId, "archived") === true;
  }
  function setPeerArchived(shortId, archived) {
    _writeChatPref("peer", shortId, "archived", archived ? true : null);
    renderPeers();
  }
  async function toggleArchiveCurrentGroup() {
    const gid = state.selectedGroup;
    if (!gid) return;
    const wasArchived = isGroupArchived(gid);
    setGroupArchived(gid, !wasArchived);
    const archiveBtn = $("#group-archive-toggle");
    if (archiveBtn) {
      archiveBtn.textContent = wasArchived ? "Archive group" : "Unarchive group";
    }
    toast(wasArchived ? "Group back on the shelf." : "Group filed away.", "good");
  }

  // v0.11.3: per-group mute apply. Backend already in place from
  // v0.11.2 - this just hooks up the duration picker.
  async function applyGroupMute() {
    const gid = state.selectedGroup;
    if (!gid) return;
    const sel = $("#group-mute-duration");
    if (!sel?.value) {
      toast("Pick a duration first", "info");
      return;
    }
    const raw = sel.value;
    let body;
    if (raw === "null") body = { duration_ms: null };
    else body = { duration_ms: parseInt(raw, 10) };
    try {
      const r = await api.post(`/api/groups/${gid}/mute`, body);
      _renderMuteStatus(
        $("#group-mute-status"), r.muted_until_ms, false,
      );
      // Refresh state.groups so other UI surfaces (sidebar) pick
      // up the change too.
      await refreshGroups();
      toast(
        body.duration_ms === null ? "Group unmuted" : "Group muted", "good",
      );
    } catch (e) {
      toast(`Mute didn't work: ${errorToastBody(e)}`, "bad");
    }
  }

  async function copyGroupInviteLink() {
    const gid = state.selectedGroup;
    if (!gid) return;
    try {
      const r = await api.get(`/api/groups/${gid}/invite-link`);
      await navigator.clipboard.writeText(r.url || r.token || "");
      toast("Invite link copied. Spend it wisely.", "good");
    } catch (e) {
      toast(`Invite didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function leaveCurrentGroup() {
    const gid = state.selectedGroup;
    if (!gid) return;
    if (!confirm("Leave this group on this device?")) return;
    try {
      await api.post(`/api/groups/${gid}/leave`, {});
      closeGroupSettings();
      state.selectedGroup = null;
      state.groupDetail = null;
      state.groupMessages = [];
      $("#convo-active").style.display = "none";
      $("#convo-empty").style.display = "grid";
      await refreshGroups();
      toast("You left the group. Walk it off.", "good");
    } catch (e) {
      toast(`Leave didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  function groupMessageLabel(msg) {
    if (!msg) return "(message)";
    if (msg.direction === "out") return "you";
    const senderHex = msg.sender_pub_hex || "";
    return senderHex ? findPeerLabelByPubHex(senderHex) : "(unknown)";
  }

  function renderGroupReplyQuote(msg, bubble) {
    if (!msg.reply_to) return;
    const parent = state.groupMessages.find(x => x.id === msg.reply_to);
    const quote = el("div", "reply-quote");
    const quoteBody = parent?.body
      ? (parent.body.length > 80 ? parent.body.slice(0, 80) + "..." : parent.body)
      : "(message)";
    quote.appendChild(el("div", "reply-who", `↩ ${groupMessageLabel(parent)}`));
    quote.appendChild(el("div", "reply-text", quoteBody));
    quote.dataset.replyTo = msg.reply_to;
    quote.onclick = () => {
      const tgt = $("#messages")
        ?.querySelector(`[data-msg-id="${CSS.escape(msg.reply_to)}"]`);
      if (tgt) tgt.scrollIntoView({ behavior: "smooth", block: "center" });
    };
    bubble.appendChild(quote);
  }

  function renderGroupConversation() {
    if (!state.selectedGroup || !state.groupDetail) return;
    renderPins();
    $("#convo-empty").style.display = "none";
    $("#convo-active").style.display = "flex";
    // v0.7.7/v0.7.8: hide per-peer trust + key-change surfaces in
    // group context (they're peer-scoped, group has its own trust UX).
    const trust = $("#convo-trust"); if (trust) trust.innerHTML = "";
    const kcb = $("#convo-keychange");
    if (kcb) { kcb.style.display = "none"; kcb.innerHTML = ""; }
    const g = state.groupDetail;
    $("#convo-who").classList.add("group-context");
    $("#convo-who").title = "";
    $("#btn-group-settings").style.display = "inline-block";
    $("#btn-attach").style.display = "none";
    if (state.replyTo?.peer) clearReplyTo();
    $("#convo-name").textContent = g.name || "(unnamed group)";
    const subEl = $("#convo-sub");
    subEl.innerHTML = "";
    subEl.appendChild(document.createTextNode(
      `Group chat · ${g.member_count} member${g.member_count === 1 ? "" : "s"}`
    ));
    const m = $("#messages");
    const firstRender = !m._renderGroupSig || m._renderGroupSig !== state.selectedGroup;
    const prevBottomState = _captureScrollState(m);
    if (firstRender && state.searchResults == null) {
      prevBottomState.wasAtBottom = true;
      prevBottomState.forceBottom = true;
      _forceNextMessagesToBottom(1800);
    }
    m._renderGroupSig = state.selectedGroup;
    m.innerHTML = "";
    if (state.groupMessages.length === 0) {
      m.appendChild(el("div", "day-sep", "No messages yet"));
    }
    for (const msg of state.groupMessages.slice().reverse()) {
      const isMine = msg.direction === "out";
      const b = el("div", `msg ${isMine ? "out" : "in"}`);
      // Attribute the sender (group msgs aren't 1:1).
      if (!isMine) {
        const senderHex = msg.sender_pub_hex || "";
        const senderLabel = senderHex
          ? findPeerLabelByPubHex(senderHex)
          : "(unknown)";
        const who = el("div", "group-sender", senderLabel);
        b.appendChild(who);
      }
      if (msg.deleted || msg.deleted_at_ms) {
        b.appendChild(el("div", "msg-deleted", "[message deleted]"));
      } else {
        renderGroupReplyQuote(msg, b);
        appendCollapsibleText(b, msg.body || "");
        if (msg.edited_at_ms) {
          const ed = el("span", "edited-badge", " (edited)");
          ed.title = `edited at ${new Date(msg.edited_at_ms).toLocaleString()}`;
          b.appendChild(ed);
        }
      }
      b.appendChild(el("span", "when", fmtTime(msg.ts_ms || msg.ts)));
      b.dataset.msgId = msg.id;
      b.appendChild(renderMsgToolbar({
        id: msg.id,
        body: msg.body,
        dir: isMine ? "out" : "in",
        ts: msg.ts_ms || msg.ts,
        group_id: state.selectedGroup,
        is_group: true,
        deleted: Boolean(msg.deleted || msg.deleted_at_ms),
        reactions: msg.reactions || {},
      }));
      // v0.10.1: multi-select hooks for group messages too. Same
      // shape as 1:1 - selection state is shared across both.
      bindSelectionToBubble(b, {
        id: msg.id,
        body: msg.body,
        dir: isMine ? "out" : "in",
        ts: msg.ts_ms || msg.ts,
        deleted: Boolean(msg.deleted || msg.deleted_at_ms),
      });
      if (state.selectedMessageIds.has(msg.id)) b.classList.add("selected");
      if (msg.reactions && Object.keys(msg.reactions).length) {
        b.appendChild(renderReactionsRow({
          ...msg,
          dir: isMine ? "out" : "in",
          group_id: state.selectedGroup,
          is_group: true,
        }));
      }
      m.appendChild(b);
    }
    _smartScrollAfter(m, prevBottomState, state.groupMessages.length);
  }

  function findPeerLabelByPubHex(pubHex) {
    for (const p of state.peers.values()) {
      if (p.ed_pub_hex === pubHex) {
        return p.display_name || p.hostname || p.short_id;
      }
    }
    return pubHex.slice(0, 8);
  }

  // Open create-group modal - populates the member checkboxes.
  function openCreateGroupModal() {
    $("#cg-name").value = "";
    const list = $("#cg-members");
    list.innerHTML = "";
    const pinned = [...state.peers.values()]
      .filter(p => p.fingerprint && p.trust === "pinned");
    if (pinned.length < 2) {
      list.appendChild(el("div", "empty",
        "Groups need at least 3 people total. Pair two devices first."));
    }
    for (const p of pinned) {
      const row = el("label", "cg-member-row");
      const cb = document.createElement("input");
      cb.type = "checkbox";
      cb.value = p.fingerprint;
      cb.dataset.fp = p.fingerprint;
      row.appendChild(cb);
      const txt = el("span", "cg-member-text",
        ` ${p.display_name || p.hostname || p.short_id}`);
      row.appendChild(txt);
      list.appendChild(row);
    }
    const createBtn = $("#cg-create");
    const updateCreateEnabled = () => {
      const checked = list.querySelectorAll("input[type=checkbox]:checked").length;
      createBtn.disabled = checked < 2;
      createBtn.title = checked < 2
        ? "Pick at least two paired devices for a group"
        : "";
    };
    list.querySelectorAll("input[type=checkbox]").forEach(cb => {
      cb.addEventListener("change", updateCreateEnabled);
    });
    updateCreateEnabled();
    $("#create-group-backdrop").classList.add("show");
  }

  function closeCreateGroupModal() {
    $("#create-group-backdrop").classList.remove("show");
  }

  async function submitCreateGroup() {
    const name = $("#cg-name").value.trim();
    if (!name) { toast("Group name required", "bad"); return; }
    const fps = [...$("#cg-members").querySelectorAll("input[type=checkbox]:checked")]
      .map(cb => cb.dataset.fp);
    if (fps.length < 2) {
      toast("Groups need at least 3 people total. Use device chat for 1-on-1.", "bad", 6000);
      return;
    }
    try {
      const r = await api.post("/api/groups", { name, members: fps });
      closeCreateGroupModal();
      toast(`Group "${r.name}" created`, "good");
      await refreshGroups();
      selectGroup(r.group_id);
    } catch (e) {
      // v0.8.0: a 404 here usually means the daemon is on a
      // pre-v0.8.0 build that doesn't have /api/groups. The
      // page-served HTML can be newer than the running daemon
      // when the user updates source but doesn't restart.
      if (e?.status === 404) {
        toast(
          "Groups need One Link v0.8.0+. Restart One Link to pick up the new endpoints.",
          "bad", 9000,
        );
      } else {
        toast(`Create didn't work: ${errorToastBody(e)}`, "bad");
      }
    }
  }

