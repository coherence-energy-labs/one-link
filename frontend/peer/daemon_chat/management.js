  // ── Phase 3a: peer roster mgmt (rename + mute) ───────────────────
  // Wired to set_peer_alias + set_peer_mute on the daemon side.
  // UI lives inside daemon-chat-card under the Info toggle.

  async function setDaemonPeerAlias(peerFp, alias) {
    return _daemonRequest("set_peer_alias", {
      peer_fp: peerFp,
      alias: alias === "" ? null : alias,
    });
  }

  async function setDaemonPeerMute(peerFp, muted) {
    return _daemonRequest("set_peer_mute", {
      peer_fp: peerFp,
      muted: !!muted,
    });
  }

  function _toggleDaemonChatPeerInfo() {
    const panel = $("#daemon-chat-peer-info");
    if (!panel) return;
    const peer = state.daemon_active_peer;
    const group = state.daemon_active_group;
    if (!peer && !group) return;
    if (panel.hidden) {
      const peerSettings = $("#daemon-chat-peer-settings");
      const groupSettings = $("#daemon-chat-group-settings");
      if (peerSettings) peerSettings.hidden = !peer;
      if (groupSettings) groupSettings.hidden = !group;
      // Pre-populate with current values.
      const aliasInput = $("#daemon-chat-peer-alias");
      const muteToggle = $("#daemon-chat-peer-mute-toggle");
      if (peer && aliasInput) aliasInput.value = peer.alias || "";
      if (peer && muteToggle) muteToggle.checked = !!peer.muted;
      const statusEl = $("#daemon-chat-peer-info-status");
      if (statusEl) statusEl.textContent = "";
      panel.hidden = false;
      if (group) _renderDaemonGroupInfo().catch((e) => {
        if (statusEl) statusEl.textContent =
          `Couldn't load group info: ${e && e.message ? e.message : e}`;
      });
    } else {
      panel.hidden = true;
    }
  }

  async function _renderDaemonGroupInfo() {
    const group = state.daemon_active_group;
    const host = $("#daemon-chat-group-members");
    const select = $("#daemon-chat-group-member-select");
    const addBtn = $("#btn-daemon-chat-group-add");
    const statusEl = $("#daemon-chat-peer-info-status");
    if (!group || !group.group_id || !host || !select) return;
    if (statusEl) statusEl.textContent = "Loading group...";
    const [detail, peers] = await Promise.all([
      fetchDaemonGroupDetail(group.group_id),
      fetchDaemonPeers(),
    ]);
    host.replaceChildren();
    const members = Array.isArray(detail?.members) ? detail.members : [];
    const canManageMembers = ["owner", "admin"].includes(String(detail?.my_role || ""));
    for (const member of members) {
      const row = document.createElement("div");
      row.style.display = "flex";
      row.style.gap = "6px";
      row.style.alignItems = "center";
      row.style.justifyContent = "space-between";
      const name = document.createElement("span");
      name.textContent =
        `${member.display_name || member.fingerprint || "member"} (${member.role || "member"})`;
      name.style.minWidth = "0";
      name.style.overflow = "hidden";
      name.style.textOverflow = "ellipsis";
      name.style.whiteSpace = "nowrap";
      row.appendChild(name);
      if (canManageMembers && !member.is_me && member.fingerprint) {
        const remove = document.createElement("button");
        remove.type = "button";
        remove.className = "btn ghost";
        remove.textContent = "Remove";
        remove.style.padding = "3px 8px";
        remove.style.minHeight = "auto";
        remove.style.fontSize = "11px";
        remove.addEventListener("click", async () => {
          if (!confirm(`Remove ${member.display_name || member.fingerprint}?`)) return;
          await removeDaemonGroupMember(group.group_id, member.fingerprint);
          await _renderDaemonGroupInfo();
          await _refreshDaemonRoster();
        });
        row.appendChild(remove);
      }
      host.appendChild(row);
    }
    select.replaceChildren();
    select.disabled = !canManageMembers;
    if (addBtn) addBtn.disabled = !canManageMembers;
    const memberFps = new Set(members.map((m) => m.fingerprint).filter(Boolean));
    for (const peer of peers || []) {
      if (!peer.fingerprint || memberFps.has(peer.fingerprint)) continue;
      const opt = document.createElement("option");
      opt.value = peer.fingerprint;
      opt.textContent = peer.alias || peer.hostname || peer.fingerprint;
      select.appendChild(opt);
    }
    if (!select.childNodes.length) {
      const opt = document.createElement("option");
      opt.value = "";
      opt.textContent = canManageMembers
        ? "No paired peers to add"
        : "Only admins can add members";
      select.appendChild(opt);
    }
    if (statusEl) statusEl.textContent =
      `${members.length} member${members.length === 1 ? "" : "s"}`;
  }

  async function _handleDaemonChatGroupAdd() {
    const group = state.daemon_active_group;
    const select = $("#daemon-chat-group-member-select");
    const statusEl = $("#daemon-chat-peer-info-status");
    const peerFp = (select?.value || "").trim();
    if (!group || !group.group_id || !peerFp) return;
    if (statusEl) statusEl.textContent = "Adding member...";
    try {
      await addDaemonGroupMember(group.group_id, peerFp);
      await _renderDaemonGroupInfo();
      await _refreshDaemonRoster();
      if (statusEl) statusEl.textContent = "Member added.";
    } catch (e) {
      if (statusEl) statusEl.textContent =
        `Couldn't add member: ${e && e.message ? e.message : e}`;
    }
  }

  async function _handleDaemonChatGroupInvite() {
    const group = state.daemon_active_group;
    const statusEl = $("#daemon-chat-peer-info-status");
    if (!group || !group.group_id) return;
    if (statusEl) statusEl.textContent = "Creating invite...";
    try {
      const invite = await fetchDaemonGroupInviteLink(group.group_id);
      const textToCopy = invite.url || invite.token || "";
      await navigator.clipboard.writeText(textToCopy);
      if (statusEl) statusEl.textContent = "Invite copied.";
    } catch (e) {
      if (statusEl) statusEl.textContent =
        `Couldn't copy invite: ${e && e.message ? e.message : e}`;
    }
  }

  async function _handleDaemonChatGroupLeave() {
    const group = state.daemon_active_group;
    const statusEl = $("#daemon-chat-peer-info-status");
    if (!group || !group.group_id) return;
    if (!confirm(`Leave ${group.name || "this group"}?`)) return;
    if (statusEl) statusEl.textContent = "Leaving group...";
    try {
      await leaveDaemonGroup(group.group_id);
      daemonConversation.leaveGroup();
      await _refreshDaemonRoster();
      _showOnly("#daemon-roster-card");
    } catch (e) {
      if (statusEl) statusEl.textContent =
        `Couldn't leave group: ${e && e.message ? e.message : e}`;
    }
  }

  async function _handleDaemonChatPeerAliasSave() {
    const peer = state.daemon_active_peer;
    const input = $("#daemon-chat-peer-alias");
    const statusEl = $("#daemon-chat-peer-info-status");
    if (!peer || !peer.fingerprint || !input) return;
    const alias = (input.value || "").trim();
    if (statusEl) statusEl.textContent = "Saving…";
    try {
      const reply = await setDaemonPeerAlias(peer.fingerprint, alias);
      // Update the in-memory peer record so the chat title reflects
      // the new alias without a full roster refetch.
      daemonConversation.updatePeer(peer, { alias: reply.alias || "" });
      const titleEl = $("#daemon-chat-title");
      if (titleEl) {
        titleEl.textContent =
          peer.alias || peer.hostname || peer.fingerprint || "Chat";
      }
      if (statusEl) statusEl.textContent = "Saved.";
    } catch (e) {
      if (statusEl) {
        statusEl.textContent =
          `Couldn't save alias: ${e && e.message ? e.message : e}`;
      }
    }
  }

  async function _handleDaemonChatPeerMuteToggle(ev) {
    const peer = state.daemon_active_peer;
    const statusEl = $("#daemon-chat-peer-info-status");
    if (!peer || !peer.fingerprint) return;
    const muted = !!ev.target.checked;
    if (statusEl) statusEl.textContent = muted ? "Muting…" : "Unmuting…";
    try {
      const reply = await setDaemonPeerMute(peer.fingerprint, muted);
      daemonConversation.updatePeer(peer, { muted: !!reply.muted });
      if (statusEl) statusEl.textContent = peer.muted ? "Muted." : "Unmuted.";
    } catch (e) {
      // Roll back the toggle on failure.
      ev.target.checked = !muted;
      if (statusEl) {
        statusEl.textContent =
          `Couldn't update mute: ${e && e.message ? e.message : e}`;
      }
    }
  }

  $("#btn-daemon-chat-info")?.addEventListener("click", _toggleDaemonChatPeerInfo);
  $("#btn-daemon-chat-peer-alias-save")?.addEventListener("click", _handleDaemonChatPeerAliasSave);
  $("#daemon-chat-peer-mute-toggle")?.addEventListener("change", _handleDaemonChatPeerMuteToggle);
  $("#btn-daemon-chat-group-add")?.addEventListener("click", _handleDaemonChatGroupAdd);
  $("#btn-daemon-chat-group-invite")?.addEventListener("click", _handleDaemonChatGroupInvite);
  $("#btn-daemon-chat-group-leave")?.addEventListener("click", _handleDaemonChatGroupLeave);

