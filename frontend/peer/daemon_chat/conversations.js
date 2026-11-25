  async function _openDaemonChat(peer) {
    // Defensive: never open the chat card without a real peer
    // record. Past bug: roster row passed an empty stub, chat
    // opened with title 'CHAT' and an empty log because
    // fetchDaemonMessages("") returns nothing.
    if (!peer || !peer.fingerprint) {
      console.warn("_openDaemonChat called without peer.fingerprint", peer);
      return;
    }
    state.daemon_active_peer = peer;
    state.daemon_active_group = null;
    // Single-pane: chat takes the screen.
    _showOnly("#daemon-chat-card");
    const titleText =
      peer.alias || peer.hostname ||
      (peer.short_id ? `Device ${peer.short_id}` : null) ||
      (peer.fingerprint
        ? peer.fingerprint.replace(/^sha256:/, "").slice(0, 12)
        : "Chat");
    text($("#daemon-chat-title"), titleText);
    text($("#daemon-chat-meta"),
      `${peer.fingerprint || ""}`);
    // 2026-05-23: refresh compose state for the new peer. Clear
    // any prior draft + status, enable Send only after the input
    // has content. Also hide the peer-info panel — stale alias /
    // mute values from a previous peer would otherwise leak.
    const input = $("#daemon-chat-input");
    const searchInput = $("#daemon-chat-search-input");
    const searchBtn = $("#btn-daemon-chat-search");
    const attachBtn = $("#btn-daemon-chat-attach");
    const sendBtn = $("#btn-daemon-chat-send");
    const sendStatus = $("#daemon-chat-send-status");
    if (input) input.value = "";
    if (input) {
      input.disabled = false;
      input.placeholder = "Message";
    }
    if (attachBtn) attachBtn.disabled = false;
    if (searchBtn) searchBtn.disabled = false;
    if (searchInput) {
      searchInput.value = "";
      searchInput.disabled = false;
      searchInput.placeholder = "Search this chat";
    }
    _clearDaemonReply();
    if (sendStatus) sendStatus.textContent = "";
    if (sendBtn) sendBtn.disabled = true;
    const infoPanel = $("#daemon-chat-peer-info");
    if (infoPanel) infoPanel.hidden = true;
    const peerSettings = $("#daemon-chat-peer-settings");
    const groupSettings = $("#daemon-chat-group-settings");
    if (peerSettings) peerSettings.hidden = false;
    if (groupSettings) groupSettings.hidden = true;
    const log = $("#daemon-chat-log");
    if (!log) return;
    log.innerHTML = "";
    const loading = document.createElement("p");
    loading.className = "help";
    loading.textContent = "Fetching messages…";
    log.appendChild(loading);
    let msgs;
    try {
      msgs = await fetchDaemonMessages(peer.fingerprint, 50);
    } catch (e) {
      loading.textContent =
        `Couldn't fetch messages: ${e && e.message ? e.message : e}`;
      return;
    }
    log.innerHTML = "";
    if (!msgs.length) {
      const empty = document.createElement("p");
      empty.className = "help";
      empty.textContent = "No messages yet.";
      log.appendChild(empty);
    } else {
      for (const m of msgs) _renderDaemonMessageBubble(log, m);
      log.scrollTop = log.scrollHeight;
    }
    if (input) input.focus();
  }

  async function _openDaemonGroupChat(group) {
    if (!group || !group.group_id) return;
    state.daemon_active_peer = null;
    state.daemon_active_group = group;
    _clearDaemonReply();
    _showOnly("#daemon-chat-card");
    text($("#daemon-chat-title"), group.name || "Group");
    text($("#daemon-chat-meta"), `${group.member_count || 0} members`);
    const input = $("#daemon-chat-input");
    const searchInput = $("#daemon-chat-search-input");
    const searchBtn = $("#btn-daemon-chat-search");
    const sendBtn = $("#btn-daemon-chat-send");
    const attachBtn = $("#btn-daemon-chat-attach");
    const sendStatus = $("#daemon-chat-send-status");
    if (input) {
      input.value = "";
      input.disabled = false;
      input.placeholder = "Message group";
    }
    if (searchInput) {
      searchInput.value = "";
      searchInput.disabled = false;
      searchInput.placeholder = "Search this group";
    }
    if (searchBtn) searchBtn.disabled = false;
    if (sendBtn) sendBtn.disabled = true;
    if (attachBtn) attachBtn.disabled = true;
    if (sendStatus) sendStatus.textContent = "";
    const infoPanel = $("#daemon-chat-peer-info");
    const peerSettings = $("#daemon-chat-peer-settings");
    const groupSettings = $("#daemon-chat-group-settings");
    if (infoPanel) infoPanel.hidden = true;
    if (peerSettings) peerSettings.hidden = true;
    if (groupSettings) groupSettings.hidden = false;
    const log = $("#daemon-chat-log");
    if (!log) return;
    log.innerHTML = "";
    const loading = document.createElement("p");
    loading.className = "help";
    loading.textContent = "Fetching group messages...";
    log.appendChild(loading);
    let msgs;
    try {
      msgs = await fetchDaemonGroupMessages(group.group_id, 50);
    } catch (e) {
      loading.textContent =
        `Couldn't fetch group messages: ${e && e.message ? e.message : e}`;
      return;
    }
    log.innerHTML = "";
    if (!msgs.length) {
      const empty = document.createElement("p");
      empty.className = "help";
      empty.textContent = "No group messages yet.";
      log.appendChild(empty);
    } else {
      for (const m of msgs) _renderDaemonMessageBubble(log, m);
      log.scrollTop = log.scrollHeight;
    }
  }

  // 2026-05-23: send a chat message from the phone to a daemon-side
  // peer via the live DC. Mirrors the desktop /api/send wire shape:
  // peer is identified by fingerprint, body is plain text (<=64KiB).
  // client_msg_id lets us paint an optimistic bubble that the
  // server's eventual echo can reconcile against.
