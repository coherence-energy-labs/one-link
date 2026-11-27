  async function sendDaemonMessage(peerFp, body, opts) {
    const o = opts || {};
    return _daemonRequest("send_message", {
      peer_fp: peerFp,
      body,
      reply_to: o.reply_to || null,
      client_msg_id: o.client_msg_id || _randomHexId(),
    });
  }

  function _randomHexId() {
    // 16 bytes → 32 hex chars; matches the daemon's client_msg_id
    // validator (8 ≤ len ≤ 64, hex+dash). crypto.getRandomValues is
    // present on every supported browser-as-peer target.
    const buf = new Uint8Array(16);
    crypto.getRandomValues(buf);
    return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  async function _handleDaemonChatSend() {
    const peer = state.daemon_active_peer;
    const group = state.daemon_active_group;
    const input = $("#daemon-chat-input");
    const sendBtn = $("#btn-daemon-chat-send");
    const sendStatus = $("#daemon-chat-send-status");
    if ((!peer || !peer.fingerprint) && (!group || !group.group_id)) return;
    if (!input) return;
    const body = (input.value || "").trim();
    if (!body) return;
    sendBtn && (sendBtn.disabled = true);
    sendStatus && (sendStatus.textContent = "Sending…");
    const optimisticId = _randomHexId();
    const replyTo = state.daemon_reply_to;
    const log = $("#daemon-chat-log");
    // Optimistic bubble — replaced by server echo on next refresh
    // OR left in place if the server confirms a matching id.
    _renderDaemonMessageBubble(log, {
      id: optimisticId,
      ts_ms: Date.now(),
      direction: "outbound",
      body,
      msg_type: "text",
      reply_to: replyTo && replyTo.id,
    });
    if (log) log.scrollTop = log.scrollHeight;
    try {
      let reply;
      if (group && group.group_id) {
        reply = await sendDaemonGroupMessage(group.group_id, body, {
          reply_to: replyTo && replyTo.id,
        });
      } else {
        reply = await sendDaemonMessage(peer.fingerprint, body, {
          client_msg_id: optimisticId,
          reply_to: replyTo && replyTo.id,
        });
      }
      if (reply && reply.queued) {
        sendStatus && (sendStatus.textContent =
          "Peer is offline. Queued for delivery when they come back.");
      } else {
        sendStatus && (sendStatus.textContent = "Sent");
      }
      input.value = "";
      _clearDaemonReply();
      // Pull the canonical view from the daemon to reconcile the
      // optimistic bubble with the persisted record.
      try {
        const msgs = group && group.group_id
          ? await fetchDaemonGroupMessages(group.group_id, 50)
          : await fetchDaemonMessages(peer.fingerprint, 50);
        if (log) {
          log.innerHTML = "";
          for (const m of msgs) _renderDaemonMessageBubble(log, m);
          log.scrollTop = log.scrollHeight;
        }
      } catch (_e) { /* reconcile best-effort */ }
    } catch (e) {
      sendStatus && (sendStatus.textContent =
        `Couldn't send: ${e && e.message ? e.message : e}`);
    } finally {
      sendBtn && (sendBtn.disabled = !((input.value || "").trim()));
      input.focus();
    }
  }

  async function _handleDaemonChatSearch() {
    const peer = state.daemon_active_peer;
    const group = state.daemon_active_group;
    const input = $("#daemon-chat-search-input");
    const log = $("#daemon-chat-log");
    if (!input || !log) return;
    const query = input.value.trim();
    if (!query) {
      if (group && group.group_id) await _openDaemonGroupChat(group);
      else if (peer && peer.fingerprint) await _openDaemonChat(peer);
      return;
    }
    if (!(group && group.group_id) && !(peer && peer.fingerprint)) return;
    log.innerHTML = "";
    const loading = document.createElement("p");
    loading.className = "help";
    loading.textContent = "Searching...";
    log.appendChild(loading);
    let msgs;
    try {
      msgs = group && group.group_id
        ? await searchDaemonGroupMessages(group.group_id, query, 50)
        : await searchDaemonMessages(peer.fingerprint, query, 50);
    } catch (e) {
      loading.textContent =
        `Search failed: ${e && e.message ? e.message : e}`;
      return;
    }
    log.innerHTML = "";
    if (!msgs.length) {
      const empty = document.createElement("p");
      empty.className = "help";
      empty.textContent = `No matches for "${query}".`;
      log.appendChild(empty);
      return;
    }
    const summary = document.createElement("p");
    summary.className = "help";
    summary.textContent = `${msgs.length} result${msgs.length === 1 ? "" : "s"} for "${query}".`;
    log.appendChild(summary);
    for (const m of msgs.reverse()) _renderDaemonMessageBubble(log, m);
    log.scrollTop = log.scrollHeight;
  }

  // Wire compose listeners once on DOM-ready. Enter sends, Shift+Enter
  // inserts a newline (standard chat ergonomics).
  $("#btn-daemon-global-search")?.addEventListener("click", _handleDaemonGlobalSearch);
  $("#daemon-global-search-input")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      _handleDaemonGlobalSearch();
    }
  });
  $("#btn-daemon-chat-send")?.addEventListener("click", _handleDaemonChatSend);
  $("#btn-daemon-chat-search")?.addEventListener("click", _handleDaemonChatSearch);
  $("#daemon-chat-search-input")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      _handleDaemonChatSearch();
    }
  });
  $("#daemon-chat-input")?.addEventListener("input", (ev) => {
    const sendBtn = $("#btn-daemon-chat-send");
    if (!sendBtn) return;
    sendBtn.disabled = !((ev.target.value || "").trim());
  });
  $("#daemon-chat-input")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" && !ev.shiftKey) {
      ev.preventDefault();
      _handleDaemonChatSend();
    }
  });

