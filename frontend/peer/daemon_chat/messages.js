  function _renderDaemonMessageBubble(host, m) {
    if (!host) return;
    const bubble = document.createElement("div");
    bubble.dataset.msgId = m.id || "";
    bubble.style.maxWidth = "85%";
    bubble.style.padding = "8px 12px";
    bubble.style.borderRadius = "12px";
    bubble.style.whiteSpace = "pre-wrap";
    bubble.style.wordBreak = "break-word";
    if (m.direction === "out") {
      bubble.style.alignSelf = "flex-end";
      bubble.style.background = "var(--accent)";
      bubble.style.color = "white";
    } else {
      bubble.style.alignSelf = "flex-start";
      bubble.style.background = "var(--bg-1)";
      bubble.style.color = "var(--text)";
      bubble.style.border = "1px solid var(--line)";
    }
    // 2026-05-23 phase A file-RECEIVE: file messages render an
    // inline file bubble with name + size + Download button (or
    // status for incomplete transfers). The daemon's fetch_messages
    // surfaces a `file` field with {name, size, blob_hash, mime}
    // when msg_type ∈ {FILE, FILE_DONE, FILE_OFFER}.
    const upperType = (m.msg_type || "").toUpperCase();
    const isFileMsg = upperType === "FILE" || upperType === "FILE_DONE"
                      || upperType === "FILE_OFFER";
    if (isFileMsg && m.file) {
      _renderFileBubbleBody(bubble, m);
    } else {
      if (m.reply_to) {
        const quote = document.createElement("div");
        quote.textContent = `Reply to ${String(m.reply_to).slice(0, 12)}`;
        quote.style.borderLeft = "3px solid currentColor";
        quote.style.opacity = "0.7";
        quote.style.paddingLeft = "8px";
        quote.style.marginBottom = "6px";
        quote.style.fontSize = "12px";
        bubble.appendChild(quote);
      }
      const body = document.createElement("div");
      if (m.deleted_at_ms) {
        body.textContent = "(deleted)";
        body.style.fontStyle = "italic";
        body.style.opacity = "0.7";
      } else {
        body.textContent = m.body || "";
      }
      bubble.appendChild(body);
    }
    const meta = document.createElement("div");
    meta.style.fontSize = "10px";
    meta.style.opacity = "0.6";
    meta.style.marginTop = "4px";
    meta.style.textAlign = m.direction === "out" ? "right" : "left";
    let timeStr = "";
    if (m.ts_ms) {
      try { timeStr = new Date(m.ts_ms).toLocaleString(); } catch {}
    }
    let metaText = timeStr;
    if (m.edited_at_ms) metaText += " · edited";
    meta.textContent = metaText;
    bubble.appendChild(meta);
    _renderDaemonReactionRow(bubble, m);
    _renderDaemonMessageActions(bubble, m);
    host.appendChild(bubble);
  }

  function _renderDaemonReactionRow(bubble, m) {
    if (!bubble || !m || m.deleted_at_ms) return;
    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.flexWrap = "wrap";
    row.style.gap = "5px";
    row.style.marginTop = "6px";
    const reactions = m.reactions || {};
    for (const [emoji, peers] of Object.entries(reactions)) {
      const chip = document.createElement("span");
      chip.textContent = `${emoji} ${Array.isArray(peers) ? peers.length : 1}`;
      chip.style.fontSize = "11px";
      chip.style.padding = "2px 6px";
      chip.style.borderRadius = "999px";
      chip.style.background = "rgba(255,255,255,.10)";
      row.appendChild(chip);
    }
    if (
      !(state.daemon_active_peer && state.daemon_active_peer.fingerprint)
      && !(state.daemon_active_group && state.daemon_active_group.group_id)
    ) {
      if (row.childNodes.length) bubble.appendChild(row);
      return;
    }
    for (const emoji of ["👍", "❤️", "😂", "🎉"]) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = emoji;
      btn.title = `React ${emoji}`;
      btn.ariaLabel = `React ${emoji}`;
      btn.style.border = "1px solid var(--line)";
      btn.style.borderRadius = "999px";
      btn.style.background = "transparent";
      btn.style.color = "inherit";
      btn.style.padding = "2px 7px";
      btn.style.fontSize = "13px";
      btn.style.minHeight = "28px";
      btn.addEventListener("click", async () => {
        const peer = state.daemon_active_peer;
        const group = state.daemon_active_group;
        if (!m.id) return;
        btn.disabled = true;
        try {
          const msgs = group && group.group_id
            ? (
              await reactDaemonGroupMessage(group.group_id, m.id, emoji, "add"),
              await fetchDaemonGroupMessages(group.group_id, 50)
            )
            : (
              await reactDaemonMessage(peer.fingerprint, m.id, emoji, "add"),
              await fetchDaemonMessages(peer.fingerprint, 50)
            );
          const log = $("#daemon-chat-log");
          if (log) {
            log.innerHTML = "";
            for (const rowMsg of msgs) _renderDaemonMessageBubble(log, rowMsg);
            log.scrollTop = log.scrollHeight;
          }
        } catch (e) {
          text($("#daemon-chat-send-status"),
            `Reaction failed: ${e && e.message ? e.message : e}`);
          btn.disabled = false;
        }
      });
      row.appendChild(btn);
    }
    bubble.appendChild(row);
  }

  function _renderDaemonMessageActions(bubble, m) {
    if (!bubble || !m || m.deleted_at_ms) return;
    const row = document.createElement("div");
    row.style.display = "flex";
    row.style.gap = "6px";
    row.style.marginTop = "6px";
    const direction = String(m.direction || "").toLowerCase();
    const actions = ["Reply"];
    if (direction === "out" || direction === "outbound") {
      actions.push("Edit", "Delete");
    }
    for (const action of actions) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = action;
      btn.style.border = "1px solid var(--line)";
      btn.style.borderRadius = "999px";
      btn.style.background = "transparent";
      btn.style.color = "inherit";
      btn.style.padding = "3px 8px";
      btn.style.fontSize = "11px";
      btn.style.minHeight = "28px";
      btn.addEventListener("click", async () => {
        const peer = state.daemon_active_peer;
        const group = state.daemon_active_group;
        if (!m.id) return;
        if (action === "Reply") {
          _setDaemonReply(m);
        } else if (group && group.group_id) {
          if (action === "Edit") {
            const next = prompt("Edit message", m.body || "");
            if (next == null || !next.trim() || next === (m.body || "")) return;
            await _mutateDaemonGroupMessage(
              () => editDaemonGroupMessage(group.group_id, m.id, next.trim()),
              group.group_id,
            );
          } else {
            if (!confirm("Delete this message?")) return;
            await _mutateDaemonGroupMessage(
              () => deleteDaemonGroupMessage(group.group_id, m.id),
              group.group_id,
            );
          }
        } else if (!peer || !peer.fingerprint) {
          return;
        } else if (action === "Edit") {
          const next = prompt("Edit message", m.body || "");
          if (next == null || !next.trim() || next === (m.body || "")) return;
          await _mutateDaemonMessage(
            () => editDaemonMessage(peer.fingerprint, m.id, next.trim()),
            peer.fingerprint,
          );
        } else {
          if (!confirm("Delete this message?")) return;
          await _mutateDaemonMessage(
            () => deleteDaemonMessage(peer.fingerprint, m.id),
            peer.fingerprint,
          );
        }
      });
      row.appendChild(btn);
    }
    bubble.appendChild(row);
  }

  async function _mutateDaemonMessage(fn, peerFp) {
    const status = $("#daemon-chat-send-status");
    try {
      status && (status.textContent = "Updating...");
      await fn();
      const msgs = await fetchDaemonMessages(peerFp, 50);
      const log = $("#daemon-chat-log");
      if (log) {
        log.innerHTML = "";
        for (const rowMsg of msgs) _renderDaemonMessageBubble(log, rowMsg);
        log.scrollTop = log.scrollHeight;
      }
      status && (status.textContent = "Updated");
    } catch (e) {
      status && (status.textContent =
        `Update failed: ${e && e.message ? e.message : e}`);
    }
  }

  async function _mutateDaemonGroupMessage(fn, groupId) {
    const status = $("#daemon-chat-send-status");
    try {
      status && (status.textContent = "Updating...");
      await fn();
      const msgs = await fetchDaemonGroupMessages(groupId, 50);
      const log = $("#daemon-chat-log");
      if (log) {
        log.innerHTML = "";
        for (const rowMsg of msgs) _renderDaemonMessageBubble(log, rowMsg);
        log.scrollTop = log.scrollHeight;
      }
      status && (status.textContent = "Updated");
    } catch (e) {
      status && (status.textContent =
        `Update failed: ${e && e.message ? e.message : e}`);
    }
  }

  function _setDaemonReply(m) {
    state.daemon_reply_to = {
      id: String(m.id || ""),
      body: String(m.body || m.file?.name || "(message)").slice(0, 160),
    };
    _renderDaemonReplyBar();
    $("#daemon-chat-input")?.focus();
  }

  function _clearDaemonReply() {
    state.daemon_reply_to = null;
    _renderDaemonReplyBar();
  }

  function _renderDaemonReplyBar() {
    const bar = $("#daemon-chat-reply-bar");
    const preview = $("#daemon-chat-reply-preview");
    if (!bar) return;
    const reply = state.daemon_reply_to;
    bar.hidden = !reply;
    if (preview) preview.textContent = reply ? reply.body : "";
  }

  $("#btn-daemon-chat-back")?.addEventListener("click", () => {
    state.daemon_active_peer = null;
    state.daemon_active_group = null;
    _clearDaemonReply();
    _showOnly("#daemon-roster-card");
  });
  $("#btn-daemon-chat-reply-cancel")?.addEventListener("click", _clearDaemonReply);

