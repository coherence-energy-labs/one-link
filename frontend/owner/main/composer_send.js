  function _expandSlashCommand(body) {
    const m = body.match(/^\/([a-z]+)(?:\s+(.*))?$/s);
    if (!m) return { body, sideEffect: null };
    const cmd = m[1].toLowerCase();
    const arg = (m[2] || "").trim();
    switch (cmd) {
      case "shrug":      return { body: `${arg ? arg + " " : ""}¯\\_(ツ)_/¯` };
      case "tableflip":  return { body: `${arg ? arg + " " : ""}(╯°□°)╯︵ ┻━┻` };
      case "unflip":     return { body: `${arg ? arg + " " : ""}┬─┬ノ( º _ ºノ)` };
      case "me":         return { body: arg ? `*${arg}*` : body };
      case "lenny":      return { body: `${arg ? arg + " " : ""}( ͡° ͜ʖ ͡°)` };
      case "wave":       return { body: arg ? `${arg} 👋` : "👋" };
      case "lol":        return { body: arg ? `${arg} 😂` : "😂" };
      case "yes":        return { body: arg ? `${arg} ✅` : "✅" };
      case "no":         return { body: arg ? `${arg} ❌` : "❌" };
      case "fix":        return { body: arg ? `${arg} 🔧` : "🔧" };
      case "ship":       return { body: arg ? `${arg} 🚢` : "🚢" };
      case "code":       return { body: arg ? "```\n" + arg + "\n```" : "```\n\n```" };
      case "clear":      return { body: null, sideEffect: "clear-pins" };
      case "help":       return { body: null, sideEffect: "help" };
      case "commands":   return { body: null, sideEffect: "commands" };
      default:           return { body, sideEffect: null };
    }
  }
  // v0.21.x: registry used by the autocomplete popover that pops up
  // when the user types `/`. Keep label / description short.
  const SLASH_REGISTRY = [
    { cmd: "/me",        desc: "Third-person action (italic)" },
    { cmd: "/shrug",     desc: "Append ¯\\_(ツ)_/¯" },
    { cmd: "/tableflip", desc: "Append (╯°□°)╯︵ ┻━┻" },
    { cmd: "/unflip",    desc: "Append ┬─┬ノ( º _ ºノ)" },
    { cmd: "/lenny",     desc: "Append ( ͡° ͜ʖ ͡°)" },
    { cmd: "/wave",      desc: "Append 👋" },
    { cmd: "/lol",       desc: "Append 😂" },
    { cmd: "/yes",       desc: "Append ✅" },
    { cmd: "/no",        desc: "Append ❌" },
    { cmd: "/fix",       desc: "Append 🔧" },
    { cmd: "/ship",      desc: "Append 🚢" },
    { cmd: "/code",      desc: "Wrap argument in a code block" },
    { cmd: "/clear",     desc: "Clear pinned messages in this chat" },
    { cmd: "/help",      desc: "Show keyboard shortcuts" },
    { cmd: "/commands",  desc: "Show this slash-command list" },
  ];

  function _maybeRunSlashSideEffect(name) {
    if (name === "help") {
      $("#shortcuts-backdrop")?.classList.add("show");
    } else if (name === "commands") {
      _openSlashCommandList();
    } else if (name === "clear-pins") {
      // Clear pinned messages for the current conversation.
      const key = state.selectedGroup
        ? `group:${state.selectedGroup}` : `peer:${state.selectedPeer || ""}`;
      try {
        const pins = JSON.parse(localStorage.getItem("one_link.pins") || "{}");
        delete pins[key];
        localStorage.setItem("one_link.pins", JSON.stringify(pins));
        renderPins();
        toast("Pins gone. Fresh start.", "good", 2500);
      } catch (e) {
        toast(`Clear pins failed: ${e.message || e}`, "bad");
      }
    }
  }

  // v0.21.x: long-press on a bubble → bottom-sheet with actions.
  // Listens on touchstart/touchend, fires after 450ms hold. Suppresses
  // the click that follows the long-press release. Mouse users still
  // get the hover toolbar; this is the touch-equivalent.
  function _attachBubbleLongPress(b, msg) {
    let timer = null;
    let triggered = false;
    const cancel = () => {
      if (timer) { clearTimeout(timer); timer = null; }
    };
    b.addEventListener("touchstart", (ev) => {
      if (ev.touches.length > 1) return;
      triggered = false;
      cancel();
      timer = setTimeout(() => {
        triggered = true;
        if (navigator.vibrate) try { navigator.vibrate(20); } catch {}
        _openMsgActionSheet(msg);
      }, 450);
    }, { passive: true });
    b.addEventListener("touchend", () => {
      cancel();
    }, { passive: true });
    b.addEventListener("touchmove", cancel, { passive: true });
    b.addEventListener("touchcancel", cancel);
    b.addEventListener("click", (ev) => {
      if (triggered) {
        ev.preventDefault();
        ev.stopPropagation();
        triggered = false;
      }
    }, true);
  }
  function _openMsgActionSheet(msg) {
    document.querySelectorAll(".msg-action-sheet, .msg-action-sheet-backdrop")
      .forEach((n) => n.remove());
    const back = el("div", "msg-action-sheet-backdrop");
    const sheet = el("div", "msg-action-sheet");
    sheet.appendChild(el("div", "mas-handle"));
    const actions = el("div", "mas-actions");
    function add(icon, label, fn) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "mas-btn";
      b.innerHTML = `<span class="mas-icon">${icon}</span><span>${_escapeHtml(label)}</span>`;
      b.onclick = (ev) => { ev.stopPropagation(); close(); fn(); };
      actions.appendChild(b);
    }
    function close() {
      sheet.classList.remove("show");
      setTimeout(() => { sheet.remove(); back.remove(); }, 200);
    }
    back.onclick = close;
    add("↩", "Reply", () => setReplyTo(msg));
    add("+", "React", () => _openReactionFullPicker(document.body, msg));
    add("⎘", "Copy", async () => {
      const txt = msg.t === "TEXT" ? (msg.body || "") : (msg.name || "");
      try { await navigator.clipboard.writeText(txt); toast("Copied.", "good"); }
      catch { toast("Couldn't copy.", "info"); }
    });
    add(isStarred(msg) ? "⭐" : "☆", isStarred(msg) ? "Unstar" : "Star",
      () => toggleStar(msg));
    add(isPinned(msg) ? "★" : "☆", isPinned(msg) ? "Unpin" : "Pin",
      () => togglePin(msg));
    add("↪", "Forward", () => {
      // openForwardPicker reads from _selectedMessages — seed
      // the selection with just this message so the forward
      // flow has the right input.
      enterSelection(msg.id);
      openForwardPicker();
    });
    if (msg.dir === "out" && !msg.deleted) {
      const ageMs = Date.now() - (msg.ts || 0);
      if (ageMs < 5 * 60 * 1000 && msg.t === "TEXT") {
        add("✎", "Edit", () => startEditMessage(msg));
      }
      add("🗑", "Delete", () => deleteMessage(msg));
    }
    sheet.appendChild(actions);
    document.body.appendChild(back);
    document.body.appendChild(sheet);
    requestAnimationFrame(() => sheet.classList.add("show"));
  }
  // v0.21.x: open a centered list of every available slash command.
  // Triggered by /commands and by a help link in the bottom-sheet
  // on mobile.
  function _openSlashCommandList() {
    document.querySelectorAll(".slash-help-modal").forEach((m) => m.remove());
    const m = el("div", "slash-help-modal");
    m.innerHTML = `
      <div class="shm-backdrop" data-shm-close></div>
      <div class="shm-pane">
        <h2 class="shm-title">Slash commands</h2>
        <ul class="shm-list"></ul>
        <div class="shm-actions">
          <button type="button" class="shm-close">Got it</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
    const list = m.querySelector(".shm-list");
    for (const { cmd, desc } of SLASH_REGISTRY) {
      const li = document.createElement("li");
      li.innerHTML = `<code>${cmd}</code> <span>${_escapeHtml(desc)}</span>`;
      list.appendChild(li);
    }
    const close = () => m.remove();
    m.querySelector(".shm-close").onclick = close;
    m.addEventListener("click", (ev) => {
      if (ev.target.hasAttribute("data-shm-close")) close();
    });
    document.addEventListener("keydown", function esc(ev) {
      if (ev.key === "Escape") { close(); document.removeEventListener("keydown", esc); }
    });
  }

  async function sendCurrent() {
    // Every trigger (Enter, Ctrl+Enter, Send button, accessibility click,
    // programmatic call) converges here.  Set the mutex synchronously, before
    // any await, so key-repeat and double-click cannot capture the same intent.
    if (state.composerSendInFlight) return;
    state.composerSendInFlight = true;
    refreshSendEnabled();
    try {
    // v0.10.5 bonus: expand slash commands BEFORE branching so
    // /shrug works in both 1:1 and group threads.
    const rawInput = $("#input").value.trim();
    const expanded = _expandSlashCommand(rawInput);
    if (expanded.sideEffect) {
      _maybeRunSlashSideEffect(expanded.sideEffect);
      $("#input").value = "";
      return;
    }
    if (expanded.body !== null && expanded.body !== rawInput) {
      $("#input").value = expanded.body;
    }
    // v0.8.0: branch on whether the user is in a group or 1:1.
    if (state.selectedGroup) {
      const groupId = state.selectedGroup;
      const body = $("#input").value.trim();
      if (!body) return;
      const replyToId = (
        state.replyTo && state.replyTo.group_id === groupId
      ) ? state.replyTo.id : null;
      // Capture + clear the exact intent before the first network await.  Text
      // typed after this point belongs to the next intent and is never erased
      // by this send's completion.
      $("#input").value = "";
      $("#input").style.height = "auto";
      clearActiveDraft();
      clearReplyTo();
      refreshSendEnabled();
      try {
        const sendBody = { body };
        if (replyToId) sendBody.reply_to = replyToId;
        await api.post(`/api/groups/${groupId}/send`, sendBody);
        // Refresh from state so the new message lands in the pane.
        const r = await api.get(
          `/api/groups/${groupId}/messages?limit=200`
        );
        // Do not paint this result into a different group if the user switched
        // conversations while the request was in flight.
        if (state.selectedGroup === groupId) {
          messageStore.replaceGroup(r.messages || []);
          _forceNextMessagesToBottom();
          renderGroupConversation();
        }
      } catch (e) {
        toast(`Group send failed: ${errorToastBody(e)}`, "bad", 8000);
      }
      return;
    }
    // v0.21.x - bulletproof send path. Previous behavior silently
    // returned when state.selectedPeer was unset (e.g. focus drifted
    // during a call, peer list refreshed mid-keystroke). User got no
    // feedback and assumed the message sent. NEVER swallow Enter
    // without telling the user what happened.
    if (!state.selectedPeer) {
      // Try to recover the intended peer from the visible chat header
      // or the last-selected fingerprint persisted at boot.
      const recovered = (function () {
        // Last-selected from localStorage (saved on every selectPeer).
        try {
          const raw = localStorage.getItem("one_link.last_selection");
          if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed.kind === "peer" && parsed.id) {
              const p = state.peers.get(parsed.id);
              if (p && p.trust !== "rejected") return parsed.id;
            }
          }
        } catch (_) { /* fall through */ }
        // First pinned online peer as a sane fallback.
        for (const p of state.peers.values()) {
          if (p.trust === "pinned" && p.online) return p.short_id;
        }
        return null;
      })();
      if (recovered) {
        selectPeer(recovered);
      } else {
        toast(
          "Pick a device first - tap a name in the left sidebar to start.",
          "info", 5000,
        );
        return;
      }
    }
    const intentPeerId = state.selectedPeer;
    const peer = state.peers.get(intentPeerId);
    if (!peer) {
      toast(
        "That device just dropped off the network. Try again in a moment.",
        "info", 5000,
      );
      return;
    }
    if (peer.trust === "rejected") {
      toast("This device is blocked. Use Allow device first.", "bad");
      return;
    }
    const body = _convertEmoticons(input.value.trim());
    const filesToSend = state.staged.slice();
    if (!body && filesToSend.length === 0) {
      // Don't silently no-op an Enter on an empty input - the user
      // probably hit Enter to send a paste that didn't land in the
      // textarea. Surface that.
      toast("Nothing to send - type or paste your message first.", "info", 3000);
      return;
    }

    const replyToId = (
      state.replyTo && state.replyTo.peer === intentPeerId
    ) ? state.replyTo.id : null;
    const capturedStagedIds = new Set(filesToSend.map((item) => item.id));
    // Atomically consume only the captured intent before the first await.
    // stageFile() calls that finish while this send is in flight append new
    // objects with different ids; the filter deliberately preserves them.
    input.value = "";
    input.style.height = "auto";
    state.staged = state.staged.filter(
      (item) => !capturedStagedIds.has(item.id)
    );
    clearActiveDraft();
    clearReplyTo();
    renderStaging();

    sendBtn.disabled = true;
    try {
      if (body) {
        // v0.21.x bulletproof send (round 2): paint an optimistic
        // outbound bubble in the chat pane IMMEDIATELY, clear the
        // composer IMMEDIATELY, then fire the API in the background
        // with a hard 25s timeout. Three failure modes that used to
        // hang the user forever — wedged channel, dead peer, lost
        // network — now visibly mark the bubble as queued/failed so
        // they always know what happened and can hit Retry. Never
        // again "I clicked Send and nothing happened".
        const clientMsgId = _newClientMsgId();
        const optimistic = {
          id: clientMsgId,
          t: "TEXT",
          body,
          ts: Date.now(),
          dir: "out",
          peer: intentPeerId,
          peer_fp: peer.fingerprint,
          _sendingState: "sending",
          _attempts: 1,
        };
        if (replyToId) optimistic.reply_to = replyToId;
        messageStore.appendDirect(optimistic);
        _forceNextMessagesToBottom();
        // Clear composer up-front so the bubble is visible where it
        // landed — no "did it send?" ambiguity.
        renderMessages();
        // v0.21.x: first-send celebration. The first message ever
        // sent to a given peer gets a one-time ✨ glow on the bubble.
        // Persists per-peer in localStorage so subsequent sends
        // don't repeat the moment.
        _maybeCelebrateFirstSend(optimistic);
        try {
          const sendBody = {
            peer: intentPeerId,
            body,
            client_msg_id: clientMsgId,
          };
          if (replyToId) sendBody.reply_to = replyToId;
          // v0.14.0: outbox-on-fail. Network errors / client timeouts
          // queue the payload into IDB; the SW drains when online.
          // v0.21.x: hard 25s timeout — slightly past the server's
          // 20s wait_for so a hung server still triggers the queue
          // path on the client before AbortError bubbles up.
          const result = await _sendWithOutbox(
            "/api/send", sendBody, { timeoutMs: 25000 },
          );
          if (result && result.ok === false) {
            // Structured soft-failure (capability_disabled, etc).
            // Mark the bubble failed inline with a Retry button so
            // the user sees the exact reason on the bubble itself
            // AND still gets the toast.
            _markBubbleState(clientMsgId, "failed", {
              _error: result.user_message || result.error || "Message couldn't be sent.",
            });
            toast(
              result.user_message
                || result.error
                || "Message couldn't be sent. Try again.",
              "bad", 8000,
            );
          } else if (result && result.queued) {
            // 202: server queued (peer offline / timeout / transient).
            // Plumb the daemon's user-facing copy ("Could not
            // establish a secure connection…" / "The other device
            // didn't respond in time" / etc.) onto the bubble so the
            // user sees the actual reason. The generic "Will send
            // when the path is healthy" line was confusing when
            // presence said "online" — presence is mDNS-level, the
            // actual wire path can still be desynced.
            const tx = result.after_failure || {};
            _markBubbleState(clientMsgId, "queued", {
              _queueReason: result.reason || null,
              _queueDetail: tx.error || null,
              _queueHint: tx.hint || null,
            });
          } else {
            // Success: daemon will broadcast the persisted event via
            // WS; the m.type === "msg" handler reconciles by id
            // (replaces the optimistic record with the canonical
            // one). If for any reason the echo never arrives, the
            // optimistic bubble stays as a faithful local record.
            // Either way the user sees their message.
            _markBubbleState(clientMsgId, "sent");
          }
        } catch (e) {
          // Truly unexpected (non-network, non-timeout) exception.
          // Bubble stays as "failed" with Retry; toast surfaces the
          // detail.
          _markBubbleState(clientMsgId, "failed", {
            _error: errorToastBody(e),
          });
          toast(errorToastBody(e), "bad", 8000);
        }
      }
      // Track every upload promise.  Fire-and-forget meant sendCurrent could
      // release its mutex while the captured intent was still dispatching,
      // which made a second Enter race a duplicate FILE_OFFER.
      const uploadResults = await Promise.allSettled(filesToSend.map((s) => uploadFile(s.file, {
        peerId: intentPeerId,
        clientDeliveryId: s.clientDeliveryId,
        ...(s.relPath ? { relPath: s.relPath } : {}),
      })));
      const failedStages = filesToSend.filter(
        (_staged, index) => {
          const settled = uploadResults[index];
          return settled?.status === "rejected"
            || settled?.value?._uploadFailed === true;
        }
      );
      if (failedStages.length) {
        // A lost HTTP response must remain retryable as the *same* browser
        // intent.  Reinsert the captured object (same File, relPath, and
        // clientDeliveryId), while leaving anything staged during this await
        // untouched.  The backend will replay a committed result or resume
        // the exact durable transfer instead of minting another offer.
        const stagedIds = new Set(state.staged.map((item) => item.id));
        const stagedDeliveryIds = new Set(
          state.staged.map((item) => item.clientDeliveryId)
        );
        for (const failed of failedStages) {
          if (
            !stagedIds.has(failed.id)
            && !stagedDeliveryIds.has(failed.clientDeliveryId)
          ) {
            state.staged.push(failed);
            stagedIds.add(failed.id);
            stagedDeliveryIds.add(failed.clientDeliveryId);
          }
        }
        renderStaging();
        toast(
          `${failedStages.length} file${failedStages.length === 1 ? "" : "s"} stayed staged for an exact safe retry.`,
          "info", 6000,
        );
      }
    } finally {
      refreshSendEnabled();
      input.focus();
    }
    } finally {
      state.composerSendInFlight = false;
      refreshSendEnabled();
      input.focus();
    }
  }

