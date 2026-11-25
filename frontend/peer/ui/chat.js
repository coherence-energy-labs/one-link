  // ── chat UI ────────────────────────────────────────────────────────

  function _appendChatBubble(rec) {
    const log = $("#chat-log");
    if (!log) return;
    const bubble = document.createElement("div");
    bubble.dataset.msgId = rec.id;
    bubble.style.maxWidth = "85%";
    bubble.style.padding = "8px 12px";
    bubble.style.borderRadius = "12px";
    bubble.style.whiteSpace = "pre-wrap";
    bubble.style.wordBreak = "break-word";
    if (rec.direction === "out") {
      bubble.style.alignSelf = "flex-end";
      bubble.style.background = "var(--accent)";
      bubble.style.color = "white";
    } else {
      bubble.style.alignSelf = "flex-start";
      bubble.style.background = "var(--bg-1)";
      bubble.style.color = "var(--text)";
      bubble.style.border = "1px solid var(--line)";
    }
    const body = document.createElement("div");
    body.textContent = rec.body;
    bubble.appendChild(body);
    const meta = document.createElement("div");
    meta.style.fontSize = "10px";
    meta.style.opacity = "0.6";
    meta.style.marginTop = "4px";
    meta.style.textAlign = rec.direction === "out" ? "right" : "left";
    const timeStr = new Date(rec.ts).toLocaleTimeString();
    if (rec.direction === "out") {
      meta.textContent = rec.ack_ms ? `${timeStr} · delivered` : timeStr;
    } else {
      meta.textContent = timeStr;
    }
    bubble.appendChild(meta);
    log.appendChild(bubble);
    log.scrollTop = log.scrollHeight;
  }

  function _markBubbleAcked(id) {
    const log = $("#chat-log");
    if (!log) return;
    const bubble = log.querySelector(`[data-msg-id="${CSS.escape(id)}"]`);
    if (!bubble) return;
    const meta = bubble.querySelector("div:last-child");
    if (meta && !meta.textContent.includes("delivered")) {
      meta.textContent = `${meta.textContent} · delivered`;
    }
  }

  async function _showChatCard() {
    const p = state.pairing;
    if (!p || !p.remote_hello) return;
    show($("#chat-card"));
    const peer = p.remote_hello;
    text($("#chat-peer-line"),
      `Connected to ${peer.fingerprint}. Messages stay encrypted in transit (DTLS) and persist locally.`);
    const log = $("#chat-log");
    if (log) {
      log.innerHTML = "";
      try {
        const history = await loadMessages(peer.fingerprint, { limit: 200 });
        for (const rec of history) _appendChatBubble(rec);
      } catch (e) {
        const err = document.createElement("p");
        err.textContent = `Couldn't load history: ${e && e.message ? e.message : e}`;
        err.className = "help";
        log.appendChild(err);
      }
    }
  }

  $("#btn-chat-send")?.addEventListener("click", async () => {
    const input = $("#chat-input");
    if (!input) return;
    const body = input.value;
    if (!body || !body.trim()) return;
    const btn = $("#btn-chat-send");
    if (btn) btn.disabled = true;
    text($("#chat-status"), "");
    try {
      const rec = await sendChatMessage(body);
      input.value = "";
      _appendChatBubble(rec);
      if (rec.queued) {
        text(
          $("#chat-status"),
          "Saved locally. Waiting for a verified reconnect before replay.",
        );
      }
    } catch (e) {
      text($("#chat-status"),
        `Send failed: ${e && e.message ? e.message : e}`);
    } finally {
      if (btn) btn.disabled = false;
      input.focus();
    }
  });

  $("#chat-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      $("#btn-chat-send")?.click();
    }
  });

  // Wire chat-receive into the control-channel router. Pair
  // protocol stays separate (already routed above); chat protocol
  // routes here.
  const _origRouteControlMessage = _routeControlMessage;
  // eslint-disable-next-line no-func-assign
  _routeControlMessage = function (session, kind, data) {
    _origRouteControlMessage(session, kind, data);
    if (kind !== "control") return;
    const pairing = state.pairing;
    if (!pairing || pairing.session !== session || !pairing.persisted ||
        pairing.local_confirm !== true || pairing.remote_confirm !== true) {
      return;
    }
    let msg;
    try {
      msg = typeof data === "string" ? JSON.parse(data) : null;
    } catch {
      return;
    }
    if (!msg || msg.v !== MSG_PROTOCOL_VERSION) return;
    if (msg.t === "text") {
      _onChatTextReceived(msg).catch((error) => {
        console.error("durable chat receive failed", error);
      });
    } else if (msg.t === "ack") {
      _onChatAckReceived(msg).catch((error) => {
        console.error("durable chat ack update failed", error);
      });
    }
  };

  // Open the chat card automatically once finalize-pairing
  // succeeds. The hook lives inside _maybeFinalizePairing — wrap
  // it so we don't lose any of the existing post-finalize work.
  const _origMaybeFinalizePairing = _maybeFinalizePairing;
  // eslint-disable-next-line no-func-assign
  _maybeFinalizePairing = async function () {
    await _origMaybeFinalizePairing();
    const p = state.pairing;
    if (p && p.persisted && p.finished &&
        p.remote_confirm === true && p.local_confirm === true) {
      await _showChatCard();
      try {
        const replay = await drainChatOutbox(p);
        if (replay.sent_ids.length > 0) {
          text(
            $("#chat-status"),
            `Replayed ${replay.sent_ids.length} saved message${
              replay.sent_ids.length === 1 ? "" : "s"
            } on this verified session.`,
          );
        }
      } catch (error) {
        text(
          $("#chat-status"),
          `Saved messages remain queued: ${
            error && error.message ? error.message : error
          }`,
        );
      }
    }
  };

