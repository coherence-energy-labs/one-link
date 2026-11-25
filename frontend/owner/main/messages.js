  // ── Render: messages ───────────────────────────────────────────────
  function _messageRenderHash(peer, messages, transfersById, searchActive) {
    const parts = [`peer=${peer || ""}`, `search=${searchActive ? 1 : 0}`];
    for (const msg of messages) {
      const blob = (msg.blob || "").toLowerCase();
      let transferSig = "";
      if (blob && (msg.t === "FILE_OFFER" || msg.t === "FILE_DONE")) {
        for (const t of transfersById.values()) {
          if (t.direction === msg.dir && (t.blob_hash || "").toLowerCase() === blob) {
            transferSig = [
              t.id, t.status, t.progress_bytes, t.total_bytes,
              t.progress_pct, t.updated_ms,
            ].join(":");
            break;
          }
        }
      }
      parts.push([
        msg.id || "", msg.t || "", msg.dir || "", msg.ts || "",
        msg.body || "", msg.name || "", msg.size || "", blob,
        msg.ok == null ? "" : msg.ok, msg.path || "", transferSig,
        // v0.21.x: include send-state so optimistic→sent/queued/
        // failed transitions actually re-render (the bubble's
        // status pill + Retry button depend on it). _queueDetail
        // and _queueHint feed the per-bubble user-facing copy
        // pulled from the daemon's translated error.
        msg._sendingState || "",
        msg._error ? "e1" : "",
        msg._queueReason || "",
        msg._queueDetail ? "d1" : "",
        // v0.21.x: CALL_LOG entries (missed / ended call bubbles)
        // need to participate in the hash so they re-render when
        // an outcome flips (e.g., user clicked Call back).
        msg.call_outcome || "", msg.call_end_label || "",
      ].join("|"));
    }
    return parts.join("\u001f");
  }

  // ── v0.21.1 smart scroll-to-bottom + new-message pill ───────────
  //
  // The conversation surface (#messages) used to unconditionally
  // snap to bottom on every render. That yanked the user away from
  // history they were reading whenever a new message arrived.
  //
  // New behaviour:
  //   - If the user was at-or-near the bottom (within 80px) before
  //     the render, snap to bottom afterward - what they're reading
  //     is the live edge.
  //   - If the user was scrolled up reading history, PRESERVE their
  //     scroll position; show a floating "↓ N new" pill they can
  //     tap to jump to bottom. Pill count auto-increments per new
  //     arrival, auto-clears on tap or when they manually scroll
  //     back to bottom.
  //   - On peer switch, force snap (no pill for new conversation).
  //
  // Used by both renderMessages (direct chat) and
  // renderGroupConversation (group chat) - same container, same
  // behaviour.
  const NEAR_BOTTOM_PX = 80;
  let _msgPillCount = 0;
  let _lastRenderedLen = 0;
  let _forceMessageBottomUntil = 0;

  function _isMessagesNearBottom(container, thresholdPx = NEAR_BOTTOM_PX) {
    if (!container) return true;
    const distFromBottom =
      container.scrollHeight - container.scrollTop - container.clientHeight;
    return distFromBottom <= thresholdPx;
  }

  function _forceNextMessagesToBottom(ms = 2500) {
    _forceMessageBottomUntil = Math.max(_forceMessageBottomUntil, Date.now() + ms);
  }

  function _forceMessagesBottomNowAndAfter(ms = 2500) {
    _forceNextMessagesToBottom(ms);
    const settle = () => {
      const container = document.querySelector("#messages");
      if (container) _scrollMessagesToVisualBottom(container);
    };
    settle();
    requestAnimationFrame(settle);
    for (const delay of [80, 250, 700, 1500]) {
      setTimeout(settle, delay);
    }
  }

  function _scrollMessagesToVisualBottom(container) {
    if (!container) return;
    container.scrollTop = container.scrollHeight;
    requestAnimationFrame(() => {
      container.scrollTop = container.scrollHeight;
      const last = container.lastElementChild;
      if (last && typeof last.scrollIntoView === "function") {
        try { last.scrollIntoView({ block: "end", inline: "nearest" }); } catch {}
      }
      container.scrollTop = container.scrollHeight;
    });
  }

  function _keepMessagesBottomAfterMediaLoad(mediaEl) {
    const container = document.querySelector("#messages");
    const shouldStick = !!container
      && (Date.now() <= _forceMessageBottomUntil
          || _isMessagesNearBottom(container, NEAR_BOTTOM_PX + 260));
    if (!mediaEl || !shouldStick) return;
    const settle = () => _scrollMessagesToVisualBottom(container);
    mediaEl.addEventListener("load", settle, { once: true });
    if (mediaEl.decode) mediaEl.decode().then(settle).catch(() => {});
  }

  function _captureScrollState(container) {
    if (!container) return { wasAtBottom: true, prevLen: 0 };
    if (state.runtimeSettings?.auto_scroll_new_messages !== false) {
      return { wasAtBottom: true, forceBottom: true, prevLen: _lastRenderedLen };
    }
    const forceBottom = Date.now() <= _forceMessageBottomUntil;
    return {
      wasAtBottom: forceBottom || _isMessagesNearBottom(container),
      forceBottom,
      prevLen: _lastRenderedLen,
    };
  }

  function _smartScrollAfter(container, before, newLen) {
    if (!container) return;
    const grew = newLen > (before?.prevLen ?? 0);
    _lastRenderedLen = newLen;
    if (before?.wasAtBottom) {
      // User was at the live edge - keep them there.
      _scrollMessagesToVisualBottom(container);
      _forceMessageBottomUntil = 0;
      _hideNewMessagePill();
      return;
    }
    // User was scrolled up. Preserve their position (do NOT touch
    // scrollTop). If new messages arrived, increment the pill.
    if (grew) {
      const delta = newLen - (before?.prevLen ?? 0);
      _showNewMessagePill(_msgPillCount + delta);
    }
  }

  function _showNewMessagePill(count) {
    _msgPillCount = count;
    const pill = document.querySelector("#msg-new-pill");
    const num = document.querySelector("#msg-new-pill-count");
    if (!pill || !num) return;
    num.textContent = String(_msgPillCount);
    pill.hidden = false;
  }

  function _hideNewMessagePill() {
    _msgPillCount = 0;
    const pill = document.querySelector("#msg-new-pill");
    const num = document.querySelector("#msg-new-pill-count");
    if (pill) pill.hidden = true;
    if (num) num.textContent = "0";
  }

  // Pill tap -> smooth scroll to bottom + clear count.
  // Messages container scroll -> if user reached the bottom, clear pill.
  // Both registered once at module load.
  (() => {
    const pill = document.querySelector("#msg-new-pill");
    if (pill) {
      pill.addEventListener("click", () => {
        const m = document.querySelector("#messages");
        if (!m) return;
        m.scrollTo({ top: m.scrollHeight, behavior: "smooth" });
        _hideNewMessagePill();
        try { window._olHaptic && window._olHaptic(6); } catch {}
      });
    }
    const m = document.querySelector("#messages");
    if (m) {
      m.addEventListener("scroll", () => {
        const distFromBottom = m.scrollHeight - m.scrollTop - m.clientHeight;
        if (distFromBottom <= NEAR_BOTTOM_PX && _msgPillCount > 0) {
          _hideNewMessagePill();
        }
      }, { passive: true });
    }
  })();

  function renderMessages() {
    return _measure("renderMessages", _renderMessagesImpl);
  }
  function _renderMessagesImpl() {
    const m = $("#messages");
    if (!state.selectedPeer) {
      if (m._renderSig !== "no-peer") {
        m._renderSig = "no-peer";
        // UX audit P1-3 - show an explicit "pick a device" empty
        // state instead of an empty white pane. The sidebar
        // already lists every device; this just confirms the
        // next step. Doctrine of invisibility honored: the copy
        // describes what to DO, not what's missing.
        m.innerHTML = `
          <div class="empty rich" style="margin: auto; max-width: 320px;">
            <div class="empty-glyph">💬</div>
            <h3>Pick someone on the left to start</h3>
            <p>
              Your messages with each device live here. Choose a
              device from the sidebar, or pair a new one to begin.
            </p>
          </div>`;
      }
      return;
    }

    const source = state.searchResults != null
      ? state.searchResults.filter(x => x.peer === state.selectedPeer)
      : state.messages.filter(x => x.peer === state.selectedPeer);

    // Hide redundant FILE_DONE messages when we already have FILE_OFFER for
    // the same blob - the FILE_OFFER bubble will reflect completion via its
    // matching transfer record, and showing both is duplicative.
    const offerBlobs = new Set();
    for (const msg of source) {
      if (msg.t === "FILE_OFFER" && msg.blob) offerBlobs.add(`${msg.dir}:${msg.blob.toLowerCase()}`);
    }
    const renderedOfferBlobs = new Set();
    const filtered = source.filter(msg => {
      const blob = (msg.blob || "").toLowerCase();
      const key = blob ? `${msg.dir}:${msg.peer || state.selectedPeer}:${blob}` : "";
      // Reconnects can legitimately repeat FILE_OFFER on the wire, but they
      // remain one logical transfer. Keep the first (canonical-name) bubble
      // and let the transfer ledger drive its changing progress/status.
      if (msg.t === "FILE_OFFER" && key) {
        if (renderedOfferBlobs.has(key)) return false;
        renderedOfferBlobs.add(key);
        return true;
      }
      if (msg.t !== "FILE_DONE") return true;
      return !blob || !offerBlobs.has(`${msg.dir}:${blob}`);
    });

    const sig = _messageRenderHash(
      state.selectedPeer, filtered, state.transfersById,
      state.searchResults != null,
    );
    renderPins();
    if (m._renderSig === sig) return;
    // Capture scroll position BEFORE we blow away the DOM so
    // _smartScrollAfter can preserve user position if they're
    // reading history, or snap to bottom if they're already there.
    const firstRender = !m._renderSig || m._renderSig === "no-peer";
    const prevBottomState = _captureScrollState(m);
    if (firstRender && state.searchResults == null) {
      prevBottomState.wasAtBottom = true;
      prevBottomState.forceBottom = true;
      _forceNextMessagesToBottom(1800);
    }
    m._renderSig = sig;
    m.innerHTML = "";

    // v0.21.x: when the filtered list is empty, render one of two
    // distinct empty states. A search with 0 hits is NOT the same
    // as a paired-but-never-messaged chat - showing 'Send the first
    // message' under a 'no matches' search banner is misleading
    // (the user just searched, they know they CAN send messages).
    if (filtered.length === 0 && state.searchResults != null) {
      const wrap = el("div", "search-empty");
      wrap.innerHTML = `
        <div class="empty-glyph">🔍</div>
        <h3>No matches</h3>
        <p>Nothing in this conversation matches
        "${_escapeHtml(state.searchQuery || "")}".</p>
      `;
      const actions = el("div", "search-empty-actions");
      const clear = document.createElement("button");
      clear.type = "button";
      clear.className = "first-action-chip";
      clear.innerHTML = `<span class="fac-icon">✕</span><span>Clear search</span>`;
      clear.onclick = () => {
        // Mirror the search banner's Clear button so the user has
        // one obvious way out without scrolling back to the header.
        if (typeof finishSearch === "function") {
          finishSearch();
        } else {
          state.searchQuery = "";
          state.searchPlain = "";
          state.searchResults = null;
          const sb = document.getElementById("search-banner");
          if (sb) sb.style.display = "none";
          renderMessages();
        }
      };
      actions.appendChild(clear);
      wrap.appendChild(actions);
      m.appendChild(wrap);
      _smartScrollAfter(m, prevBottomState, 0);
      return;
    }

    // v0.21.x: first-action chips for a paired-but-empty chat. When
    // there's a selected peer + zero messages AND no search active,
    // surface three example actions. Auto-dismisses on first send.
    if (filtered.length === 0) {
      const wrap = el("div", "first-action-empty");
      const peer = state.peers.get(state.selectedPeer);
      const who = peer?.display_name || peer?.hostname || "this device";
      wrap.innerHTML = `
        <div class="empty-glyph">👋</div>
        <h3>You're paired with ${_escapeHtml(who)}.</h3>
        <p>Send the first message, drop a file, or jump on a call.</p>
      `;
      const chips = el("div", "first-action-chips");
      const tryThing = (icon, label, action) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "first-action-chip";
        b.innerHTML = `<span class="fac-icon">${icon}</span><span>${_escapeHtml(label)}</span>`;
        b.onclick = action;
        return b;
      };
      chips.appendChild(tryThing("✉️", "Send hi", () => {
        const input = $("#input");
        input.value = "hi 👋";
        input.focus();
        input.dispatchEvent(new Event("input", { bubbles: true }));
      }));
      chips.appendChild(tryThing("📎", "Send a photo", () => {
        $("#btn-attach2")?.click();
      }));
      if (peer?.fingerprint && peer.trust === "pinned") {
        chips.appendChild(tryThing("📞", "Voice call", () => {
          if (typeof window.startLivingPresenceCall === "function") {
            window.startLivingPresenceCall(
              peer.fingerprint,
              peer.display_name || peer.hostname || peer.short_id,
              { video: false },
            );
          }
        }));
      }
      wrap.appendChild(chips);
      m.appendChild(wrap);
      _smartScrollAfter(m, prevBottomState, 0);
      return;
    }

    // v0.21.x: unread divider. When user opens a peer with N pending
    // inbound messages, insert a "── N new ──" line above the first
    // unread inbound bubble so they know where they left off. Uses
    // state.unreadByPeer to compute "first unread" — that's the
    // count freshly bumped on inbound, cleared on selectPeer.
    let unreadInsertIndex = -1;
    const unreadCount = state.unreadByPeer[state.selectedPeer] || 0;
    if (unreadCount > 0) {
      // The bottom-most N inbound messages are the unread ones.
      const inboundIdxs = [];
      for (let i = 0; i < filtered.length; i++) {
        if (filtered[i].dir === "in") inboundIdxs.push(i);
      }
      if (inboundIdxs.length >= unreadCount) {
        unreadInsertIndex = inboundIdxs[inboundIdxs.length - unreadCount];
      }
    }
    let lastTs = null;
    for (let i = 0; i < filtered.length; i++) {
      const msg = filtered[i];
      if (!lastTs || !sameDay(lastTs, msg.ts)) {
        m.appendChild(el("div", "day-sep", dayLabel(msg.ts)));
      }
      lastTs = msg.ts;
      if (i === unreadInsertIndex) {
        const div = el("div", "unread-divider",
          unreadCount === 1 ? "1 new message" : `${unreadCount} new messages`);
        m.appendChild(div);
      }

      if (msg.t === "TEXT") {
        const b = el("div", `msg ${msg.dir}`);
        // v0.7.6: deleted-message placeholder.
        if (msg.deleted || msg.deleted_at_ms) {
          const placeholder = el("div", "msg-deleted", "[message deleted]");
          b.appendChild(placeholder);
          b.appendChild(el("span", "when", fmtTime(msg.ts)));
          b.dataset.msgId = msg.id;
          m.appendChild(b);
          continue;
        }
        // v0.7.5: inline-quote of the parent message when this is
        // a reply. Truncate the quote to 80 chars; clicking it
        // scrolls to the original (handled below via data-id).
        if (msg.reply_to) {
          const parent = state.messages.find(x =>
            x.id === msg.reply_to && x.peer === msg.peer
          );
          const quote = el("div", "reply-quote");
          const quoteBody = parent?.body
            ? (parent.body.length > 80 ? parent.body.slice(0, 80) + "…" : parent.body)
            : "(message)";
          const who = parent?.dir === "in"
            ? (state.peers.get(msg.peer)?.display_name
               || state.peers.get(msg.peer)?.hostname || msg.peer)
            : "you";
          quote.appendChild(el("div", "reply-who", `↩ ${who}`));
          quote.appendChild(el("div", "reply-text", quoteBody));
          if (msg.reply_to) {
            quote.dataset.replyTo = msg.reply_to;
            quote.onclick = () => {
              const tgt = m.querySelector(`[data-msg-id="${CSS.escape(msg.reply_to)}"]`);
              if (tgt) tgt.scrollIntoView({ behavior: "smooth", block: "center" });
            };
          }
          b.appendChild(quote);
        }
        appendCollapsibleText(b, msg.body || "");
        // v0.21.x: highlight search matches inside the bubble body.
        // Skipped when no search is active. Walks text nodes only —
        // never touches inline elements like <a> or <code> attrs.
        if (state.searchPlain && state.searchResults != null) {
          _highlightSearchMatches(b, state.searchPlain);
        }
        // v0.7.6: (edited) badge.
        if (msg.edited_at_ms) {
          const ed = el("span", "edited-badge", " (edited)");
          ed.title = `edited at ${new Date(msg.edited_at_ms).toLocaleString()}`;
          b.appendChild(ed);
        }
        const whenEl = el("span", "when", fmtTime(msg.ts));
        // v0.7.6: read-receipt checkmark on outbound messages.
        // ✓  = sent; ✓✓ = peer's read marker has passed this ts.
        // v0.12.2: gated by display_read_receipts (off → always
        // show ✓ regardless of peer state). Tooltip shows the
        // local timestamp the receipt was received so users know
        // when peers actually saw it.
        if (msg.dir === "out") {
          const peerFp = state.peers.get(msg.peer)?.fingerprint;
          const displayReceipts = state.runtimeSettings?.display_read_receipts !== false;
          const readUpTo = peerFp ? state.readMarkers?.[peerFp] : null;
          const isRead = displayReceipts && readUpTo != null && msg.ts <= readUpTo;
          const tick = el("span", `read-tick ${isRead ? "read" : ""}`,
                         isRead ? "✓✓" : "✓");
          if (isRead) {
            const readAt = state.readMarkerReceivedAt?.[peerFp];
            tick.title = readAt
              ? `Read at ${new Date(readAt).toLocaleTimeString()}`
              : "Read";
          } else {
            tick.title = "Sent";
          }
          whenEl.appendChild(document.createTextNode(" "));
          whenEl.appendChild(tick);
        }
        b.appendChild(whenEl);
        // v0.21.x bulletproof send: visible per-bubble send-state.
        // Replaces the silent disabled-button era — every Send now
        // produces a bubble that explicitly says where it is.
        //   "sending" → faint Sending… (animated dots)
        //   "queued"  → muted Queued · will retry
        //   "failed"  → red Failed · Retry (inline button)
        //   "sent"    → no badge; the ✓ / ✓✓ tick above covers it
        if (msg.dir === "out" && msg._sendingState && msg._sendingState !== "sent") {
          b.appendChild(renderSendStatePill(msg));
        }
        b.dataset.msgId = msg.id;
        if (msg._sendingState) b.dataset.sendState = msg._sendingState;
        // v0.10.2: live "🔥 5m" countdown badge for messages with
        // a TTL. Updated by the per-second tick.
        if (msg.expires_at_ms && !msg.deleted) {
          b.appendChild(renderExpiryBadge(msg));
        }
        // v0.7.5: hover toolbar (Reply + React + Edit + Delete).
        b.appendChild(renderMsgToolbar(msg));
        // v0.7.5: reactions row (chips per emoji w/ count).
        if (msg.reactions && Object.keys(msg.reactions).length) {
          b.appendChild(renderReactionsRow(msg));
        }
        // v0.10.1: multi-select hooks (right-click → enter
        // selection; click while selecting → toggle).
        bindSelectionToBubble(b, msg);
        if (state.selectedMessageIds.has(msg.id)) b.classList.add("selected");
        // v0.21.x: long-press on mobile opens an action bottom-sheet
        // with Reply / React / Copy / Star / Edit / Delete / Pin /
        // Forward. The hover toolbar above is mouse-only; on touch
        // devices users need an equivalent gesture.
        _attachBubbleLongPress(b, msg);
        m.appendChild(b);
      } else if (msg.t === "FILE_OFFER" || msg.t === "FILE_DONE") {
        m.appendChild(renderFileBubble(msg));
      } else if (msg.t === "CALL_LOG") {
        // v0.21.x: missed call / ended call entry in chat history.
        m.appendChild(renderCallLogBubble(msg));
      }
    }
    _smartScrollAfter(m, prevBottomState, source.length);
  }

  // v0.21.x: small bubble for missed / ended calls. Lives in the
  // chat stream so a missed call leaves a visible trace ("Alice
  // called you · No answer · Call back") instead of vanishing.
