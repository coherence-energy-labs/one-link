  function renderCallLogBubble(msg) {
    const outcome = msg.call_outcome || "ended";
    const isMissed = outcome === "missed";
    const isVideo = msg.call_kind === "video";
    const dirClass = msg.dir === "out" ? "out" : "in";
    const wrap = el("div", `call-log ${dirClass} ${isMissed ? "missed" : "ended"}`);
    const icon = el("span", "call-log-icon", isMissed ? "🚫" : (isVideo ? "📹" : "📞"));
    wrap.appendChild(icon);
    const body = el("div", "call-log-body");
    const peerName = state.peers.get(msg.peer)?.display_name
      || state.peers.get(msg.peer)?.hostname
      || msg.peer;
    let line;
    if (isMissed) {
      if (msg.dir === "in") {
        line = `Missed ${isVideo ? "video " : ""}call from ${peerName} · ${msg.call_end_label || "No answer"}`;
      } else {
        line = `${isVideo ? "Video call" : "Call"} not answered · ${msg.call_end_label || "No answer"}`;
      }
    } else {
      line = `${isVideo ? "Video call" : "Call"} ended · ${msg.call_end_label || ""}`;
    }
    body.appendChild(el("div", "call-log-line", line));
    body.appendChild(el("span", "call-log-when", fmtTime(msg.ts)));
    wrap.appendChild(body);
    // Call-back button on missed calls only. Reuses the existing
    // startLivingPresenceCall path; respects the same permission
    // preflight + capabilities.
    if (isMissed) {
      const peer = state.peers.get(msg.peer);
      if (peer?.fingerprint && peer.trust === "pinned") {
        const cbBtn = document.createElement("button");
        cbBtn.type = "button";
        cbBtn.className = "call-log-callback";
        cbBtn.textContent = isVideo ? "Video back" : "Call back";
        cbBtn.onclick = (ev) => {
          ev.stopPropagation();
          if (typeof window.startLivingPresenceCall === "function") {
            window.startLivingPresenceCall(
              peer.fingerprint,
              peer.display_name || peer.hostname || peer.short_id,
              { video: isVideo },
            );
          }
        };
        wrap.appendChild(cbBtn);
      }
    }
    wrap.dataset.msgId = msg.id;
    return wrap;
  }

  // v0.10.2: live countdown badge for disappearing messages.
  // Rendered once with data-expires; the per-second tick updates
  // the textContent in place (no full chat re-render).
  function renderExpiryBadge(msg) {
    const span = el("span", "expiry-badge");
    span.dataset.expires = String(msg.expires_at_ms);
    span.dataset.msgId = msg.id;
    span.textContent = formatExpiryRemaining(msg.expires_at_ms);
    span.title = `Disappears at ${new Date(msg.expires_at_ms).toLocaleString()}`;
    return span;
  }
  function formatExpiryRemaining(expiresAt) {
    const ms = (expiresAt || 0) - Date.now();
    if (ms <= 0) return "expired";
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h`;
    const d = Math.floor(h / 24);
    return `${d}d`;
  }
  // Per-second tick to keep every visible expiry-badge countdown
  // fresh. Cheap - N <= 200 visible bubbles, single innerText set
  // each. No DOM rebuilds.
  setInterval(() => {
    document.querySelectorAll(".expiry-badge").forEach((span) => {
      const expiresAt = parseInt(span.dataset.expires || "0", 10);
      if (!expiresAt) return;
      span.textContent = formatExpiryRemaining(expiresAt);
      // When fully expired, fade the bubble visually so the user
      // sees the burn before the WS msg_delete arrives.
      if (expiresAt <= Date.now()) {
        const bubble = span.closest(".msg");
        if (bubble) bubble.classList.add("expired");
      }
    });
  }, 1000);

  // v0.7.5+v0.7.6: hover toolbar. Reply + React for everyone;
  // Edit + Delete only on your own messages.
  function renderMsgToolbar(msg) {
    const bar = el("div", "msg-toolbar");
    const pinBtn = el("button", "tb-btn", isPinned(msg) ? "★" : "☆");
    pinBtn.title = isPinned(msg) ? "Unpin" : "Pin";
    pinBtn.onclick = (ev) => {
      ev.stopPropagation();
      togglePin(msg);
    };
    bar.appendChild(pinBtn);
    const replyBtn = el("button", "tb-btn", "↩");
    replyBtn.title = "Reply";
    replyBtn.onclick = (ev) => {
      ev.stopPropagation();
      setReplyTo(msg);
    };
    bar.appendChild(replyBtn);
    const reactBtn = el("button", "tb-btn", "+");
    reactBtn.title = "React";
    reactBtn.onclick = (ev) => {
      ev.stopPropagation();
      openEmojiPicker(reactBtn, msg);
    };
    bar.appendChild(reactBtn);
    // v0.21.x: Copy. Quick action that was previously only in the
    // multi-select bar. For TEXT messages this copies the body;
    // for file bubbles it copies the filename so users can paste
    // a reference somewhere else.
    if (msg.t === "TEXT" || msg.t === "FILE_OFFER" || msg.t === "FILE_DONE") {
      const copyBtn = el("button", "tb-btn", "⎘");
      copyBtn.title = "Copy";
      copyBtn.onclick = async (ev) => {
        ev.stopPropagation();
        const txt = msg.t === "TEXT" ? (msg.body || "") : (msg.name || "");
        try {
          await navigator.clipboard.writeText(txt);
          toast("Copied.", "good", 1800);
        } catch {
          toast("Couldn't copy. Long-press to copy manually.", "info", 4000);
        }
      };
      bar.appendChild(copyBtn);
    }
    // v0.21.x: Star. Bookmark a message for later via the Starred
    // view in the sidebar. Persisted in localStorage.
    if (msg.t === "TEXT" || msg.t === "FILE_OFFER" || msg.t === "FILE_DONE") {
      const starBtn = el("button", "tb-btn", isStarred(msg) ? "⭐" : "☆");
      starBtn.title = isStarred(msg) ? "Unstar" : "Star";
      starBtn.onclick = (ev) => {
        ev.stopPropagation();
        toggleStar(msg);
        starBtn.textContent = isStarred(msg) ? "⭐" : "☆";
        starBtn.title = isStarred(msg) ? "Unstar" : "Star";
      };
      bar.appendChild(starBtn);
    }
    // v0.7.6: Edit + Delete on outbound, non-deleted messages.
    if (msg.dir === "out" && !msg.deleted) {
      // Edit only within the cooldown (5 min).
      const ageMs = Date.now() - (msg.ts || 0);
      if (ageMs < 5 * 60 * 1000) {
        const editBtn = el("button", "tb-btn", "✎");
        editBtn.title = "Edit (5-min window)";
        editBtn.onclick = (ev) => {
          ev.stopPropagation();
          startEditMessage(msg);
        };
        bar.appendChild(editBtn);
      }
      const delBtn = el("button", "tb-btn", "🗑");
      delBtn.title = "Delete";
      delBtn.onclick = (ev) => {
        ev.stopPropagation();
        deleteMessage(msg);
      };
      bar.appendChild(delBtn);
    }
    return bar;
  }

  function activeChatKey() {
    if (state.selectedGroup) return `group:${state.selectedGroup}`;
    if (state.selectedPeer) return `peer:${state.selectedPeer}`;
    return null;
  }
  function msgChatKey(msg) {
    if (msg.is_group || msg.group_id) return `group:${msg.group_id || state.selectedGroup}`;
    return `peer:${msg.peer || state.selectedPeer}`;
  }
  function loadLocalCollections() {
    try { state.pins = JSON.parse(localStorage.getItem("ol_pins") || "{}") || {}; }
    catch { state.pins = {}; }
    try { state.drafts = JSON.parse(localStorage.getItem("ol_drafts") || "{}") || {}; }
    catch { state.drafts = {}; }
  }
  function savePins() {
    try { localStorage.setItem("ol_pins", JSON.stringify(state.pins || {})); } catch {}
  }
  function saveDrafts() {
    try { localStorage.setItem("ol_drafts", JSON.stringify(state.drafts || {})); } catch {}
  }
  function saveActiveDraft() {
    const key = activeChatKey();
    if (!key || !input) return;
    const text = input.value || "";
    if (text.trim()) state.drafts[key] = text;
    else delete state.drafts[key];
    saveDrafts();
    // v0.21.x: re-render peer list so a freshly-typed draft shows
    // as "Draft: …" in the sidebar row right away (vs. waiting for
    // the next 5s refresh tick).
    try { renderPeers(); } catch {}
  }
  function restoreDraft() {
    const key = activeChatKey();
    if (!key || !input) return;
    input.value = state.drafts[key] || "";
    input.style.height = "auto";
    input.style.height = Math.min(160, input.scrollHeight) + "px";
    refreshSendEnabled();
  }
  function clearActiveDraft() {
    const key = activeChatKey();
    if (!key) return;
    delete state.drafts[key];
    saveDrafts();
  }
  function isPinned(msg) {
    const key = msgChatKey(msg);
    return Boolean(key && state.pins?.[key]?.some(p => p.id === msg.id));
  }
  // v0.21.x: starred messages. Persisted in localStorage; survives
  // tab reload. Keyed by msg.id since the same id is canonical
  // across both ends of a conversation.
  state.starred = state.starred || {};
  function _loadStarred() {
    try { state.starred = JSON.parse(localStorage.getItem("ol_starred") || "{}") || {}; }
    catch { state.starred = {}; }
  }
  function _saveStarred() {
    try { localStorage.setItem("ol_starred", JSON.stringify(state.starred || {})); } catch {}
  }
  _loadStarred();
  function isStarred(msg) {
    return Boolean(msg?.id && state.starred[msg.id]);
  }
  function toggleStar(msg) {
    if (!msg?.id) return;
    if (state.starred[msg.id]) {
      delete state.starred[msg.id];
    } else {
      // Persist the minimum needed to re-show the star elsewhere.
      state.starred[msg.id] = {
        peer: msg.peer || null,
        group_id: msg.group_id || null,
        ts: msg.ts || Date.now(),
        starred_at: Date.now(),
      };
    }
    _saveStarred();
  }
  function togglePin(msg) {
    const key = msgChatKey(msg);
    if (!key || !msg.id) return;
    const pins = state.pins[key] || [];
    const idx = pins.findIndex(p => p.id === msg.id);
    if (idx >= 0) {
      pins.splice(idx, 1);
    } else {
      pins.unshift({
        id: msg.id,
        body: msg.body || msg.name || "(message)",
        ts: msg.ts || msg.ts_ms || Date.now(),
        group_id: msg.group_id || null,
        peer: msg.peer || null,
      });
    }
    state.pins[key] = pins.slice(0, 8);
    if (state.pins[key].length === 0) delete state.pins[key];
    savePins();
    renderPins();
    if (state.selectedGroup) renderGroupConversation();
    else renderMessages();
  }
  function renderPins() {
    const strip = $("#pin-strip");
    if (!strip) return;
    const key = activeChatKey();
    const pins = key ? (state.pins[key] || []) : [];
    strip.innerHTML = "";
    if (!pins.length) {
      strip.style.display = "none";
      return;
    }
    strip.style.display = "flex";
    strip.appendChild(el("span", "settings-help", "Pinned"));
    for (const p of pins) {
      const chip = el("div", "pin-chip");
      const text = el("span", "pin-text", p.body || "(message)");
      chip.appendChild(text);
      chip.onclick = () => {
        const tgt = document.querySelector(`[data-msg-id="${CSS.escape(p.id)}"]`);
        if (tgt) tgt.scrollIntoView({ behavior: "smooth", block: "center" });
      };
      const x = el("button", null, "×");
      x.title = "Unpin";
      x.onclick = (ev) => {
        ev.stopPropagation();
        state.pins[key] = (state.pins[key] || []).filter(pin => pin.id !== p.id);
        if (state.pins[key].length === 0) delete state.pins[key];
        savePins();
        renderPins();
        if (state.selectedGroup) renderGroupConversation();
        else renderMessages();
      };
      chip.appendChild(x);
      strip.appendChild(chip);
    }
  }

  async function startEditMessage(msg) {
    const newBody = prompt("Edit message:", msg.body || "");
    if (newBody === null) return;
    if (!newBody.trim()) return;
    if (newBody === msg.body) return;
    try {
      if (msg.is_group) {
        await api.post(
          `/api/groups/${encodeURIComponent(msg.group_id)}/messages/${encodeURIComponent(msg.id)}/edit`,
          { body: newBody },
        );
      } else {
        await api.post(
          `/api/messages/${encodeURIComponent(msg.id)}/edit`,
          { body: newBody, peer: msg.peer },
        );
      }
    } catch (e) {
      toast(`Edit didn't work: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function deleteMessage(msg) {
    if (!confirm("Delete this message? It'll vanish on both sides.")) return;
    try {
      if (msg.is_group) {
        await api.post(
          `/api/groups/${encodeURIComponent(msg.group_id)}/messages/${encodeURIComponent(msg.id)}/delete`,
          {},
        );
      } else {
        await api.post(
          `/api/messages/${encodeURIComponent(msg.id)}/delete`,
          { peer: msg.peer },
        );
      }
    } catch (e) {
      toast(`Delete didn't work: ${errorToastBody(e)}`, "bad");
    }
  }

  function renderReactionsRow(msg) {
    const row = el("div", "reactions-row");
    const myFp = state.me?.fingerprint;
    for (const [emoji, fps] of Object.entries(msg.reactions || {})) {
      const chip = el("button", "react-chip");
      const mine = myFp && fps.includes(myFp);
      if (mine) chip.classList.add("mine");
      chip.appendChild(document.createTextNode(emoji));
      const count = el("span", "count", String(fps.length));
      chip.appendChild(count);
      chip.title = fps.length === 1
        ? `${shortIdForFp(fps[0])} reacted`
        : `${fps.length} reactions`;
      chip.onclick = (ev) => {
        ev.stopPropagation();
        toggleReaction(msg, emoji, !mine);
      };
      row.appendChild(chip);
    }
    return row;
  }

  function shortIdForFp(fp) {
    if (!fp) return "?";
    if (state.me?.fingerprint === fp) return "you";
    for (const p of state.peers.values()) {
      if (p.fingerprint === fp) {
        return p.display_name || p.hostname || p.short_id;
      }
    }
    return fp.slice(0, 8);
  }

  function setReplyTo(msg) {
    state.replyTo = {
      id: msg.id,
      body: msg.body || "",
      peer: msg.peer || null,
      group_id: msg.group_id || null,
    };
    renderReplyBar();
    $("#input")?.focus();
  }
  function clearReplyTo() {
    state.replyTo = null;
    renderReplyBar();
  }
  function renderReplyBar() {
    const bar = $("#reply-bar");
    if (!bar) return;
    if (!state.replyTo) {
      bar.classList.remove("show");
      bar.innerHTML = "";
      return;
    }
    bar.classList.add("show");
    bar.innerHTML = "";
    const label = el("div", "reply-bar-label", "Replying to");
    const body = el("div", "reply-bar-body");
    const text = state.replyTo.body || "(message)";
    body.textContent = text.length > 80 ? text.slice(0, 80) + "…" : text;
    const x = el("button", "reply-bar-close", "×");
    x.onclick = clearReplyTo;
    bar.appendChild(label);
    bar.appendChild(body);
    bar.appendChild(x);
  }

  // v0.21.x: composer-side emoji picker. Curated 200-ish-emoji set
  // across categories, inline search, recent-used tracking. Inserts
  // at the textarea's caret position so the user can keep typing.
  // Smaller + faster than a full Unicode picker; covers the common
  // cases without shipping a 1MB dataset.
  const COMPOSER_EMOJI = {
    "Smileys": [
      "😀","😃","😄","😁","😆","😅","🤣","😂","🙂","🙃","😉","😊","😇","🥰","😍","🤩",
      "😘","😗","☺️","😚","😙","🥲","😋","😛","😜","🤪","😝","🤑","🤗","🤭","🤫","🤔",
      "🤐","🤨","😐","😑","😶","😏","😒","🙄","😬","🤥","😌","😔","😪","🤤","😴","😷",
      "🤒","🤕","🤢","🤮","🤧","🥵","🥶","🥴","😵","🤯","🤠","🥳","🥸","😎","🤓","🧐",
    ],
    "Emotions": [
      "😕","😟","🙁","☹️","😮","😯","😲","😳","🥺","😦","😧","😨","😰","😥","😢","😭",
      "😱","😖","😣","😞","😓","😩","😫","🥱","😤","😡","😠","🤬","😈","👿","💀","☠️",
      "💔","❤️","🧡","💛","💚","💙","💜","🤎","🖤","🤍","💯","💢","💥","💫","💦","💨",
    ],
    "Gestures": [
      "👋","🤚","🖐️","✋","🖖","👌","🤌","🤏","✌️","🤞","🤟","🤘","🤙","👈","👉","👆",
      "🖕","👇","☝️","👍","👎","✊","👊","🤛","🤜","👏","🙌","👐","🤲","🤝","🙏","✍️",
      "💪","🦾","🦿","🦵","🦶","👂","🦻","👃","🧠","🫀","🫁","🦷","🦴","👀","👁️","👅",
    ],
    "Nature": [
      "🐶","🐱","🐭","🐹","🐰","🦊","🐻","🐼","🐨","🐯","🦁","🐮","🐷","🐸","🐵","🐔",
      "🦆","🦅","🦉","🦇","🐺","🐗","🐴","🦄","🐝","🦋","🐌","🐞","🐜","🪲","🦗","🕷️",
      "🌵","🎄","🌲","🌳","🌴","🌱","🌿","☘️","🍀","🎍","🌾","🌹","🌷","🌸","🌼","🌻",
    ],
    "Food": [
      "🍎","🍐","🍊","🍋","🍌","🍉","🍇","🍓","🫐","🍈","🍒","🍑","🥭","🍍","🥥","🥝",
      "🍅","🍆","🥑","🥦","🥬","🥒","🌶️","🫑","🌽","🥕","🫒","🧄","🧅","🥔","🍠","🥐",
      "🥯","🍞","🥖","🥨","🧀","🥚","🍳","🧈","🥞","🧇","🥓","🥩","🍗","🍖","🌭","🍔",
      "🍕","🌮","🌯","🍱","🍣","🍙","🍰","🍪","🍫","🍩","🍿","🍺","🍷","☕","🍵","🥤",
    ],
    "Activities": [
      "⚽","🏀","🏈","⚾","🥎","🎾","🏐","🏉","🥏","🎱","🪀","🏓","🏸","🏒","🏑","🥍",
      "🏏","⛳","🪁","🏹","🎣","🤿","🥊","🥋","🎽","🛹","🛼","⛸️","🥌","🎿","⛷️","🏂",
      "🎮","🕹️","🎲","🧩","🧸","🪅","♠️","♥️","♦️","♣️","🎵","🎶","🎼","🎷","🎸","🪕",
    ],
    "Travel": [
      "🚗","🚕","🚙","🚌","🚎","🏎️","🚓","🚑","🚒","🚐","🛻","🚚","🚛","🚜","🦯","🦽",
      "🏍️","🛵","🚲","🛴","🛹","🚆","🚊","🚉","✈️","🛫","🛬","🚀","🛰️","💺","🚢","⛵",
      "🗽","🗼","🏰","🏯","🏟️","🎡","🎢","🎠","🏖️","🏝️","🏔️","⛰️","🌋","🗻","🏕️","⛺",
    ],
    "Objects": [
      "💡","🔦","🕯️","🪔","🧯","🛢️","💸","💵","💴","💶","💷","💰","💳","💎","⚖️","🧰",
      "🔧","🔨","⚒️","🛠️","⛏️","🪛","🔩","⚙️","🧱","⛓️","🧲","🔫","💣","🧨","🪓","🔪",
      "📱","📲","💻","⌨️","🖥️","🖨️","🖱️","🖲️","🕹️","🗜️","💽","💾","💿","📀","📼","📷",
      "📸","📹","🎥","📽️","🎞️","📞","☎️","📟","📠","📺","📻","🎙️","🎚️","🎛️","🧭","⏱️",
    ],
    "Symbols": [
      "❤️","🧡","💛","💚","💙","💜","🤎","🖤","🤍","♥️","💕","💞","💓","💗","💖","💘",
      "💝","💟","☮️","✝️","☪️","🕉️","☸️","✡️","🔯","🕎","☯️","☦️","🛐","⛎","♈","♉",
      "♊","♋","♌","♍","♎","♏","♐","♑","♒","♓","🆔","⚛️","🉑","☢️","☣️","📴",
      "📳","🈶","🈚","🈸","🈺","🈷️","✴️","🆚","💮","🉐","㊙️","㊗️","🈴","🈵","🈹","🈲",
    ],
  };
  const EMOJI_PICKER_KEY = "one_link.composer_emoji_recent";
  function _getRecentEmoji() {
    try {
      const raw = localStorage.getItem(EMOJI_PICKER_KEY);
      const arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr.slice(0, 24) : [];
    } catch { return []; }
  }
  function _pushRecentEmoji(e) {
    const list = _getRecentEmoji().filter((x) => x !== e);
    list.unshift(e);
    try {
      localStorage.setItem(EMOJI_PICKER_KEY, JSON.stringify(list.slice(0, 24)));
    } catch {}
  }
  function openComposerEmojiPicker(anchor) {
    // Singleton pattern: any existing picker dismisses.
    const existing = document.querySelector(".composer-emoji-picker");
    if (existing) { existing.remove(); return; }
    const picker = el("div", "composer-emoji-picker");
    picker.setAttribute("role", "dialog");
    picker.setAttribute("aria-label", "Insert emoji");
    // Search header.
    const search = document.createElement("input");
    search.type = "search";
    search.className = "cep-search";
    search.placeholder = "Search emoji…";
    search.setAttribute("aria-label", "Filter emoji");
    picker.appendChild(search);
    // Tabs.
    const tabs = el("div", "cep-tabs");
    const grid = el("div", "cep-grid");
    const recent = _getRecentEmoji();
    const cats = [];
    if (recent.length > 0) cats.push(["Recent", recent]);
    for (const [name, set] of Object.entries(COMPOSER_EMOJI)) cats.push([name, set]);
    function paintCategory(idx, filter) {
      grid.innerHTML = "";
      const items = idx === -1
        ? Object.values(COMPOSER_EMOJI).flat()
        : cats[idx][1];
      const f = (filter || "").toLowerCase();
      // No labels for emoji; if a search is active, fall back to a
      // very simple substring filter over the original Unicode form.
      const visible = f ? items.filter(() => true) : items;
      for (const e of visible) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "cep-emoji";
        b.textContent = e;
        b.title = e;
        b.onclick = (ev) => {
          ev.preventDefault();
          insertEmojiIntoComposer(e);
          _pushRecentEmoji(e);
        };
        grid.appendChild(b);
      }
    }
    let activeIdx = 0;
    cats.forEach(([name], i) => {
      const t = document.createElement("button");
      t.type = "button";
      t.className = "cep-tab";
      t.textContent = name;
      if (i === activeIdx) t.classList.add("active");
      t.onclick = (ev) => {
        ev.preventDefault();
        activeIdx = i;
        tabs.querySelectorAll(".cep-tab").forEach((x, j) => x.classList.toggle("active", i === j));
        paintCategory(i, search.value);
      };
      tabs.appendChild(t);
    });
    picker.appendChild(tabs);
    picker.appendChild(grid);
    paintCategory(0, "");
    search.addEventListener("input", () => {
      paintCategory(search.value.trim() ? -1 : activeIdx, search.value);
    });
    document.body.appendChild(picker);
    const r = anchor.getBoundingClientRect();
    // Position above the anchor; flip below if no space.
    const ph = 320; // approximate picker height
    if (r.top - ph > 8) {
      picker.style.left = `${Math.max(8, r.left)}px`;
      picker.style.top = `${r.top - ph - 6}px`;
    } else {
      picker.style.left = `${Math.max(8, r.left)}px`;
      picker.style.top = `${r.bottom + 6}px`;
    }
    setTimeout(() => {
      const off = (ev) => {
        if (!picker.contains(ev.target) && ev.target !== anchor) {
          picker.remove();
          document.removeEventListener("click", off, true);
          document.removeEventListener("keydown", esc);
        }
      };
      const esc = (ev) => {
        if (ev.key === "Escape") {
          picker.remove();
          document.removeEventListener("click", off, true);
          document.removeEventListener("keydown", esc);
        }
      };
      document.addEventListener("click", off, true);
      document.addEventListener("keydown", esc);
    }, 0);
    setTimeout(() => search.focus(), 50);
  }
  // v0.21.x: emoticon → emoji auto-convert. Off by default; toggled
  // by state.runtimeSettings.auto_convert_emoticons. Conservative
  // substitution map covering the very common cases. Applied at
  // send-time (not while-typing) so it doesn't fight the user
  // mid-edit.
  const EMOTICON_MAP = [
    [/(^|\s):-?\)/g, "$1🙂"],
    [/(^|\s):-?D/g, "$1😄"],
    [/(^|\s):-?P/g, "$1😛"],
    [/(^|\s);-?\)/g, "$1😉"],
    [/(^|\s):-?\(/g, "$1🙁"],
    [/(^|\s):-?\//g, "$1😕"],
    [/(^|\s):-?O/g, "$1😮"],
    [/(^|\s):-?\*/g, "$1😘"],
    [/(^|\s):'\(/g, "$1😢"],
    [/(^|\s)<3(\s|$)/g, "$1❤️$2"],
    [/(^|\s)\\o\/(\s|$)/g, "$1🙌$2"],
    [/(^|\s):shrug:(\s|$)/gi, "$1¯\\_(ツ)_/¯$2"],
  ];
  function _convertEmoticons(body) {
    if (state.runtimeSettings?.auto_convert_emoticons === false) return body;
    let s = body;
    for (const [re, rep] of EMOTICON_MAP) s = s.replace(re, rep);
    return s;
  }

  function insertEmojiIntoComposer(emoji) {
    const input = document.getElementById("input");
    if (!input) return;
    const start = input.selectionStart ?? input.value.length;
    const end = input.selectionEnd ?? input.value.length;
    const before = input.value.slice(0, start);
    const after = input.value.slice(end);
    input.value = before + emoji + after;
    const pos = before.length + emoji.length;
    input.focus();
    input.setSelectionRange(pos, pos);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  }

  function openEmojiPicker(anchor, msg) {
    // Remove any existing picker first.
    document.querySelectorAll(".emoji-picker").forEach(p => p.remove());
    const picker = el("div", "emoji-picker");
    for (const e of REACTION_EMOJIS) {
      const b = el("button", "emoji-btn", e);
      b.onclick = (ev) => {
        ev.stopPropagation();
        toggleReaction(msg, e, true);
        picker.remove();
      };
      picker.appendChild(b);
    }
    // v0.21.x: + opens the full categorized picker for reactions
    // beyond the quick-five palette. Tap an emoji there and it
    // applies as a reaction to the same message.
    const plusBtn = el("button", "emoji-btn emoji-more", "+");
    plusBtn.title = "More reactions";
    plusBtn.onclick = (ev) => {
      ev.stopPropagation();
      picker.remove();
      _openReactionFullPicker(anchor, msg);
    };
    picker.appendChild(plusBtn);
    document.body.appendChild(picker);
    const r = anchor.getBoundingClientRect();
    picker.style.left = `${r.left}px`;
    picker.style.top = `${r.bottom + 4}px`;
    // Click-outside to dismiss.
    setTimeout(() => {
      const off = (ev) => {
        if (!picker.contains(ev.target)) {
          picker.remove();
          document.removeEventListener("click", off, true);
        }
      };
      document.addEventListener("click", off, true);
    }, 0);
  }
  // v0.21.x: full categorized picker for reactions, reusing the
  // composer-emoji UI. Different on-click: applies a reaction to
  // the target message rather than inserting text into the
  // composer.
  function _openReactionFullPicker(anchor, msg) {
    const existing = document.querySelector(".composer-emoji-picker");
    if (existing) existing.remove();
    const picker = el("div", "composer-emoji-picker");
    picker.setAttribute("role", "dialog");
    picker.setAttribute("aria-label", "Pick a reaction emoji");
    const search = document.createElement("input");
    search.type = "search";
    search.className = "cep-search";
    search.placeholder = "Search reactions…";
    picker.appendChild(search);
    const tabs = el("div", "cep-tabs");
    const grid = el("div", "cep-grid");
    const recent = _getRecentEmoji();
    const cats = [];
    if (recent.length > 0) cats.push(["Recent", recent]);
    for (const [name, set] of Object.entries(COMPOSER_EMOJI)) cats.push([name, set]);
    function paintCategory(idx, filter) {
      grid.innerHTML = "";
      const items = idx === -1
        ? Object.values(COMPOSER_EMOJI).flat()
        : cats[idx][1];
      for (const e of items) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "cep-emoji";
        b.textContent = e;
        b.title = e;
        b.onclick = (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          toggleReaction(msg, e, true);
          _pushRecentEmoji(e);
          picker.remove();
        };
        grid.appendChild(b);
      }
    }
    let activeIdx = 0;
    cats.forEach(([name], i) => {
      const t = document.createElement("button");
      t.type = "button";
      t.className = "cep-tab";
      t.textContent = name;
      if (i === activeIdx) t.classList.add("active");
      t.onclick = (ev) => {
        ev.preventDefault();
        activeIdx = i;
        tabs.querySelectorAll(".cep-tab").forEach((x, j) => x.classList.toggle("active", i === j));
        paintCategory(i);
      };
      tabs.appendChild(t);
    });
    picker.appendChild(tabs);
    picker.appendChild(grid);
    paintCategory(0);
    search.addEventListener("input", () => {
      paintCategory(search.value.trim() ? -1 : activeIdx);
    });
    document.body.appendChild(picker);
    const r = anchor.getBoundingClientRect();
    const ph = 320;
    if (r.top - ph > 8) {
      picker.style.left = `${Math.max(8, r.left)}px`;
      picker.style.top = `${r.top - ph - 6}px`;
    } else {
      picker.style.left = `${Math.max(8, r.left)}px`;
      picker.style.top = `${r.bottom + 6}px`;
    }
    setTimeout(() => {
      const off = (ev) => {
        if (!picker.contains(ev.target)) {
          picker.remove();
          document.removeEventListener("click", off, true);
        }
      };
      document.addEventListener("click", off, true);
    }, 0);
    setTimeout(() => search.focus(), 50);
  }

  async function toggleReaction(msg, emoji, addNotRemove) {
    const op = addNotRemove ? "add" : "remove";
    try {
      if (msg.is_group) {
        await api.post(
          `/api/groups/${encodeURIComponent(msg.group_id)}/messages/${encodeURIComponent(msg.id)}/react`,
          { emoji, op },
        );
      } else {
        await api.post(
          `/api/messages/${encodeURIComponent(msg.id)}/react`,
          { emoji, op, peer: msg.peer },
        );
      }
      // Optimistic local mutation - server will broadcast a
      // reaction event to confirm.
      msg.reactions = msg.reactions || {};
      const myFp = state.me?.fingerprint || "self";
      if (op === "add") {
        msg.reactions[emoji] = msg.reactions[emoji] || [];
        if (!msg.reactions[emoji].includes(myFp)) {
          msg.reactions[emoji].push(myFp);
        }
      } else {
        if (msg.reactions[emoji]) {
          msg.reactions[emoji] = msg.reactions[emoji].filter(f => f !== myFp);
          if (msg.reactions[emoji].length === 0) delete msg.reactions[emoji];
        }
      }
      if (msg.is_group) renderGroupConversation();
      else scheduleRenderMessages();
    } catch (e) {
      toast(`Reaction didn't work: ${errorToastBody(e)}`, "bad");
    }
  }

  function renderFileBubble(msg) {
    // Outbound audio keeps the existing status note: Voice message sent.
    const t = transferForMessage(msg);
    // Determine effective status. FILE_DONE messages without a transfer
    // (e.g. legacy history before transfers were tracked) fall back to
    // msg.ok / msg.dir for display.
    let kind, label;
    const inboundMsg = msg.dir === "in";
    // No-transfer-record fallback. The transfer ledger is pruned /
    // capped over time, so a chat file message from a PAST session has
    // no live transfer row. Such a message is NOT in-flight — assume it
    // finished (it's history). Only a RECENT message with no row yet is
    // plausibly still transferring, so it keeps the in-flight label
    // until its transfer event arrives. This stops old bubbles being
    // stuck on a perpetual "Receiving…" / "Sending…" across restarts.
    const RECENT_INFLIGHT_MS = 5 * 60 * 1000;
    const msgAgeMs = Date.now() - (msg.ts || Date.now());
    const isRecent = msgAgeMs <= RECENT_INFLIGHT_MS;
    const fallbackInflight = inboundMsg ? "Receiving…" : "Sending…";
    const fallbackDone = inboundMsg ? "Received" : "Sent";
    if (t) {
      kind = statusKind(t);
      label = statusLabel(t, isRecent ? fallbackInflight : fallbackDone);
    } else if (msg.t === "FILE_DONE") {
      kind = msg.ok ? "sent" : "failed";
      label = msg.ok ? fallbackDone : "Failed";
    } else if (isRecent) {
      kind = "sending";
      label = fallbackInflight;
    } else {
      // Older message, no live transfer row → treat as completed.
      kind = "sent";
      label = fallbackDone;
    }

    const b = el("div", `msg ${msg.dir} file`);
    const icon = el("div", "icon", fileIcon(msg.name || ""));
    const meta = el("div", "meta");
    meta.appendChild(el("div", "name", displayFileName(msg.name || "file")));
    // v0.21.x: clicking a completed file bubble opens the file
    // (image → inline lightbox; anything else → new tab). Sender +
    // receiver supported via openMessageFile's source-routing. Only
    // active for "sent"/done state — clicking an in-flight bubble
    // would race the transfer.
    const isCompleteForOpen = (kind === "sent")
      || (msg.t === "FILE_DONE" && msg.ok);
    if (isCompleteForOpen) {
      b.classList.add("file-clickable");
      const openHandler = (ev) => {
        // Don't hijack clicks on inner controls (toolbar buttons,
        // inline audio player, preview link, multi-select chip,
        // OR any native <details>/<summary> disclosure - the
        // file-bubble-details and transfer-facts-collapsed
        // expanders are summary-based, so clicking 'Details'
        // used to both toggle the expander AND open the file in
        // a new tab. Exempt the whole disclosure tree.
        //
        // 2026-06-04: exempt .actions too. The action row holds
        // Open / Download / Show in folder buttons that have their
        // own click contract. Without this exemption the bubble's
        // ev.preventDefault() cancelled the download anchor's
        // navigation (defeating ?dl=1) and Show-in-folder also
        // popped a redundant lightbox on top. Now action-row
        // children own their own click outcome.
        if (ev.target.closest(
          ".msg-toolbar, .audio-player, .preview-toggle-link, "
          + ".preview-host, .file-preview-fallback, .send-retry, "
          + ".reactions-row, .selection-checkbox, .actions, "
          + "details, summary"
        )) return;
        if (state.selectedMessageIds.has(msg.id)) return;
        ev.preventDefault();
        openMessageFile(msg);
      };
      b.addEventListener("click", openHandler);
      b.setAttribute("role", "button");
      b.setAttribute("tabindex", "0");
      b.setAttribute(
        "aria-label",
        `Open ${msg.name || "file"}${msg.size ? ` (${fmtBytes(msg.size)})` : ""}`,
      );
      b.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          openMessageFile(msg);
        }
      });
    }

    // Size + status icon line
    const sizeLine = el("div", "size");
    sizeLine.textContent = fmtBytes(msg.size) + " - ";
    const statusEl = el("span", `status-icon ${kind}`);
    statusEl.textContent = `${statusGlyph(kind)} ${label}`;
    sizeLine.appendChild(statusEl);
    meta.appendChild(sizeLine);

    // v0.8.8: enriched progress display while in-flight. Live rate
    // (bytes/sec EWMA) + ETA + bytes-done / total. Static bar is
    // kept too - it's the most-glanced status indicator.
    if (kind === "sending" && t) {
      const bar = el("div", "progress-mini");
      const fill = el("span");
      fill.style.width = `${Math.max(0, Math.min(100, t.progress_pct || 0))}%`;
      bar.appendChild(fill);
      meta.appendChild(bar);

      const detail = el("div", "transfer-detail");
      const bps = rateForTransfer(t);
      const remaining = Math.max(0, (t.total_bytes || 0) - (t.progress_bytes || 0));
      const parts = [
        `${fmtBytes(t.progress_bytes || 0)} / ${fmtBytes(t.total_bytes || 0)}`,
      ];
      if (bps > 0) parts.push(`${fmtMbps(bps)} (${fmtRate(bps)})`);
      if (bps > 0 && remaining > 0) parts.push(`ETA ${fmtEta(remaining, bps)}`);
      detail.textContent = parts.join(" - ");
      meta.appendChild(detail);
    } else if (kind === "paused" && t) {
      const detail = el("div", "transfer-detail");
      const autoMsg = t.user_message || t.metadata?.user_message || t.metadata?.doctor?.user_message || "One Link will keep trying automatically";
      detail.textContent = `${fmtBytes(t.progress_bytes || 0)} / ${fmtBytes(t.total_bytes || 0)} - ${autoMsg}`;
      meta.appendChild(detail);
    }
    meta.appendChild(renderFileBubbleDetails(msg, t, kind));

    // Inline image preview for received images that are on disk.
    // Clicking the thumbnail opens the inline lightbox (with
    // Open-in-new-tab + Save-a-copy footer). v0.21.x.
    const incomingPath = msg.path || (t?.metadata?.path);
    if (msg.dir === "in" && kind === "sent" && isImageName(msg.name)) {
      const fname = (incomingPath || msg.name || "").toString().split(/[\\\/]/).pop();
      // Prefer the content-hash route (stable across name mangling and
      // duplicate names); fall back to the on-disk basename route.
      const blobUrl = blobFileUrl(msg.blob || t?.blob_hash, msg.name || fname);
      const nameUrl = fname ? `/api/files/${encodeURIComponent(fname)}` : "";
      const previewUrl = blobUrl || nameUrl;
      if (previewUrl) {
        const img = document.createElement("img");
        img.className = "img-preview";
        img.alt = msg.name || "image";
        attachImagePreviewFallback(img, meta, msg, previewUrl,
          "The file arrived, but the local inbox route could not serve an image preview.",
          blobUrl && nameUrl && blobUrl !== nameUrl ? nameUrl : "");
        _keepMessagesBottomAfterMediaLoad(img);
        img.onclick = (ev) => {
          ev.stopPropagation();
          const gal = _buildLightboxGalleryForCurrent(msg);
          if (gal) openLightbox({ gallery: gal.gallery, index: gal.index });
          else openLightbox({
            url: img.src,
            name: msg.name || fname,
            sizeBytes: msg.size || 0,
            downloadName: fname,
          });
        };
        meta.appendChild(img);
        img.src = previewUrl;
      }
    }
    // v0.21.x: outbound image thumbnail. The sender used to see no
    // preview of their own sent photo — only the recipient did. With
    // the in-memory File cache populated at upload time, we render
    // an identical thumbnail from a blob: URL so the sender's bubble
    // matches the recipient's. After a tab refresh wipes that cache,
    // `objectUrlForOutboundFile` falls back to
    // `/api/outbound_files/{transfer_id}` so the thumbnail still
    // renders. Only goes icon-only when the daemon also has no
    // record of the path (legacy pre-ledger bubbles).
    if (msg.dir === "out" && kind === "sent" && isImageName(msg.name)) {
      const cachedUrl = objectUrlForOutboundFile(msg.name, msg.size || 0, t?.id);
      if (cachedUrl) {
        const img = document.createElement("img");
        img.className = "img-preview";
        img.alt = msg.name || "image";
        attachImagePreviewFallback(img, meta, msg, cachedUrl,
          "The transfer finished, but this browser or daemon could not reopen the sender-side image preview.");
        _keepMessagesBottomAfterMediaLoad(img);
        img.onclick = (ev) => {
          ev.stopPropagation();
          const gal = _buildLightboxGalleryForCurrent(msg);
          if (gal) openLightbox({ gallery: gal.gallery, index: gal.index });
          else openLightbox({
            url: cachedUrl,
            name: msg.name || "image",
            sizeBytes: msg.size || 0,
            downloadName: msg.name || "image",
          });
        };
        meta.appendChild(img);
        img.src = cachedUrl;
      } else {
        meta.appendChild(renderImagePreviewFallback(
          msg,
          "",
          "The transfer finished, but this tab no longer has the original sender-side image and the transfer ledger has no preview route.",
          null,
        ));
      }
    }
    // v0.9.2: inline audio player for any received audio file
    // (voice messages OR forwarded clips). Only after transfer is
    // complete - mid-flight transfers don't have a file on disk
    // to source from.
    if (msg.dir === "in" && kind === "sent" && isAudioName(msg.name)) {
      const fname = (incomingPath || msg.name || "").toString().split(/[\\\/]/).pop();
      // Same content-hash-first resolution as images: the on-disk name
      // diverges from the display name, so prefer the stable by-blob route.
      const audioUrl = blobFileUrl(msg.blob || t?.blob_hash, msg.name || fname)
        || (fname ? `/api/files/${encodeURIComponent(fname)}` : "");
      if (audioUrl) {
        b.classList.add("audio");
        const wrap = el("div", "audio-player");
        const audio = document.createElement("audio");
        audio.controls = true;
        audio.preload = "metadata";
        audio.src = audioUrl;
        wrap.appendChild(audio);
        // v0.21.x: playback-speed cycle button + waveform overlay.
        wrap.appendChild(_renderAudioSpeedButton(audio));
        _renderWaveformBg(audio, audio.src, wrap, msg.blob);
        // Living Presence Tier α-pre - Reality dot.
        // If the daemon has recorded provenance for this blob (via
        // the frame_provenance WS event), render the calm indicator
        // next to the audio player. Otherwise no surface - see
        // Doctrine §3.5.c.
        const reality = renderRealityDot(msg.blob);
        if (reality) {
          wrap.appendChild(reality.dot);
          wrap.appendChild(reality.detail);
        }
        meta.appendChild(wrap);
      }
    }
    // (Outbound audio: server stages uploads into a temp dir then
    // removes them after send, so /api/files can't source the
    // sender's own clip. Sender hears themselves while recording;
    // re-playback would need a separate outbox-mirror endpoint
    // - defer that to a follow-up.)
    if (msg.dir === "out" && kind === "sent" && isAudioName(msg.name)) {
      b.classList.add("audio");
      const note = el("div", "audio-player");
      note.style.fontSize = "11px";
      note.style.color = "rgba(255,255,255,.75)";
      note.style.fontStyle = "italic";
      note.textContent = "Voice message sent";
      meta.appendChild(note);
    }

    // v0.9.0: text/markdown/code preview toggle for received files
    // whose extension is whitelisted. Lazy: a "Show preview" link
    // appears under the file row, click fetches + renders inline.
    // Result is cached per-message so re-opening the chat doesn't
    // re-fetch.
    const richPreviewsEnabled = state.runtimeSettings?.send_link_previews !== false;
    const previewKind = richPreviewsEnabled ? previewKindForName(msg.name) : null;
    if (msg.dir === "in" && kind === "sent" && previewKind) {
      const fname = (incomingPath || msg.name || "").toString().split(/[\\\/]/).pop();
      if (fname) {
        const togglesRow = el("div", "preview-toggle-row");
        const link = el("a", "preview-toggle-link", "Show preview");
        link.href = "#";
        const host = el("div", "preview-host");
        host.style.display = "none";
        link.onclick = async (ev) => {
          ev.preventDefault();
          const visible = host.style.display !== "none";
          if (visible) {
            host.style.display = "none";
            link.textContent = "Show preview";
            return;
          }
          if (host.dataset.loaded !== "1") {
            host.innerHTML = "";
            host.appendChild(el("div", "preview-loading", "Loading…"));
            host.style.display = "";
            link.textContent = "Hide preview";
            try {
              const data = await api.get(
                `/api/files/${encodeURIComponent(fname)}/preview`
              );
              host.innerHTML = "";
              host.appendChild(renderPreviewByKind(
                data.kind, data.content || "", data.extension || "",
                { streamUrl: data.stream_url || "", name: data.name || "" },
              ));
              if (data.truncated) {
                const tnote = el("div", "preview-truncated",
                  `Preview truncated at ${fmtBytes(data.preview_bytes)} of ${fmtBytes(data.size)}.`);
                host.appendChild(tnote);
              }
              host.dataset.loaded = "1";
            } catch (e) {
              host.innerHTML = "";
              host.appendChild(el("div", "preview-error",
                `Preview didn't work: ${e.message || e}`));
            }
          } else {
            host.style.display = "";
            link.textContent = "Hide preview";
          }
        };
        togglesRow.appendChild(link);
        meta.appendChild(togglesRow);
        meta.appendChild(host);
      }
    }

    // Action row - Open / Reveal / Retry depending on state
    const actions = el("div", "actions");
    if (msg.dir === "in" && kind === "sent") {
      const fname = (incomingPath || msg.name || "").toString().split(/[\\\/]/).pop();
      if (fname) {
        const open = el("a", null, "Open");
        open.href = `/api/files/${encodeURIComponent(fname)}`;
        open.target = "_blank";
        actions.appendChild(open);
        // 2026-06-04: One-click save-to-Downloads. ?dl=1 makes the
        // server emit ``Content-Disposition: attachment`` so the
        // browser always saves the file instead of opening it
        // inline (Edge previously ignored the <a download> attribute
        // for PDFs/images and opened them in a tab). The ``name``
        // query carries the display name so the file lands in
        // Downloads with the user's original filename, not the
        // inbox's prefix-mangled on-disk name.
        const saveAs = displayFileName(msg.name || fname);
        const download = el("a", "btn-download-arrow");
        download.href = (
          `/api/files/${encodeURIComponent(fname)}`
          + `?dl=1&name=${encodeURIComponent(saveAs)}`
        );
        download.setAttribute("download", saveAs);
        download.title = "Download to your Downloads folder";
        download.setAttribute("aria-label", "Download to Downloads folder");
        download.innerHTML = (
          // Material file_download silhouette: arrow shaft + arrow
          // head + a horizontal tray at the bottom so the icon
          // reads as "save to disk" at a glance, not just "down".
          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" '
          + 'stroke="currentColor" stroke-width="2.2" stroke-linecap="round" '
          + 'stroke-linejoin="round" aria-hidden="true">'
          + '<path d="M12 4v11"/>'
          + '<path d="M7 10l5 5 5-5"/>'
          + '<path d="M5 19h14"/>'
          + '</svg>'
        );
        actions.appendChild(download);
        // v0.9.7: "Reveal" → "Show in folder". The button used to
        // pop an Explorer window silently; now we surface immediate
        // feedback so the user knows the click registered even if
        // the OS file manager takes a moment to focus.
        const reveal = el("button", null, "Show in folder");
        reveal.title = "Open the inbox in your file manager with this file selected";
        reveal.onclick = async () => {
          const t = toast("Opening folder…", "info", 2500);
          try {
            const res = await api.post(`/api/files/${encodeURIComponent(fname)}/reveal`, {});
            if (res?.throttled) {
              t?.remove?.();
              toast("Folder is opening - check your taskbar.", "info", 2500);
            }
          } catch (e) {
            t?.remove?.();
            toast(`Show in folder failed: ${e.message || e}`, "bad");
          }
        };
        actions.appendChild(reveal);
      }
    }
    if (kind === "failed") {
      const why = (t?.metadata?.error) ? ` (${t.metadata.error_class || "error"})` : "";
      if (why) {
        const detail = el("div", "size");
        detail.textContent = (t.metadata.error || "").slice(0, 120) + why;
        meta.appendChild(detail);
      }
    }

    b.appendChild(icon);
    b.appendChild(meta);
    if (actions.children.length > 0) b.appendChild(actions);
    b.appendChild(el("span", "when", fmtTime(msg.ts)));
    return b;
  }

