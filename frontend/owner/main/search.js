  // ── Search wiring ──────────────────────────────────────────────────
  const searchWrap = $("#search-wrap");
  const searchInput = $("#search-input");
  const searchToggle = $("#btn-search-toggle");
  const searchBanner = $("#search-banner");
  const searchBannerText = $("#search-banner-text");
  const clearSearch = $("#btn-clear-search");
  let searchTimer = null;

  searchToggle.onclick = () => {
    searchWrap.classList.toggle("open");
    if (searchWrap.classList.contains("open")) {
      searchInput.focus();
    } else {
      searchInput.value = "";
      finishSearch();
    }
  };
  searchInput.addEventListener("input", () => {
    clearTimeout(searchTimer);
    const q = searchInput.value.trim();
    if (!q) { finishSearch(); return; }
    searchTimer = setTimeout(() => runSearch(q), 220);
  });
  searchInput.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { searchInput.value = ""; finishSearch(); searchToggle.click(); }
  });
  clearSearch.onclick = () => { searchInput.value = ""; finishSearch(); };

  // v0.21.x: jump to date. Click Date -> tiny date-picker popover. On
  // pick, find the first message on (or after) that date and scroll
  // it into view. Toast if no messages exist on the chosen date.
  function _localDateKeyFromMs(ms) {
    const d = new Date(ms);
    if (!Number.isFinite(d.getTime())) return "";
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, "0");
    const day = String(d.getDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
  }

  function _friendlyDateKey(key) {
    if (!key) return "";
    const [y, m, d] = key.split("-").map((x) => parseInt(x, 10));
    if (!y || !m || !d) return key;
    return new Date(y, m - 1, d).toLocaleDateString();
  }

  function _normalizeJumpDateInput(raw) {
    const v = String(raw || "").trim();
    if (!v) return { ok: false, reason: "Choose a date first." };
    if (/(^|[\/-])\d{5,}($|[\/-])/.test(v)) {
      return {
        ok: false,
        reason: "Years must be four digits. Use a date like 2026-05-21.",
      };
    }
    let y; let m; let d;
    let match = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(v);
    if (match) {
      y = parseInt(match[1], 10);
      m = parseInt(match[2], 10);
      d = parseInt(match[3], 10);
    } else {
      match = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(v);
      if (!match) {
        return {
          ok: false,
          reason: "Use YYYY-MM-DD or MM/DD/YYYY, or pick a date from the calendar.",
        };
      }
      m = parseInt(match[1], 10);
      d = parseInt(match[2], 10);
      y = parseInt(match[3], 10);
    }
    const chosenYear = y;
    if (chosenYear < 2000 || chosenYear > 2100 || m < 1 || m > 12 || d < 1 || d > 31) {
      return { ok: false, reason: "That date looks wrong. Pick a date inside the conversation range." };
    }
    const dt = new Date(y, m - 1, d);
    if (dt.getFullYear() !== y || dt.getMonth() !== m - 1 || dt.getDate() !== d) {
      return { ok: false, reason: "That calendar date does not exist." };
    }
    return {
      ok: true,
      value: `${y}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`,
    };
  }

  function _messagesForJumpDate() {
    if (state.selectedGroup) {
      return (state.groupMessages || [])
        .map((mm) => ({ ...mm, _jumpTs: mm.ts_ms || mm.ts }))
        .filter((mm) => Number.isFinite(mm._jumpTs))
        .sort((a, b) => a._jumpTs - b._jumpTs);
    }
    if (state.selectedPeer) {
      return (state.messages || [])
        .filter((mm) => mm.peer === state.selectedPeer)
        .map((mm) => ({ ...mm, _jumpTs: mm.ts_ms || mm.ts }))
        .filter((mm) => Number.isFinite(mm._jumpTs))
        .sort((a, b) => a._jumpTs - b._jumpTs);
    }
    return [];
  }

  function _jumpToMessageNode(target, note) {
    const node = target?.id
      ? document.querySelector(`[data-msg-id="${CSS.escape(target.id)}"]`)
      : null;
    if (!node) {
      toast("I found that date, but the message is not visible yet. Refreshing this conversation...", "info", 4000);
      if (state.selectedGroup) renderGroupConversation();
      else renderMessages();
      setTimeout(() => _jumpToMessageNode(target, note), 120);
      return;
    }
    node.scrollIntoView({ behavior: "smooth", block: "center" });
    node.classList.add("jumped-to");
    setTimeout(() => node.classList.remove("jumped-to"), 1800);
    if (note) toast(note, "info", 5000);
  }

  $("#btn-jump-date")?.addEventListener("click", (ev) => {
    ev.stopPropagation();
    document.querySelectorAll(".jump-date-popover").forEach((p) => p.remove());
    if (!state.selectedPeer && !state.selectedGroup) {
      toast("Pick a chat first to jump within a conversation.", "info", 3500);
      return;
    }
    const jumpMessages = _messagesForJumpDate();
    if (!jumpMessages.length) {
      toast("This conversation has no messages to jump through yet.", "info", 4000);
      return;
    }
    const firstKey = _localDateKeyFromMs(jumpMessages[0]._jumpTs);
    const lastKey = _localDateKeyFromMs(jumpMessages[jumpMessages.length - 1]._jumpTs);
    const pop = el("div", "jump-date-popover");
    pop.setAttribute("role", "dialog");
    pop.innerHTML = `
      <label class="jdp-label" for="jump-date-input">Jump to date</label>
      <input type="date" class="jdp-input" id="jump-date-input" />
      <button type="button" class="jdp-go">Jump</button>
      <div class="jdp-hint" id="jump-date-hint" role="status" aria-live="polite"></div>
    `;
    document.body.appendChild(pop);
    const r = ev.currentTarget.getBoundingClientRect();
    pop.style.left = `${Math.max(8, r.left - 120)}px`;
    pop.style.top = `${r.bottom + 6}px`;
    const input = pop.querySelector(".jdp-input");
    const go = pop.querySelector(".jdp-go");
    const hint = pop.querySelector(".jdp-hint");
    input.min = firstKey;
    input.max = lastKey;
    input.value = lastKey;
    input.setAttribute("aria-describedby", "jump-date-hint");
    input.setAttribute("inputmode", "numeric");
    hint.textContent = `Available: ${_friendlyDateKey(firstKey)} - ${_friendlyDateKey(lastKey)}. If that day has no messages, I will jump to the nearest one.`;
    setTimeout(() => {
      input.focus();
      try { input.showPicker?.(); } catch {}
    }, 60);
    function setJumpHint(text, kind = "info") {
      hint.textContent = text;
      hint.classList.toggle("bad", kind === "bad");
      input.classList.toggle("invalid", kind === "bad");
      input.setAttribute("aria-invalid", kind === "bad" ? "true" : "false");
      if (kind === "bad") toast(text, "bad", 4500);
    }
    input.addEventListener("input", () => {
      hint.classList.remove("bad");
      input.classList.remove("invalid");
      input.setAttribute("aria-invalid", "false");
    });
    function close() {
      pop.remove();
      document.removeEventListener("click", off, true);
      document.removeEventListener("keydown", esc);
    }
    function off(e) { if (!pop.contains(e.target)) close(); }
    function esc(e) { if (e.key === "Escape") close(); }
    setTimeout(() => {
      document.addEventListener("click", off, true);
      document.addEventListener("keydown", esc);
    }, 0);
    const jump = () => {
      const parsed = _normalizeJumpDateInput(input.value);
      if (!parsed.ok) {
        setJumpHint(parsed.reason, "bad");
        return;
      }
      const v = parsed.value;
      input.value = v;
      if (v < firstKey || v > lastKey) {
        setJumpHint(
          `That date is outside this conversation. I will jump to the nearest message between ${_friendlyDateKey(firstKey)} and ${_friendlyDateKey(lastKey)}.`,
          "info",
        );
      } else {
        setJumpHint(`Jumping to ${_friendlyDateKey(v)}...`);
      }
      const exact = jumpMessages.find((mm) => _localDateKeyFromMs(mm._jumpTs) === v);
      let target = exact;
      let note = "";
      if (!target) {
        const after = jumpMessages.find((mm) => _localDateKeyFromMs(mm._jumpTs) > v);
        const before = [...jumpMessages].reverse().find((mm) => _localDateKeyFromMs(mm._jumpTs) < v);
        target = after || before || null;
        if (target) {
          const actual = _localDateKeyFromMs(target._jumpTs);
          note = `No messages on ${_friendlyDateKey(v)}. Jumped to nearest message: ${_friendlyDateKey(actual)}.`;
        }
      }
      close();
      if (!target) {
        toast("No messages found in this conversation.", "info", 4500);
        return;
      }
      _jumpToMessageNode(target, note);
    };
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") jump(); });
    go.onclick = jump;
  });

  // v0.7.3: the previous global `.cap-toggle` binding lived here.
  // It was leftover from the now-deleted chat-header peer-tools
  // row, and it ran AFTER the drawer-specific binding - silently
  // overwriting the drawer's onclick handlers, which is why the
  // drawer's toggles + Save flow appeared dead. Drawer wiring is
  // now self-contained inside openDeviceDrawer.

  // v0.21.x: parse search operators out of the query.
  // Supports: from:<name>  has:photo|file|link  before:YYYY-MM-DD
  // after:YYYY-MM-DD  is:starred  Anything else stays as the plain
  // text query sent to the server.
  // v0.21.x: wrap occurrences of `needle` (case-insensitive) in <mark>
  // inside `root`. Walks text nodes only so <a>/<code>/<pre> remain
  // intact. Skips already-highlighted nodes.
  function _highlightSearchMatches(root, needle) {
    if (!needle) return;
    const re = new RegExp(needle.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        if (!node.nodeValue) return NodeFilter.FILTER_REJECT;
        if (node.parentNode && node.parentNode.tagName === "MARK") return NodeFilter.FILTER_REJECT;
        if (node.parentNode && node.parentNode.tagName === "SCRIPT") return NodeFilter.FILTER_REJECT;
        return re.test(node.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
      },
    });
    const targets = [];
    let n;
    while ((n = walker.nextNode())) targets.push(n);
    for (const node of targets) {
      const parts = node.nodeValue.split(re);
      const matches = node.nodeValue.match(re);
      if (!matches || matches.length === 0) continue;
      const frag = document.createDocumentFragment();
      for (let i = 0; i < parts.length; i++) {
        if (parts[i]) frag.appendChild(document.createTextNode(parts[i]));
        if (i < matches.length) {
          const mark = document.createElement("mark");
          mark.textContent = matches[i];
          frag.appendChild(mark);
        }
      }
      node.parentNode.replaceChild(frag, node);
    }
  }

  function _parseSearchQuery(raw) {
    const ops = {
      from: null, has: [], before: null, after: null, is_starred: false,
    };
    const plainParts = [];
    const tokens = String(raw).match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    for (const tok of tokens) {
      const m = tok.match(/^(from|has|before|after|is):(.+)$/i);
      if (!m) { plainParts.push(tok.replace(/^"|"$/g, "")); continue; }
      const op = m[1].toLowerCase();
      const val = m[2].replace(/^"|"$/g, "").toLowerCase();
      if (op === "from") ops.from = val;
      else if (op === "has") ops.has.push(val);
      else if (op === "before") ops.before = Date.parse(val) || null;
      else if (op === "after") ops.after = Date.parse(val) || null;
      else if (op === "is" && val === "starred") ops.is_starred = true;
    }
    return { plain: plainParts.join(" ").trim(), ops };
  }
  function _matchesSearchOps(msg, ops) {
    if (ops.from) {
      const peer = state.peers.get(msg.peer);
      const who = (peer?.display_name || peer?.hostname || msg.peer || "").toLowerCase();
      const me = (state.me?.display_name || state.me?.hostname || "").toLowerCase();
      if (msg.dir === "out") {
        if (!me.includes(ops.from) && ops.from !== "me") return false;
      } else if (!who.includes(ops.from)) return false;
    }
    for (const h of ops.has) {
      if (h === "photo" || h === "image") {
        if (msg.t !== "FILE_OFFER" || !isImageName(msg.name)) return false;
      } else if (h === "file") {
        if (msg.t !== "FILE_OFFER" && msg.t !== "FILE_DONE") return false;
      } else if (h === "link") {
        if (!(msg.body || "").match(/\bhttps?:\/\//)) return false;
      } else if (h === "voice" || h === "audio") {
        if (!(msg.t === "FILE_OFFER" && isAudioName(msg.name))) return false;
      }
    }
    if (ops.before && msg.ts > ops.before) return false;
    if (ops.after && msg.ts < ops.after) return false;
    if (ops.is_starred && !state.starred[msg.id]) return false;
    return true;
  }
  async function runSearch(q) {
    if (!state.selectedPeer) {
      searchBanner.style.display = "flex";
      searchBannerText.textContent = "Select a peer to search their conversation.";
      return;
    }
    try {
      const { plain, ops } = _parseSearchQuery(q);
      const peer = state.peers.get(state.selectedPeer);
      const fp = peer?.fingerprint || state.selectedPeer;
      const url = `/api/search?q=${encodeURIComponent(plain)}&peer=${encodeURIComponent(fp)}&limit=200`;
      const r = await api.get(url);
      let results = r.messages || [];
      // Apply operator filters client-side.
      const hasOps = ops.from || ops.has.length || ops.before || ops.after || ops.is_starred;
      if (hasOps) results = results.filter((m) => _matchesSearchOps(m, ops));
      state.searchQuery = q;
      state.searchPlain = plain;
      state.searchResults = results;
      searchBanner.style.display = "flex";
      const hintSuffix = hasOps ? " (with filters)" : "";
      searchBannerText.textContent = `${results.length} result${results.length === 1 ? "" : "s"} for "${q}"${hintSuffix}`;
      renderMessages();
    } catch (e) {
      searchBannerText.textContent = `Search didn't work: ${e.message || e}`;
      searchBanner.style.display = "flex";
    }
  }

  function finishSearch() {
    state.searchQuery = "";
    state.searchPlain = "";
    state.searchResults = null;
    searchBanner.style.display = "none";
    renderMessages();
  }

