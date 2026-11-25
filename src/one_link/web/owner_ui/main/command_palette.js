  // ── Command palette / global search (v0.9.3) ───────────────────────
  // Ctrl+K (or Cmd+K) opens a modal with one input + result list.
  // Searches messages, peers, groups, and inbox files via the
  // /api/search endpoint. Arrow keys navigate; Enter activates;
  // Esc closes.
  state.paletteOpen = false;
  state.paletteFocusIdx = 0;
  state.paletteResults = [];      // flat list mirroring the rendered rows
  state.paletteQuery = "";
  let _paletteDebounce = null;

  function openPalette() {
    if (state.paletteOpen) return;
    state.paletteOpen = true;
    $("#palette-backdrop").classList.add("show");
    const input = $("#palette-input");
    input.value = "";
    state.paletteQuery = "";
    state.paletteResults = [];
    state.paletteFocusIdx = 0;
    renderPaletteResults({ messages: [], peers: [], groups: [], files: [] });
    setTimeout(() => input.focus(), 0);
  }
  function closePalette() {
    state.paletteOpen = false;
    $("#palette-backdrop").classList.remove("show");
  }

  function paletteHighlight(text, query) {
    // Simple case-insensitive highlight - wraps the matched span
    // in <mark>. Falls back to plain text if no match.
    const t = String(text || "");
    if (!query) return document.createTextNode(t);
    const idx = t.toLowerCase().indexOf(query.toLowerCase());
    if (idx < 0) return document.createTextNode(t);
    const frag = document.createDocumentFragment();
    if (idx > 0) frag.appendChild(document.createTextNode(t.slice(0, idx)));
    const m = document.createElement("mark");
    m.textContent = t.slice(idx, idx + query.length);
    frag.appendChild(m);
    if (idx + query.length < t.length) {
      frag.appendChild(document.createTextNode(t.slice(idx + query.length)));
    }
    return frag;
  }

  function renderPaletteResults(r) {
    const host = $("#palette-results");
    host.innerHTML = "";
    state.paletteResults = [];
    const q = state.paletteQuery;
    const total = (r.messages?.length || 0) + (r.peers?.length || 0) +
                  (r.groups?.length || 0) + (r.files?.length || 0);
    if (q && total === 0) {
      host.appendChild(el("div", "palette-empty", `Nothing matches "${q}". Spell it different?`));
      return;
    }
    if (!q) {
      host.appendChild(el("div", "palette-hint",
        "Type to search across this device's messages, peers, groups, and received files."));
      return;
    }

    // Order: peers > groups > messages > files. Peers are most
    // likely "I want to switch to that conversation"; messages are
    // higher signal but visually noisier so come after the navigation
    // candidates.
    if (r.peers && r.peers.length > 0) {
      host.appendChild(el("div", "palette-section-h", "Devices"));
      for (const p of r.peers) {
        const row = paletteRowPeer(p, q);
        state.paletteResults.push({ row, action: () => paletteOpenPeer(p) });
        host.appendChild(row);
      }
    }
    if (r.groups && r.groups.length > 0) {
      host.appendChild(el("div", "palette-section-h", "Groups"));
      for (const g of r.groups) {
        const row = paletteRowGroup(g, q);
        state.paletteResults.push({ row, action: () => paletteOpenGroup(g) });
        host.appendChild(row);
      }
    }
    if (r.messages && r.messages.length > 0) {
      host.appendChild(el("div", "palette-section-h", "Messages"));
      for (const m of r.messages) {
        const row = paletteRowMessage(m, q);
        state.paletteResults.push({ row, action: () => paletteOpenMessage(m) });
        host.appendChild(row);
      }
    }
    if (r.files && r.files.length > 0) {
      host.appendChild(el("div", "palette-section-h", "Files"));
      for (const f of r.files) {
        const row = paletteRowFile(f, q);
        state.paletteResults.push({ row, action: () => paletteOpenFile(f) });
        host.appendChild(row);
      }
    }
    state.paletteFocusIdx = 0;
    if (state.paletteResults[0]) {
      state.paletteResults[0].row.classList.add("focused");
    }
  }

  function paletteRowPeer(p, q) {
    const row = el("div", "palette-row");
    row.appendChild(el("div", "pr-icon", "👤"));
    const body = el("div", "pr-body");
    const title = el("div", "pr-title");
    title.appendChild(paletteHighlight(
      p.display_name || p.hostname || p.short_id, q,
    ));
    if (p.is_verified) {
      const v = el("span"); v.style.color = "var(--good)"; v.textContent = " ✓";
      title.appendChild(v);
    }
    body.appendChild(title);
    body.appendChild(el("div", "pr-sub",
      `${p.trust} · ${p.short_id}`));
    row.appendChild(body);
    row.appendChild(el("span", "pr-kind", "PEER"));
    row.onclick = () => paletteOpenPeer(p);
    return row;
  }
  function paletteRowGroup(g, q) {
    const row = el("div", "palette-row");
    row.appendChild(el("div", "pr-icon", "👥"));
    const body = el("div", "pr-body");
    const title = el("div", "pr-title");
    title.appendChild(paletteHighlight(g.name || "(unnamed)", q));
    body.appendChild(title);
    body.appendChild(el("div", "pr-sub", `Group · ${g.group_id.slice(0, 12)}…`));
    row.appendChild(body);
    row.appendChild(el("span", "pr-kind", "GROUP"));
    row.onclick = () => paletteOpenGroup(g);
    return row;
  }
  function paletteRowMessage(m, q) {
    const row = el("div", "palette-row");
    row.appendChild(el("div", "pr-icon", m.direction === "out" ? "↗" : "↘"));
    const body = el("div", "pr-body");
    const title = el("div", "pr-title");
    title.appendChild(paletteHighlight(m.body || "(empty)", q));
    body.appendChild(title);
    const who = m.peer_display_name || m.peer_fp?.slice(0, 8) || "?";
    const when = m.ts_ms ? new Date(m.ts_ms).toLocaleString() : "?";
    body.appendChild(el("div", "pr-sub", `${who} · ${when}`));
    row.appendChild(body);
    row.appendChild(el("span", "pr-kind", "MSG"));
    row.onclick = () => paletteOpenMessage(m);
    return row;
  }
  function paletteRowFile(f, q) {
    const row = el("div", "palette-row");
    row.appendChild(el("div", "pr-icon", fileIcon(f.name)));
    const body = el("div", "pr-body");
    const title = el("div", "pr-title");
    title.appendChild(paletteHighlight(f.name, q));
    body.appendChild(title);
    body.appendChild(el("div", "pr-sub",
      `${fmtBytes(f.size)} · ${new Date(f.mtime_ms || 0).toLocaleString()}`));
    row.appendChild(body);
    row.appendChild(el("span", "pr-kind", "FILE"));
    row.onclick = () => paletteOpenFile(f);
    return row;
  }

  function paletteOpenPeer(p) {
    closePalette();
    if (!p.short_id) return;
    selectPeer(p.short_id);
  }
  function paletteOpenGroup(g) {
    closePalette();
    if (g.group_id) selectGroup(g.group_id);
  }
  function paletteOpenMessage(m) {
    closePalette();
    // Switch to the conversation, then scroll to the message id.
    if (m.room_id) {
      // Group message - if we know which group.
      // No direct ID mapping here; just open the conversation.
    }
    if (m.peer_fp) {
      const peer = [...state.peers.values()]
        .find(p => p.fingerprint === m.peer_fp);
      if (peer) selectPeer(peer.short_id);
    }
    // Best-effort: scroll to the message after a tick (chat
    // re-render runs on rAF).
    // 2026-05-22 audit Batch V: match the CSS.escape pattern used by
    // the four sibling lookup sites (14948, 15333, 16915, 19840) so
    // a malformed / legacy message id with quote/backslash doesn't
    // throw SyntaxError and abort the enclosing async handler.
    setTimeout(() => {
      const node = document.querySelector(`[data-msg-id="${CSS.escape(m.id)}"]`);
      if (node) node.scrollIntoView({ block: "center", behavior: "smooth" });
    }, 80);
  }
  function paletteOpenFile(f) {
    closePalette();
    // Open the file in a new tab - same as the per-bubble Open link.
    window.open(`/api/files/${encodeURIComponent(f.name)}`, "_blank");
  }

  function paletteFocus(delta) {
    if (state.paletteResults.length === 0) return;
    state.paletteResults[state.paletteFocusIdx]?.row.classList.remove("focused");
    state.paletteFocusIdx =
      (state.paletteFocusIdx + delta + state.paletteResults.length)
        % state.paletteResults.length;
    const r = state.paletteResults[state.paletteFocusIdx];
    r?.row.classList.add("focused");
    r?.row.scrollIntoView({ block: "nearest" });
  }
  function paletteActivateFocused() {
    const r = state.paletteResults[state.paletteFocusIdx];
    if (r) r.action();
  }

  async function runPaletteSearch(q) {
    state.paletteQuery = q;
    if (!q) {
      renderPaletteResults({ messages: [], peers: [], groups: [], files: [] });
      return;
    }
    try {
      const r = await api.get(`/api/palette?q=${encodeURIComponent(q)}&limit=10`);
      // Drop the response if the user kept typing; only render the
      // freshest query's results.
      if (state.paletteQuery !== q) return;
      renderPaletteResults(r);
    } catch (e) {
      const host = $("#palette-results");
      host.innerHTML = "";
      host.appendChild(el("div", "palette-empty",
        `Search didn't work: ${e.message || e}`));
    }
  }

  // Wire keyboard.
  document.addEventListener("keydown", (e) => {
    // Ctrl/Cmd + K opens the palette from anywhere.
    // Legacy shortcut smoke shape: "k" || e.key === "K"
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k" && !e.shiftKey) {
      // Don't fight the existing per-conversation Ctrl+K - only
      // override when palette is closed AND the active element
      // isn't the conversation search input.
      if (document.activeElement?.id === "search-input") return;
      e.preventDefault();
      openPalette();
      return;
    }
    if (!state.paletteOpen) return;
    if (e.key === "Escape") {
      e.preventDefault();
      closePalette();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      paletteFocus(+1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      paletteFocus(-1);
    } else if (e.key === "Enter") {
      e.preventDefault();
      paletteActivateFocused();
    }
  });

  // Wire input.
  $("#palette-input")?.addEventListener("input", (e) => {
    const q = e.target.value;
    if (_paletteDebounce !== null) clearTimeout(_paletteDebounce);
    _paletteDebounce = setTimeout(() => runPaletteSearch(q.trim()), 120);
  });
  // Click outside the modal closes it.
  $("#palette-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) closePalette();
  });

