  function _daemonSearchResultButton(kind, title, subtitle, onClick) {
    const row = document.createElement("button");
    row.type = "button";
    row.style.display = "flex";
    row.style.alignItems = "center";
    row.style.gap = "10px";
    row.style.padding = "10px 12px";
    row.style.background = "var(--bg-3)";
    row.style.border = "1px solid var(--line)";
    row.style.borderRadius = "10px";
    row.style.color = "var(--text)";
    row.style.cursor = onClick ? "pointer" : "default";
    row.style.textAlign = "left";
    row.style.width = "100%";
    row.style.fontFamily = "inherit";
    const badge = document.createElement("span");
    badge.textContent = kind;
    badge.style.flex = "0 0 auto";
    badge.style.fontSize = "10px";
    badge.style.color = "var(--text-dim)";
    badge.style.textTransform = "uppercase";
    badge.style.letterSpacing = "0.5px";
    const body = document.createElement("span");
    body.style.flex = "1 1 auto";
    body.style.minWidth = "0";
    const name = document.createElement("span");
    name.textContent = title || "(untitled)";
    name.style.display = "block";
    name.style.fontWeight = "600";
    name.style.fontSize = "14px";
    name.style.overflow = "hidden";
    name.style.textOverflow = "ellipsis";
    name.style.whiteSpace = "nowrap";
    const sub = document.createElement("span");
    sub.textContent = subtitle || "";
    sub.style.display = "block";
    sub.style.fontSize = "11px";
    sub.style.color = "var(--text-dim)";
    sub.style.overflow = "hidden";
    sub.style.textOverflow = "ellipsis";
    sub.style.whiteSpace = "nowrap";
    body.appendChild(name);
    body.appendChild(sub);
    row.appendChild(badge);
    row.appendChild(body);
    if (onClick) row.onclick = onClick;
    return row;
  }

  function _findDaemonRosterPeer(fp) {
    const peers = Array.isArray(state.daemon_roster_peers)
      ? state.daemon_roster_peers : [];
    return peers.find((p) => p && p.fingerprint === fp) || null;
  }

  function _findDaemonRosterGroup(groupId) {
    const groups = Array.isArray(state.daemon_roster_groups)
      ? state.daemon_roster_groups : [];
    return groups.find((g) => g && g.group_id === groupId) || null;
  }

  function _renderDaemonGlobalSearchResults(results, query) {
    const wrap = $("#daemon-global-search-results");
    if (!wrap) return;
    wrap.innerHTML = "";
    const messages = Array.isArray(results.messages) ? results.messages : [];
    const peers = Array.isArray(results.peers) ? results.peers : [];
    const groups = Array.isArray(results.groups) ? results.groups : [];
    const files = Array.isArray(results.files) ? results.files : [];
    const total = messages.length + peers.length + groups.length + files.length;
    wrap.hidden = false;
    if (!total) {
      const empty = document.createElement("p");
      empty.className = "help";
      empty.textContent = `No matches for "${query}".`;
      wrap.appendChild(empty);
      return;
    }
    const summary = document.createElement("p");
    summary.className = "help";
    summary.textContent =
      `${total} result${total === 1 ? "" : "s"} for "${query}".`;
    wrap.appendChild(summary);
    for (const p of peers) {
      const peer = _findDaemonRosterPeer(p.fingerprint) || {
        fingerprint: p.fingerprint,
        alias: p.display_name,
        hostname: p.hostname,
        short_id: p.short_id,
        trust: p.trust,
        last_seen_ms: p.last_seen_ms,
      };
      wrap.appendChild(_daemonSearchResultButton(
        "peer",
        p.display_name || p.hostname || p.short_id || p.fingerprint,
        p.fingerprint || "",
        () => _openDaemonChat(peer),
      ));
    }
    for (const g of groups) {
      const group = _findDaemonRosterGroup(g.group_id) || {
        group_id: g.group_id,
        name: g.name || "Group",
        member_count: g.member_count || 0,
      };
      wrap.appendChild(_daemonSearchResultButton(
        "group",
        g.name || "Group",
        g.group_id || "",
        () => _openDaemonGroupChat(group),
      ));
    }
    for (const m of messages) {
      const peer = _findDaemonRosterPeer(m.peer_fp) || {
        fingerprint: m.peer_fp,
        alias: m.peer_display_name,
      };
      wrap.appendChild(_daemonSearchResultButton(
        "msg",
        m.peer_display_name || m.peer_fp || "Message",
        m.body || "",
        () => peer && peer.fingerprint && _openDaemonChat(peer),
      ));
    }
    for (const f of files) {
      wrap.appendChild(_daemonSearchResultButton(
        "file",
        f.name || "File",
        f.size ? `${f.size} bytes` : "",
        null,
      ));
    }
  }

  async function _handleDaemonGlobalSearch() {
    const input = $("#daemon-global-search-input");
    const results = $("#daemon-global-search-results");
    if (!input || !results) return;
    const query = input.value.trim();
    if (!query) {
      results.innerHTML = "";
      results.hidden = true;
      return;
    }
    results.hidden = false;
    results.innerHTML = "";
    const loading = document.createElement("p");
    loading.className = "help";
    loading.textContent = "Searching everything...";
    results.appendChild(loading);
    try {
      const reply = await searchDaemonGlobal(query, 10);
      _renderDaemonGlobalSearchResults(reply, query);
    } catch (e) {
      loading.textContent =
        `Search failed: ${e && e.message ? e.message : e}`;
    }
  }

