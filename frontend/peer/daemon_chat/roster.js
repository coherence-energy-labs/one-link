  async function _refreshDaemonRoster() {
    const list = $("#daemon-peers-list");
    const status = $("#daemon-roster-status");
    if (!list) return;
    // Single-pane: roster takes the screen. Hides any prior
    // autopair / enroll / chat / settings card.
    _showOnly("#daemon-roster-card");
    text(status, "Fetching your chats from the laptop…");
    list.innerHTML = "";
    let peers;
    let groups = [];
    try {
      peers = await fetchDaemonPeers();
      groups = await fetchDaemonGroups().catch(() => []);
    } catch (e) {
      text(status,
        `Couldn't fetch chats: ${e && e.message ? e.message : e}`);
      return;
    }
    state.daemon_roster_peers = peers.slice();
    state.daemon_roster_groups = groups.slice();
    if (!peers.length && !groups.length) {
      text(status, "No chats yet on this device. Pair a peer on your laptop first.");
      return;
    }
    const totalChats = peers.length + groups.length;
    text(status, `${totalChats} chat${totalChats === 1 ? "" : "s"}`);
    // Sort by last_seen_ms desc so most-recent activity floats up.
    peers.sort((a, b) =>
      Number(b.last_seen_ms || 0) - Number(a.last_seen_ms || 0)
    );
    for (const peer of peers) {
      const row = document.createElement("button");
      row.style.display = "flex";
      row.style.alignItems = "center";
      row.style.gap = "12px";
      row.style.padding = "12px 14px";
      row.style.background = "var(--bg-3)";
      row.style.border = "1px solid var(--line)";
      row.style.borderRadius = "10px";
      row.style.color = "var(--text)";
      row.style.cursor = "pointer";
      row.style.textAlign = "left";
      row.style.minHeight = "60px";
      row.style.width = "100%";
      row.style.fontFamily = "inherit";
      const left = document.createElement("div");
      left.style.flex = "1 1 auto";
      left.style.minWidth = "0";
      const name = document.createElement("div");
      name.textContent =
        peer.alias || peer.hostname ||
        (peer.fingerprint || "").split(":").pop().slice(0, 12);
      name.style.fontWeight = "600";
      name.style.fontSize = "15px";
      const sub = document.createElement("div");
      sub.style.fontSize = "11px";
      sub.style.color = "var(--text-dim)";
      sub.style.fontFamily = "ui-monospace, SFMono-Regular, Consolas, monospace";
      sub.style.overflow = "hidden";
      sub.style.textOverflow = "ellipsis";
      sub.style.whiteSpace = "nowrap";
      sub.textContent = peer.fingerprint || "(no fingerprint)";
      left.appendChild(name);
      left.appendChild(sub);
      const chev = document.createElement("div");
      chev.textContent = "›";
      chev.style.fontSize = "20px";
      chev.style.color = "var(--text-dim)";
      row.appendChild(left);
      row.appendChild(chev);
      row.onclick = () => _openDaemonChat(peer);
      list.appendChild(row);
    }
    for (const group of groups) {
      const row = document.createElement("button");
      row.style.display = "flex";
      row.style.alignItems = "center";
      row.style.gap = "12px";
      row.style.padding = "12px 14px";
      row.style.background = "var(--bg-3)";
      row.style.border = "1px solid var(--line)";
      row.style.borderRadius = "10px";
      row.style.color = "var(--text)";
      row.style.cursor = "pointer";
      row.style.textAlign = "left";
      row.style.minHeight = "60px";
      row.style.width = "100%";
      row.style.fontFamily = "inherit";
      const left = document.createElement("div");
      left.style.flex = "1 1 auto";
      left.style.minWidth = "0";
      const name = document.createElement("div");
      name.textContent = group.name || "Group";
      name.style.fontWeight = "600";
      name.style.fontSize = "15px";
      const sub = document.createElement("div");
      sub.style.fontSize = "11px";
      sub.style.color = "var(--text-dim)";
      sub.textContent = `${group.member_count || 0} members`;
      left.appendChild(name);
      left.appendChild(sub);
      const chev = document.createElement("div");
      chev.textContent = "›";
      chev.style.fontSize = "20px";
      chev.style.color = "var(--text-dim)";
      row.appendChild(left);
      row.appendChild(chev);
      row.onclick = () => _openDaemonGroupChat(group);
      list.appendChild(row);
    }
  }

