  function renderOneNow() {
    const card = $("#one-now");
    if (card) {
      const nearbyOpen = $("#activity-nearby-panel")?.classList.contains("show");
      card.style.display = nearbyOpen ? "none" : "";
    }
    const title = $("#one-now-title");
    const detail = $("#one-now-detail");
    if (!title || !detail) return;
    const status = state.status || {};
    const mesh = state.selfMesh || {};
    const moving = Number(status.transfers?.active || 0);
    const sessions = Number(status.performance?.sessions?.open || 0);
    const devices = Array.isArray(mesh.devices) ? mesh.devices.filter(d => !d.revoked) : [];
    const awake = Array.isArray(mesh.presence)
      ? mesh.presence.filter(p => p.state === "awake").length
      : 0;
    if (moving > 0) {
      title.textContent = `${moving} transfer${moving === 1 ? "" : "s"} moving`;
      detail.textContent = "Autopilot is choosing the safest fast path. Open Files only if you want the details.";
    } else if (nearbyCount() > 0) {
      const nearby = nearbyCount();
      title.textContent = `${nearby} nearby device${nearby === 1 ? "" : "s"}`;
      detail.textContent = sessions > 0
        ? `${sessions} secure link${sessions === 1 ? "" : "s"} open. Chat, files, and folders are ready.`
        : "Trusted devices are ready, and other nearby devices can be paired or invited.";
    } else if (devices.length > 1) {
      title.textContent = "Your personal mesh is ready";
      detail.textContent = `${awake}/${devices.length} device${devices.length === 1 ? "" : "s"} awake. One Link can pick the best device for you.`;
    } else {
      title.textContent = "Everything is quiet";
      detail.textContent = "Pair a device, send a file, or open Privacy to see exactly what One Link is doing.";
    }
  }

  function trustedNearbyPeers() {
    return [...state.peers.values()].filter(p => p.trust === "pinned" && p.online);
  }

  function nearbyDiscoveryRows() {
    const smart = state.discoverSmart || {};
    return [
      ...(smart.ready_to_pair || []),
      ...(smart.pairable || []),
      ...(smart.other_gear || []),
    ];
  }

  function nearbyCount() {
    const seen = new Set();
    let count = 0;
    for (const p of trustedNearbyPeers()) {
      const key = p.fingerprint || p.address || p.short_id;
      if (!key || seen.has(key)) continue;
      seen.add(key);
      count += 1;
    }
    for (const d of nearbyDiscoveryRows()) {
      const peer = d.one_link_peer || {};
      const key = peer.fingerprint || d.ip || d.hostname;
      if (!key || seen.has(key)) continue;
      seen.add(key);
      count += 1;
    }
    return count;
  }

  function updateNearbyMetric() {
    const n = Math.max(
      Number(state.status?.peers?.online || 0),
      nearbyCount(),
    );
    const metric = $("#metric-online");
    if (metric) metric.textContent = String(n);
    const tile = $("#metric-tile-online");
    if (tile) {
      const open = $("#activity-nearby-panel")?.classList.contains("show");
      tile.setAttribute("aria-expanded", open ? "true" : "false");
      tile.setAttribute("aria-label", open ? "Hide nearby devices" : "Show nearby devices");
    }
    const count = $("#activity-nearby-count");
    if (count) count.textContent = `${n} found`;
  }

  function closeActivityNearby() {
    $("#activity-nearby-panel")?.classList.remove("show");
    updateNearbyMetric();
    renderOneNow();
  }

  function nearbyRow(icon, name, sub, actionLabel, onAction) {
    const row = el("div", "activity-nearby-row");
    row.appendChild(el("div", "activity-nearby-icon", icon));
    const meta = el("div", null);
    const label = name || "Nearby device";
    meta.appendChild(el("div", "activity-nearby-name", label));
    meta.appendChild(el("div", "activity-nearby-sub", sub || "On your network"));
    row.appendChild(meta);
    const actions = Array.isArray(actionLabel)
      ? actionLabel
      : [{ label: actionLabel || "Open", action: onAction }];
    const primaryAction = actions[0]?.action || onAction;
    const runAction = (action = primaryAction) => {
      if (action) action();
    };
    if (primaryAction) {
      row.setAttribute("role", "button");
      row.tabIndex = 0;
      row.setAttribute("aria-label", `${actions[0]?.label || "Open"} ${label}`);
      row.onclick = (ev) => {
        if (ev.target?.closest?.("button, a, input, select, textarea")) return;
        runAction();
      };
      row.onkeydown = (ev) => {
        if (ev.key !== "Enter" && ev.key !== " ") return;
        ev.preventDefault();
        runAction();
      };
    }
    const buttonWrap = el("div", "activity-nearby-actions");
    for (const item of actions) {
      const btn = el("button", null, item.label || "Open");
      btn.type = "button";
      btn.onclick = (ev) => {
        ev.stopPropagation();
        runAction(item.action);
      };
      buttonWrap.appendChild(btn);
    }
    row.appendChild(buttonWrap);
    return row;
  }

  function renderActivityNearby() {
    const panel = $("#activity-nearby-panel");
    const list = $("#activity-nearby-list");
    if (!panel || !list) return;
    list.innerHTML = "";
    const seen = new Set();
    for (const p of trustedNearbyPeers()) {
      const key = p.fingerprint || p.short_id;
      if (!key || seen.has(key)) continue;
      seen.add(key);
      list.appendChild(nearbyRow(
        deviceKindLabel(p)?.icon || "💻",
        p.display_name || p.hostname || p.short_id,
        `${reachLabel(p)} - trusted`,
        [
          {
            label: "Details",
            action: () => {
              openDeviceDrawer(p.short_id);
              toast(`Opened details for ${p.display_name || p.hostname || p.short_id}.`, "info", 2500);
            },
          },
          {
            label: "Chat",
            action: () => {
              selectPeer(p.short_id);
              document.querySelector('[data-pane="convo"]')?.click();
              toast(`Opened chat with ${p.display_name || p.hostname || p.short_id}.`, "info", 2500);
            },
          },
        ],
        () => {
          openDeviceDrawer(p.short_id);
          toast(`Opened details for ${p.display_name || p.hostname || p.short_id}.`, "info", 2500);
        },
      ));
    }
    for (const d of nearbyDiscoveryRows()) {
      const peer = d.one_link_peer || {};
      const key = peer.fingerprint || d.ip || d.hostname;
      if (!key || seen.has(key)) continue;
      seen.add(key);
      const canPair = !!peer.fingerprint;
      list.appendChild(nearbyRow(
        _kindIcon(d.kind),
        d.hostname || peer.hostname || d.vendor || _kindLabel(d.kind),
        [d.ip, _kindLabel(d.kind), canPair ? "ready to pair" : "invite available"]
          .filter(Boolean).join(" - "),
        canPair ? "Pair" : "Invite",
        () => {
          if (canPair) openPairModal(peer);
          else openInviteModal(d);
        },
      ));
    }
    if (!list.children.length) {
      list.appendChild(el(
        "div",
        "activity-nearby-sub",
        "No nearby devices found yet. Refresh will scan Wi-Fi and trusted links again.",
      ));
    }
    updateNearbyMetric();
  }

  async function loadActivityNearby({ force = false } = {}) {
    const panel = $("#activity-nearby-panel");
    const list = $("#activity-nearby-list");
    if (!panel || !list) return;
    panel.classList.add("show");
    if (force || !state.discoverSmart) {
      list.innerHTML = "";
      list.appendChild(el("div", "activity-nearby-sub", "Scanning nearby devices..."));
      try {
        await loadDiscoverable({ prune: false });
      } catch (_e) {
        // loadDiscoverable already soft-fails into the discovery UI.
      }
    }
    renderActivityNearby();
    renderOneNow();
    panel.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }

  async function toggleActivityNearby() {
    const panel = $("#activity-nearby-panel");
    if (panel?.classList.contains("show")) {
      closeActivityNearby();
      return;
    }
    await loadActivityNearby({ force: true });
  }

