  function _settingsNetworkSnapshot() {
    const status = state.status || {};
    const fabric = state.fabric || status.performance?.fabric || {};
    const peers = [...(state.peers?.values?.() || [])].filter((p) => p && p.trust !== "rejected");
    const pinned = peers.filter((p) => p.trust === "pinned");
    const online = pinned.filter((p) => p.online);
    const latencies = online
      .map((p) => Number(p.health?.latency_ewma_ms ?? p.latency_ms))
      .filter((n) => Number.isFinite(n) && n >= 0);
    const avgLatency = latencies.length
      ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
      : null;
    const routeTruth = fabric.route_truth || {};
    const route = routeTruth.kind || routeTruth.route || routeTruth.route_name || "Auto";
    const transfers = Number(status.transfers?.active || 0);
    const sessions = Number(status.performance?.sessions?.open || 0);
    const cacheBytes = Number(status.performance?.cdc_cache?.bytes || 0);
    const rdz = state.rendezvousUrls || [];
    return {
      daemon: status.app_version || status.version || state.me?.app_version || "unknown",
      pinned: pinned.length,
      online: online.length,
      avgLatency,
      route,
      fabricOk: fabric.ok !== false,
      fabricState: routeTruth.state || (fabric.ok === false ? "Needs attention" : "Autopilot ready"),
      fabricReason: routeTruth.reason || fabric.no_router?.message || "One Link is checking every safe communication path.",
      transfers,
      sessions,
      cacheBytes,
      rendezvousCount: rdz.length,
    };
  }

  function _settingsOverviewSnapshot() {
    const net = _settingsNetworkSnapshot();
    const peers = [...(state.peers?.values?.() || [])].filter((p) => p && p.trust !== "rejected");
    const paired = peers.filter((p) => p.trust === "pinned");
    const online = paired.filter((p) => p.online);
    const verified = paired.filter((p) => p.is_verified);
    const setup = state.setup || {};
    const identity = state.me?.fingerprint || "";
    const setupDone = !!setup.completed || !!state.me?.one_setup_completed || !!state.me?.onboarding_completed;
    const privacy = state.runtimeSettings || {};
    const privacyMode = privacy.pair_default_allow_all === false ? "Approve each pairing" : "Trusted local pairing";
    const routeReady = net.fabricOk && (online.length > 0 || paired.length === 0);
    const storageBytes = Number(state.status?.performance?.cdc_cache?.bytes || net.cacheBytes || 0);
    const overallBad = !identity || (paired.length > 0 && online.length === 0);
    const overallWarn = !setupDone || !routeReady || (paired.length > 0 && verified.length < paired.length);
    const overall = overallBad ? "Needs attention" : (overallWarn ? "Almost ready" : "Ready");
    const generatedAt = new Date().toISOString();
    return {
      generatedAt,
      overall,
      identity,
      setupDone,
      peers: peers.length,
      paired: paired.length,
      online: online.length,
      verified: verified.length,
      privacyMode,
      routeReady,
      network: net,
      storageBytes,
      diagnosticsReady: true,
      version: net.daemon,
    };
  }

  function renderSettingsOverview() {
    const host = $("#settings-overview-health");
    const list = $("#settings-readiness-list");
    if (!host && !list) return;
    const snap = _settingsOverviewSnapshot();
    const title = $("#settings-overview-title");
    const copy = $("#settings-overview-copy");
    if (title) title.textContent = `One Link is ${snap.overall.toLowerCase()}`;
    if (copy) {
      const latency = snap.network.avgLatency == null ? "latency pending" : `${snap.network.avgLatency} ms average`;
      copy.textContent =
        `${snap.online}/${snap.paired} trusted devices online, ${latency}, ` +
        `${snap.privacyMode.toLowerCase()}, ${fmtBytes(snap.storageBytes)} saved locally.`;
    }
    if (host) {
      host.innerHTML = "";
      const card = (label, value, detail, cls = "") => {
        const c = el("div", `settings-health-card flat ${cls}`.trim());
        c.appendChild(el("div", "settings-health-label", label));
        c.appendChild(el("div", "settings-health-value", value));
        c.appendChild(el("div", "settings-health-detail", detail));
        host.appendChild(c);
      };
      card("Identity", snap.identity ? "Loaded" : "Missing",
        snap.identity ? `${snap.identity.slice(0, 12)}...${snap.identity.slice(-8)}` : "Reload One Link to restore identity",
        snap.identity ? "good" : "bad");
      card("Devices", `${snap.online}/${snap.paired} online`,
        snap.paired ? `${snap.verified}/${snap.paired} verified` : "Pair your first device",
        snap.online || !snap.paired ? "good" : "warn");
      card("Network", snap.network.avgLatency == null ? snap.network.route : `${snap.network.avgLatency} ms`,
        snap.network.fabricState, snap.routeReady ? "good" : "warn");
      card("Storage", fmtBytes(snap.storageBytes),
        "Local dedupe cache and received file metadata", "good");
      card("Privacy", snap.privacyMode,
        state.runtimeSettings?.send_read_receipts === false ? "Receipts hidden" : "Receipts and typing can be controlled", "good");
      card("Diagnostics", "Ready",
        "Copy this report when something feels wrong", "good");
    }
    if (list) {
      list.innerHTML = "";
      const rows = [
        {
          cls: snap.identity ? "good" : "bad",
          state: snap.identity ? "OK" : "Fix",
          label: "Identity",
          detail: snap.identity ? "Fingerprint available" : "Security key expired or not loaded",
        },
        {
          cls: snap.setupDone ? "good" : "warn",
          state: snap.setupDone ? "OK" : "Check",
          label: "One Setup",
          detail: snap.setupDone ? "Setup receipt complete" : "Finish setup checklist",
        },
        {
          cls: snap.paired ? "good" : "warn",
          state: snap.paired ? "OK" : "Check",
          label: "Paired devices",
          detail: snap.paired ? `${snap.paired} trusted, ${snap.online} reachable` : "No trusted devices yet",
        },
        {
          cls: snap.paired && snap.verified === snap.paired ? "good" : "warn",
          state: snap.paired && snap.verified === snap.paired ? "OK" : "Check",
          label: "Verification",
          detail: snap.paired ? `${snap.verified}/${snap.paired} devices verified` : "Pair before verifying",
        },
        {
          cls: snap.routeReady ? "good" : "warn",
          state: snap.routeReady ? "OK" : "Check",
          label: "Route health",
          detail: snap.network.fabricReason,
        },
        {
          cls: "good",
          state: "OK",
          label: "Diagnostics",
          detail: "Network, device, privacy, and storage report available",
        },
      ];
      for (const r of rows) {
        const row = el("div", `settings-readiness-row ${r.cls}`);
        row.appendChild(el("span", "state", r.state));
        row.appendChild(el("span", "label", r.label));
        row.appendChild(el("span", "detail", r.detail));
        list.appendChild(row);
      }
    }
  }

  async function copySettingsOverviewReport() {
    const snap = _settingsOverviewSnapshot();
    const report = {
      generated_at: snap.generatedAt,
      app_version: snap.version,
      overall: snap.overall,
      identity_short: snap.identity ? `${snap.identity.slice(0, 12)}...${snap.identity.slice(-8)}` : null,
      devices: {
        visible: snap.peers,
        paired: snap.paired,
        online: snap.online,
        verified: snap.verified,
      },
      network: snap.network,
      privacy: {
        mode: snap.privacyMode,
        read_receipts: state.runtimeSettings?.send_read_receipts !== false,
        typing_indicators: state.runtimeSettings?.send_typing_indicators !== false,
      },
      storage: {
        cache_bytes: snap.storageBytes,
      },
    };
    await copyToClipboard(JSON.stringify(report, null, 2), "settings health report");
  }

  function renderSettingsNetwork() {
    const snap = _settingsNetworkSnapshot();
    const health = $("#settings-network-health");
    if (health) {
      health.innerHTML = "";
      const card = (label, value, detail, cls = "") => {
        const c = el("div", `settings-health-card flat ${cls}`.trim());
        c.appendChild(el("div", "settings-health-label", label));
        c.appendChild(el("div", "settings-health-value", value));
        c.appendChild(el("div", "settings-health-detail", detail));
        health.appendChild(c);
      };
      card("Daemon", snap.daemon, "Local UI authority", "good");
      card("Peers", `${snap.online}/${snap.pinned} online`,
        snap.avgLatency == null ? "No live peer latency yet" : `${snap.avgLatency} ms average`);
      card("Fabric", snap.fabricOk ? "Ready" : "Attention",
        snap.fabricState, snap.fabricOk ? "good" : "warn");
    }
    const report = $("#settings-network-report");
    if (report) {
      report.innerHTML = "";
      report.appendChild(el("div", "settings-card-kicker", "Current route"));
      report.appendChild(el("div", "settings-card-title", `${snap.route} - ${snap.fabricState}`));
      report.appendChild(el("div", "settings-card-detail", snap.fabricReason));
      const pills = el("div", "settings-pill-row");
      const add = (label, value, cls = "") => {
        const p = el("span", `settings-pill ${cls}`.trim(), `${label}: ${value}`);
        pills.appendChild(p);
      };
      add("peers", `${snap.online}/${snap.pinned}`, snap.online ? "good" : "warn");
      add("latency", snap.avgLatency == null ? "unknown" : `${snap.avgLatency} ms`, snap.avgLatency == null ? "warn" : "good");
      add("sessions", String(snap.sessions));
      add("transfers", String(snap.transfers));
      add("cache", fmtBytes(snap.cacheBytes));
      add("rendezvous", snap.rendezvousCount ? String(snap.rendezvousCount) : "Wi-Fi only", snap.rendezvousCount ? "good" : "");
      report.appendChild(pills);
    }
    renderSettingsOverview();
  }

  async function refreshSettingsNetwork() {
    try {
      state.status = await api.status();
      if (state.status?.performance?.fabric) state.fabric = state.status.performance.fabric;
    } catch (e) {
      console.warn("refreshSettingsNetwork status:", e);
    }
    try {
      state.fabric = await api.fabric();
      try { state.fabric.no_router = await api.noRouter(); } catch (_e) {}
      try { state.fabric.mobile_reach = await api.mobileReach(); } catch (_e) {}
    } catch (e) {
      console.warn("refreshSettingsNetwork fabric:", e);
    }
    renderSettingsNetwork();
  }

  async function copySettingsNetworkReport() {
    const snap = _settingsNetworkSnapshot();
    const report = {
      generated_at: new Date().toISOString(),
      version: snap.daemon,
      peers: { paired: snap.pinned, online: snap.online, average_latency_ms: snap.avgLatency },
      route: { selected: snap.route, state: snap.fabricState, ok: snap.fabricOk },
      activity: { sessions: snap.sessions, transfers: snap.transfers, cdc_cache_bytes: snap.cacheBytes },
      rendezvous_configured: snap.rendezvousCount,
    };
    await copyToClipboard(JSON.stringify(report, null, 2), "network report");
  }

  // v0.11.0: fill Profile + About panes from /api/me. Done up-front
  // (state.me is already loaded by init()) so opening Settings is
  // instant - no flash of empty fields.
  function refreshSettingsAbout() {
    _resetPairPhoneCard();
    const me = state.me || {};
    const fp = me.fingerprint || "";
    const fpEl = $("#settings-identity-fp");
    if (fpEl) fpEl.textContent = fp ? fp : "(unknown)";
    const verEl = $("#settings-about-version");
    if (verEl) verEl.textContent = me.app_version || "?";
    const protoEl = $("#settings-about-protocol");
    if (protoEl) protoEl.textContent = me.protocol_version || "?";
    const schemaEl = $("#settings-about-schema");
    if (schemaEl) schemaEl.textContent = String(me.schema_version ?? "?");
    const runtimeEl = $("#settings-about-runtime");
    if (runtimeEl) runtimeEl.textContent = `v${me.app_version || "unknown"}`;
    const runtimeDetail = $("#settings-about-runtime-detail");
    if (runtimeDetail) {
      runtimeDetail.textContent =
        `Protocol ${me.protocol_version || "?"}; schema ${String(me.schema_version ?? "?")}; ` +
        `page ${PAGE_BUILT_FOR || "unknown"}.`;
    }
    renderSettingsPrivacySummary();
    // v0.20.5: do not call _refreshConnectInfo here. The legacy
    // connect-info section intentionally has no render target, so
    // the old UI QR cannot reappear beside the unified add-device QR.
    // v0.20.1: reset the pair-phone surface to the "click to mint"
    // state on every settings open. Tokens expire in 5 minutes; we
    // don't want a stale QR sitting around from a previous session.
  }

