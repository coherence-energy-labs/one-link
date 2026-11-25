  function renderFabricTruth() {
    const host = $("#fabric-truth");
    if (!host) return;
    const fabric = state.fabric || state.status?.performance?.fabric || {};
    const truth = fabric.route_truth || {};
    const routeCandidates = fabric.route_candidates || {};
    const noRouter = fabric.no_router || {};
    const mobile = fabric.mobile_reach || {};
    const perf = fabric.performance || {};
    const route = truth.kind || transferRouteLabel(truth.route || truth.route_name || "");
    const stateText = truth.state || (fabric.ok === false ? "Path check paused" : "Finding best path");
    const verifiedRoutes = Number(routeCandidates.verified || 0);
    const knownRoutes = Number(routeCandidates.known || 0);
    const peerRoutes = Number(routeCandidates.peers || 0);
    const reason = verifiedRoutes > 0
      ? `One Link remembers ${verifiedRoutes} verified trusted path${verifiedRoutes === 1 ? "" : "s"}${peerRoutes > 0 ? ` across ${peerRoutes} device${peerRoutes === 1 ? "" : "s"}` : ""} and will try the best one automatically.`
      : (noRouter.message || truth.reason || "One Link is checking every safe communication path this device can use.");
    const available = Number(fabric.available_paths || 0);
    const ready = Number(fabric.ready_paths || 0);
    const scoreCount = Number(fabric.score_count || (Array.isArray(fabric.scores) ? fabric.scores.length : 0));
    const cacheAge = Number(fabric.cache_age_s || 0);
    const chips = [];
    if (route && route !== "Best available") chips.push({ label: "route", value: route });
    if (noRouter.state === "trusted_path_ready") chips.push({ label: "no router", value: "ready" });
    else if (noRouter.token_ready) chips.push({ label: "local link", value: "token" });
    if (verifiedRoutes > 0) chips.push({ label: "trusted paths", value: String(verifiedRoutes) });
    else if (knownRoutes > 0) chips.push({ label: "candidate paths", value: String(knownRoutes) });
    if (truth.automatic) chips.push({ label: "activation", value: "automatic" });
    else if (truth.needs_user) chips.push({ label: "activation", value: "confirm" });
    if (ready > 0) chips.push({ label: "ready", value: String(ready) });
    if (available > 0) chips.push({ label: "ready paths", value: String(available) });
    if (scoreCount > 0) chips.push({ label: "ranked paths", value: String(scoreCount) });
    if (perf.health) chips.push({ label: "route brain", value: String(perf.health) });
    if (Number(mobile.connected || 0) > 0) chips.push({ label: "phones", value: String(mobile.connected) });
    if (Number(mobile.control_bridges || 0) > 0) chips.push({ label: "phone bridge", value: String(mobile.control_bridges) });
    if (Number(mobile.couriers || 0) > 0) chips.push({ label: "phone courier", value: String(mobile.couriers) });
    if (cacheAge > 0) chips.push({ label: "checked", value: cacheAge < 1 ? "now" : `${Math.round(cacheAge)}s ago` });

    host.replaceChildren();
    const top = el("div", "ft-top");
    top.appendChild(el("div", "ft-state", stateText));
    top.appendChild(el("div", "ft-pill", route && route !== "Best available" ? route : "Autopilot"));
    host.appendChild(top);
    host.appendChild(el("div", "ft-reason", reason));
    if (chips.length) {
      const grid = el("div", "ft-grid");
      for (const c of chips.slice(0, 4)) {
        const chip = el("div", "ft-chip");
        chip.appendChild(el("b", "", c.value));
        chip.appendChild(el("span", "", c.label));
        grid.appendChild(chip);
      }
      host.appendChild(grid);
    }
    host.title = "Universal Comms Fabric: One Link ranks safe local, relay, courier, and future hardware paths before moving data.";
    renderNoRouterKit(noRouter);
    renderSelfMesh();
  }
  function _selfMeshPubKey(row) {
    return row?.device_pub_b64 || row?.device_pub || row?.fingerprint || "";
  }
  function _selfMeshPresenceFor(device) {
    const mesh = state.selfMesh || {};
    const facts = Array.isArray(mesh.presence) ? mesh.presence : [];
    const key = _selfMeshPubKey(device);
    return facts.find(p => _selfMeshPubKey(p) === key) || null;
  }
  function _selfMeshDeviceLabel(device) {
    return String(device?.label || device?.device_kind || device?.fingerprint || "Device").trim();
  }
  function _selfMeshDeviceRootKey(device) {
    return String(device?.root_pub_b64 || device?.root_pub || "root").trim();
  }
  function _selfMeshIsBrowserPeer(device) {
    const kind = String(device?.device_kind || "").toLowerCase();
    return kind === "browser-peer" || kind.includes("browser") || kind.includes("phone");
  }
  function _selfMeshIsGenericBrowserLabel(label) {
    const s = String(label || "").trim().toLowerCase();
    return !s || [
      "phone browser",
      "browser",
      "browser-peer",
      "remote-device",
      "device",
      "one link device",
      "one_link device",
    ].includes(s);
  }
  function _selfMeshFreshness(device) {
    return Math.max(
      Number(device?.updated_ms || 0),
      Number(device?.created_ms || 0),
      Number(device?.claimed_ms || 0),
      Number(device?.paired_ms || 0),
    );
  }
  function _dedupeSelfMeshDevices(devices) {
    const rows = Array.isArray(devices) ? devices.filter(Boolean) : [];
    if (rows.length <= 1) return rows.slice();

    const hasNamedBrowserByRoot = new Map();
    for (const d of rows) {
      if (d.local || d.revoked || !_selfMeshIsBrowserPeer(d)) continue;
      const label = _selfMeshDeviceLabel(d);
      if (_selfMeshIsGenericBrowserLabel(label)) continue;
      hasNamedBrowserByRoot.set(_selfMeshDeviceRootKey(d), true);
    }

    const byKey = new Map();
    const out = [];
    for (const d of rows) {
      const label = _selfMeshDeviceLabel(d);
      const root = _selfMeshDeviceRootKey(d);
      if (
        !d.local &&
        !d.revoked &&
        _selfMeshIsBrowserPeer(d) &&
        _selfMeshIsGenericBrowserLabel(label) &&
        hasNamedBrowserByRoot.get(root)
      ) {
        continue;
      }

      const key = d.local
        ? `local:${_selfMeshPubKey(d) || label}`
        : (
            _selfMeshIsBrowserPeer(d)
              ? `browser:${root}:${label.toLowerCase()}`
              : `${root}:${String(d.device_kind || "").toLowerCase()}:${label.toLowerCase()}`
          );
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, { device: d, index: out.length });
        out.push(d);
        continue;
      }
      if (_selfMeshFreshness(d) >= _selfMeshFreshness(existing.device)) {
        byKey.set(key, { device: d, index: existing.index });
        out[existing.index] = d;
      }
    }
    return out;
  }
  function renderSelfMesh() {
    const host = $("#self-mesh-kit");
    if (!host) return;
    const mesh = state.selfMesh || {};
    const rawDevices = Array.isArray(mesh.devices) ? mesh.devices : [];
    const devices = _dedupeSelfMeshDevices(rawDevices);
    const facts = Array.isArray(mesh.presence) ? mesh.presence : [];
    const localCount = devices.filter(d => d.local && !d.revoked).length;
    const awake = facts.filter(p => p.state === "awake").length;
    const pill = $("#self-mesh-pill");
    const copy = $("#self-mesh-copy");
    const list = $("#self-mesh-devices");
    if (pill) {
      pill.textContent = devices.length ? `${awake}/${devices.length} awake` : "ready";
    }
    if (copy) {
      const perf = mesh.performance || {};
      const speed = perf.route_probe_avg_ms != null
        ? ` Route choice ${Number(perf.route_probe_avg_ms).toFixed(2)} ms.`
        : "";
      copy.textContent = devices.length
        ? `${localCount || 1} of your devices ${(localCount || 1) === 1 ? "is" : "are"} ready to help move files. ${speed}`
        : "Only this device so far. Open Settings → Devices and pair another one of yours to set up the safety net.";
    }
    if (!list) return;
    list.replaceChildren();
    const perfHost = $("#self-mesh-perf");
    if (perfHost) {
      perfHost.replaceChildren();
      const perf = mesh.performance || {};
      const hist = Array.isArray(mesh.performance_history) ? mesh.performance_history : [];
      const latest = hist[0] || perf;
      const chips = [
        ["route", `${Number(latest.route_probe_avg_ms || 0).toFixed(2)} ms`],
        ["ready", `${latest.route_probe_ready || 0}/${latest.route_probe_runs || 0}`],
        ["devices", String(latest.device_rows ?? devices.length)],
      ];
      const obs = Array.isArray(mesh.performance_observations)
        ? mesh.performance_observations
        : [];
      for (const sample of obs.slice(0, 3)) {
        const name = String(sample.metric || "").replaceAll("_", " ");
        chips.push([name, `${Number(sample.duration_ms || 0).toFixed(2)} ms`]);
      }
      const budgets = Array.isArray(mesh.performance_budgets?.items)
        ? mesh.performance_budgets.items
        : [];
      const warnBudget = budgets.find((b) => b.status !== "pass");
      chips.push([
        "budget",
        warnBudget
          ? `${String(warnBudget.metric || "metric").replaceAll("_", " ")} warn`
          : `${mesh.performance_budgets?.status || "pass"}`,
      ]);
      for (const [label, value] of chips) {
        const card = el("div", "sm-device");
        card.appendChild(el("b", "", value));
        card.appendChild(el("span", "", label));
        perfHost.appendChild(card);
      }
    }
    const select = $("#self-mesh-device-select");
    const selectedBefore = select?.value || "";
    if (select) select.replaceChildren();
    const rows = devices.length ? devices : [{
      label: state.me?.hostname || "This device",
      device_kind: "local",
      local: true,
      trusted: true,
      device_pub_b64: "",
    }];
    // 2026-05-23: show ALL devices, not just the first 6. The
    // earlier slice hid stale entries from view (user reported
    // 11 paired phones; the list pretended only 6 existed and
    // there was no prune surface). Each non-local row now has a
    // prune button.
    for (const d of rows) {
      const p = _selfMeshPresenceFor(d);
      const card = el("div", "sm-device");
      const label = d.label || d.device_kind || d.fingerprint || "Device";
      const stateLabel = p?.state || (d.local ? "awake" : "unknown");
      const safety = d.safety_state || (d.revoked ? "revoked" : "trusted");
      const route = p?.route ? ` via ${p.route}` : "";
      // Device-kind glyph for at-a-glance distinction in a long list.
      const kind = (d.device_kind || "").toLowerCase();
      let glyph = "🖥";
      if (kind.includes("phone") || kind === "browser-peer") glyph = "📱";
      else if (kind.includes("tablet") || kind === "ipad") glyph = "📋";
      else if (kind.includes("desktop") || kind === "desktop-daemon") glyph = "🖥";
      const titleRow = el("b", "");
      titleRow.textContent = `${glyph} ${label}`;
      card.appendChild(titleRow);
      card.appendChild(el("span", "", `${stateLabel}${d.local ? " local" : ""}${route} · Guardian ${safety.replaceAll("_", " ")}`));
      // Prune button on non-local rows. Local-self is server-side
      // protected too, but UI also hides the button so the user
      // doesn't try.
      if (!d.local && d.root_pub_b64 && d.device_pub_b64) {
        const pruneBtn = document.createElement("button");
        pruneBtn.className = "btn-ghost";
        pruneBtn.textContent = "Prune";
        pruneBtn.title = "Remove this device entry from your One identity (does not affect the device itself)";
        pruneBtn.style.marginTop = "6px";
        pruneBtn.style.fontSize = "11px";
        pruneBtn.style.padding = "4px 10px";
        pruneBtn.addEventListener("click", async () => {
          if (!confirm(
            `Prune "${label}"?\n\n` +
            "This removes the device from your One identity's list. " +
            "If the device is still online it will be able to re-join " +
            "by pairing again."
          )) return;
          pruneBtn.disabled = true;
          try {
            await api.post("/api/self-mesh/devices/delete", {
              root_pub_b64: d.root_pub_b64,
              device_pub_b64: d.device_pub_b64,
            });
            toast(`Pruned ${label}.`, "good", 2500);
            await refreshSelfMesh();
          } catch (e) {
            toast(`Couldn't prune: ${errorToastBody(e)}`, "bad", 4000);
            pruneBtn.disabled = false;
          }
        });
        card.appendChild(pruneBtn);
      }
      list.appendChild(card);
      if (select && d.device_pub_b64) {
        const opt = document.createElement("option");
        opt.value = d.device_pub_b64;
        opt.textContent = `${label}${safety !== "trusted" ? ` ${safety.replaceAll("_", " ")}` : ""}`;
        opt.dataset.root = d.root_pub_b64 || "";
        opt.disabled = !!d.revoked;
        select.appendChild(opt);
      }
    }
    const timeline = Array.isArray(mesh.timeline) ? mesh.timeline : [];
    for (const item of timeline.slice(0, 3)) {
      const card = el("div", "sm-device");
      const label = `${item.status || "sent"} ${selfMeshActionLabel(item.action)}`;
      const events = Array.isArray(item.events) ? item.events : [];
      const last = events[events.length - 1] || {};
      const detail = last.detail || item.path || item.peer_fp || "recorded";
      card.appendChild(el("b", "", label));
      card.appendChild(el("span", "", detail));
      list.appendChild(card);
    }
    if (select && selectedBefore) select.value = selectedBefore;
    // 2026-05-23: also render to the sidebar so the user SEES
    // their paired iPhone / iPad / other-laptop without digging
    // into Settings → Self-mesh. The 'i dont see it meshed or
    // paired anywhere' UX problem.
    renderSelfMeshSidebar(rawDevices);
  }

  function renderSelfMeshSidebar(devices) {
    const wrap = $("#self-mesh-sidebar");
    const heading = $("#self-mesh-section-h");
    const count = $("#self-mesh-count");
    if (!wrap || !heading) return;
    const rows = _dedupeSelfMeshDevices(devices);
    // Hide the section entirely if there are no devices at all.
    if (!rows || rows.length === 0) {
      wrap.style.display = "none";
      heading.style.display = "none";
      return;
    }
    heading.style.display = "";
    wrap.style.display = "";
    if (count) count.textContent = rows.length;
    wrap.replaceChildren();
    for (const d of rows) {
      const row = document.createElement("div");
      row.className = "peer self-mesh-peer";
      row.style.padding = "10px 12px";
      row.style.borderRadius = "10px";
      row.style.marginBottom = "6px";
      row.style.background = "var(--bg-2)";
      row.style.border = "1px solid var(--line)";
      row.style.display = "flex";
      row.style.alignItems = "center";
      row.style.gap = "10px";

      // Device-kind glyph.
      const kind = (d.device_kind || "").toLowerCase();
      let glyph = "🖥";
      if (kind.includes("phone") || kind === "browser-peer") glyph = "📱";
      else if (kind.includes("tablet") || kind === "ipad") glyph = "📋";
      const icon = el("div", "");
      icon.textContent = glyph;
      icon.style.fontSize = "20px";
      icon.style.flex = "0 0 auto";
      icon.title = d.device_kind || "device";
      row.appendChild(icon);

      const info = el("div", "");
      info.style.flex = "1 1 auto";
      info.style.minWidth = "0";
      const nameEl = el("div", "");
      const label = d.label || d.device_kind || "Device";
      nameEl.textContent = d.local ? `${label} · this device` : label;
      nameEl.style.fontWeight = "600";
      nameEl.style.fontSize = "13px";
      nameEl.style.overflow = "hidden";
      nameEl.style.textOverflow = "ellipsis";
      nameEl.style.whiteSpace = "nowrap";
      info.appendChild(nameEl);

      const safety = d.safety_state || (d.revoked ? "revoked" : "trusted");
      const presence = _selfMeshPresenceFor(d);
      const statusText = d.local
        ? "local"
        : (presence && presence.state) || (safety === "trusted" ? "paired ✓" : safety);
      const sub = el("div", "");
      sub.textContent = statusText;
      sub.style.fontSize = "11px";
      sub.style.color = "var(--text-dim)";
      info.appendChild(sub);
      row.appendChild(info);

      // Non-local: inline prune button (no Settings dive).
      if (!d.local && d.root_pub_b64 && d.device_pub_b64) {
        const pruneBtn = document.createElement("button");
        pruneBtn.className = "btn-ghost";
        pruneBtn.textContent = "×";
        pruneBtn.title = `Prune ${label}`;
        pruneBtn.setAttribute("aria-label", `Prune ${label}`);
        pruneBtn.style.padding = "2px 8px";
        pruneBtn.style.fontSize = "16px";
        pruneBtn.style.minHeight = "auto";
        pruneBtn.style.flex = "0 0 auto";
        pruneBtn.style.color = "var(--text-dim)";
        pruneBtn.addEventListener("click", async (ev) => {
          ev.stopPropagation();
          if (!confirm(
            `Prune "${label}"?\n\nRemoves the device from your ` +
            `One identity's list. If the device is still online ` +
            `it can re-join by pairing again.`
          )) return;
          pruneBtn.disabled = true;
          try {
            await api.post("/api/self-mesh/devices/delete", {
              root_pub_b64: d.root_pub_b64,
              device_pub_b64: d.device_pub_b64,
            });
            toast(`Pruned ${label}.`, "good", 2500);
            await refreshSelfMesh();
          } catch (e) {
            toast(`Couldn't prune: ${errorToastBody(e)}`, "bad", 4000);
            pruneBtn.disabled = false;
          }
        });
        row.appendChild(pruneBtn);
      }
      wrap.appendChild(row);
    }
  }

