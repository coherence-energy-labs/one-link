  async function refreshStatus() {
    const [status, selfMesh, rendezvous] = await Promise.allSettled([
      api.status(),
      api.selfMesh(),
      api.get("/api/rendezvous"),
    ]);
    if (status.status === "fulfilled") {
      state.status = status.value;
      if (state.status?.performance?.fabric) state.fabric = state.status.performance.fabric;
      updateNearbyMetric();
      $("#metric-active").textContent = state.status.transfers?.active ?? 0;
      $("#metric-cache").textContent = fmtBytes(state.status.performance?.cdc_cache?.bytes || 0);
      $("#metric-sessions").textContent = state.status.performance?.sessions?.open ?? 0;
      renderOneNow();
      renderFabricTruth();
    } else {
      console.warn(status.reason);
    }
    if (selfMesh.status === "fulfilled") {
      identityStore.replaceSelfMesh(selfMesh.value);
      renderSelfMesh();
    }
    // Keep rendezvous URLs cached so the empty-state nudge is accurate without
    // waiting for Settings. All three independent snapshots start together.
    if (rendezvous.status === "fulfilled") {
      const r = rendezvous.value;
      const before = (state.rendezvousUrls || []).length;
      settingsStore.setRendezvousUrls(r.urls || []);
      if (before === 0 && state.peers && state.peers.size === 0) {
        renderPeers();
      }
    }
    renderOneNow();
  }

  async function refreshFabricTruth() {
    const [fabric, noRouter, mobileReach] = await Promise.allSettled([
      api.fabric(),
      api.noRouter(),
      api.mobileReach(),
    ]);
    try {
      if (fabric.status === "rejected") throw fabric.reason;
      state.fabric = fabric.value;
      if (noRouter.status === "fulfilled") {
        state.fabric.no_router = noRouter.value;
      }
      if (mobileReach.status === "fulfilled") {
        state.fabric.mobile_reach = mobileReach.value;
      }
      renderFabricTruth();
    } catch (e) {
      if (!state.fabric) {
        state.fabric = {
          ok: false,
          route_truth: {
            state: "Path check paused",
            reason: "One Link will retry the route check automatically.",
          },
        };
      }
      renderFabricTruth();
    }
  }

  async function copyRouteBootstrapToken() {
    try {
      const nr = await api.noRouter();
      state.fabric = state.fabric || {};
      state.fabric.no_router = nr;
      renderFabricTruth();
      if (!nr.token_ready) throw new Error(nr.message || "Local setup code is not ready yet");
      const r = await api.routeBootstrap();
      if (!r.ok || !r.token) throw new Error(r.message || "No setup code available yet");
      const input = $("#route-bootstrap-token");
      if (input) input.value = r.token;
      const qr = $("#route-bootstrap-qr");
      if (qr) {
        qr.src = `/api/route-bootstrap/qr.svg?t=${Date.now()}`;
        qr.style.display = "block";
        qr.title = "Scan this from another paired device to share a short-lived path hint.";
      }
      await copyToClipboard(r.token, "setup code");
      toast("Setup code ready", "good", 2500);
    } catch (e) {
      toast(`Setup code unavailable: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function importRouteBootstrapToken() {
    const input = $("#route-bootstrap-token");
    const token = (input?.value || "").trim();
    if (!token) {
      toast("Paste a setup code first.", "info", 3000);
      input?.focus();
      return;
    }
    try {
      const r = await api.importRouteBootstrap(token);
      toast(
        `Path check queued for ${r.peer || "device"} (${r.queued || 0})`,
        "good",
        3500,
      );
      if (input) input.value = "";
      const qr = $("#route-bootstrap-qr");
      if (qr) {
        qr.removeAttribute("src");
        qr.style.display = "none";
      }
      await refreshPeers();
      await refreshFabricTruth();
    } catch (e) {
      toast(`Setup code refused: ${errorToastBody(e)}`, "bad", 7000);
    }
  }

  // v0.9.1: cross-peer activity feed.
  // v0.21.x: added search + day-grouping headers + folder/offer chips
  // + click-peer-to-filter + issues-only severity toggle. The feed
  // now collapses per-file rows of a folder send under their summary
  // parent (link via folder_send_group); the user expands when they
  // actually want the file list.
  state.activityFilter = "all";
  state.activityEvents = [];
  state.activitySearch = "";
  state.activityFailedOnly = false;
  state.activityPeerFilter = null;
  state.activityExpandedGroups = state.activityExpandedGroups || {};

