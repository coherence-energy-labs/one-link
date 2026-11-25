  function _settingsDeviceHealth(peer) {
    if (!peer) return { cls: "bad", label: "Unknown", detail: "Device record is missing." };
    if (peer.compatibility && peer.compatibility.compatible === false) {
      return {
        cls: "bad",
        label: "Version mismatch",
        detail: "Update both devices before trusting this path for calls or large files.",
      };
    }
    if (!peer.online) {
      return {
        cls: "warn",
        label: "Offline",
        detail: "Messages and files queue until this device is back on the network.",
      };
    }
    const ms = Number(peer.health?.latency_ewma_ms ?? peer.latency_ms);
    if (Number.isFinite(ms) && ms >= 250) {
      return {
        cls: "warn",
        label: "Slow path",
        detail: "The link is reachable, but latency is high. Try repair or keep both devices awake.",
      };
    }
    if (!peer.is_verified) {
      return {
        cls: "warn",
        label: "Not verified",
        detail: "Works now, but verify the code before relying on this device for sensitive work.",
      };
    }
    return {
      cls: "good",
      label: "Healthy",
      detail: "Reachable, trusted, and verified. One Link can use this path automatically.",
    };
  }

  async function _settingsRunDeviceAction(peer, label, fn) {
    if (!peer?.fingerprint) {
      toast("Device fingerprint unavailable.", "bad", 4000);
      return;
    }
    try {
      await fn();
      await refreshPeers();
      renderSettingsDevices();
      toast(label, "good", 2200);
    } catch (e) {
      toast(`${label} failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  function renderSettingsDevices() {
    const host = $("#settings-devices-list");
    if (!host) return;
    const peers = [...(state.peers?.values?.() || [])]
      .filter((p) => p && p.trust !== "rejected")
      .sort((a, b) => {
        const ao = a.online ? 0 : 1;
        const bo = b.online ? 0 : 1;
        if (ao !== bo) return ao - bo;
        const an = (a.display_name || a.hostname || a.short_id || "").toLowerCase();
        const bn = (b.display_name || b.hostname || b.short_id || "").toLowerCase();
        return an.localeCompare(bn);
      });
    const pinned = peers.filter((p) => p.trust === "pinned");
    const online = pinned.filter((p) => p.online);
    const verified = pinned.filter((p) => p.is_verified);
    const attention = pinned.filter((p) =>
      !p.online || !p.is_verified || (p.compatibility && p.compatibility.compatible === false));
    const summary = $("#settings-devices-summary");
    if (summary) {
      summary.innerHTML = "";
      const stat = (value, label) => {
        const box = el("div", "settings-device-stat");
        box.appendChild(el("strong", null, String(value)));
        box.appendChild(el("span", null, label));
        summary.appendChild(box);
      };
      stat(pinned.length, "paired");
      stat(online.length, "online");
      stat(verified.length, "verified");
      stat(attention.length, "attention");
    }
    renderSettingsOverview();
    host.innerHTML = "";
    if (!peers.length) {
      host.appendChild(el(
        "div",
        "settings-device-empty",
        "No paired devices yet. Pair a device, or scan nearby devices from the action below.",
      ));
      return;
    }
    for (const p of peers) {
      const name = p.display_name || p.hostname || p.short_id || "Device";
      const kind = deviceKindLabel(p);
      const health = _settingsDeviceHealth(p);
      const row = el("div", `settings-device-row ${health.cls === "good" ? "" : health.cls}`.trim());
      row.appendChild(el("div", "settings-device-avatar", kind?.icon || "PC"));

      const meta = el("div", null);
      meta.appendChild(el("div", "settings-device-name", name));
      const bits = [
        p.online ? "Online" : "Offline",
        reachLabel(p),
        p.health?.latency_ewma_ms == null ? null : `${Math.round(p.health.latency_ewma_ms)} ms`,
        p.is_verified ? "Verified" : "Not verified",
        p.app_version ? `v${p.app_version}` : null,
      ].filter(Boolean);
      meta.appendChild(el("div", "settings-device-sub", bits.join(" - ")));
      const pills = el("div", "settings-pill-row");
      pills.appendChild(el("span", `settings-pill ${health.cls}`, health.label));
      pills.appendChild(el("span", `settings-pill ${p.online ? "good" : "warn"}`, p.online ? "reachable" : "queued"));
      pills.appendChild(el("span", `settings-pill ${p.is_verified ? "good" : "warn"}`, p.is_verified ? "verified" : "needs verify"));
      meta.appendChild(pills);
      meta.appendChild(el("div", "settings-device-advice", health.detail));
      if (p.fingerprint) {
        const codeLine = el("div", "settings-code-line");
        codeLine.appendChild(el("code", null, p.fingerprint));
        const copyInline = el("button", "btn-ghost", "Copy");
        copyInline.type = "button";
        copyInline.onclick = () => copyToClipboard(p.fingerprint, "device fingerprint");
        codeLine.appendChild(copyInline);
        meta.appendChild(codeLine);
      }
      if (p.fingerprint) {
        const quick = el("div", "settings-device-quick");
        const aliasInput = el("input");
        aliasInput.type = "text";
        aliasInput.maxLength = 64;
        aliasInput.placeholder = "Custom name";
        aliasInput.value = p.local_alias || "";
        aliasInput.setAttribute("aria-label", `Custom name for ${name}`);
        const aliasSave = el("button", null, "Rename");
        aliasSave.type = "button";
        aliasSave.onclick = () => _settingsRunDeviceAction(p, "Device renamed", async () => {
          await api.post(`/api/peers/${encodeURIComponent(p.fingerprint)}/profile`, {
            local_alias: aliasInput.value.trim(),
          });
        });
        quick.appendChild(aliasInput);
        quick.appendChild(aliasSave);
        meta.appendChild(quick);
      }
      row.appendChild(meta);

      const actions = el("div", "settings-device-actions");
      const chat = el("button", null, "Chat");
      chat.type = "button";
      chat.onclick = () => {
        selectPeer(p.short_id);
        settingsBackdrop?.classList.remove("show");
        document.querySelector('[data-pane="convo"]')?.click();
        toast(`Opened chat with ${name}.`, "info", 1800);
      };
      const details = el("button", null, "Details");
      details.type = "button";
      details.onclick = () => openDeviceDrawer(p.short_id);
      const repair = el("button", null, "Repair");
      repair.type = "button";
      repair.title = "Refresh peers and resume queued work for this device.";
      repair.onclick = () => _settingsRunDeviceAction(p, "Device path refreshed", async () => {
        await api.post("/api/peers/prune", {});
        await api.post(`/api/peers/${encodeURIComponent(p.fingerprint)}/resume`, {});
      });
      const verify = el("button", null, p.is_verified ? "Unverify" : "Verify");
      verify.type = "button";
      verify.onclick = () => _settingsRunDeviceAction(
        p,
        p.is_verified ? "Verification removed" : "Device marked verified",
        async () => {
          const fp = encodeURIComponent(p.fingerprint);
          if (p.is_verified) {
            await api.del(`/api/peers/${fp}/verify`);
          } else {
            await api.post(`/api/peers/${fp}/verify`, {
              method: "manual",
              note: "Marked from Settings after checking the device identity.",
            });
          }
        },
      );
      const mutedNow = !!p.muted || p.muted_until_ms === 0 || Number(p.muted_until_ms || 0) > Date.now();
      const mute = el("button", null, mutedNow ? "Unmute" : "Mute");
      mute.type = "button";
      mute.onclick = () => _settingsRunDeviceAction(
        p,
        mutedNow ? "Device unmuted" : "Device muted",
        async () => {
          const fp = encodeURIComponent(p.fingerprint);
          if (mutedNow) await api.post(`/api/peers/${fp}/mute`, { muted: false, muted_until_ms: null });
          else await api.post(`/api/peers/${fp}/mute`, { muted: true, muted_until_ms: 0 });
        },
      );
      const copy = el("button", null, "Copy ID");
      copy.type = "button";
      copy.onclick = () => copyToClipboard(p.fingerprint || p.short_id || "", "device ID");
      const exportBtn = el("button", null, "Export");
      exportBtn.type = "button";
      exportBtn.onclick = async () => {
        try {
          const fp = encodeURIComponent(p.fingerprint || "");
          if (!fp) throw new Error("device fingerprint unavailable");
          const r = await api.get(`/api/peers/${fp}/export`);
          await copyToClipboard(JSON.stringify(r, null, 2), "device export");
        } catch (e) {
          toast(`Export failed: ${errorToastBody(e)}`, "bad", 5000);
        }
      };
      const block = el("button", "danger", "Block");
      block.type = "button";
      block.title = "Stop trusting this device. You can pair it again later.";
      block.onclick = () => {
        if (!confirm(`Block ${name}? Messages and files to this device will stop until you trust it again.`)) return;
        _settingsRunDeviceAction(p, "Device blocked", async () => {
          await api.post(`/api/peers/${encodeURIComponent(p.fingerprint)}/trust`, { trust: "rejected" });
        });
      };
      actions.appendChild(chat);
      if (p.fingerprint) actions.appendChild(repair);
      if (p.fingerprint) actions.appendChild(verify);
      if (p.fingerprint) actions.appendChild(mute);
      actions.appendChild(details);
      actions.appendChild(copy);
      if (p.fingerprint) actions.appendChild(exportBtn);
      if (p.fingerprint) actions.appendChild(block);
      row.appendChild(actions);
      host.appendChild(row);
    }
  }

  $("#settings-copy-identity")?.addEventListener("click", () => {
    const txt = ($("#settings-identity-fp")?.textContent || "").trim();
    if (!txt || txt === "..." || txt === "(unknown)") {
      toast("Identity is still loading.", "info", 1800);
      return;
    }
    copyToClipboard(txt, "identity fingerprint");
  });
  $("#settings-copy-identity-privacy")?.addEventListener("click", () => {
    const txt = (state.me?.fingerprint || $("#settings-identity-fp")?.textContent || "").trim();
    if (!txt || txt === "..." || txt === "(unknown)") {
      toast("Identity is still loading.", "info", 1800);
      return;
    }
    copyToClipboard(txt, "identity fingerprint");
  });
  $("#settings-open-privacy-proof")?.addEventListener("click", async () => {
    await api.setupAction("privacy_proof_viewed").catch(() => {});
    switchSettingsPane("setup");
    $("#settings-one-setup-proof-list")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });

  $("#settings-network-refresh")?.addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    btn.textContent = "Refreshing...";
    try {
      await refreshSettingsNetwork();
      toast("Network report refreshed.", "good", 1800);
    } finally {
      btn.disabled = false;
      btn.textContent = "Refresh route health";
    }
  });
  $("#settings-network-copy-report")?.addEventListener("click", () => {
    copySettingsNetworkReport().catch((e) => {
      toast(`Couldn't copy report: ${errorToastBody(e)}`, "bad", 4000);
    });
  });
  $("#settings-network-run-doctor")?.addEventListener("click", async () => {
    switchSettingsPane("advanced");
    $("#settings-run-doctor")?.click();
    $("#doctor-results")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });
  $("#settings-overview-repair")?.addEventListener("click", async () => {
    switchSettingsPane("network");
    await refreshSettingsNetwork();
    $("#settings-network-run-doctor")?.click();
  });
  $("#settings-overview-copy")?.addEventListener("click", () => {
    copySettingsOverviewReport().catch((e) => toast(`Copy failed: ${errorToastBody(e)}`, "bad", 5000));
  });
  $("#settings-overview-devices")?.addEventListener("click", () => switchSettingsPane("devices"));
  $("#settings-overview-privacy")?.addEventListener("click", () => switchSettingsPane("privacy"));
  $("#settings-overview-storage")?.addEventListener("click", () => switchSettingsPane("storage"));

  $("#settings-devices-refresh")?.addEventListener("click", async () => {
    const btn = $("#settings-devices-refresh");
    if (btn) btn.textContent = "Refreshing...";
    try {
      await refreshPeers();
      renderSettingsDevices();
      toast("Device list refreshed.", "good", 1600);
    } finally {
      if (btn) btn.textContent = "Refresh";
    }
  });

  $("#settings-devices-pair")?.addEventListener("click", () => {
    _resetPairPhoneCard();
    $("#pair-phone-section")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    $("#btn-mint-pair")?.focus();
  });
  $("#settings-about-open-devices")?.addEventListener("click", openSettingsDeviceHub);

  $("#settings-devices-nearby")?.addEventListener("click", async () => {
    settingsBackdrop?.classList.remove("show");
    document.querySelector('[data-pane="activity"]')?.click();
    await loadActivityNearby({ force: true });
    toast("Nearby devices refreshed.", "info", 1800);
  });
  $("#settings-devices-copy-roster")?.addEventListener("click", async () => {
    const peers = [...(state.peers?.values?.() || [])]
      .filter((p) => p && p.trust !== "rejected")
      .map((p) => ({
        name: p.display_name || p.hostname || p.short_id || "Device",
        short_id: p.short_id || null,
        fingerprint: p.fingerprint || null,
        trust: p.trust || "unknown",
        online: !!p.online,
        verified: !!p.is_verified,
        route: reachLabel(p),
        latency_ms: p.health?.latency_ewma_ms == null ? null : Math.round(p.health.latency_ewma_ms),
        version: p.app_version || null,
      }));
    await copyToClipboard(
      JSON.stringify({ generated_at: new Date().toISOString(), peers }, null, 2),
      "device report",
    );
  });
  $("#settings-about-copy-diagnostics")?.addEventListener("click", () => {
    $("#settings-copy-diagnostics")?.click();
  });
  $("#settings-about-download-diagnostics")?.addEventListener("click", () => {
    $("#settings-export-diagnostics")?.click();
  });

  // v0.21.x: 'Show daemon log location' surfaces where the
  // daemon writes its log file on disk + offers to copy the
  // path to the clipboard. Avoids the common 'how do I find
  // the log?' support question.
  $("#settings-about-show-log-location")?.addEventListener("click", async () => {
    const out = $("#settings-about-log-location-out");
    if (!out) return;
    out.style.display = "";
    out.textContent = "Looking up log location…";
    try {
      // /api/me already includes the daemon's package + data
      // roots. Log file lives at <data_dir>/data/daemon.log on
      // every platform (the daemon writes it via debug_log on
      // startup).
      const me = await api.get("/api/me");
      const dataDir = me?.data_dir
        || me?.package_root
        || "(unknown - check your One Link folder for daemon.log)";
      const guess = dataDir.replace(/[\\/]+$/, "") + "/daemon.log";
      out.innerHTML = "";
      const path = document.createElement("code");
      path.textContent = guess;
      path.style.cssText = "user-select:all; word-break:break-all;";
      out.appendChild(path);
      out.appendChild(document.createElement("br"));
      const copyBtn = document.createElement("button");
      copyBtn.type = "button";
      copyBtn.className = "btn-ghost";
      copyBtn.style.marginTop = "6px";
      copyBtn.textContent = "Copy path";
      copyBtn.onclick = async (ev) => {
        ev.preventDefault();
        try {
          await navigator.clipboard.writeText(guess);
          toast("Path copied. Paste into File Explorer or Finder.", "good", 3000);
        } catch (e) {
          toast(`Could not copy: ${errorToastBody(e)}`, "bad");
        }
      };
      out.appendChild(copyBtn);
    } catch (e) {
      out.textContent = `Could not look up log location: ${errorToastBody(e)}`;
    }
  });

