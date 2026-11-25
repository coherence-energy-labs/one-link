  // ── v0.4: Discovery modal ──────────────────────────────────────────
  // Opening prunes ghosts (TCP probe), then loads the unpaired view.
  // Stays in sync with mDNS via the WS peers_changed signal while open.
  state.discoverable = [];
  state.discoverOpen = false;
  state.discoverLoading = false;

  async function openDiscoverModal() {
    state.discoverOpen = true;
    $("#discover-overlay").classList.add("show");
    await loadDiscoverable({ prune: true });
  }

  function closeDiscoverModal() {
    state.discoverOpen = false;
    state.discoverable = [];
    $("#discover-overlay").classList.remove("show");
  }

  async function loadDiscoverable({ prune = false } = {}) {
    if (state.discoverLoading) return;
    state.discoverLoading = true;
    const refreshBtn = $("#discover-refresh");
    if (refreshBtn) refreshBtn.classList.add("spinning");
    try {
      if (prune) {
        try { await api.post("/api/peers/prune", {}); } catch {}
      }
      // May 16 2026 - call the new smart-discovery endpoint that
      // runs mDNS + ARP + SSDP + NetBIOS in parallel and returns
      // three sections. Falls back to the legacy peer-only path
      // if the endpoint isn't available yet (e.g., daemon is
      // pre-update).
      let smart = null;
      try {
        smart = await api.get("/api/discover/all?timeout=5");
      } catch (_) {}
      const { peers } = await api.get("/api/peers?include_unpaired=1");
      const unpairedReady = peers.filter(
        (p) => p.trust !== "pinned" && p.online && p.fingerprint
      );
      if (smart) {
        // Merge the legacy unpaired-but-running-One-Link list into
        // smart.ready_to_pair. They're the same set logically but
        // the smart endpoint may not yet see the most-recently-
        // arrived peer.
        const seen_ips = new Set((smart.ready_to_pair || []).map(d => d.ip));
        for (const p of unpairedReady) {
          if (!seen_ips.has(p.address)) {
            smart.ready_to_pair = smart.ready_to_pair || [];
            smart.ready_to_pair.push({
              ip: p.address || "",
              hostname: p.hostname || p.short_id || "",
              vendor: "",
              kind: deviceKindLabel(p)?.label?.toLowerCase().includes("laptop") ? "laptop" : "unknown",
              one_link_peer: p,
            });
          }
        }
        state.discoverSmart = smart;
      } else {
        state.discoverSmart = {
          ready_to_pair: unpairedReady.map(p => ({
            ip: p.address || "",
            hostname: p.hostname || p.short_id || "",
            kind: "laptop",
            one_link_peer: p,
          })),
          pairable: [],
          other_gear: [],
          network_health: {},
        };
      }
      renderDiscoverable();
    } catch (e) {
      console.warn(e);
      const body = $("#discover-body");
      // 2026-05-21 audit T3-A: e.message is server-controlled; escape it.
      if (body) body.innerHTML = `<div class="empty">One Link isn't responding right now. Try restarting it from your system tray, or close + reopen this tab. <small style="display:block; margin-top:6px; opacity:0.6;">${_escapeHtml(String(e?.message || e || ""))}</small></div>`;
    } finally {
      state.discoverLoading = false;
      if (refreshBtn) refreshBtn.classList.remove("spinning");
    }
  }

  function _kindIcon(kind) {
    if (kind === "mobile") return "📱";
    return {
      phone: "📱", tablet: "📱", laptop: "💻", desktop: "🖥️",
      watch: "⌚", tv: "📺", speaker: "🔊", printer: "🖨️",
      router: "📡", iot: "🔌", console: "🎮", unknown: "❓",
    }[kind] || "❓";
  }

  function _kindLabel(kind) {
    if (kind === "mobile") return "Phone or tablet";
    return {
      phone: "Phone", tablet: "Tablet", laptop: "Laptop",
      desktop: "Desktop", watch: "Watch", tv: "TV",
      speaker: "Speaker", printer: "Printer", router: "Router",
      iot: "Smart device", console: "Game console",
      unknown: "Unknown device",
    }[kind] || "Device";
  }

  function _isPersonalDeviceKind(kind) {
    return ["phone", "tablet", "mobile", "laptop", "desktop"].includes(String(kind || ""));
  }

  async function startOneSetupDevicePairing() {
    closeDiscoverModal();
    await refreshOneSetup();
    showOnboardingStep(4);
    $("#onboarding-backdrop").style.display = "flex";
    await oneSetupAddDevice();
  }

  function _renderDeviceRow(d, action) {
    /* action = "pair" | "invite" */
    const row = el("div", "discover-row");
    const av = el("div", "avatar", _kindIcon(d.kind));
    const meta = el("div", "meta");
    const nameRow = el("div", "name");
    nameRow.textContent = d.hostname
      || (d.vendor ? `${d.vendor} ${_kindLabel(d.kind).toLowerCase()}` : _kindLabel(d.kind));
    meta.appendChild(nameRow);
    const subParts = [];
    if (d.vendor) subParts.push(d.vendor);
    subParts.push(_kindLabel(d.kind));
    if (d.ip) subParts.push(d.ip);
    meta.appendChild(el("div", "sub", subParts.join(" - ")));
    const btn = el(
      "button",
      action === "pair" ? "pair-btn" : "pair-btn",
      action === "pair" ? "Pair" : (_isPersonalDeviceKind(d.kind) ? "Pair" : "Invite"),
    );
    row.appendChild(av);
    row.appendChild(meta);
    row.appendChild(btn);
    row.onclick = async () => {
      if (action === "pair" && d.one_link_peer) {
        if (!d.one_link_peer.fingerprint) {
          toast("That device is still starting up. Try again in a few seconds.", "warn");
          return;
        }
        closeDiscoverModal();
        openPairModal(d.one_link_peer);
      } else if (_isPersonalDeviceKind(d.kind)) {
        await startOneSetupDevicePairing();
      } else {
        await openInviteModal(d);
      }
    };
    return row;
  }

  function _hasDiscoveredPhone(devices) {
    return (devices || []).some((d) => {
      const text = [
        d.kind, d.hostname, d.vendor, d.model,
        d.one_link_peer?.hostname, d.one_link_peer?.display_name,
      ].filter(Boolean).join(" ").toLowerCase();
      return /\b(phone|iphone|android|pixel|galaxy|oneplus|xiaomi|redmi)\b/.test(text);
    });
  }

  function _renderPhoneHelp() {
    const box = el("div", "discover-phone-help");
    box.appendChild(el("b", "", "Don't see your phone?"));
    box.appendChild(el(
      "p",
      "",
      "Phones hide more than laptops: private Wi-Fi addresses, sleep, guest networks, and hotspot modes can stop passive discovery. The reliable path is to send an invite or scan the QR from the phone.",
    ));
    const actions = el("div", "actions");
    const invite = el("button", "primary", "Pair phone by QR");
    invite.onclick = startOneSetupDevicePairing;
    const scan = el("button", "", "Scan again");
    scan.onclick = () => loadDiscoverable({ prune: true });
    actions.appendChild(invite);
    actions.appendChild(scan);
    box.appendChild(actions);
    return box;
  }

  function renderDiscoverable() {
    const body = $("#discover-body");
    if (!body) return;
    body.innerHTML = "";
    const smart = state.discoverSmart || {};
    const ready = smart.ready_to_pair || [];
    const pairable = smart.pairable || [];
    const other = smart.other_gear || [];
    const allDiscovered = [...ready, ...pairable, ...other];
    const health = smart.network_health || {};

    // Status line under the title.
    const status = $("#discover-status");
    if (status) {
      const total = ready.length + pairable.length + other.length;
      if (total === 0) {
        status.textContent = "";
      } else {
        status.textContent =
          `${total} device${total === 1 ? "" : "s"} on your network · ` +
          `${ready.length} ready to pair, ${pairable.length} inviteable`;
      }
    }

    // Network-health banner - surface AP isolation / captive
    // portal issues so the user knows WHY the scan looks empty.
    if (health.ap_isolation_suspected || health.captive_portal_suspected) {
      const banner = el("div", "discover-health-warn");
      banner.style.cssText = `
        padding: 12px 14px; margin-bottom: 14px;
        background: rgba(255,180,90,0.08);
        border: 1px solid rgba(255,180,90,0.32);
        border-radius: 10px; font-size: 13px;
      `;
      banner.textContent = (health.messages || []).join(" ");
      body.appendChild(banner);
    }

    if (ready.length === 0 && pairable.length === 0 && other.length === 0) {
      const empty = el("div", "empty");
      empty.style.padding = "32px 16px";
      empty.innerHTML = `
        <p style="margin: 0 0 6px;">No other devices found on your Wi-Fi yet.</p>
        <p style="margin: 0; color: rgba(180,200,255,0.7); font-size: 13px;">
          Either no devices are around, or your Wi-Fi blocks
          device-to-device discovery. You can still pair anyone by
          sending them an invite link.
        </p>`;
      body.appendChild(empty);
    }

    if (!_hasDiscoveredPhone(allDiscovered)) {
      body.appendChild(_renderPhoneHelp());
    }

    // Section 1: Ready to pair (already running One Link).
    if (ready.length > 0) {
      body.appendChild(el(
        "div", "discover-section-h",
        `Ready to pair · already running One Link (${ready.length})`,
      ));
      for (const d of ready) body.appendChild(_renderDeviceRow(d, "pair"));
    }
    // Section 2: Other devices on your Wi-Fi.
    if (pairable.length > 0) {
      body.appendChild(el(
        "div", "discover-section-h",
        `Other devices on your Wi-Fi (${pairable.length})`,
      ));
      for (const d of pairable) body.appendChild(_renderDeviceRow(d, "invite"));
    }
    // Section 3: Other gear (TVs / speakers / printers) - collapsed.
    if (other.length > 0) {
      const details = el("details");
      details.style.marginTop = "12px";
      const summary = el("summary", "discover-section-h");
      summary.style.cursor = "pointer";
      summary.textContent = `Other gear on your network (${other.length})`;
      details.appendChild(summary);
      for (const d of other) details.appendChild(_renderDeviceRow(d, "invite"));
      body.appendChild(details);
    }
  }

  // Invite sub-modal. Mints a pair code, renders a real SVG QR
  // (from /api/discover/invite/qr.svg), runs a live MM:SS countdown,
  // and exposes platform-appropriate share actions:
  //   - mobile / touch-primary: navigator.share -> native sheet
  //   - desktop: Email link / Show fullscreen QR / Save QR file
  let _inviteCountdownTimer = null;
  let _inviteCurrentCode = null;
  let _inviteExpiresAtMs = 0;

  // Best-effort platform detection. UA-string + touch-primary
  // pointer check; tablets with a stylus still count as touch.
  function _isMobileLikely() {
    try {
      const ua = navigator.userAgent || "";
      if (/Android|iPhone|iPad|iPod|Mobile/i.test(ua)) return true;
      // Some Windows tablets report Mobile UA; double-check via
      // pointer media query.
      if (window.matchMedia &&
          window.matchMedia("(pointer: coarse)").matches &&
          navigator.maxTouchPoints > 1) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  async function openInviteModal(targetDevice) {
    if (!targetDevice || _isPersonalDeviceKind(targetDevice.kind) || targetDevice.kind === "unknown") {
      await startOneSetupDevicePairing();
      return;
    }
    const overlay = $("#invite-backdrop");
    const codeEl = $("#invite-code");
    const urlEl = $("#invite-url");
    const expiryEl = $("#invite-expiry");
    const qrHost = $("#invite-qr");
    const tgtLine = $("#invite-target-line");
    if (!overlay || !codeEl || !urlEl || !qrHost) return;
    overlay.classList.add("show");

    // Target line copy.
    if (tgtLine) {
      if (targetDevice) {
        const who = targetDevice.hostname || targetDevice.vendor || "this device";
        const ip = targetDevice.ip ? ` (${targetDevice.ip})` : "";
        tgtLine.textContent = `Inviting ${who}${ip}. Have them scan the code or open the link.`;
      } else {
        tgtLine.textContent = "Hand them the QR code or send them the link.";
      }
    }

    // Loading state.
    codeEl.textContent = "------";
    urlEl.textContent = "";
    if (expiryEl) expiryEl.textContent = "...";
    qrHost.innerHTML = '<div style="color:#888; font-size:12px;">Generating QR...</div>';
    _stopInviteCountdown();

    try {
      const body = await api.post("/api/discover/invite", {
        target_label: targetDevice
          ? (targetDevice.hostname || targetDevice.vendor || "")
          : "",
      });
      const code = body.code || "";
      const landing = body.landing_url || "";
      _inviteCurrentCode = code;
      _inviteExpiresAtMs = body.expires_ms || (Date.now() + 300000);
      codeEl.textContent = code;
      urlEl.textContent = landing;
      // Real SVG QR from the daemon, sized to the card. <img src>
      // is authenticated by the same-origin service worker on plaintext
      // loopback (and by the HTTPS compatibility path where configured).
      const qrUrl = `/api/discover/invite/qr.svg?code=${encodeURIComponent(code)}`;
      // 2026-05-21 audit T3-B: replace inline ``onerror=`` handler
      // with a programmatic listener so the daemon's CSP can drop
      // ``unsafe-inline`` without breaking this fallback. Inline
      // handlers also can't escape user-supplied content safely;
      // building the DOM directly removes that surface entirely.
      qrHost.replaceChildren();
      const qrImg = document.createElement("img");
      qrImg.src = qrUrl;
      qrImg.alt = "Pair QR code";
      qrImg.style.width = "100%";
      qrImg.style.height = "100%";
      qrImg.style.objectFit = "contain";
      qrImg.addEventListener("error", () => {
        const fail = el("div", null, "QR generation failed");
        fail.style.color = "#c33";
        fail.style.fontSize = "12px";
        qrHost.replaceChildren(fail);
      });
      qrHost.appendChild(qrImg);
      // Live MM:SS countdown.
      _startInviteCountdown();
      // Tailor the action row to the platform.
      //
      // On Windows desktop, navigator.share() routes through the
      // Windows share sheet which defaults to Microsoft Phone Link
      // (a corp account-tied service that violates the sovereignty
      // floor and confuses users). So Web Share is ONLY used when
      // we're on a real mobile / touch-primary device - there the
      // OS share sheet is a first-class send mechanism (Messages /
      // Mail / AirDrop / etc.).
      //
      // On desktop we show our own sovereign options: Email link
      // via mailto:, Show fullscreen QR (great for showing across
      // a room), and Save QR (downloads the SVG to disk).
      const isMobile = _isMobileLikely();
      $("#invite-share").style.display = (isMobile && navigator.share) ? "" : "none";
      $("#invite-email").style.display = isMobile ? "none" : "";
      $("#invite-fullscreen").style.display = isMobile ? "none" : "";
      $("#invite-save-qr").style.display = isMobile ? "none" : "";
      // Wire the save-QR anchor to the qr.svg URL.
      const dl = $("#invite-qr-download");
      if (dl) {
        dl.href = qrUrl;
        dl.download = `one-link-invite-${code}.svg`;
        dl.dataset.ready = "1";
      }
    } catch (e) {
      codeEl.textContent = "ERROR";
      urlEl.textContent = "";
      qrHost.innerHTML = `<div style="color:#c33; font-size:12px;">`
        + `Couldn't generate invite.<br>${escapeText(e.message || String(e))}</div>`;
    }
  }

  function _startInviteCountdown() {
    _stopInviteCountdown();
    const expiryEl = $("#invite-expiry");
    if (!expiryEl) return;
    const tick = () => {
      const ms = _inviteExpiresAtMs - Date.now();
      if (ms <= 0) {
        expiryEl.textContent = "Expired";
        expiryEl.style.color = "#e36a6a";
        _stopInviteCountdown();
        return;
      }
      const total = Math.floor(ms / 1000);
      const mm = Math.floor(total / 60);
      const ss = total % 60;
      expiryEl.textContent = `${mm}:${ss.toString().padStart(2, "0")}`;
      expiryEl.style.color = ms < 60000 ? "#e3a86a" : "";
    };
    tick();
    _inviteCountdownTimer = setInterval(tick, 1000);
  }

  function _stopInviteCountdown() {
    if (_inviteCountdownTimer) {
      clearInterval(_inviteCountdownTimer);
      _inviteCountdownTimer = null;
    }
  }

  function closeInviteModal() {
    const overlay = $("#invite-backdrop");
    if (overlay) overlay.classList.remove("show");
    _stopInviteCountdown();
    _inviteCurrentCode = null;
  }

  // Trust API - kept for power-user paths (right-click menu later); the
  // primary trust UX is the pair modal now.
  async function setTrust(fingerprint, trust) {
    try {
      await api.post(`/api/peers/${fingerprint}/trust`, { trust });
      await refreshPeers();
    } catch (e) {
      toast(`Trust update failed: ${e.message || e}`, "bad");
    }
  }

