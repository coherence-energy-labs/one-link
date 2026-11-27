  function _downloadConvoExport(url) {
    const a = document.createElement("a");
    a.href = url;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  // v0.12.1 - wallpaper accent for an individual chat. Now
  // server-synced via _writeChatPref so the user's other devices
  // see the same tint.
  const _CHAT_WALLPAPER_PRESETS = [
    "",  // None / default
    "#1a1f3a", "#1f1a3a", "#1a3a2f", "#3a2f1a",
    "#3a1a2a", "#1a2e3a", "#2a3a1a", "#3a1a1a",
  ];
  function getChatWallpaper(scope, key) {
    return _readChatPref(scope, key, "wallpaper") || "";
  }
  function setChatWallpaper(scope, key, hex) {
    _writeChatPref(scope, key, "wallpaper", hex || null);
    applyActiveChatWallpaper();
  }
  function applyActiveChatWallpaper() {
    const host = document.querySelector("#convo-active");
    if (!host) return;
    let hex = "";
    if (state.selectedPeer) {
      const peer = state.peers.get(state.selectedPeer);
      if (peer?.fingerprint) {
        hex = getChatWallpaper("peer", peer.fingerprint);
      }
    } else if (state.selectedGroup) {
      hex = getChatWallpaper("group", state.selectedGroup);
    }
    host.style.background = hex || "";
  }
  function _renderChatWallpaperSwatches(host, scope, key) {
    if (!host) return;
    host.innerHTML = "";
    const current = getChatWallpaper(scope, key);
    for (const c of _CHAT_WALLPAPER_PRESETS) {
      const sw = document.createElement("button");
      sw.className = "profile-color-swatch" + (c === current ? " active" : "");
      sw.style.background = c || "var(--bg)";
      sw.dataset.color = c;
      sw.title = c || "None";
      if (c === "") {
        sw.textContent = "✕";
        sw.style.color = "var(--text-dim)";
        sw.style.fontSize = "11px";
      }
      sw.onclick = (ev) => {
        ev.preventDefault();
        host.querySelectorAll(".profile-color-swatch").forEach(
          (b) => b.classList.toggle("active", b === sw),
        );
        setChatWallpaper(scope, key, c);
      };
      host.appendChild(sw);
    }
  }

  // v0.11.5 - media gallery modal (peer scope only for now; group
  // gallery slots in here once the backend list_group_files lands).
  async function openMediaGallery(fp) {
    const host = $("#media-gallery-list");
    const title = $("#media-gallery-title");
    if (!host) return;
    host.innerHTML = "<p class=\"settings-help\">Loading photos + videos…</p>";
    const peer = [...state.peers.values()].find(p => p.fingerprint === fp);
    if (title) {
      title.textContent = `Shared files · ${peer?.display_name || peer?.hostname || "device"}`;
    }
    $("#media-gallery-backdrop").classList.add("show");
    try {
      const r = await api.get(`/api/peers/${fp}/media`);
      _renderMediaGallery(host, r.items || []);
    } catch (e) {
      // 2026-05-21 audit T3-A: errorToastBody returns server-controlled
      // text (e.message + e.hint + e.error_detail); escape before
      // injecting via innerHTML.
      host.innerHTML = `<p class="settings-help">Failed to load: ${_escapeHtml(errorToastBody(e))}</p>`;
    }
  }
  function _renderMediaGallery(host, items) {
    host.innerHTML = "";
    if (items.length === 0) {
      const p = el("p", "settings-help blocked-empty",
        "No files exchanged in this chat yet.");
      host.appendChild(p);
      return;
    }
    for (const it of items) {
      const row = el("div", "blocked-row");
      const wrap = el("div");
      wrap.style.flex = "1";
      wrap.appendChild(el("div", "name", it.name || "(file)"));
      const subBits = [];
      if (it.size != null) subBits.push(fmtBytes(it.size));
      if (it.direction) subBits.push(it.direction === "out" ? "Sent" : "Received");
      if (it.ts_ms) subBits.push(new Date(it.ts_ms).toLocaleString());
      wrap.appendChild(el("div", "sub", subBits.join(" - ")));
      row.appendChild(wrap);
      // For inbox files we have a direct download URL via /api/files.
      if (it.direction === "in" && it.name) {
        const dl = el("a", "btn-ghost", "Download");
        dl.href = `/api/files/${encodeURIComponent(it.name)}`;
        dl.setAttribute("download", it.name);
        row.appendChild(dl);
      }
      host.appendChild(row);
    }
  }
  $("#media-gallery-close")?.addEventListener("click", () => {
    $("#media-gallery-backdrop").classList.remove("show");
  });
  $("#media-gallery-backdrop")?.addEventListener("click", (e) => {
    if (e.target === e.currentTarget) {
      $("#media-gallery-backdrop").classList.remove("show");
    }
  });
  $("#device-save").onclick = async () => {
    const fp = state.deviceDrawerFp;
    const pending = state.deviceDrawerPending;
    if (!fp || !pending) return;
    const payload = {};
    payload.local_alias = (pending.local_alias || "").trim() || null;
    payload.muted = !!pending.muted;
    try {
      await api.post(`/api/peers/${fp}/profile`, payload);
      toast("Device settings saved", "good");
      closeDeviceDrawer();
      await refreshPeers();
    } catch (e) {
      toast(`Save didn't work: ${errorToastBody(e)}`, "bad");
    }
  };

  // v0.7.7 verified-in-person actions. Confirm flow opens a small
  // prompt for a free-text note (location, witness, etc) so the
  // audit log captures HOW the SAS was compared. Revoke is a
  // single-click revert with a confirm() guard.
  $("#dev-verify-confirm").onclick = async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    const peer = drawerPeerByFp(fp);
    if (!peer) return;
    const sas = ($("#dev-sas").textContent || "").trim();
    const sasLine = sas && sas !== "…" && sas !== "-" && sas !== "(unavailable)"
      ? `\n\nSAS for ${peer.display_name || peer.short_id}: ${sas}\n\nConfirm only if it matches what the other device shows.`
      : "\n\nConfirm only if you have already compared the SAS through a side channel.";
    if (!confirm(
      `Mark "${peer.display_name || peer.hostname || peer.short_id}" as verified in person?` + sasLine
    )) return;
    let note = window.prompt(
      "Optional reminder (e.g. 'compared at home Tue', 'phone call w/ Alice'). Leave blank to skip:",
      ""
    );
    if (note === null) return;  // user hit Cancel on the prompt
    note = (note || "").trim();
    if (note.length > 280) {
      toast("Note's running long. 280 char cap.", "warn");
      return;
    }
    try {
      const res = await api.post(`/api/peers/${fp}/verify`, {
        method: "sas-digits",
        note: note || null,
      });
      if (peer) {
        peer.verified_at_ms = res.verified_at_ms;
        peer.verified_method = res.verified_method;
        peer.verified_note = res.verified_note;
        peer.is_verified = !!res.is_verified;
      }
      renderDrawerVerification(peer || drawerPeerByFp(fp));
      renderPeers();
      // Reflect the new pill in the conversation header without a
      // round-trip to refreshPeers.
      if (state.selectedPeer && peer && peer.short_id === state.selectedPeer) {
        renderConvHeaderTrust(peer);
      }
      toast("Verified in person. Hard to fake that.", "good");
    } catch (e) {
      toast(`Verify didn't work: ${errorToastBody(e)}`, "bad");
    }
  };
  // v0.7.8: drawer's "Acknowledge" button - clears the red banner +
  // overlay for THIS peer and writes acked_ms on every unacked event
  // for the peer's fingerprint. Audit rows persist (the events stay
  // in the DB; just marked seen).
  $("#dev-keychange-ack").onclick = async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    if (!confirm(
      "Acknowledge every key-change event for this device?\n\n" +
      "The events stay in the audit log. Acknowledging only clears " +
      "the red warning banner - it does NOT re-trust the new key. " +
      "If you want to chat with the new identity, re-pair from scratch."
    )) return;
    await ackPeerKeyChange(fp);
  };

  // v0.10.2: TTL picker change → save to /api/peers/{fp}/ttl + cache.
  $("#dev-dm-ttl")?.addEventListener("change", async (e) => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    const raw = e.target.value;
    const ttl = raw ? parseInt(raw, 10) : null;
    try {
      await api.post(`/api/peers/${fp}/ttl`, { ttl_ms: ttl });
      // Patch the peer record so next render uses the new value.
      const peer = drawerPeerByFp(fp);
      if (peer) peer.dm_ttl_ms = ttl;
      toast(
        ttl ? `Messages with this device now expire after ${_humanTtl(ttl)}.`
            : "Disappearing messages turned off for this device.",
        "good", 4000,
      );
    } catch (err) {
      toast(`TTL save failed: ${errorToastBody(err)}`, "bad");
    }
  });
  function _humanTtl(ms) {
    if (ms < 60000) return `${Math.round(ms / 1000)}s`;
    if (ms < 3600000) return `${Math.round(ms / 60000)}m`;
    if (ms < 86400000) return `${Math.round(ms / 3600000)}h`;
    return `${Math.round(ms / 86400000)}d`;
  }

  $("#dev-verify-revoke").onclick = async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    const peer = drawerPeerByFp(fp);
    if (!peer) return;
    if (!confirm(
      `Revoke the in-person verification for "${peer.display_name || peer.hostname || peer.short_id}"?\n\n` +
      "The cryptographic channel stays intact - only the side-channel " +
      "trust mark is cleared. The original verification stays in the audit log."
    )) return;
    try {
      await api.del(`/api/peers/${fp}/verify`);
      if (peer) {
        peer.verified_at_ms = null;
        peer.verified_method = null;
        peer.verified_note = null;
        peer.is_verified = false;
      }
      renderDrawerVerification(peer || drawerPeerByFp(fp));
      renderPeers();
      if (state.selectedPeer && peer && peer.short_id === state.selectedPeer) {
        renderConvHeaderTrust(peer);
      }
      toast("Verification revoked", "info");
    } catch (e) {
      toast(`Revoke didn't work: ${errorToastBody(e)}`, "bad");
    }
  };

  // Conversation header click → open drawer for the selected peer.
  $("#convo-who")?.addEventListener("click", () => {
    if (state.selectedPeer) openDeviceDrawer(state.selectedPeer);
  });

  // v0.14.0 mobile sidebar drawer toggle. The CSS does all the
  // animation; JS only flips `.mobile-side-open` on `.app`. We
  // close on: hamburger tap (toggle), scrim tap, peer/group select,
  // and Escape key.
  function openMobileSidebar() {
    document.querySelector(".app")?.classList.add("mobile-side-open");
  }
  function closeMobileSidebar() {
    document.querySelector(".app")?.classList.remove("mobile-side-open");
  }
  function toggleMobileSidebar() {
    const app = document.querySelector(".app");
    if (!app) return;
    app.classList.toggle("mobile-side-open");
  }
  $("#mobile-hamburger")?.addEventListener("click", (ev) => {
    ev.stopPropagation();
    toggleMobileSidebar();
  });
  $("#mobile-hamburger-top")?.addEventListener("click", (ev) => {
    ev.stopPropagation();
    toggleMobileSidebar();
  });
  $("#mobile-scrim")?.addEventListener("click", closeMobileSidebar);
  // Escape closes the drawer (and any modal - that's already handled
  // elsewhere; we no-op when a modal is open so we don't compete).
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Escape") return;
    if (document.querySelector(".modal-backdrop.show, .discover-overlay.show")) return;
    if (document.querySelector(".app")?.classList.contains("mobile-side-open")) {
      closeMobileSidebar();
    }
  });

