  async function openDeviceDrawer(shortId) {
    const peer = _peerFromShort(shortId);
    if (!peer || !peer.fingerprint) {
      toast("This device isn't paired yet.", "info");
      return;
    }
    state.deviceDrawerFp = peer.fingerprint;
    state.deviceDrawerPending = {
      local_alias: peer.local_alias ?? "",
      muted: !!peer.muted,
    };

    // v0.13.2: every helper call below is wrapped in a try/catch so
    // a regression in any cosmetic side-effect (mute-status renderer,
    // wallpaper swatches, capability sync, etc.) doesn't prevent the
    // drawer from opening. The drawer's PRIMARY action is "show me
    // device settings"; if a sub-helper breaks, log + continue. We
    // still flip .show at the end so the user always gets the modal.
    const tryStep = (label, fn) => {
      try { fn(); } catch (e) { console.warn(`drawer: ${label} failed`, e); }
    };

    const kind = deviceKindLabel(peer);
    const drawerNameEl = $("#device-drawer-name");
    if (drawerNameEl) {
      drawerNameEl.textContent = "";
      if (kind) {
        const ic = el("span", "kind-icon", kind.icon + " ");
        ic.title = kind.label;
        drawerNameEl.appendChild(ic);
      }
      drawerNameEl.appendChild(document.createTextNode(
        peer.display_name || peer.hostname || peer.short_id
      ));
    }
    const subParts = [peer.short_id, reachLabel(peer)];
    if (kind) subParts.push(kind.label);
    const subEl = $("#device-drawer-sub");
    if (subEl) subEl.textContent = subParts.join(" - ");

    const aliasEl = $("#dev-alias");
    if (aliasEl) aliasEl.value = peer.local_alias || "";
    const muteEl = $("#dev-mute");
    if (muteEl) muteEl.checked = !!peer.muted;
    tryStep("mute-status", () => _renderMuteStatus(
      $("#dev-mute-status"),
      peer.muted_until_ms,
      !!peer.muted,
    ));
    tryStep("wallpaper-swatches", () => _renderChatWallpaperSwatches(
      $("#dev-wallpaper-swatches"),
      "peer", peer.fingerprint,
    ));
    const dur = $("#dev-mute-duration");
    if (dur) dur.value = "";

    tryStep("capability-sync", () => syncDrawerCapabilityControls(
      peer.allowed_capabilities,
    ));

    // Permission history for THIS peer. Fire-and-forget inside tryStep, the
    // same as every other optional panel here: a drawer that fails to open
    // because a history could not be fetched would be a worse product than
    // one that shows no history.
    tryStep("capability-history", () => renderCapabilityHistory(peer.fingerprint));

    const regEl = $("#dev-regime");
    if (regEl) regEl.textContent = reachLabel(peer);
    const lat = peer.health?.latency_ewma_ms;
    const latEl = $("#dev-latency");
    if (latEl) latEl.textContent = lat == null ? "-" : `${Math.round(lat)} ms`;
    const lastAliveEl = $("#dev-lastalive");
    if (lastAliveEl) lastAliveEl.textContent =
      _humanRelMs(peer.health?.last_alive_ms || peer.last_seen_ms);
    const addrEl = $("#dev-address");
    if (addrEl) addrEl.textContent = `${peer.address || "?"}:${peer.port || "?"}`;

    const sidEl = $("#dev-shortid");
    if (sidEl) sidEl.textContent = peer.short_id;
    const fpEl = $("#dev-fp");
    if (fpEl) fpEl.textContent = peer.fingerprint;

    // v0.13.2: every block wrapped so a single helper crash doesn't
    // stop the modal from opening.
    tryStep("sas-init", () => {
      const sasEl = $("#dev-sas");
      if (sasEl) sasEl.textContent = "…";
      state.deviceDrawerSas = null;
      renderSasArt($("#dev-sas-art"), null);
      const art = $("#dev-sas-art");
      if (art) art.style.display = "none";
      $("#dev-sas-art-toggle")?.classList.remove("on");
    });
    // SAS fetch is async; we still want to surface the modal even if
    // /api/peers/{fp}/sas hangs or 404s. We don't await it before
    // showing the modal - fire-and-forget below.

    tryStep("verification", () => renderDrawerVerification(peer));
    tryStep("key-change", () => renderDrawerKeyChange(peer));

    const ttlSel = $("#dev-dm-ttl");
    if (ttlSel) ttlSel.value = peer.dm_ttl_ms ? String(peer.dm_ttl_ms) : "";

    const tl = $("#dev-trust-timeline");
    if (tl) {
      tl.style.display = "none";
      tl.innerHTML = "";
    }
    const tlBtn = $("#dev-trust-history-toggle");
    if (tlBtn) {
      tlBtn.textContent = "▾";
      tlBtn.classList.remove("on");
    }

    // v0.13.2: show the modal NOW - every cosmetic helper has run
    // (or failed soft) and the user gets settings up regardless.
    $("#device-backdrop")?.classList.add("show");

    // SAS fetch happens AFTER the modal is up. Late-arriving SAS
    // populates the field; failure surfaces "(unavailable)".
    (async () => {
      try {
        const sas = await api.get(`/api/peers/${peer.fingerprint}/sas`);
        const sasEl = $("#dev-sas");
        if (sasEl) sasEl.textContent = sas.sas || "-";
        if (sas.sas) {
          state.deviceDrawerSas = sas.sas;
          tryStep("sas-art", () => renderSasArt($("#dev-sas-art"), sas.sas));
        }
      } catch {
        const sasEl = $("#dev-sas");
        if (sasEl) sasEl.textContent = "(unavailable)";
      }
    })();
  }

  // v0.7.7: pretty label for a verification method tag stored in
  // peers.verified_method. Single source of truth - the device
  // drawer status row, the avatar overlay tooltip, and any future
  // audit-log surface use the same labels.
  function verifyMethodLabel(method) {
    switch (method) {
      case "sas-digits": return "SAS digits";
      case "sas-qr":     return "QR scan";
      case "sas-audio":  return "Spoken SAS";
      case "manual":     return "Manual";
      default:           return method || "-";
    }
  }

  function renderDrawerVerification(peer) {
    const verified = !!peer?.is_verified;
    const helpEl = $("#dev-verify-help");
    const whenRow = $("#dev-verify-when-row");
    const methodRow = $("#dev-verify-method-row");
    const noteRow = $("#dev-verify-note-row");
    const confirmBtn = $("#dev-verify-confirm");
    const revokeBtn = $("#dev-verify-revoke");
    if (verified) {
      helpEl.textContent =
        "This device has been confirmed in person. The green " +
        "checkmark in the sidebar reflects that. Revoke if you " +
        "have reason to doubt the side-channel match (key change, " +
        "device passed to someone else, etc).";
      whenRow.style.display = "";
      $("#dev-verify-when").textContent = peer.verified_at_ms
        ? `${_humanRelMs(peer.verified_at_ms)} (${new Date(peer.verified_at_ms).toLocaleString()})`
        : "-";
      methodRow.style.display = "";
      $("#dev-verify-method").textContent = verifyMethodLabel(peer.verified_method);
      if (peer.verified_note) {
        noteRow.style.display = "";
        $("#dev-verify-note").textContent = peer.verified_note;
      } else {
        noteRow.style.display = "none";
      }
      confirmBtn.style.display = "none";
      revokeBtn.style.display = "";
    } else {
      helpEl.textContent =
        "Compare the SAS above with the same value on the other " +
        "device - face-to-face, on a call, or by reading it aloud. " +
        "If they match, mark this device verified to surface a " +
        "green checkmark across the chat.";
      whenRow.style.display = "none";
      methodRow.style.display = "none";
      noteRow.style.display = "none";
      confirmBtn.style.display = "";
      revokeBtn.style.display = "none";
    }
  }

  function closeDeviceDrawer() {
    state.deviceDrawerFp = null;
    state.deviceDrawerPending = null;
    state.deviceDrawerSas = null;
    try { window.speechSynthesis?.cancel(); } catch {}
    $("#device-backdrop").classList.remove("show");
  }

  function bindSwitch(inputId) {
    const input = $("#" + inputId);
    const toggle = input?.closest(".toggle");
    if (!input || !toggle) return;
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("tabindex", "0");
    const syncA11y = () => {
      toggle.setAttribute("aria-checked", input.checked ? "true" : "false");
    };
    input.addEventListener("change", syncA11y);
    toggle.addEventListener("click", (e) => {
      if (e.target === input) return;
      e.preventDefault();
      input.checked = !input.checked;
      syncA11y();
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
    toggle.addEventListener("keydown", (e) => {
      if (e.key !== " " && e.key !== "Enter") return;
      e.preventDefault();
      input.checked = !input.checked;
      syncA11y();
      input.dispatchEvent(new Event("change", { bubbles: true }));
    });
    syncA11y();
  }

  // May 16 2026 - RED-TEAM FIX. The Settings panel + device drawer
  // had 13 visual "toggle" UIs (CSS-styled checkboxes), but only 4
  // were wired through bindSwitch. The other 9 were dead - clicking
  // the slider did NOTHING because the underlying input element never
  // flipped + no change event ever fired. (The input itself is
  // hidden via `display: none` so users can't click it directly
  // either.) Users reported "no toggle works."
  //
  // Fix: bindSwitch every checkbox that lives inside a .toggle
  // wrapper. Plus remove the stale "set-rendezvous" entry (it's a
  // textarea - bindSwitch silently no-oped for it but it confused
  // future maintainers).
  //
  // We pull the list dynamically from the DOM so a future toggle
  // added to the HTML is auto-wired without touching this list.
  document.querySelectorAll(".toggle > input[type='checkbox'][id]").forEach((input) => {
    bindSwitch(input.id);
  });

  const DRAWER_CAPS = ["chat", "files", "folder_sync", "voice_call", "video_call"];
  const LEGACY_DRAWER_ALLOW_ALL_CAPS = ["chat", "files", "folder_sync"];

  function pairDefaultAllowAllEnabled() {
    return state.runtimeSettings?.pair_default_allow_all !== false;
  }

  function policyLooksLikeLegacyDrawerAllowAll(policy) {
    if (!Array.isArray(policy) || !pairDefaultAllowAllEnabled()) return false;
    const allowed = new Set(policy);
    return LEGACY_DRAWER_ALLOW_ALL_CAPS.every(cap => allowed.has(cap))
      && !allowed.has("voice_call")
      && !allowed.has("video_call");
  }

  function peerCapabilityAllowed(peer, cap) {
    const policy = peer?.allowed_capabilities;
    if (!Array.isArray(policy)) return true;
    if (policy.indexOf(cap) >= 0) return true;
    return (cap === "voice_call" || cap === "video_call")
      && policyLooksLikeLegacyDrawerAllowAll(policy);
  }

  function drawerPeerByFp(fp = state.deviceDrawerFp) {
    return [...state.peers.values()].find(p => p.fingerprint === fp) || null;
  }

  function drawerAllowedSet(policy) {
    if (policy == null) return new Set(DRAWER_CAPS);
    const allowed = new Set(policy || []);
    if (policyLooksLikeLegacyDrawerAllowAll(policy)) {
      allowed.add("voice_call");
      allowed.add("video_call");
    }
    return allowed;
  }

  // Describe a stored capability policy the way a person would say it.
  // `null` and `["*"]` both mean "everything" in the wire format; a user
  // reading their own permission history should not have to know that.
  function _capPolicyLabel(policy) {
    if (policy == null) return "everything";
    const list = Array.isArray(policy) ? policy : [policy];
    if (!list.length) return "nothing";
    if (list.includes("*")) return "everything";
    const names = {
      chat: "Chat", files: "Files", folder_sync: "Folders",
      voice_call: "Voice", video_call: "Video",
    };
    return list.map(c => names[c] || c).join(", ");
  }

  // Render this peer's permission history from /api/capability-audit.
  //
  // The daemon has recorded every capability change since the first schema
  // version, and no shipped asset ever asked for them -- the endpoint was
  // registered, authenticated, correct, and consumed by nothing. Found by
  // auditing which registered routes have no consumer.
  //
  // Everything here degrades to "show nothing": an empty history and a failed
  // request are the same to the user, because a peer whose permissions were
  // never changed genuinely has no history, and inventing a distinction
  // between "none" and "could not load" would be noise on a panel nobody
  // opened to debug the UI.
  async function renderCapabilityHistory(fingerprint) {
    const wrap = $("#dev-cap-history-wrap");
    const host = $("#dev-cap-history");
    if (!wrap || !host || !fingerprint) return;
    wrap.hidden = true;
    host.innerHTML = "";

    let payload;
    try {
      payload = await api.get(
        `/api/capability-audit?fp=${encodeURIComponent(fingerprint)}&limit=20`
      );
    } catch (_e) {
      return;
    }
    const events = (payload && payload.events) || [];
    if (!events.length) return;

    for (const ev of events) {
      const row = document.createElement("div");
      row.className = "cap-history-row";

      const when = document.createElement("span");
      when.className = "cap-history-when";
      when.textContent = _humanRelMs(ev.ts_ms);
      row.appendChild(when);

      const what = document.createElement("span");
      what.className = "cap-history-what";
      const before = _capPolicyLabel(ev.before_json);
      const after = _capPolicyLabel(ev.after_json);
      what.textContent = before === after
        ? `${ev.kind || "changed"}: ${after}`
        : `${before} → ${after}`;
      row.appendChild(what);

      // The actor is the accountability half. "Who changed this" is the
      // question that makes an audit trail an audit trail rather than a log.
      if (ev.actor) {
        const who = document.createElement("span");
        who.className = "cap-history-who";
        who.textContent = ev.actor;
        row.appendChild(who);
      }
      host.appendChild(row);
    }
    wrap.hidden = false;
  }

  function syncDrawerCapabilityControls(policy) {
    const allowed = drawerAllowedSet(policy);
    const allOn = DRAWER_CAPS.every(cap => allowed.has(cap));
    const allowAll = $("#dev-allow-all");
    if (allowAll) {
      allowAll.checked = allOn;
      const toggle = allowAll.closest(".toggle");
      if (toggle) toggle.setAttribute("aria-checked", allOn ? "true" : "false");
    }
    document.querySelectorAll("#dev-cap-row .cap-toggle").forEach(btn => {
      btn.classList.toggle("on", allowed.has(btn.dataset.cap));
    });
  }

  function drawerCapabilityPolicyFromButtons() {
    const allowed = [];
    document.querySelectorAll("#dev-cap-row .cap-toggle").forEach(btn => {
      if (btn.classList.contains("on")) allowed.push(btn.dataset.cap);
    });
    return allowed;
  }

  // Wire drawer interactions.
  $("#device-cancel").onclick = closeDeviceDrawer;
  $("#dev-alias").addEventListener("input", (e) => {
    if (state.deviceDrawerPending) {
      state.deviceDrawerPending.local_alias = e.target.value;
    }
  });
  $("#dev-mute").addEventListener("change", (e) => {
    if (state.deviceDrawerPending) {
      state.deviceDrawerPending.muted = !!e.target.checked;
    }
  });
  // v0.11.2 mute-with-duration apply.
  $("#dev-mute-apply")?.addEventListener("click", async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    const sel = $("#dev-mute-duration");
    if (!sel?.value) {
      toast("Pick a duration first", "info");
      return;
    }
    const raw = sel.value;
    let body;
    if (raw === "null") body = { duration_ms: null };
    else body = { duration_ms: parseInt(raw, 10) };
    try {
      const r = await api.post(
        `/api/peers/${encodeURIComponent(fp)}/mute`, body,
      );
      _renderMuteStatus(
        $("#dev-mute-status"), r.muted_until_ms, r.muted_until_ms != null,
      );
      $("#dev-mute").checked = r.muted_until_ms != null;
      toast(
        body.duration_ms === null ? "Unmuted" : "Mute applied", "good",
      );
      // Refresh sidebar so the row reflects the change.
      await refreshPeers();
    } catch (e) {
      toast(`Mute didn't work: ${errorToastBody(e)}`, "bad");
    }
  });
  document.querySelectorAll("#dev-cap-row .cap-toggle").forEach(btn => {
    btn.onclick = async () => {
      const fp = state.deviceDrawerFp;
      if (!fp) return;
      const cap = btn.dataset.cap;
      const isOn = btn.classList.contains("on");
      const peer = drawerPeerByFp(fp);
      const previous = peer ? peer.allowed_capabilities : null;
      btn.classList.toggle("on", !isOn);
      const nextAllowed = drawerCapabilityPolicyFromButtons();
      syncDrawerCapabilityControls(nextAllowed);
      try {
        const res = await setCapability(cap, !isOn, { fingerprint: fp });
        syncDrawerCapabilityControls(res.allowed);
      } catch {
        syncDrawerCapabilityControls(previous);
      }
    };
  });

  // v0.7.3: master "Allow all" toggle. ON sets policy=null (legacy
  // allow-everything). OFF sets policy=[] (explicit deny everything;
  // user grants individually below).
  $("#dev-allow-all")?.addEventListener("change", async (e) => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    const wantsAll = !!e.target.checked;
    const peer = drawerPeerByFp(fp);
    const previous = peer ? peer.allowed_capabilities : null;
    syncDrawerCapabilityControls(wantsAll ? null : []);
    try {
      const body = { allowed: wantsAll ? null : [] };
      const res = await api.post(`/api/peers/${fp}/capabilities`, body);
      // Update local state.peers cache so refreshPeers doesn't flip
      // the toggle back on the next render-coalesce tick.
      if (peer) peer.allowed_capabilities = res.allowed;
      syncDrawerCapabilityControls(res.allowed);
      toast(wantsAll ? "Allowing all capabilities" : "Permissions cleared", "good");
    } catch (err) {
      syncDrawerCapabilityControls(previous);
      toast(`Update didn't work: ${err.message || err}`, "bad");
    }
  });
  // v0.8.6: render the trust-history timeline inside the device
  // drawer. Lazy-loaded on toggle so a quick drawer open doesn't
  // hit the DB. The rendered list is keyed off ts_ms; severity
  // drives the left-rail color (good/warn/bad/info).
  async function loadDrawerTrustHistory() {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    const tl = $("#dev-trust-timeline");
    if (!tl) return;
    tl.innerHTML = "";
    tl.appendChild(el("div", "empty", "Loading…"));
    let events = [];
    try {
      const res = await api.get(
        `/api/peers/${fp}/trust-history?limit=200`
      );
      events = res.events || [];
    } catch (e) {
      tl.innerHTML = "";
      tl.appendChild(el("div", "empty", `Couldn\'t load: ${e.message || e}`));
      return;
    }
    // Drawer might have been closed while we waited on the network.
    if (state.deviceDrawerFp !== fp) return;
    tl.innerHTML = "";
    if (events.length === 0) {
      tl.appendChild(el("div", "empty", "No recorded trust events for this device."));
      return;
    }
    for (const ev of events) {
      const sev = ev.severity || "info";
      const row = el("div", `tev sev-${sev}`);
      row.appendChild(el("div", "tev-time", _humanRelMs(ev.ts_ms)));
      const body = el("div", "tev-body");
      body.appendChild(el("div", "tev-label", ev.label || ev.kind || "(unknown)"));
      if (ev.detail) {
        body.appendChild(el("div", "tev-detail", ev.detail));
      }
      const dateLine = el("div", "tev-detail",
        new Date(ev.ts_ms).toLocaleString());
      dateLine.style.fontSize = "10px";
      dateLine.style.opacity = "0.7";
      body.appendChild(dateLine);
      row.appendChild(body);
      tl.appendChild(row);
    }
  }

  $("#dev-trust-history-toggle")?.addEventListener("click", async (e) => {
    const tl = $("#dev-trust-timeline");
    const btn = e.currentTarget;
    if (!tl) return;
    const showing = tl.style.display !== "none";
    if (showing) {
      tl.style.display = "none";
      btn.textContent = "▾";
      btn.classList.remove("on");
    } else {
      tl.style.display = "block";
      btn.textContent = "▴";
      btn.classList.add("on");
      await loadDrawerTrustHistory();
    }
  });

  // v0.7.9: drawer SAS multi-modal helpers (mirrors pair-modal).
  $("#dev-sas-speak")?.addEventListener("click", () => {
    speakSas("", state.deviceDrawerSas);
  });
  $("#dev-sas-art-toggle")?.addEventListener("click", (e) => {
    const art = $("#dev-sas-art");
    if (!art) return;
    const showing = art.style.display !== "none";
    art.style.display = showing ? "none" : "grid";
    e.currentTarget.classList.toggle("on", !showing);
  });
  $("#dev-shortid").onclick = () => {
    if (state.deviceDrawerFp) {
      const peer = state.peers.get(
        [...state.peers.values()].find(p => p.fingerprint === state.deviceDrawerFp)?.short_id || ""
      );
      if (peer) copyToClipboard(peer.short_id, "device ID");
    }
  };
  $("#dev-fp").onclick = () => {
    if (state.deviceDrawerFp) {
      copyToClipboard(state.deviceDrawerFp, "fingerprint");
    }
  };
  $("#dev-unpair").onclick = async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    if (!confirm(
      "Unpair this device? You'll need to re-verify before chatting again."
    )) return;
    try {
      await setTrust(fp, "pending");
      closeDeviceDrawer();
      toast("Device unpaired", "info");
    } catch (e) {
      toast(`Unpair didn't work: ${e.message || e}`, "bad");
    }
  };
  $("#dev-block").onclick = async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    if (!confirm(
      "Block this device? Outgoing sends will be refused; incoming will be dropped."
    )) return;
    try {
      await setTrust(fp, "rejected");
      closeDeviceDrawer();
      toast("Device blocked", "info");
    } catch (e) {
      toast(`Block didn't work: ${e.message || e}`, "bad");
    }
  };

  // v0.11.5 per-chat tools - peer scope.
  $("#dev-clear-history")?.addEventListener("click", async () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    if (!confirm(
      "Clear local chat history with this device?\n\n" +
      "Only YOUR copy is deleted. The peer keeps their messages."
    )) return;
    try {
      const r = await api.del(`/api/peers/${fp}/history`);
      toast(`Cleared ${r.deleted || 0} message${r.deleted === 1 ? "" : "s"}`, "good");
      // Reload current view if we're looking at this peer.
      if (state.selectedPeer) {
        const peer = state.peers.get(state.selectedPeer);
        if (peer && peer.fingerprint === fp) {
          await loadHistory();
        }
      }
    } catch (e) {
      toast(`Clear didn't work: ${errorToastBody(e)}`, "bad");
    }
  });
  $("#dev-export-md")?.addEventListener("click", () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    _downloadConvoExport(`/api/peers/${fp}/export?format=md`);
  });
  $("#dev-export-json")?.addEventListener("click", () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    _downloadConvoExport(`/api/peers/${fp}/export?format=json`);
  });
  $("#dev-media-gallery")?.addEventListener("click", () => {
    const fp = state.deviceDrawerFp;
    if (!fp) return;
    openMediaGallery(fp);
  });

  // v0.11.5 - kick off a download via a temporary anchor. Avoids the
  // CORS / fetch-blob dance and lets the browser handle saving.
