  const LAST_SELECTION_KEY = "one_link.last_selection.v1";
  function _saveLastSelection(scope, id) {
    try {
      if (!scope || !id) {
        localStorage.removeItem(LAST_SELECTION_KEY);
        return;
      }
      localStorage.setItem(
        LAST_SELECTION_KEY,
        JSON.stringify({ scope, id, ts: Date.now() }),
      );
    } catch {}
  }
  function _readLastSelection() {
    try {
      const raw = localStorage.getItem(LAST_SELECTION_KEY);
      if (!raw) return null;
      const j = JSON.parse(raw);
      if (!j || typeof j !== "object") return null;
      if (j.scope !== "peer" && j.scope !== "group") return null;
      if (typeof j.id !== "string" || !j.id) return null;
      return { scope: j.scope, id: j.id, ts: j.ts || 0 };
    } catch {
      return null;
    }
  }
  // v0.14.1: restore the last-selected conversation on boot. Called
  // from init() after refreshPeers + refreshGroups have populated
  // state. If the previous selection target is gone (peer
  // unpaired, group disbanded), we silently no-op.
  function _restoreLastSelection() {
    const last = _readLastSelection();
    if (!last) return;
    if (last.scope === "peer") {
      // Look up by short_id (the persisted shape) AND tolerate the
      // case where peers refreshed under a different id (rare but
      // possible after a peer's hostname changes).
      if (state.peers.has(last.id)) {
        try { selectPeer(last.id); } catch (e) {
          console.warn("restore peer failed:", e);
        }
      }
    } else if (last.scope === "group") {
      if (state.groups.has(last.id)) {
        try { selectGroup(last.id); } catch (e) {
          console.warn("restore group failed:", e);
        }
      }
    }
  }

  function selectPeer(shortId) {
    saveActiveDraft();
    // v0.10.1: switching conversations exits multi-select so IDs
    // from the old chat don't bleed into the new one.
    if (state.selecting) exitSelection();
    // v0.14.0 mobile: tapping a peer auto-closes the drawer.
    closeMobileSidebar();
    // v0.21.1: switching peers resets the new-message pill state
    // - a stale "↓ 3 new" badge from the previous conversation
    // would mislead the user about the new one.
    _hideNewMessagePill();
    _lastRenderedLen = 0;
    _forceMessagesBottomNowAndAfter();
    // v0.14.0 prefetch: record this switch in the Markov chain
    // and pre-warm the predicted next peer in idle time.
    _recordSwitch(shortId);
    _maybePrefetchNext(shortId);
    // v0.14.1 persist for boot-time restore.
    _saveLastSelection("peer", shortId);
    state.selectedPeer = shortId;
    state.selectedGroup = null;
    state.groupDetail = null;
    state.groupMessages = [];
    // v0.21.x: opening a peer is "I've read everything queued there",
    // so the per-peer badge clears and the tab title + OS badge
    // recompute. Reading a group does the same in selectGroup below.
    clearUnread(shortId);
    const peer = state.peers.get(shortId);
    if (!peer) {
      $("#convo-empty").style.display = "grid";
      $("#convo-active").style.display = "none";
      clearReplyTo();
      return;
    }
    $("#convo-empty").style.display = "none";
    $("#convo-active").style.display = "flex";
    $("#convo-who").classList.remove("group-context");
    $("#convo-who").title = "Open device settings";
    $("#btn-group-settings").style.display = "none";
    $("#btn-attach").style.display = "";
    // v0.11.5 - apply this peer's wallpaper accent.
    applyActiveChatWallpaper();
    if (state.replyTo?.group_id) clearReplyTo();
    $("#convo-name").textContent = peer.display_name || peer.hostname || "(unknown)";
    // v0.10.2: surface disappearing-message badge in the conversation
    // header so the user always knows messages here have a TTL.
    const ttlHost = $("#convo-trust");
    if (ttlHost && peer.dm_ttl_ms) {
      const dmPill = el("span", "dm-ttl-pill", `TTL ${_humanTtl(peer.dm_ttl_ms)}`);
      dmPill.title = `Messages disappear after ${_humanTtl(peer.dm_ttl_ms)}`;
      // ttlHost may already contain the verified-pill; append.
      ttlHost.appendChild(dmPill);
    }
    const subEl = $("#convo-sub");
    subEl.innerHTML = "";
    subEl.classList.remove("copyable");
    subEl.title = "";
    subEl.onclick = null;
    if (peer.trust === "rejected") {
      subEl.appendChild(document.createTextNode("Device chat - blocked"));
    } else {
      subEl.appendChild(document.createTextNode("Device chat - "));
      const lc = latencyClass(peer);
      if (lc) {
        const dot = el("span", `lat-dot ${lc}`);
        dot.title = latencyTitle(peer);
        subEl.appendChild(dot);
      }
      subEl.appendChild(document.createTextNode(reachLabel(peer)));
      const ms = peer.health?.latency_ewma_ms;
      if (ms != null) {
        subEl.appendChild(document.createTextNode(` - ${Math.round(ms)} ms`));
      }
      // v0.21.x: peer-version comparison in the convo header. Same
      // semantics as the sidebar badge — only surfaces when there's
      // something the user should know (older / newer / incompat /
      // fallback). Lives here too so during an active chat the
      // version-mismatch reason for queued sends is visible without
      // hunting in the sidebar.
      const verBadge = renderPeerVersionBadge(peer);
      if (verBadge) {
        subEl.appendChild(document.createTextNode(" "));
        subEl.appendChild(verBadge);
      }
    }
    $("#btn-unblock").style.display = peer.trust === "rejected" && peer.fingerprint ? "inline-block" : "none";
    $("#btn-attach").disabled = peer.trust === "rejected";
    $("#btn-attach2").disabled = peer.trust === "rejected";
    renderConvHeaderTrust(peer);
    renderConvKeyChangeBanner(peer);
    renderPeers();
    renderMessages();
    renderPins();
    restoreDraft();
    renderPeerControls();
    $("#input").focus();
    $("#drop-peer").textContent = peer.hostname || peer.short_id;
    // v0.7.6: opening the conversation marks all of this peer's
    // messages as read. Best-effort - don't block on the network.
    maybeSendReadMarker(peer);
  }

  // v0.7.8: pretty severity label.
  function severityLabel(sev) {
    if (sev === "high") return "high - was a paired device";
    if (sev === "medium") return "medium - known peer";
    if (sev === "low") return "low - never paired";
    return sev || "unknown";
  }
  function severityClass(sev) {
    return `severity-tag severity-${sev || "low"}`;
  }
  function shortFp(fp) {
    if (!fp) return "-";
    return fp.length > 16 ? `${fp.slice(0, 8)}…${fp.slice(-8)}` : fp;
  }

  // v0.7.8: render the prominent red banner under the conversation
  // header when the selected peer has 1+ unacked key-change events.
  // Hidden if zero. The banner is conversation-scoped - moving to
  // a different peer reruns this with that peer's events.
  function renderConvKeyChangeBanner(peer) {
    const banner = $("#convo-keychange");
    if (!banner) return;
    banner.style.display = "none";
    banner.innerHTML = "";
    const ev = peer?.key_change_alert;
    if (!ev) return;
    const count = peer.key_change_unacked || 1;
    banner.style.display = "flex";
    const icon = el("span", "kcb-icon", "⚠");
    const text = el("div", "kcb-text");
    const sev = el("span", severityClass(ev.severity), (ev.severity || "low").toUpperCase());
    text.appendChild(sev);
    const strong = el("strong", null, "Key change detected");
    text.appendChild(strong);
    const detail = document.createTextNode(
      ` - "${ev.hostname}" is now advertising a different identity key. ` +
      (count > 1 ? `${count} events unacknowledged. ` : "") +
      "Re-pair only after confirming the new identity through a side channel."
    );
    text.appendChild(detail);
    const actions = el("div", "kcb-actions");
    const details = el("button", "btn-details", "Details");
    details.onclick = (e) => {
      e.stopPropagation();
      openDeviceDrawer(peer.short_id);
    };
    const ack = el("button", "btn-ack", "Acknowledge");
    ack.onclick = async (e) => {
      e.stopPropagation();
      await ackPeerKeyChange(peer.fingerprint);
    };
    actions.appendChild(details);
    actions.appendChild(ack);
    banner.appendChild(icon);
    banner.appendChild(text);
    banner.appendChild(actions);
  }

  async function ackPeerKeyChange(fp) {
    if (!fp) return;
    try {
      await api.post(`/api/peers/${fp}/key-change-events/ack-all`, {});
      // Optimistic clear so the UI doesn't lag the click.
      const peer = [...state.peers.values()].find(p => p.fingerprint === fp);
      if (peer) {
        peer.key_change_unacked = 0;
        peer.key_change_alert = null;
        renderPeers();
        if (state.selectedPeer === peer.short_id) {
          renderConvKeyChangeBanner(peer);
          renderConvHeaderTrust(peer);
        }
        if (state.deviceDrawerFp === fp) {
          renderDrawerKeyChange(peer);
        }
      }
      toast("Key-change events acknowledged", "good");
    } catch (e) {
      toast(`Acknowledge didn't work: ${errorToastBody(e)}`, "bad");
    }
  }

  // v0.7.8: render drawer's key-change section. Calls the server
  // `?peer=` endpoint to enumerate every event for this fingerprint
  // (full audit trail, not just the freshest like the header banner).
  async function renderDrawerKeyChange(peer) {
    const section = $("#dev-keychange-section");
    if (!section) return;
    if (!peer || !peer.fingerprint) {
      section.style.display = "none";
      return;
    }
    if (!peer.key_change_unacked) {
      section.style.display = "none";
      return;
    }
    section.style.display = "";
    let events = [];
    try {
      const res = await api.get(
        `/api/key-change-events?peer=${encodeURIComponent(peer.fingerprint)}&unacked=1&limit=50`
      );
      events = res.events || [];
    } catch (e) {
      $("#dev-keychange-events").innerHTML = "";
      $("#dev-keychange-summary").textContent =
        `Couldn\'t load events: ${e.message || e}`;
      return;
    }
    if (state.deviceDrawerFp !== peer.fingerprint) return;
    $("#dev-keychange-summary").textContent =
      `${events.length} unacknowledged event${events.length === 1 ? "" : "s"} for "${peer.hostname || peer.short_id}".`;
    const list = $("#dev-keychange-events");
    list.innerHTML = "";
    for (const ev of events) {
      const card = el("div", "key-event");
      const sev = el("span", severityClass(ev.severity), (ev.severity || "low").toUpperCase());
      card.appendChild(sev);
      card.appendChild(document.createTextNode(
        ` ${new Date(ev.ts_ms).toLocaleString()} · severity ${severityLabel(ev.severity)}`
      ));
      card.appendChild(el("br"));
      card.appendChild(document.createTextNode("Old fingerprint: "));
      card.appendChild(el("span", "fp", shortFp(ev.old_fingerprint)));
      card.appendChild(el("br"));
      card.appendChild(document.createTextNode("New fingerprint: "));
      card.appendChild(el("span", "fp", shortFp(ev.new_fingerprint)));
      list.appendChild(card);
    }
  }

  // v0.7.7: render the trust marker in the conversation header.
  // Three states:
  //   1. peer.is_verified           → green ✓ "Verified" pill
  //   2. peer paired but unverified → yellow "Verify in person" CTA
  //   3. peer rejected/pending      → nothing (other UI surfaces handle it)
  // The CTA's onclick opens the device drawer scrolled to the
  // verification section, so the user lands one click from the
  // confirm button.
  // The glyph id the proven renderer emits for VERIFIED. Nothing else may ever be 7 --
  // that is the theorem, discharged over every integer input at build time.
  const GLYPH_VERIFIED = 7;

  // 2026-08-06: WHO DECIDES the badge is now the proven table, not this function.
  //
  // `peer.certified_row` is stamped by /api/peers from a renderer whose laws were discharged
  // over EVERY integer input by the Coherence prover (see one_link/certified_surface.py). The
  // pixels are unchanged -- the server maps VERIFIED from `is_verified`, so glyph===7 exactly
  // when the pill used to show. What changed is the AUTHORITY: the badge is now the output of
  // a proven function rather than a conditional a reviewer has to notice is correct.
  //
  // Falls back to `is_verified` when the surface is unavailable (older daemon, artifact absent).
  // The fallback is the ordinary unproven path, so it must never be silent about which one ran
  // -- `data-proven` records it, and the test suite asserts on that attribute.
  function verifiedByProof(peer) {
    const row = peer && peer.certified_row;
    if (!row || typeof row.glyph !== "number") return null;   // no proven answer available
    return row.glyph === GLYPH_VERIFIED;
  }

  // The accessible text comes from the SAME proven renderer as the badge. A theorem
  // (`the-spoken-label-cannot-contradict-the-pixel`, discharged over every integer input)
  // says these cannot disagree -- so a screen reader and a sighted user are told the same
  // thing, and it is not maintained by anyone remembering to update an aria-label.
  // The proven unread badge. `certified_unread` is stamped by /api/peers from a renderer whose
  // five laws are discharged over every integer input. The fallback repeats the old arithmetic
  // and marks itself, because a fallback nobody can see is how the unproven path returns.
  function unreadBadgeOf(peer, count) {
    const c = peer && peer.certified_unread;
    if (c && typeof c.show === "number") {
      return {
        show: c.show === 1,
        text: c.overflow === 1 ? `${c.shown}+` : String(c.shown),
        proven: true,
      };
    }
    return { show: count > 0, text: count > 99 ? "99+" : String(count), proven: false };
  }

  function spokenByProof(peer) {
    const row = peer && peer.certified_row;
    return (row && typeof row.spoken === "string" && row.spoken) ? row.spoken : null;
  }

  function renderConvHeaderTrust(peer) {
    const host = $("#convo-trust");
    if (!host) return;
    host.innerHTML = "";
    if (!peer || peer.trust !== "pinned") return;
    const proven = verifiedByProof(peer);
    host.setAttribute("data-proven", proven === null ? "unavailable" : "yes");
    if (proven === null ? !!peer.is_verified : proven) {
      const pill = el("span", "verified-pill", "Verified");
      const label = peer.verified_method
        ? `Verified in person · ${verifyMethodLabel(peer.verified_method)}`
        : "Verified in person";
      // aria-label from the proof, not from a string built beside the badge.
      const spoken = spokenByProof(peer);
      if (spoken) pill.setAttribute("aria-label", spoken);
      const base = peer.verified_note ? `${label} - ${peer.verified_note}` : label;
      // Show WHICH proven table drew this, so a screenshot can be matched to an artifact.
      pill.title = proven === null
        ? base
        : `${base}\nDrawn by a proven renderer · table ${peer.certified_row.digest}`;
      host.appendChild(pill);
    } else {
      const cta = el("span", "verify-cta", "Verify in person");
      cta.title = "Confirm this device's SAS through a side channel (face-to-face, phone) to surface a green checkmark.";
      cta.onclick = (ev) => {
        ev.stopPropagation();
        openDeviceDrawer(peer.short_id);
      };
      host.appendChild(cta);
    }
  }

  // Render the ephemeral typing banner for the active direct or group
  // conversation. Expired entries are pruned in-place so long-running tabs
  // do not retain peer or former-member composition metadata.
  function renderTypingBanner() {
    const banner = $("#convo-typing");
    if (!banner) return;
    const now = Date.now();
    const nameEl = $("#convo-typing-name");
    const verbEl = $("#convo-typing-verb");

    // Prune every conversation, not only the selected one. A tab can remain
    // open for days while the user switches chats; expired composition
    // metadata must not accumulate invisibly in the background.
    for (const [fp, exp] of Object.entries(state.peerTyping || {})) {
      if (!Number.isSafeInteger(exp) || now >= exp) delete state.peerTyping[fp];
    }
    for (const [gid, entries] of Object.entries(state.groupTyping || {})) {
      for (const [fp, exp] of Object.entries(entries || {})) {
        if (!Number.isSafeInteger(exp) || now >= exp) delete entries[fp];
      }
      if (Object.keys(entries || {}).length === 0) delete state.groupTyping[gid];
    }

    if (state.selectedPeer) {
      const peer = state.peers.get(state.selectedPeer);
      if (!peer?.fingerprint) {
        banner.style.display = "none";
        return;
      }
      const exp = state.peerTyping?.[peer.fingerprint] || 0;
      if (!exp || now >= exp) {
        if (state.peerTyping) delete state.peerTyping[peer.fingerprint];
        banner.style.display = "none";
        return;
      }
      if (nameEl) {
        nameEl.textContent = peer.display_name || peer.hostname || "Peer";
      }
      if (verbEl) verbEl.textContent = "is typing...";
      banner.style.display = "flex";
      return;
    }

    if (state.selectedGroup) {
      const groupEntries = state.groupTyping?.[state.selectedGroup] || {};
      const active = [];
      for (const [fp, exp] of Object.entries(groupEntries)) {
        if (!exp || now >= exp) delete groupEntries[fp];
        else active.push(fp);
      }
      if (Object.keys(groupEntries).length === 0 && state.groupTyping) {
        delete state.groupTyping[state.selectedGroup];
      }
      if (active.length === 0) {
        banner.style.display = "none";
        return;
      }
      const members = new Map(
        (state.groupDetail?.members || []).map(member => [member.fingerprint, member]),
      );
      const labels = active.map((fp) => {
        const member = members.get(fp);
        if (member) return memberLabel(member);
        const peer = [...state.peers.values()].find(p => p.fingerprint === fp);
        return peer?.display_name || peer?.hostname || fp.slice(0, 8);
      }).sort((a, b) => a.localeCompare(b));
      let label;
      if (labels.length === 1) label = labels[0];
      else if (labels.length === 2) label = `${labels[0]} and ${labels[1]}`;
      else label = `${labels[0]}, ${labels[1]}, and ${labels.length - 2} others`;
      if (nameEl) nameEl.textContent = label;
      if (verbEl) verbEl.textContent = labels.length === 1
        ? "is typing..." : "are typing...";
      banner.style.display = "flex";
      return;
    }

    banner.style.display = "none";
  }
  // 500ms tick to auto-hide expired banners. Cheap; only does
  // anything when state.peerTyping is non-empty.
  setInterval(renderTypingBanner, 500);

  function maybeSendReadMarker(peer) {
    if (!peer || !peer.fingerprint || peer.trust !== "pinned") return;
    // Highest ts among inbound messages from this peer.
    let highestTs = 0;
    for (const m of state.messages) {
      if (m.peer === peer.short_id && m.dir === "in" && m.ts > highestTs) {
        highestTs = m.ts;
      }
    }
    if (highestTs <= 0) return;
    const already = state.sentReadUpTo[peer.fingerprint] || 0;
    if (highestTs <= already) return;
    state.sentReadUpTo[peer.fingerprint] = highestTs;
    api.post(
      `/api/peers/${peer.fingerprint}/read`,
      { up_to_ts_ms: highestTs },
    ).catch(() => { /* best-effort; never bother user */ });
  }

  function renderPeerControls() {
    // v0.7.3: per-device permission toggles moved out of the chat
    // header AND out of the global Settings modal. They now live in
    // the Device drawer (gear next to each peer row, or click the
    // device card in the conversation header). This function is
    // kept as a no-op so legacy call sites don't need to change.
  }

  // v0.7.3: per-device drawer.
  state.deviceDrawerFp = null;
  state.deviceDrawerPending = null;  // pending unsaved changes
  state.deviceDrawerSas = null;      // v0.7.9: cached SAS for speak / art

  function _humanRelMs(ms) {
    if (!ms) return "-";
    const d = Date.now() - ms;
    if (d < 0) return "just now";
    const m = Math.floor(d / 60000);
    if (m < 1) return "just now";
    if (m < 60) return `${m} min ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h} h ago`;
    const days = Math.floor(h / 24);
    return `${days} d ago`;
  }

  function _peerFromShort(shortId) {
    return state.peers.get(shortId) || null;
  }

