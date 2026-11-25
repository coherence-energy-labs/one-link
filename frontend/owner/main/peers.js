  // ── Render: peer list ──────────────────────────────────────────────
  // v0.4: sidebar is paired-only. The server filters; the UI renders
  // whatever it gets. Unpaired peers live in the discovery modal, not here.
  function _peerListHash(peers, selected) {
    // v0.7.x: stable signature of everything renderPeers reads off
    // each peer record. If this is unchanged across two refreshPeers
    // ticks, skip the DOM rebuild - the previous version was tearing
    // down + re-attaching every peer row every 5s, which the user
    // sees as a visible flicker. We coalesce latency into 80/250 ms
    // buckets so a few ms of jitter don't trigger redraws.
    const parts = [];
    parts.push(`sel=${selected || ""}`);
    // v0.21.x: my own version goes into the hash so a daemon update
    // re-renders every peer row's version-compare badge.
    parts.push(`my=${state.me?.app_version || ""}`);
    // v0.21.x: per-peer unread counts in the hash so the sidebar
    // badge appears/disappears as unread state changes.
    const uk = Object.keys(state.unreadByPeer).sort().map((k) =>
      `${k}:${state.unreadByPeer[k]}`).join(",");
    parts.push(`u=${uk}`);
    // v0.21.x: drafts in hash so the "Draft: …" line shows up
    // when a new draft is typed (and disappears on clear).
    const dk = Object.keys(state.drafts || {}).sort()
      .map((k) => `${k}:${((state.drafts || {})[k] || "").length}`).join(",");
    parts.push(`d=${dk}`);
    // v0.21.x: pin + archive state so sidebar re-renders when a
    // peer is pinned/unpinned/archived/unarchived.
    const pa = peers.map((p) =>
      `${p.short_id}:${isPeerPinned(p.short_id) ? "p" : ""}${isPeerArchived(p.short_id) ? "a" : ""}`).join(",");
    parts.push(`pa=${pa}`);
    parts.push(`ax=${state._peerArchiveExpanded ? 1 : 0}`);
    const presenceSig = peers.map((p) => `${p.short_id}:${p.presence || ""}`).join(",");
    parts.push(`presence=${presenceSig}`);
    for (const p of peers) {
      const lat = p?.health?.latency_ewma_ms;
      const latBucket = lat == null ? -1 : (lat < 80 ? 0 : lat < 250 ? 1 : 2);
      // v0.21.x channel staleness bucket — coalesces last_alive_ms
      // into "fresh / stale / unknown" so a few seconds of jitter
      // doesn't trigger redraws but a transition (fresh→stale) does.
      const la = p?.health?.last_alive_ms;
      const staleBucket = la == null || la <= 0
        ? -1
        : ((Date.now() - la) < 60_000 ? 0 : 1);
      parts.push([
        p.short_id, p.hostname || "", p.address || "", p.port || 0,
        p.online ? 1 : 0, p.trust || "", latBucket, staleBucket,
        (p.allowed_capabilities || ["*"]).join(","),
        // v0.7.7: avatar overlay flips when verification toggles.
        p.is_verified ? 1 : 0,
        // v0.7.8: red ⚠ overlay flips when unacked-event count
        // changes. Bucketed at 0 / 1 / many to coalesce repeats.
        (p.key_change_unacked || 0) === 0 ? 0 : ((p.key_change_unacked || 0) === 1 ? 1 : 2),
        // v0.10.4: presence drives the avatar dot color.
        p.presence || "",
        // v0.21.x: peer's advertised app_version drives a "matches /
        // older / newer" pill in the row sub-line. Compatibility
        // verdict drives a yellow ⚠ badge when the negotiated path
        // is degraded vs our local preferred. Both surface so the
        // "queued while online" confusion has a visible cause.
        p.app_version || "",
        (p.compatibility?.compatible === false) ? "incompat" : "",
        (p.compatibility?.mode || ""),
      ].join("|"));
    }
    return parts.join("§");
  }

  // v0.21.x: numeric-aware semver-ish compare. Accepts strings like
  // "0.21.0-alpha", "0.20.6", "1.0.0". Returns negative if a<b, 0 if
  // equal, positive if a>b. Falls back to lexical compare on parse
  // failure (still useful, and the worst case is the badge says
  // "different version" without older/newer arrow).
  function _compareAppVersion(a, b) {
    if (!a || !b) return 0;
    if (a === b) return 0;
    const partsA = String(a).split(/[-+]/, 1)[0].split(".").map(n => parseInt(n, 10));
    const partsB = String(b).split(/[-+]/, 1)[0].split(".").map(n => parseInt(n, 10));
    const len = Math.max(partsA.length, partsB.length);
    for (let i = 0; i < len; i++) {
      const x = partsA[i] || 0;
      const y = partsB[i] || 0;
      if (isNaN(x) || isNaN(y)) return a < b ? -1 : 1;
      if (x !== y) return x - y;
    }
    // numeric parts equal; compare pre-release suffix (none > any suffix)
    const sufA = String(a).split(/[-+]/).slice(1).join("-");
    const sufB = String(b).split(/[-+]/).slice(1).join("-");
    if (sufA === sufB) return 0;
    if (!sufA) return 1;
    if (!sufB) return -1;
    return sufA < sufB ? -1 : 1;
  }
  // v0.21.x: returns a small DOM badge or null when nothing useful to
  // say. Three cases worth surfacing:
  //   - peer is on an older build than us  → "On older build" + ⬇
  //   - peer is on a newer build than us  → "On newer build" + ⬆
  //   - peer never did a CAPS exchange    → null (we don't speak FUD)
  //   - peer is same version               → null (least clutter)
  // When the daemon's compatibility negotiation marks the path as
  // incompatible OR forced to a fallback transfer_mode, we also
  // surface that as a yellow ⚠ chip — this is the case that drives
  // "queued while online" symptoms.
  function renderPeerVersionBadge(peer) {
    const myVer = state.me?.app_version || null;
    const theirVer = peer?.app_version || null;
    const compat = peer?.compatibility || null;
    let chip = null;
    let kind = null;
    // Compatibility-degraded path takes priority because that's the
    // case that actually breaks sends; version-only diff is just
    // informational.
    if (compat && compat.compatible === false) {
      chip = el("span", "peer-ver-badge peer-ver-incompat", "⚠ Incompatible");
      const reasons = (compat.reasons || []).filter(Boolean).slice(0, 3).join(", ");
      chip.title = reasons
        ? `Wire-path renegotiation needed: ${reasons}. Click for details.`
        : "Wire-path renegotiation needed. Sends may queue until both sides catch up. Click for details.";
      kind = "incompat";
    } else if (compat && compat.mode === "fallback") {
      chip = el("span", "peer-ver-badge peer-ver-fallback", "⚠ Fallback path");
      chip.title = `Negotiated transfer_mode: ${compat.transfer_mode || "fallback"}. Some features may be limited. Click for details.`;
      kind = "fallback";
    } else if (myVer && theirVer) {
      const cmp = _compareAppVersion(theirVer, myVer);
      if (cmp < 0) {
        chip = el("span", "peer-ver-badge peer-ver-older", "⬇ Older build");
        chip.title = `Other device is on v${theirVer}. You're on v${myVer}. Click for how to update.`;
        kind = "older";
      } else if (cmp > 0) {
        chip = el("span", "peer-ver-badge peer-ver-newer", "⬆ Newer build");
        chip.title = `Other device is on v${theirVer}. You're on v${myVer}. Click for what to do.`;
        kind = "newer";
      }
    }
    if (!chip) return null;
    // v0.21.x: every surface a "why is this badge here" affordance.
    // Click opens a calm explainer modal with concrete next steps.
    // Buttons inside the modal route to: copy install path, open
    // dist folder, dismiss. Sender-side: no auto-push of binaries
    // (that's the next layer); this is the human-readable path.
    chip.style.cursor = "pointer";
    chip.tabIndex = 0;
    chip.setAttribute("role", "button");
    const openExplainer = (ev) => {
      ev.stopPropagation();
      ev.preventDefault();
      openVersionMismatchModal(peer, kind, { myVer, theirVer, compat });
    };
    chip.addEventListener("click", openExplainer);
    chip.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") openExplainer(ev);
    });
    return chip;
  }
  // v0.21.x: explainer modal for the peer-version badge. Lives as a
  // singleton on document.body so renderPeers can fire-and-forget.
  // Three flavors (older / newer / incompat / fallback) share one
  // shell; copy differs.
  function openVersionMismatchModal(peer, kind, ctx) {
    const peerLabel = peer?.display_name || peer?.hostname || peer?.short_id || "the other device";
    let title, lead, steps, primaryLabel, primaryAction;
    const myVer = ctx.myVer || "unknown";
    const theirVer = ctx.theirVer || "unknown";
    if (kind === "incompat") {
      title = "Secure path needs renegotiation";
      lead = `Your daemon and ${peerLabel}'s daemon disagree on the wire format right now. Sends will queue until both sides catch up.`;
      steps = [
        "Open One Link on the other device and let it run for a few seconds. The daemons re-handshake automatically.",
        "If it doesn't clear in 30 seconds, both sides probably need the same build. Update whichever side is older.",
        `Your build is v${myVer}. The other device reports v${theirVer || "unknown"}.`,
      ];
      if (Array.isArray(ctx.compat?.reasons) && ctx.compat.reasons.length) {
        steps.push(`Detected reasons: ${ctx.compat.reasons.slice(0, 3).join(", ")}`);
      }
      primaryLabel = "Got it";
      primaryAction = null;
    } else if (kind === "fallback") {
      title = "Using a fallback wire path";
      lead = `${peerLabel} can talk to you, but on a slower or older transfer mode (${ctx.compat?.transfer_mode || "legacy"}). Sends still work, but features added in your build may not be available until the other side catches up.`;
      steps = [
        `Your build is v${myVer}. The other device reports v${theirVer || "unknown"}.`,
        "Update whichever side is older to get the full feature set on both ends.",
      ];
      primaryLabel = "OK";
      primaryAction = null;
    } else if (kind === "older") {
      title = "Other device is on an older build";
      lead = `${peerLabel} is running v${theirVer}. You're running v${myVer}. Some sends may queue or fall back to a slower path until both sides match.`;
      steps = [
        "Identify the exact reviewed source commit or verified immutable release used on this device.",
        "Use that same reviewed commit on the other device. No verified public installer is currently available.",
        "On the other device: close One Link completely, replace the folder, then reopen.",
        "Both sides will re-handshake automatically. The badge clears within a few seconds.",
      ];
      primaryLabel = "Copy my version label";
      primaryAction = () => {
        const label = `One Link v${myVer}`;
        try {
          if (navigator.clipboard?.writeText) {
            navigator.clipboard.writeText(label);
            toast("Version copied. Tell the other device which build to match.", "good", 4500);
          } else {
            toast(label, "info", 6000);
          }
        } catch {
          toast(label, "info", 6000);
        }
      };
    } else { // newer
      title = "Other device is on a newer build";
      lead = `${peerLabel} is running v${theirVer}. You're running v${myVer}. Newer features they add may not be available on your side until you catch up.`;
      steps = [
        "Identify the exact reviewed source commit used by the other device.",
        "Build that commit with the frozen lock; do not trust a mutable 'latest' binary or an unauthenticated copied folder.",
        "Restart One Link only after independently verifying the replacement.",
      ];
      primaryLabel = "OK";
      primaryAction = null;
    }
    _ensureVersionMismatchModal();
    const modal = document.getElementById("version-mismatch-modal");
    modal.querySelector(".vmm-title").textContent = title;
    modal.querySelector(".vmm-lead").textContent = lead;
    const stepsHost = modal.querySelector(".vmm-steps");
    stepsHost.innerHTML = "";
    steps.forEach((s) => {
      const li = document.createElement("li");
      li.textContent = s;
      stepsHost.appendChild(li);
    });
    const primaryBtn = modal.querySelector(".vmm-primary");
    primaryBtn.textContent = primaryLabel;
    primaryBtn.onclick = (ev) => {
      ev.stopPropagation();
      if (primaryAction) primaryAction();
      else closeVersionMismatchModal();
    };
    modal.classList.add("show");
    document.body.classList.add("vmm-open");
  }
  function _ensureVersionMismatchModal() {
    let m = document.getElementById("version-mismatch-modal");
    if (m) return m;
    m = document.createElement("div");
    m.id = "version-mismatch-modal";
    m.className = "vmm-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-labelledby", "vmm-title-id");
    m.innerHTML = `
      <div class="vmm-backdrop" data-vmm-close></div>
      <div class="vmm-pane">
        <div class="vmm-head">
          <h2 class="vmm-title" id="vmm-title-id">Version mismatch</h2>
          <button class="vmm-close" data-vmm-close aria-label="Close">✕</button>
        </div>
        <p class="vmm-lead"></p>
        <ol class="vmm-steps"></ol>
        <div class="vmm-actions">
          <button class="vmm-secondary" data-vmm-close>Close</button>
          <button class="vmm-primary">OK</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
    m.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t instanceof Element && t.hasAttribute("data-vmm-close")) {
        closeVersionMismatchModal();
      }
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && m.classList.contains("show")) {
        closeVersionMismatchModal();
      }
    });
    return m;
  }
  function closeVersionMismatchModal() {
    const m = document.getElementById("version-mismatch-modal");
    if (!m) return;
    m.classList.remove("show");
    document.body.classList.remove("vmm-open");
  }

  // v0.21.x: call permission preflight. The first time a user
  // clicks 📞 / 📹 we explain WHY the browser is about to ask for
  // mic / camera. Without this, the cold prompt feels random and
  // some users deny it by reflex, which then leaves the call
  // half-set-up with no useful UI feedback. Returns true to
  // proceed with the call, false to abort silently.
  //
  // Skip conditions:
  //   - The user already saw the preflight (localStorage flag).
  //   - The browser reports the permission as "granted" already.
  // Both conditions can apply per-permission (mic-only voice calls
  // don't preflight camera).
  const CALL_PREFLIGHT_KEY = "one_link.call_preflight.v1";
  async function _callPermissionPreflight({ video, peerLabel }) {
    const needs = ["microphone"];
    if (video) needs.push("camera");
    // Fast path: every permission already granted -> proceed.
    let allGranted = true;
    if (navigator.permissions && navigator.permissions.query) {
      for (const name of needs) {
        try {
          const st = await navigator.permissions.query({ name });
          if (st.state !== "granted") { allGranted = false; break; }
        } catch {
          allGranted = false;
          break;
        }
      }
    } else {
      allGranted = false;
    }
    if (allGranted) return true;
    // Already acked the explainer in a previous call? Skip directly to the cold prompt.
    try {
      const ack = JSON.parse(localStorage.getItem(CALL_PREFLIGHT_KEY) || "{}");
      const needed = needs.every((n) => ack[n] === true);
      if (needed) return true;
    } catch {}
    // Otherwise show the preflight modal and wait for user choice.
    return await _showCallPreflightModal({ needs, peerLabel });
  }
  if (typeof window !== "undefined") {
    window._callPermissionPreflight = _callPermissionPreflight;
  }
  function _showCallPreflightModal({ needs, peerLabel }) {
    return new Promise((resolve) => {
      _ensureCallPreflightModal();
      const modal = document.getElementById("call-preflight-modal");
      const wantsCamera = needs.includes("camera");
      modal.querySelector(".cpm-title").textContent = wantsCamera
        ? "One Link needs your mic and camera"
        : "One Link needs your microphone";
      const leadLines = [];
      if (peerLabel) {
        leadLines.push(`To call ${peerLabel}, your browser is about to ask permission.`);
      } else {
        leadLines.push("Your browser is about to ask permission.");
      }
      leadLines.push(
        wantsCamera
          ? "Your mic and camera are used for this end-to-end encrypted call and are not saved by One Link unless you separately choose Save. A network relay, when needed, carries only encrypted call traffic. Captions stay off unless you enable the separate on-device control. You can revoke access any time in browser settings."
          : "Your microphone is used for this end-to-end encrypted call and is not saved by One Link unless you separately choose Save. A network relay, when needed, carries only encrypted call traffic. Captions stay off unless you enable the separate on-device control. You can revoke access any time in browser settings.",
      );
      modal.querySelector(".cpm-lead").innerHTML = leadLines
        .map((s) => `<p>${_escapeHtml(s)}</p>`)
        .join("");
      const proceedBtn = modal.querySelector(".cpm-primary");
      const cancelBtn = modal.querySelector(".cpm-secondary");
      const onProceed = () => {
        try {
          const ack = JSON.parse(localStorage.getItem(CALL_PREFLIGHT_KEY) || "{}");
          for (const n of needs) ack[n] = true;
          localStorage.setItem(CALL_PREFLIGHT_KEY, JSON.stringify(ack));
        } catch {}
        cleanup();
        resolve(true);
      };
      const onCancel = () => {
        cleanup();
        resolve(false);
      };
      const onBackdrop = (ev) => {
        const t = ev.target;
        if (t && t instanceof Element && t.hasAttribute("data-cpm-close")) {
          onCancel();
        }
      };
      const onKey = (ev) => {
        if (ev.key === "Escape") onCancel();
        if (ev.key === "Enter") onProceed();
      };
      function cleanup() {
        proceedBtn.removeEventListener("click", onProceed);
        cancelBtn.removeEventListener("click", onCancel);
        modal.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
        modal.classList.remove("show");
        document.body.classList.remove("cpm-open");
      }
      proceedBtn.addEventListener("click", onProceed);
      cancelBtn.addEventListener("click", onCancel);
      modal.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);
      modal.classList.add("show");
      document.body.classList.add("cpm-open");
      setTimeout(() => proceedBtn.focus(), 50);
    });
  }
  function _ensureCallPreflightModal() {
    if (document.getElementById("call-preflight-modal")) return;
    const m = document.createElement("div");
    m.id = "call-preflight-modal";
    m.className = "cpm-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-labelledby", "cpm-title-id");
    m.innerHTML = `
      <div class="cpm-backdrop" data-cpm-close></div>
      <div class="cpm-pane">
        <div class="cpm-head">
          <h2 class="cpm-title" id="cpm-title-id">Allow mic and camera</h2>
        </div>
        <div class="cpm-lead"></div>
        <div class="cpm-actions">
          <button type="button" class="cpm-secondary">Not now</button>
          <button type="button" class="cpm-primary">Continue</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
  }
  // 2026-05-21 audit T3-Q: global focus-trap for any modal that
  // sets ``role="dialog"`` AND ``aria-modal="true"``. Without this,
  // Tab from inside a modal lets focus escape into the underlying
  // page (which is still ``aria-hidden=false``); screen-reader users
  // and keyboard-only users lose context. Listener is installed
  // once at script load; it cheaply no-ops when no modal is visible.
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Tab") return;
    // Find the topmost visible modal. ``offsetParent !== null`` is
    // the cheap "is this element rendered" check (works for
    // ``.show`` toggles + display:none alike). We pick the LAST
    // visible match so a stacked modal traps independently.
    const dialogs = document.querySelectorAll(
      '[role="dialog"][aria-modal="true"]'
    );
    let active = null;
    for (const d of dialogs) {
      if (d.offsetParent !== null) active = d;
    }
    if (!active) return;
    // Collect focusable descendants in DOM order. Excludes
    // disabled / aria-hidden / tabindex="-1" elements.
    const focusables = active.querySelectorAll(
      'a[href], button:not([disabled]), textarea:not([disabled]),'
      + ' input:not([disabled]):not([type="hidden"]), select:not([disabled]),'
      + ' [tabindex]:not([tabindex="-1"])'
    );
    if (focusables.length === 0) {
      ev.preventDefault();
      active.focus();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const cur = document.activeElement;
    if (ev.shiftKey && cur === first) {
      ev.preventDefault();
      last.focus();
    } else if (!ev.shiftKey && cur === last) {
      ev.preventDefault();
      first.focus();
    } else if (!active.contains(cur)) {
      // Focus drifted outside the modal somehow; pull it back.
      ev.preventDefault();
      first.focus();
    }
  });

  // v0.21.x: aliases for the recovery-wizard render code which
  // calls `escapeText` / `escapeAttr` (defined in the second
  // <script> tag below). Without these, the wizard renders fail
  // silently with ReferenceError caught by .catch() wrappers,
  // leaving every track card empty. Real bug found 2026-05-25
  // by visual sweep; the wizard had been shipping non-functional.
  function escapeText(s) {
    if (s == null) return "";
    const div = document.createElement("div");
    div.textContent = String(s);
    return div.innerHTML;
  }
  function escapeAttr(s) {
    return String(s == null ? "" : s).replace(/"/g, "&quot;");
  }

  function _escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function renderPeers() {
    const list = $("#peerlist");
    const allPeers = [...state.peers.values()];
    $("#peers-count").textContent = allPeers.length;
    // v0.21.x: split into pinned / active / archived. Pinned float
    // to the top, archived collapse under an expandable header at
    // the bottom. Active is the middle bucket — everything not
    // pinned and not archived.
    const pinnedPeers = [];
    const activePeers = [];
    const archivedPeers = [];
    for (const p of allPeers) {
      if (isPeerArchived(p.short_id)) archivedPeers.push(p);
      else if (isPeerPinned(p.short_id)) pinnedPeers.push(p);
      else activePeers.push(p);
    }
    const peers = [...pinnedPeers, ...activePeers];
    // v0.7.x: skip a full DOM rebuild when nothing visible changed.
    const sig = _peerListHash(peers, state.selectedPeer);
    if (list._renderSig === sig) return;
    list._renderSig = sig;
    list.innerHTML = "";

    if (peers.length === 0 && archivedPeers.length === 0) {
      const wrap = el("div", "empty-state");
      const glyph = el("div", "glyph");
      const img = document.createElement("img");
      // Reuse the already-requested header asset instead of decoding the
      // 923px source for a 36px empty-state glyph. This is also the usual
      // LCP element on a clean install, so let the browser prioritize it.
      img.src = "/static/one-glyph-128.png";
      img.srcset = "/static/one-glyph-128.png 1x, /static/one-glyph-256.png 2x";
      img.fetchPriority = "high";
      img.alt = "";
      glyph.appendChild(img);
      wrap.appendChild(glyph);
      wrap.appendChild(el("h4", "", "It's just you"));
      wrap.appendChild(el("p", "",
        "Add a phone or another computer. Pairing takes 30 seconds."));
      // 2026-05-22 UX: surface a one-click "Connect a device" button
      // in the empty state so a brand-new user lands directly on
      // the QR + invite without having to find Settings → Setup.
      // Same target as the tray "Connect a device" menu item.
      const btn = el("a", "empty-state-link empty-state-primary");
      btn.textContent = "Connect a device →";
      btn.href = "?setup=add-device";
      btn.style.fontWeight = "600";
      btn.style.borderRadius = "12px";
      btn.style.padding = "12px 18px";
      btn.style.marginBottom = "12px";
      btn.style.textDecoration = "none";
      btn.style.display = "inline-block";
      btn.style.textAlign = "center";
      wrap.appendChild(btn);
      // v0.5.3: nudge to set up cross-network reach if no rendezvous configured.
      if (!state.rendezvousUrls || state.rendezvousUrls.length === 0) {
        const link = el("a", "empty-state-link",
          "Need to reach a device across the internet? Set up a rendezvous →");
        link.href = "#";
        link.onclick = (e) => {
          e.preventDefault();
          $("#btn-settings").click();
        };
        wrap.appendChild(link);
      }
      list.appendChild(wrap);
      return;
    }

    for (const p of peers) {
      // v0.10.4: presence class drives the avatar dot color.
      // Reported 'offline' (peer is invisible OR truly offline)
      // wins over the connection's 'online' bit so the dot
      // visually matches what the peer wants to show.
      const reported = p.presence || (p.online ? "online" : "offline");
      const cls = [
        "peer",
        p.online ? "online" : "offline",
        `presence-${reported}`,
      ].join(" ");
      const row = el("div", cls);
      row.dataset.short = p.short_id;
      if (state.selectedPeer === p.short_id) row.classList.add("active");

      // v0.7.7: a verified ✓ overlay sits on top of the avatar so a
      // glance at the sidebar tells the user which devices have been
      // SAS-confirmed in person.
      // v0.7.8: a red ⚠ overlay supersedes ✓ when the peer has any
      // unacked key-change event - a rotated key invalidates trust.
      const avWrap = el("div", "avatar-wrap");
      const av = el("div", "avatar", initials(p.display_name || p.hostname || p.short_id));
      av.style.background = peerAccentColor(p);
      avWrap.appendChild(av);
      if ((p.key_change_unacked || 0) > 0) {
        const badge = el("span", "keychange-overlay", "!");
        badge.title = `Key change detected - ${p.key_change_unacked} unacknowledged event${p.key_change_unacked === 1 ? "" : "s"}. Click for details.`;
        avWrap.appendChild(badge);
      } else if (p.is_verified) {
        const badge = el("span", "verified-overlay", "✓");
        badge.title = `Verified in person${p.verified_method ? " (" + verifyMethodLabel(p.verified_method) + ")" : ""}`;
        avWrap.appendChild(badge);
      }
      const txt = el("div", "text");
      const kind = deviceKindLabel(p);
      const nameEl = el("div", "name");
      if (kind) {
        const ic = el("span", "kind-icon", kind.icon + " ");
        ic.title = kind.label;
        nameEl.appendChild(ic);
      }
      nameEl.appendChild(document.createTextNode(p.display_name || p.hostname || "(unknown)"));
      // v0.11.3: 🔕 indicator when peer is currently muted (auto-
      // expires when muted_until_ms passes).
      if (p.muted_until_ms != null) {
        const now = Date.now();
        if (p.muted_until_ms === 0 || p.muted_until_ms > now) {
          const mi = el("span", "mute-indicator", " 🔕");
          mi.title = "Notifications muted";
          nameEl.appendChild(mi);
        }
      } else if (p.muted) {
        // Legacy boolean fallback.
        const mi = el("span", "mute-indicator", " 🔕");
        mi.title = "Notifications muted";
        nameEl.appendChild(mi);
      }
      txt.appendChild(nameEl);
      const sub = el("div", "sub");
      const lc = latencyClass(p);
      if (lc) {
        const dot = el("span", `lat-dot ${lc}`);
        dot.title = latencyTitle(p);
        sub.appendChild(dot);
      }
      sub.appendChild(document.createTextNode(reachLabel(p)));
      // v0.21.x: peer-version comparison badge. Surfaces "older" /
      // "newer" / "incompatible" / "fallback path" so the user sees
      // why a send queued even though presence says online. Returns
      // null for same-version + unknown cases (least clutter).
      const verBadge = renderPeerVersionBadge(p);
      if (verBadge) {
        sub.appendChild(document.createTextNode(" "));
        sub.appendChild(verBadge);
      }
      txt.appendChild(sub);
      // v0.21.x: drafts indicator in sidebar row. When there's a
      // saved draft for this peer (and we're not currently editing
      // it), show "Draft: …" so the user remembers there's something
      // half-finished waiting.
      const draftKey = `peer:${p.short_id}`;
      const draftText = (state.drafts || {})[draftKey];
      if (draftText && p.short_id !== state.selectedPeer) {
        const preview = String(draftText).replace(/\s+/g, " ").slice(0, 40);
        const draftLine = el("div", "sub draft-line",
          `Draft: ${preview}${draftText.length > 40 ? "…" : ""}`);
        txt.appendChild(draftLine);
      }

      row.title = `${p.display_name || p.hostname || p.short_id} - ${reachLabel(p)}`;
      // v0.21.x: per-peer unread badge. Lives on the row so the user
      // sees WHICH conversation has waiting messages without opening
      // every one. Cap display at "99+".
      // WHAT THE COUNT IS ALLOWED TO SAY is proven; the count itself is this tab's.
      // Five laws at scope `exact` (idem/scripts/emit_certified_views.py): a count of zero or
      // less never draws a badge, the badge never shows a negative number, it never shows more
      // than the pill can fit, the overflow marker means the count really overflowed, and a
      // count that fits is shown exactly.
      //
      // The old code did `ucount > 99 ? "99+" : String(ucount)` -- correct, and re-decided in
      // JS every render. `unreadBadgeOf` asks the table instead, and falls back to the same
      // arithmetic when the surface is unavailable.
      const ucount = state.unreadByPeer[p.short_id] || 0;
      const ub = unreadBadgeOf(p, ucount);
      if (ub.show && p.short_id !== state.selectedPeer) {
        const badge = el("span", "peer-unread-badge", ub.text);
        badge.title = `${ucount} unread`;
        badge.setAttribute("data-proven", ub.proven ? "yes" : "unavailable");
        row.appendChild(badge);
      }
      row.appendChild(avWrap);
      row.appendChild(txt);

      // v0.7.3: gear opens the per-device drawer for THIS peer.
      // Only render for paired (pinned/rejected) peers; unpaired
      // peers are managed via the discovery / pair flow instead.
      if (p.fingerprint && p.trust !== "pending") {
        // Living Presence Tier α - Call buttons. May 15 2026: split
        // the single 📞 button into TWO buttons so the user can pick
        // audio-only OR video at call time. The icons read like
        // standard phone-app affordances: phone glyph = voice, video-
        // camera glyph = video. Hover colors differ (green/blue) so
        // a quick visual scan distinguishes them at a glance. Each
        // honors its own capability (voice_call / video_call) - a
        // peer who's only been granted Voice has the video button
        // hidden.
        if (p.trust === "pinned") {
          const peerLabel = p.display_name || p.hostname || p.short_id;
          const voiceAllowed = peerCapabilityAllowed(p, "voice_call");
          const videoAllowed = peerCapabilityAllowed(p, "video_call");

          if (voiceAllowed) {
            const voiceBtn = el("button", "call-btn-voice", "📞");
            voiceBtn.title = `Voice call ${peerLabel}`;
            voiceBtn.setAttribute("aria-label", `Voice call ${peerLabel}`);
            voiceBtn.onclick = (ev) => {
              ev.stopPropagation();
              if (typeof window.startLivingPresenceCall === "function") {
                window.startLivingPresenceCall(
                  p.fingerprint, peerLabel, { video: false },
                );
              }
            };
            row.appendChild(voiceBtn);
          }
          if (videoAllowed) {
            const videoBtn = el("button", "call-btn-video", "📹");
            videoBtn.title = `Video call ${peerLabel}`;
            videoBtn.setAttribute("aria-label", `Video call ${peerLabel}`);
            videoBtn.onclick = (ev) => {
              ev.stopPropagation();
              if (typeof window.startLivingPresenceCall === "function") {
                window.startLivingPresenceCall(
                  p.fingerprint, peerLabel, { video: true },
                );
              }
            };
            row.appendChild(videoBtn);
          }
        }
        const gear = el("button", "gear-btn", "⚙");
        gear.title = `${p.display_name || p.hostname || p.short_id} settings`;
        gear.onclick = (ev) => {
          ev.stopPropagation();
          openDeviceDrawer(p.short_id);
        };
        row.appendChild(gear);
      }

      row.onclick = () => selectPeer(p.short_id);
      // v0.21.x: right-click context menu for pin / archive.
      row.oncontextmenu = (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        _openPeerContextMenu(ev.clientX, ev.clientY, p);
      };
      list.appendChild(row);
    }

    // Auto-select if there's exactly one paired peer and nothing currently selected.
    // v0.10.8 bug fix: must also check selectedGroup - otherwise the
    // 5s refreshPeers tick would silently snap back to the lone peer
    // a few seconds after the user clicks a group, since selectGroup
    // sets selectedPeer = null. Symptom was: "chat changes for a few
    // seconds then goes back to the chat I was on".
    if (peers.length === 1 && !state.selectedPeer && !state.selectedGroup) {
      selectPeer(peers[0].short_id);
    }
    // v0.21.x: archived peers section at the bottom of the peer
    // list. Matches the group archive pattern.
    if (archivedPeers.length > 0) {
      const expanded = state._peerArchiveExpanded === true;
      const header = el("div", "archived-header");
      header.textContent = `${expanded ? "▾" : "▸"} Archived (${archivedPeers.length})`;
      header.onclick = () => {
        state._peerArchiveExpanded = !state._peerArchiveExpanded;
        list._renderSig = null;
        renderPeers();
      };
      list.appendChild(header);
      if (expanded) {
        for (const p of archivedPeers) {
          list.appendChild(_renderPeerRowArchived(p));
        }
      }
    }
  }
  // v0.21.x: minimal row for archived peers. Click to unarchive.
  function _renderPeerRowArchived(p) {
    const row = el("div", `peer archived ${p.online ? "online" : "offline"}`);
    row.dataset.short = p.short_id;
    const avWrap = el("div", "avatar-wrap");
    const av = el("div", "avatar", initials(p.display_name || p.hostname || p.short_id));
    av.style.background = peerAccentColor(p);
    avWrap.appendChild(av);
    const txt = el("div", "text");
    txt.appendChild(el("div", "name", p.display_name || p.hostname || "(unknown)"));
    txt.appendChild(el("div", "sub", "Archived · click to unarchive"));
    row.appendChild(avWrap);
    row.appendChild(txt);
    row.onclick = () => {
      setPeerArchived(p.short_id, false);
      toast("Brought back from the archive.", "good", 3000);
    };
    return row;
  }

