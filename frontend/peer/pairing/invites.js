  // ── v0.20.1 — auto-pair flow (browser ↔ daemon, no manual UX) ──
  //
  // The phone visits /peer?pair=<token>&fp=<algo>:<hex>&ws=<url>.
  // The page detects the params, hides ALL the manual cards
  // (identity provisioning, rendezvous, manual signaling, SAS),
  // shows a single "Connecting…" status, and runs:
  //
  //   1. Provision identity silently (existing boot path; we just
  //      don't render the identity card).
  //   2. Resolve the active sovereignty preset's disclosed STUN set, then
  //      open RTCPeerConnection (host-only when that set is empty).
  //   3. Create a control + bulk DataChannel (so the daemon side
  //      can pin the channel labels).
  //   4. createOffer() + setLocalDescription.
  //   5. Build a signed offer envelope:
  //        {v:"OL-PEER-RTC-1", t:"offer", sdp,
  //         pubkey_b64u, fingerprint, pair_token, ts, signature}
  //      Signature = Ed25519 over canonical(envelope minus signature).
  //   6. Open WS to ws=, send envelope.
  //   7. On answer, setRemoteDescription.
  //   8. On control:open, sign the daemon's fresh, session- and
  //      channel-bound identity challenge with the enrolled browser key.
  //   9. Only after the daemon's exact acknowledgement, save the pinned
  //      daemon to OPFS and surface "Connected" / owner requests.
  //
  // Failure modes are surfaced as a single "Couldn't pair: <reason>"
  // line + a Retry button. We do NOT fall back to manual SAS — if
  // the QR pair flow fails, the user picks up their phone and
  // taps Retry; if it still fails, they regenerate the QR on their
  // laptop. Manual SAS is the advanced override path, not the
  // recovery path.

  const AUTOPAIR_DAEMON_CONTROL_LABEL = "one-link-daemon-control-v1";
  const AUTOPAIR_DAEMON_BULK_LABEL = "one-link-daemon-bulk-v1";

  // v0.20.7 (security audit M9): validate the WS URL the QR
  // wants us to connect to. Without this check, an attacker who
  // crafts (or substitutes) a QR can route a phone's signed
  // pairing offer to an attacker-controlled WS endpoint. The
  // attacker then either replays the captured offer against the
  // real daemon (consuming the single-use token) or drops the
  // offer + serves the phone an unsigned answer trying to steer
  // it onto an attacker-controlled DataChannel.
  //
  // The defense: the QR is supposed to live alongside this page
  // — both are served from the same daemon. So the WS URL's host
  // MUST equal window.location.host. We additionally restrict
  // the scheme to ws/wss so a "javascript:" or "file:" or
  // "http:" URL can't be smuggled through.
  function _isSafePairWsUrl(rawUrl) {
    try {
      const u = new URL(rawUrl);
      if (u.protocol !== "ws:" && u.protocol !== "wss:") return false;
      // host = hostname + (port if non-default). Compare ignoring
      // case + folding default ports.
      if (u.host.toLowerCase() !== window.location.host.toLowerCase()) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  function _detectPairQuery() {
    try {
      const params = new URLSearchParams(window.location.search);
      const pair = params.get("pair");
      const fp = params.get("fp");
      const ws = params.get("ws");
      if (!pair || !fp || !ws) return null;
      if (!_isSafePairWsUrl(ws)) return null;
      return { pair_token: pair, daemon_fingerprint: fp, ws_url: ws };
    } catch {
      return null;
    }
  }

  function _autopairSetState(pillKind, pillLabel, statusLine) {
    const pill = $("#autopair-pill");
    if (pill) {
      pill.classList.remove("good", "warn", "bad", "dim");
      pill.classList.add(pillKind);
      pill.textContent = pillLabel;
    }
    text($("#autopair-status"), statusLine);
  }

  function _autopairShowHost(daemonFingerprint) {
    text($("#autopair-host"), daemonFingerprint);
    show($("#autopair-host-wrap"));
  }

  // Hide every manual surface so the auto-pair UX feels like
  // "scan → connected" with nothing else on screen.
  // 2026-05-23: every top-level card on peer.html. Single source
  // of truth for the "what panels exist" list; _showOnly + the
  // hide-manual-cards helper both read from here so adding a new
  // card means updating one array.
  const _PHONE_TOP_LEVEL_CARDS = [
    "#welcome-card",
    "#autopair-card",
    "#selfmesh-enroll-card",
    "#daemon-roster-card",
    "#daemon-chat-card",
    "#phone-settings-card",
    "#identity-card",
    "#status-card",
    "#actions-card",
    "#unlock-card",
    "#rdz-card",
    "#webrtc-card",
    "#pair-card",
    "#peers-card",
    "#chat-card",
  ];

  function _autopairHideManualCards() {
    // Legacy name; matches the cards that should disappear when
    // an automated pair / chat flow takes the screen. Now backed
    // by the single _PHONE_TOP_LEVEL_CARDS list so it can't drift.
    for (const id of _PHONE_TOP_LEVEL_CARDS) {
      // Don't hide cards that the active flow JUST showed —
      // callers that need single-pane navigation should use
      // _showOnly instead. This legacy helper preserves the
      // older "hide manual surfaces" semantics for the pair
      // flow's early stages.
      if (id === "#autopair-card") continue;
      if (id === "#selfmesh-enroll-card") continue;
      hide($(id));
    }
  }

  // 2026-05-23: strict single-pane navigation. Hides every
  // top-level card then shows exactly one. Use this instead of
  // ad-hoc show()/hide() pairs to enforce "one card at a time"
  // and prevent the multi-card stack the user hit at the
  // 'JOIN MY DEVICES + YOUR CHATS + CHAT all visible' bug.
  function _showOnly(cardId) {
    if (!cardId.startsWith("#")) cardId = "#" + cardId;
    for (const id of _PHONE_TOP_LEVEL_CARDS) {
      if (id === cardId) continue;
      const el = $(id);
      if (el) el.hidden = true;
    }
    const target = $(cardId);
    if (target) target.hidden = false;
  }

  const SELF_MESH_CERT_KEY = "ol_peer.self_mesh_cert.v1"; // gitleaks:allow - storage key

  function _detectSelfMeshInviteQuery() {
    const params = new URLSearchParams(window.location.search);
    const token = (
      params.get("self_mesh_invite") ||
      params.get("selfMeshInvite") ||
      params.get("mesh") ||
      params.get("token")
    );
    if (!token) return null;
    return { token };
  }

  function _detectSetupDeviceInviteQuery() {
    const params = new URLSearchParams(window.location.search);
    const token = (
      params.get("setup_device_invite") ||
      params.get("oneSetupInvite") ||
      params.get("setupInvite")
    );
    if (!token) return null;
    return { token };
  }

  function _selfMeshEnrollSetState(pillKind, pillLabel, statusLine) {
    const pill = $("#selfmesh-enroll-pill");
    if (pill) {
      pill.classList.remove("good", "warn", "bad", "dim");
      pill.classList.add(pillKind);
      pill.textContent = pillLabel;
    }
    text($("#selfmesh-enroll-status"), statusLine);
  }

  async function _previewSelfMeshInvite(query) {
    const params = new URLSearchParams();
    params.set("token", query.token);
    if (state.rec && state.rec.public_key_b64u) {
      params.set("device_pub_b64", state.rec.public_key_b64u);
    }
    const resp = await fetch(
      `/api/v1/self-mesh/enrollment-invite/preview?${params.toString()}`,
      { cache: "no-store" },
    );
    const body = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(body.hint || body.error || `HTTP ${resp.status}`);
    }
    return body;
  }

  async function _storeSelfMeshInvite(query, preview) {
    if (!state.rec || !state.rec.public_key_b64u) {
      throw new Error("device identity is not loaded");
    }
    if (preview.device_pub_b64 !== state.rec.public_key_b64u) {
      throw new Error("this invite was minted for a different device key");
    }
    const record = {
      v: 1,
      claimed_ms: Date.now(),
      token: query.token,
      root_pub_b64: preview.root_pub_b64,
      device_pub_b64: preview.device_pub_b64,
      device_kind: preview.device_kind,
      label: preview.label || preview.device_kind || "This device",
      fingerprint: state.rec.fingerprint,
    };
    localStorage.setItem(SELF_MESH_CERT_KEY, JSON.stringify(record));
    return record;
  }

  async function _runSelfMeshInviteFlow(query) {
    _autopairHideManualCards();
    show($("#selfmesh-enroll-card"));
    _selfMeshEnrollSetState("dim", "checking", "Verifying signed invite...");
    let preview;
    try {
      preview = await _previewSelfMeshInvite(query);
    } catch (e) {
      _selfMeshEnrollSetState(
        "bad",
        "rejected",
        `Invite rejected: ${e && e.message ? e.message : e}`,
      );
      return;
    }
    text(
      $("#selfmesh-enroll-root"),
      `${preview.label || preview.device_kind} · ${preview.root_pub_b64}`,
    );
    show($("#selfmesh-enroll-details"));
    if (preview.device_pub_b64 === (state.rec && state.rec.public_key_b64u)) {
      _selfMeshEnrollSetState("good", "ready", "This invite matches this device.");
      show($("#selfmesh-enroll-actions"));
    } else {
      _selfMeshEnrollSetState(
        "warn",
        "wrong device",
        "This invite is valid, but it was minted for a different device key.",
      );
    }
    $("#btn-selfmesh-claim")?.addEventListener("click", async () => {
      try {
        const rec = await _storeSelfMeshInvite(query, preview);
        _selfMeshEnrollSetState(
          "good",
          "claimed",
          `${rec.label} is now trusted under this root identity.`,
        );
        hide($("#selfmesh-enroll-actions"));
      } catch (e) {
        _selfMeshEnrollSetState(
          "bad",
          "failed",
          `Couldn't claim invite: ${e && e.message ? e.message : e}`,
        );
      }
    }, { once: true });
  }

