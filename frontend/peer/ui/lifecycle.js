  const ADV_KEY = "ol_peer.show_advanced";
  function _setShowAdvanced(on) {
    document.documentElement.classList.toggle("show-advanced", on);
    try { localStorage.setItem(ADV_KEY, on ? "1" : "0"); } catch {}
    const btn = $("#btn-show-advanced");
    if (btn) btn.textContent = on ? "Hide advanced surfaces" : "Advanced surfaces";
  }
  try {
    if (localStorage.getItem(ADV_KEY) === "1") {
      document.documentElement.classList.add("show-advanced");
    }
  } catch {}
  $("#btn-show-advanced")?.addEventListener("click", () => {
    const on = document.documentElement.classList.contains("show-advanced");
    _setShowAdvanced(!on);
  });

  // v0.20.1 — boot dispatch. Detect pair query first so we can hide
  // the manual surfaces before the manual identity card flashes
  // visible. Run identity boot in either mode (we always need an
  // identity); the pair flow consumes it as soon as it's ready.
  const _pairQuery = _detectPairQuery();
  const _selfMeshQuery = _detectSelfMeshInviteQuery();
  const _setupDeviceInviteQuery = _detectSetupDeviceInviteQuery();

  // 2026-05-23: detect if this phone has a valid pair cert from a
  // prior session. If yes (and no pair query is active), try to
  // auto-reconnect via /api/setup/device-invite/relogin so a tab
  // reload after a daemon restart doesn't dead-end at the welcome
  // card. The cert proves authorization; a signature over the daemon's
  // one-time, device-bound proof proves current private-key possession;
  // the daemon returns a fresh pair_token + handoff and
  // _runAutoPairFlow takes it from there.
  function _hasExistingPairCert() {
    try {
      const raw = localStorage.getItem(SELF_MESH_CERT_KEY);
      if (!raw) return false;
      const parsed = JSON.parse(raw);
      return !!(parsed && parsed.cert_b64 && parsed.trusted !== false
                && !parsed.pending);
    } catch { return false; }
  }
  // 2026-05-23 (user feedback): if the page reloads with a stale
  // ?setup_device_invite=<old-token> in the URL AND we already have
  // a valid cert, prefer relogin over re-claiming an expired invite.
  // The cert is permanent; the invite token is single-use and 30-min
  // TTL — so the cert path is always the right thing once it exists.
  const _hasValidCert = _hasExistingPairCert();
  const _hasReturningPair = !_pairQuery && !_selfMeshQuery
    && (!_setupDeviceInviteQuery || _hasValidCert)
    && _hasValidCert;

  if (_pairQuery) {
    _showOnly("#autopair-card");
    _autopairSetState("dim", "starting", "Setting up your phone's identity…");
  } else if (_hasReturningPair) {
    // Cert-authed reconnect wins over a stale setup_device_invite
    // query in the URL. Otherwise a Safari reload with the
    // original pair URL still in history tries to re-claim a
    // 30-min-expired invite and dead-ends at 'invite expired or
    // not found' even though the permanent cert from the original
    // pair is sitting in localStorage. Cert path always wins
    // once it exists.
    _showOnly("#autopair-card");
    _autopairSetState(
      "dim", "restoring",
      "Restoring your live link to the laptop…",
    );
  } else if (_selfMeshQuery || _setupDeviceInviteQuery) {
    _showOnly("#selfmesh-enroll-card");
    _selfMeshEnrollSetState("dim", "starting", "Loading this device...");
  } else {
    // v0.20.3 — default landing. No pair query → show the welcome
    // card explaining how to scan a QR. Identity provisioning still
    // runs (so a future ?pair= visit is instant) but its card stays
    // hidden behind data-tier="advanced".
    _showOnly("#welcome-card");
  }

  // 2026-05-23: attempt cert-authed reconnect when the phone has
  // a valid cert from a previous pair. Async — boot fires it in
  // parallel with identity load and only runs if no fresh-pair
  // query is active.
  async function _attemptReloginWithStoredCert() {
    let cert;
    try {
      cert = JSON.parse(localStorage.getItem(SELF_MESH_CERT_KEY) || "null");
    } catch { return null; }
    if (!cert || !cert.cert_b64) return null;
    // Need an identity to sign the daemon-selected proof.
    const rec = await _waitForIdentity(8000);
    if (!rec || !rec.private_key_jwk) {
      _autopairSetState(
        "bad", "no identity",
        "Saved pair cert found but can't load this phone's key. " +
        "Sign out and re-pair to start fresh.",
      );
      return null;
    }
    let challengeResp, challengePayload;
    try {
      challengeResp = await fetch(
        "/api/setup/device-invite/relogin/challenge",
        {
          method: "POST",
          headers: {"Content-Type": "application/json"},
          cache: "no-store",
          body: JSON.stringify({cert_b64: cert.cert_b64}),
        },
      );
      challengePayload = await challengeResp.json().catch(() => ({}));
    } catch (e) {
      _autopairSetState(
        "bad", "offline",
        `Couldn't reach the laptop: ${e && e.message ? e.message : e}. ` +
        "Check Wi-Fi and reload.",
      );
      return null;
    }
    if (!challengeResp.ok || !challengePayload.ok) {
      const hint = challengePayload.hint || challengePayload.error
        || `HTTP ${challengeResp.status}`;
      _showOnly("#welcome-card");
      const status = $("#selfmesh-enroll-status");
      if (status) {
        status.textContent =
          `Couldn't restore the previous pair: ${hint}. Scan a fresh pair QR.`;
      }
      return null;
    }
    const challengeId = challengePayload.challenge_id;
    const proofText = challengePayload.proof_b64;
    if (
      typeof challengeId !== "string" ||
      !/^[A-Za-z0-9_-]{32}$/.test(challengeId) ||
      typeof proofText !== "string" ||
      proofText.length < 128 || proofText.length > 512 ||
      !/^[A-Za-z0-9_-]+$/.test(proofText)
    ) {
      _autopairSetState(
        "bad", "bad challenge",
        "The laptop returned an invalid reconnect challenge. Reload and try again.",
      );
      return null;
    }
    let proof;
    try {
      proof = b64UrlToBytes(proofText);
    } catch {
      _autopairSetState(
        "bad", "bad challenge",
        "The laptop returned an invalid reconnect challenge. Reload and try again.",
      );
      return null;
    }
    let sig;
    try {
      sig = await _signEd25519(rec.private_key_jwk, proof);
    } catch (e) {
      _autopairSetState(
        "bad", "sign failed",
        `Couldn't sign reconnect challenge: ${e && e.message ? e.message : e}`,
      );
      return null;
    }
    let resp, payload;
    try {
      resp = await fetch("/api/setup/device-invite/relogin", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        cache: "no-store",
        body: JSON.stringify({
          cert_b64: cert.cert_b64,
          challenge_id: challengeId,
          sig_b64: bytesToB64Url(sig),
        }),
      });
      payload = await resp.json().catch(() => ({}));
    } catch (e) {
      _autopairSetState(
        "bad", "offline",
        `Couldn't reach the laptop: ${e && e.message ? e.message : e}. ` +
        "Check Wi-Fi and reload.",
      );
      return null;
    }
    if (!resp.ok || !payload.ok) {
      const hint = payload.hint || payload.error || `HTTP ${resp.status}`;
      // Common case: the daemon restarted with a fresh root, or the
      // device was revoked. Push the user to the welcome card with
      // a clear message.
      _showOnly("#welcome-card");
      const status = $("#selfmesh-enroll-status");
      if (status) {
        status.textContent =
          `Couldn't restore the previous pair: ${hint}. Scan a fresh pair QR.`;
      }
      return null;
    }
    return {
      pair_token: payload.pair_token,
      daemon_fingerprint: payload.daemon_fingerprint,
      ws_url: payload.ws_signaling_url,
    };
  }

