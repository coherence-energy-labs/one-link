  async function _runSetupDeviceInviteFlow(query) {
    _showOnly("#selfmesh-enroll-card");
    // 2026-05-23: actions row hosts the "Claim this device" button
    // for the OLDER self_mesh_invite flow. This setup_device_invite
    // flow never asks the user to click anything — claim is
    // automatic and the independently verified trust phrase shows up. Force-hide so a stale
    // shown state from any prior path can't bleed through.
    hide($("#selfmesh-enroll-actions"));
    _selfMeshEnrollSetState("dim", "checking", "Preparing this device...");
    const rec = await _waitForIdentity(8000);
    if (!rec || !rec.public_key_b64u) {
      hide($("#selfmesh-enroll-actions"));
      _selfMeshEnrollSetState(
        "bad",
        state.boot_error_msg ? "boot failed" : "no identity",
        state.boot_error_msg
          ? `Identity boot failed: ${state.boot_error_msg}`
          : "This browser could not create a device identity.",
      );
      return;
    }
    try {
      const resp = await fetch("/api/setup/device-invite/claim", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: query.token,
          device_pub_b64: rec.public_key_b64u,
          label: rec.label || "Phone browser",
          device_kind: "browser-peer",
        }),
      });
      const body = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(body.hint || body.error || `HTTP ${resp.status}`);
      const verifiedSas = await _validateSetupClaim(query, rec, body);
      const record = {
        v: 3,
        claimed_ms: Date.now(),
        root_pub_b64: body.root_pub_b64,
        device_pub_b64: body.device_pub_b64,
        cert_b64: body.cert_b64 || "",
        device_kind: body.device_kind,
        label: body.label || "This device",
        fingerprint: rec.fingerprint,
        pending: !!body.pending,
        trust_phrase: verifiedSas.phrase,
        trust_words: verifiedSas.words,
        sas_version: SETUP_SAS_VERSION,
        compatibility_code: body.compatibility_code || "",
      };
      localStorage.setItem(SELF_MESH_CERT_KEY, JSON.stringify(record));
      text(
        $("#selfmesh-enroll-root"),
        `${record.label} · ${record.root_pub_b64}`,
      );
      show($("#selfmesh-enroll-details"));
      hide($("#selfmesh-enroll-actions"));
      _selfMeshEnrollSetState(
        "good",
        body.pending ? "check words" : "trusted",
        body.pending
          ? `Check all five words on the other device: ${verifiedSas.phrase}`
          : `${record.label} is now part of your One identity.`,
      );
      // 2026-05-23: when the daemon returns pending=true, the
        // operator still has to tap "Words match" on the desktop.
      // The phone has no WebSocket back to the daemon, so we
      // poll /api/setup/device-invite/status until the operator
      // acts (or the invite expires). Without this poll the
        // phone sits forever on "check words" even after the
      // desktop confirms.
      if (body.pending) {
        _pollSetupDeviceInviteStatus(query.token, record);
      }
    } catch (e) {
      // 2026-05-23: hide actions on failure too — prior shown
      // state could otherwise leave a button that calls into the
      // wrong flow's handler and silently no-ops on click.
      hide($("#selfmesh-enroll-actions"));
      _selfMeshEnrollSetState(
        "bad",
        "failed",
        `Couldn't add this device: ${e && e.message ? e.message : e}`,
      );
    }
  }

  // 2026-05-23: poll /api/setup/device-invite/status until the
  // operator confirms or rejects, the invite expires, or we hit
  // the overall deadline. 1.5s cadence matches the desktop
  // refresh poll. We use _waitForIdentity-style backoff via
  // setTimeout (not setInterval) so a slow response doesn't
  // stack overlapping polls.
  async function _pollSetupDeviceInviteStatus(token, baseRecord) {
    const POLL_MS = 1500;
    const DEADLINE_MS = Date.now() + 10 * 60 * 1000; // 10 min hard cap
    while (Date.now() < DEADLINE_MS) {
      await new Promise((r) => setTimeout(r, POLL_MS));
      let payload;
      try {
        const resp = await fetch(
          `/api/setup/device-invite/status?token=${encodeURIComponent(token)}`,
          { method: "GET", headers: { "Accept": "application/json" } },
        );
        payload = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          // 429 = slow down; anything else = keep trying. Don't
          // give up on a single transient network blip.
          continue;
        }
      } catch (_e) {
        // Network blip — keep polling until the deadline.
        continue;
      }
      const status = payload && payload.status;
      if (status === "confirmed") {
        const merged = {
          ...baseRecord,
          pending: false,
          cert_b64: payload.cert_b64 || baseRecord.cert_b64 || "",
          device_pub_b64: payload.device_pub_b64 || baseRecord.device_pub_b64,
          root_pub_b64: payload.root_pub_b64 || baseRecord.root_pub_b64,
          label: payload.label || baseRecord.label,
          device_kind: payload.device_kind || baseRecord.device_kind,
          trusted: payload.trusted !== false,
          trust_phrase: "",
          trust_words: [],
          compatibility_code: "",
        };
        localStorage.setItem(SELF_MESH_CERT_KEY, JSON.stringify(merged));
        text(
          $("#selfmesh-enroll-root"),
          `${merged.label} · ${merged.root_pub_b64}`,
        );
        // 2026-05-23: aggressively hide the wrong-flow button on
        // success — Safari cache + browser back-button can leave
        // stale DOM state otherwise.
        hide($("#selfmesh-enroll-actions"));
        _selfMeshEnrollSetState(
          "good",
          "trusted",
          `${merged.label} is part of your One identity. Opening live link…`,
        );
        // 2026-05-23: bridge into the autopair WebRTC bootstrap
        // so the phone gets a live control DataChannel + roster
        // load. The /confirm handler returned pair_token +
        // daemon_fingerprint + ws_signaling_url in device_row;
        // build the pair object _runAutoPairFlow expects and
        // hand off. Without this the phone has a device cert
        // but no live link and dead-ends at 'trusted' with
        // nowhere to go.
        if (payload.pair_token && payload.daemon_fingerprint && payload.ws_signaling_url) {
          // Single-pane: _runAutoPairFlow shows autopair-card.
          // _showOnly enforces no overlap with enroll-card.
          _showOnly("#autopair-card");
          await _runAutoPairFlow({
            pair_token: payload.pair_token,
            daemon_fingerprint: payload.daemon_fingerprint,
            ws_url: payload.ws_signaling_url,
          });
        } else {
          // Fallback: no handoff fields (shouldn't happen post
          // server fix, but defensive). Try roster directly; if
          // it fails, surface a clear next-step.
          try {
            await _refreshDaemonRoster();
          } catch (_e) {
            _selfMeshEnrollSetState(
              "good",
              "trusted",
              `${merged.label} is paired. Open One Link on the laptop to start using it.`,
            );
          }
        }
        return;
      }
      if (status === "rejected") {
        _selfMeshEnrollSetState(
          "bad",
          "rejected",
          `The other device rejected this pair: ${payload.reason || "codes did not match"}. Scan a fresh QR to try again.`,
        );
        return;
      }
      if (status === "expired") {
        _selfMeshEnrollSetState(
          "warn",
          "expired",
          "This invite expired before the other device confirmed. Scan a fresh QR.",
        );
        return;
      }
      // status === "pending" or "awaiting_claim" — keep polling.
    }
    // Hit the overall deadline without resolution.
    _selfMeshEnrollSetState(
      "warn",
      "timed out",
      "Stopped waiting after 10 minutes. Scan a fresh QR to retry.",
    );
  }

