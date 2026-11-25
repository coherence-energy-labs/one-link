  async function _runAutoPairFlow(pair) {
    const mark = _pairingProgress();
    mark("preflight");
    _showOnly("#autopair-card");
    show($("#autopair-actions"));
    _autopairSetState("dim", "starting", "Setting up your phone's identity…");
    _autopairShowHost(pair.daemon_fingerprint);

    // v0.20.4: surface specific platform failures BEFORE waiting
    // 12s only to surface a generic "no identity" message.
    const pf = _autopairPreflight();
    if (pf) {
      mark("preflight_failed");
      _autopairSetState("bad", pf.pill, pf.status);
      throw new Error(pf.status);
    }

    // Identity must be unlocked + loaded before we can sign.
    mark("identity_loading");
    const rec = await _waitForIdentity(12_000);
    if (!rec) {
      mark("identity_unavailable");
      // v0.20.4: surface the real boot error if we have one.
      const bootMsg = state.boot_error_msg
        ? `Identity boot failed: ${state.boot_error_msg}`
        : "Couldn't provision an identity in time. Try reloading.";
      _autopairSetState(
        "bad",
        state.boot_error_msg ? "boot failed" : "no identity",
        bootMsg,
      );
      throw new Error(bootMsg);
    }

    _autopairSetState("warn", "negotiating", "Connecting to your laptop…");

    let ws;
    let pc;
    let controlDc;
    let localCandidateAddresses = [];
    let cancelPairing = null;
    let dataChannelOpened = false;
    let dataChannelFinalizing = false;
    let flowSettled = false;
    let resolveFlow, rejectFlow;
    let pairingTimer;
    const flowDone = new Promise((resolve, reject) => {
      resolveFlow = resolve;
      rejectFlow = reject;
    });
    // The deadline can reject while setup is still awaiting a browser API.
    // Attach a handler now; the original promise still rejects to the caller.
    void flowDone.catch(() => {});
    // RUN-01: a browser can hold a WebRTC/crypto/fetch call for minutes (a
    // stalled Firefox parent process held createOffer() from 2 s to 756 s).
    // Every held step therefore races the flow itself: the deadline or a
    // cancel rejects the caller's promise at once, and each await below
    // re-checks `flowSettled` so a late browser result can neither rewrite
    // the settled status nor start signaling.
    const step = (promise) => Promise.race([promise, flowDone]);
    const cleanup = () => {
      if (pairingTimer) clearTimeout(pairingTimer);
      if (cancelPairing) {
        $("#btn-autopair-cancel")?.removeEventListener("click", cancelPairing);
      }
    };
    const finishFlow = (value) => {
      if (flowSettled) return;
      flowSettled = true;
      cleanup();
      mark("connected", pc, controlDc);
      resolveFlow(value);
    };
    const failFlow = (error) => {
      if (flowSettled) return;
      flowSettled = true;
      cleanup();
      mark("failed", pc, controlDc);
      try { ws && ws.close(); } catch {}
      try { pc && pc.close(); } catch {}
      rejectFlow(error instanceof Error ? error : new Error(String(error)));
    };
    pairingTimer = setTimeout(() => {
      const phase = state.autopair_diagnostics.phase;
      const error = new Error(`pairing timed out during ${phase} after 90 seconds`);
      _autopairSetState(
        "bad", "timed out",
        "Pairing timed out. Check the laptop is reachable, then scan a fresh QR.",
      );
      failFlow(error);
    }, 90_000);
    cancelPairing = () => {
      _autopairSetState("dim", "cancelled", "Pairing cancelled.");
      hide($("#autopair-actions"));
      failFlow(new Error("pairing cancelled"));
    };
    $("#btn-autopair-cancel")?.addEventListener("click", cancelPairing, { once: true });

    // Catch browser API failures outside the individual, user-facing error
    // branches too, so no path leaves a negotiating spinner or live timer.
    try {
      try {
        mark("ice_config");
        const iceConfig = await step(loadPublicIceConfig());
        if (flowSettled) return flowDone;
        const iceServers = iceConfig.iceServers;
        localCandidateAddresses = iceConfig.localCandidateAddresses;
        pc = new RTCPeerConnection({
          iceServers,
          bundlePolicy: "max-bundle",
          rtcpMuxPolicy: "require",
        });
      } catch (e) {
        if (flowSettled) return flowDone;
        _autopairSetState(
          "bad", "no webrtc",
          `WebRTC unavailable: ${e && e.message ? e.message : e}. Try a current ` +
            "Chromium or Firefox build; WebKit/Safari is not yet release-qualified.",
        );
        failFlow(e);
        return flowDone;
      }

      // Open control + bulk channels with the daemon-pinned labels.
      mark("data_channels", pc);
      controlDc = pc.createDataChannel(
        AUTOPAIR_DAEMON_CONTROL_LABEL,
        { ordered: true },
      );
      const bulkDc = pc.createDataChannel(
        AUTOPAIR_DAEMON_BULK_LABEL,
        { ordered: false, maxRetransmits: 0 },
      );
      controlDc.binaryType = "arraybuffer";
      bulkDc.binaryType = "arraybuffer";

      const finalize = async () => {
        if (flowSettled || dataChannelOpened || dataChannelFinalizing) return;
        mark("identity_proof", pc, controlDc);
        dataChannelFinalizing = true;
        // Register before the daemon's first reliable control frame arrives,
        // then require its acknowledgement of a fresh channel-bound signature
        // before any owner request or "connected" success is surfaced.
        const identityReady = _registerDaemonDc(
          controlDc, pair.daemon_fingerprint,
        );
        let identityTimer;
        try {
          await Promise.race([
            identityReady,
            new Promise((_, reject) => {
              identityTimer = setTimeout(
                () => reject(new Error("identity-possession proof timed out")),
                20_000,
              );
            }),
          ]);
          if (flowSettled) return;
        } catch (error) {
          // A channel the settled flow closed rejects its proof too; that is
          // not a second, different failure.
          if (flowSettled) return;
          _autopairSetState(
            "bad", "identity rejected",
            `The laptop did not accept this device identity: ${
              error && error.message ? error.message : error
            }. Re-pair this device from the laptop.`,
          );
          try { controlDc.close(); } catch (_) {}
          try { pc.close(); } catch (_) {}
          dataChannelFinalizing = false;
          failFlow(error);
          return;
        } finally {
          if (identityTimer) clearTimeout(identityTimer);
        }
        dataChannelOpened = true;
        dataChannelFinalizing = false;
        mark("identity_verified", pc, controlDc);
        // Persist the daemon as a paired peer in OPFS so future
        // /peer visits (without ?pair=) recognize this daemon and
        // auto-reconnect. Public key isn't on the wire yet — we'll
        // fill it from the answer envelope when v0.20.2 wires it.
        try {
          await savePeer({
            v: 1,
            fingerprint: pair.daemon_fingerprint,
            public_key_b64u: state._pendingDaemonPubkey || "",
            alias: "Laptop daemon",
            paired_ms: Date.now(),
            last_seen_ms: Date.now(),
            paired_via: "qr",
          });
        } catch (e) {
          console.warn("save daemon peer failed", e);
        }
        if (flowSettled) return;
        _autopairSetState(
          "good", "connected",
          "Connected. Your phone is now paired with this laptop.",
        );
        hide($("#autopair-actions"));
        // Identity possession is now verified; owner requests can start.
        try {
          await _refreshDaemonRoster();
        } catch (e) {
          console.warn("daemon roster fetch failed", e);
        }
        finishFlow({
          challenge_id: state.daemon_identity_context?.challenge?.challenge_id,
          verified_ms: state.daemon_identity_ready?.verified
            ? Date.now()
            : null,
        });
      };

      controlDc.onopen = () => {
        void finalize().catch((error) => {
          if (flowSettled) return;
          _autopairSetState("bad", "identity failed", "Device identity verification could not finish.");
          failFlow(error);
        });
      };
      // Wire incoming messages to the daemon-DC router so request/
      // response correlation works for fetch_peers + fetch_messages.
      controlDc.onmessage = (event) => _routeDaemonDcMessage(
        event.data, controlDc,
      );

      pc.onconnectionstatechange = () => {
        if (flowSettled) return;
        mark("connection_state", pc, controlDc);
        if (pc.connectionState === "failed" || pc.connectionState === "closed") {
          if (!dataChannelOpened) {
            const error = new Error(
              `WebRTC connection ${pc.connectionState || "failed"}`,
            );
            _autopairSetState(
              "bad", "failed",
              "Connection failed. Check that you're on the same Wi-Fi as the laptop.",
            );
            failFlow(error);
          }
        }
      };

      // Create offer + sign envelope.
      let offer;
      try {
        mark("creating_offer", pc, controlDc);
        offer = await step(pc.createOffer());
        if (flowSettled) return flowDone;
        await step(pc.setLocalDescription(offer));
        if (flowSettled) return flowDone;
      } catch (e) {
        if (flowSettled) return flowDone;
        _autopairSetState(
          "bad", "offer failed",
          `Couldn't build offer: ${e && e.message ? e.message : e}`,
        );
        failFlow(e);
        return flowDone;
      }

      // The QR handoff has no separate trickle-candidate channel. Wait for a
      // complete SDP, but retain already-gathered host candidates if an optional
      // STUN server is unresponsive so same-network pairing still works.
      mark("gathering_ice", pc, controlDc);
      const iceComplete = await step(_waitForIceGatheringComplete(pc));
      if (flowSettled) return flowDone;
      if (!iceComplete) {
        _autopairSetState(
          "warn", "direct routes only",
          "Network helper timed out; trying already-gathered same-network routes.",
        );
      }

      const signalDescription = _descriptionForSignal({
        pc,
        local_candidate_addresses: localCandidateAddresses,
      });
      const offerEnvelope = {
        v: "OL-PEER-RTC-1",
        t: "offer",
        sdp: signalDescription.sdp,
        pubkey_b64u: rec.public_key_b64u,
        fingerprint: rec.fingerprint,
        pair_token: pair.pair_token,
        ts: Date.now(),
      };
      let sig;
      try {
        mark("signing_offer", pc, controlDc);
        const enc = new TextEncoder();
        sig = await step(_signEd25519(
          rec.private_key_jwk,
          enc.encode(_canonicalJson(offerEnvelope)),
        ));
      } catch (e) {
        if (flowSettled) return flowDone;
        _autopairSetState(
          "bad", "sign failed",
          `Couldn't sign offer: ${e && e.message ? e.message : e}`,
        );
        failFlow(e);
        return flowDone;
      }
      if (flowSettled) return flowDone;
      offerEnvelope.signature = bytesToB64Url(sig);

      // Open WS, send envelope, wait for answer.
      try {
        mark("signaling", pc, controlDc);
        ws = new WebSocket(pair.ws_url);
      } catch (e) {
        _autopairSetState(
          "bad", "ws failed",
          `Couldn't open signaling: ${e && e.message ? e.message : e}`,
        );
        failFlow(e);
        return flowDone;
      }

      ws.onopen = () => {
        if (flowSettled) return;
        try {
          ws.send(JSON.stringify(offerEnvelope));
        } catch (e) {
          _autopairSetState(
            "bad", "send failed",
            `Couldn't send offer: ${e && e.message ? e.message : e}`,
          );
          failFlow(e);
        }
      };
      ws.onerror = () => {
        if (!dataChannelOpened && !flowSettled) {
          _autopairSetState(
            "bad", "ws error",
            "Signaling WebSocket failed. Check the laptop is reachable.",
          );
          failFlow(new Error("signaling WebSocket failed"));
        }
      };
      ws.onmessage = async (event) => {
        if (flowSettled) return;
        let msg;
        try { msg = JSON.parse(event.data); } catch { return; }
        if (!msg || msg.v !== "OL-PEER-RTC-1") return;
        if (msg.t === "answer") {
          try {
            mark("verifying_answer", pc, controlDc);
            // v0.20.7 audit C1 + H6: verify signed answer + DTLS
            // fp + QR-pinned daemon fingerprint before applying.
            // See _verifySignedDaemonAnswer for the full rationale.
            await _verifySignedDaemonAnswer(msg, pair.daemon_fingerprint);
            if (flowSettled) return;
            await pc.setRemoteDescription(
              new RTCSessionDescription({ sdp: msg.sdp, type: "answer" }),
            );
            if (flowSettled) return;
            // Stash the daemon's pubkey for the OPFS save above.
            state._pendingDaemonPubkey = msg.daemon_pubkey_b64u || "";
            // Once setRemoteDescription resolves, ICE proceeds and
            // the DataChannel will fire onopen automatically.
          } catch (e) {
            if (flowSettled) return;
            _autopairSetState(
              "bad", "answer failed",
              `Couldn't apply answer: ${e && e.message ? e.message : e}`,
            );
            failFlow(e);
          }
        } else if (msg.t === "error") {
          _autopairSetState(
            "bad", msg.code || "rejected",
            msg.message || "Daemon rejected the pairing.",
          );
          failFlow(new Error(msg.message || msg.code || "pairing rejected"));
        }
      };
      return flowDone;
    } catch (error) {
      // A step that lost its race to the deadline or a cancel lands here
      // after the flow already reported why it stopped.
      if (flowSettled) return flowDone;
      _autopairSetState(
        "bad", "pairing failed",
        `Pairing could not continue: ${error && error.message ? error.message : error}`,
      );
      failFlow(error);
      return flowDone;
    }
  }

