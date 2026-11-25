  function _callValidObservedCandidateAddress(value) {
    if (typeof value !== "string" || value !== value.trim() || value.length > 45) {
      return null;
    }
    const ipv4 = value.split(".");
    if (ipv4.length === 4 && ipv4.every((part) =>
      /^(?:0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255
    )) {
      const first = Number(ipv4[0]);
      if (first === 0 || first >= 224) return null;
      return value;
    }
    if (!value.includes(":") || !/^[0-9A-Fa-f:]+$/.test(value) || value.includes(":::")) {
      return null;
    }
    const compression = value.indexOf("::");
    if (compression !== -1 && compression !== value.lastIndexOf("::")) return null;
    const groups = value.split(":").filter(Boolean);
    if (groups.some((group) => group.length > 4)) return null;
    if (compression === -1 ? groups.length !== 8 : groups.length >= 8) return null;
    const lowered = value.toLowerCase();
    if (lowered === "::" || lowered.startsWith("ff")) return null;
    return lowered;
  }

  function _callLocalAddressesFromIceConfig(config) {
    const assist = config && config.local_address_discovery;
    if (!assist || assist.enabled !== true || assist.external !== false ||
        assist.scope !== "same-device-or-lan") {
      return [];
    }
    const raw = Array.isArray(assist.candidate_addresses)
      ? assist.candidate_addresses.slice(0, 8)
      : [assist.candidate_address];
    return raw
      .map(_callValidObservedCandidateAddress)
      .filter((address, index, all) => address && all.indexOf(address) === index);
  }

  function _callNumericCandidateLine(line, candidateAddress, ordinal) {
    if (typeof line !== "string") return null;
    const address = _callValidObservedCandidateAddress(candidateAddress);
    if (!address) return null;
    const withAttributePrefix = line.startsWith("a=");
    const body = withAttributePrefix ? line.slice(2) : line;
    const parts = body.trim().split(/\s+/);
    if (parts.length < 8 || !parts[0].startsWith("candidate:")) return null;
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+local$/i.test(parts[4] || "")) {
      return null;
    }
    if (parts[1] !== "1" || String(parts[2]).toUpperCase() !== "UDP") return null;
    if (!/^[0-9]{1,10}$/.test(parts[3]) || !/^[0-9]{1,5}$/.test(parts[5])) return null;
    const port = Number(parts[5]);
    if (port < 1 || port > 65535 || parts[6] !== "typ" || parts[7] !== "host") {
      return null;
    }
    // Give the additional route its own bounded foundation so the remote ICE
    // agent cannot collapse it back into Firefox's unresolved mDNS candidate.
    let foundationHash = 2166136261;
    const foundationInput = `${parts[0]}|${address}|${Number(ordinal || 0)}`;
    for (let i = 0; i < foundationInput.length; i += 1) {
      foundationHash ^= foundationInput.charCodeAt(i);
      foundationHash = Math.imul(foundationHash, 16777619) >>> 0;
    }
    parts[0] = `candidate:ol${foundationHash.toString(36)}`;
    parts[4] = address;
    return `${withAttributePrefix ? "a=" : ""}${parts.join(" ")}`;
  }

  function _callCandidateLinesForSignal(candidateLine, candidateAddresses) {
    if (typeof candidateLine !== "string" || !candidateLine.trim()) return [];
    const output = [candidateLine];
    const addresses = Array.isArray(candidateAddresses)
      ? candidateAddresses.slice(0, 8)
      : [];
    addresses.forEach((address, ordinal) => {
      const numeric = _callNumericCandidateLine(candidateLine, address, ordinal);
      if (numeric && !output.includes(numeric)) output.push(numeric);
    });
    return output;
  }

  // Narrow diagnostics/test surface: the production call driver and browser
  // qualification gates execute the same frozen helpers.  No call state,
  // credentials, SDP, or daemon authority is exposed here.
  if (typeof window !== "undefined") {
    window.__oneLinkCallTransport = Object.freeze({
      localAddressesFromIceConfig: _callLocalAddressesFromIceConfig,
      numericCandidateLine: _callNumericCandidateLine,
      candidateLinesForSignal: _callCandidateLinesForSignal,
    });
  }

  function _queueCallIcePayloads(payloads) {
    const bounded = Array.isArray(payloads) ? payloads.slice(0, 9) : [];
    const previous = media.iceSignalChain || Promise.resolve();
    media.iceSignalChain = previous
      .catch(() => undefined)
      .then(async () => {
        for (const payload of bounded) {
          const result = await callApiPost(payload);
          if (!result || result.ok !== true) {
            reportCallEvent("ice_candidate_signal_failed", {
              state: payload.end_of_candidates ? "end" : "candidate",
            });
          }
        }
      });
    return media.iceSignalChain;
  }

  function setupRtcPeerConnection() {
    // Build the RTCPeerConnection + wire signaling transport.
    //
    // SDP + ICE exchange flows through the daemon's /api/v1/calls
    // surface (action: send_sdp_offer / send_sdp_answer /
    // send_ice_candidate). Inbound SDP / ICE arrives as
    // ``call_event`` tail messages over the existing WebSocket.
    if (!window.RTCPeerConnection) return null;
    if (media.pc && media.pc.signalingState !== "closed") return media.pc;
    media.localCandidateAddresses = [];
    media.iceSignalChain = Promise.resolve();
    // Sovereignty default: no third-party STUN servers. The daemon may return
    // its private LAN-only Binding responder plus its OS-observed address;
    // together those preserve a direct same-LAN route when Firefox masks host
    // candidates behind unresolvable mDNS names. Cross-NAT calls still require
    // user/operator-configured public STUN and, where necessary, TURN.
    const pc = new RTCPeerConnection({
      iceServers: [],
      iceTransportPolicy: media.preferRelayNext ? "relay" : "all",
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
      iceCandidatePoolSize: 4,
    });
    // Resolve both local assistance and any explicitly configured public
    // STUN/TURN before the offer. Failure remains host-only and is observable;
    // it never triggers an undisclosed third-party fallback.
    media.iceConfigReady = (async () => {
      try {
        const iceUrl = callUI.activeCallId
          ? `/api/peer-rtc/ice-config?call_id=${encodeURIComponent(callUI.activeCallId)}`
          : "/api/peer-rtc/ice-config";
        const r = await fetch(iceUrl, {
          credentials: "include", cache: "no-store",
        });
        if (!r.ok) return;
        const cfg = await r.json();
        media.localCandidateAddresses = _callLocalAddressesFromIceConfig(cfg);
        media.iceRelayReady = Array.isArray(cfg.iceServers)
          && cfg.iceServers.some((srv) => {
            const urls = Array.isArray(srv.urls) ? srv.urls : [srv.urls];
            return urls.some((u) => String(u || "").toLowerCase().startsWith("turn:") || String(u || "").toLowerCase().startsWith("turns:"));
          });
        media.iceHelperReady = Array.isArray(cfg.iceServers) && cfg.iceServers.length > 0;
        media.routePolicy = String(cfg.routePolicy?.mode || "direct_first");
        media.routePolicyDetail = cfg.routePolicy || null;
        media.bestRelayHealth = String(cfg.routePolicy?.best_relay_health || "");
        media.bestRelayScore = Number.isFinite(Number(cfg.routePolicy?.best_relay_score))
          ? Number(cfg.routePolicy.best_relay_score)
          : null;
        media.turnCredentialExpiresAtMs = Number(cfg.routePolicy?.credential_expires_at_ms || 0) || null;
        media.forceRelayOnRepair = cfg.routePolicy?.force_relay_on_repair === true;
        if (Array.isArray(cfg.iceServers) && cfg.iceServers.length > 0) {
          pc.setConfiguration({ iceServers: cfg.iceServers });
          if (media.iceRelayReady) {
            reportCallEvent("ice_relay_ready", { state: "available" });
            requestRelayHealthProbe("ice_config").catch(() => {});
          }
        } else {
          reportCallEvent("ice_host_only_mode", { state: "enabled" });
        }
      } catch (_) {
        reportCallEvent("ice_config_unavailable", { state: "host_only" });
      }
    })();
    pc.ontrack = (ev) => {
      bindRemoteTrackDiagnostics(ev.track);
      bindRemoteVideoElementDiagnostics();
      let stream = media.remoteStream;
      if (!stream || (ev.streams && ev.streams[0] && stream !== ev.streams[0])) {
        stream = (ev.streams && ev.streams[0]) || new MediaStream();
      }
      try { stream.addTrack(ev.track); } catch (_) {}
      attachRemoteStream(stream);
      addOneCallEvent(`Remote ${ev.track.kind} connected.`);
      reportCallEvent("remote_track_connected", {
        media_kind: ev.track.kind,
        state: ev.track.muted ? "muted" : "connected",
      });
      reportCallMetricsOnce();
    };
    pc.onicecandidate = (ev) => {
      // Trickle each candidate to the daemon as it's gathered.
      // ev.candidate === null signals end-of-gathering.
      if (!callUI.activeCallId) return;
      if (ev.candidate === null) {
        _queueCallIcePayloads([{
          action: "send_ice_candidate",
          call_id: callUI.activeCallId,
          candidate: "",
          sdp_mid: null,
          sdp_m_line_index: null,
          end_of_candidates: true,
        }]);
        return;
      }
      const candidateLines = _callCandidateLinesForSignal(
        ev.candidate.candidate,
        media.localCandidateAddresses,
      );
      _queueCallIcePayloads(candidateLines.map((candidate) => ({
          action: "send_ice_candidate",
          call_id: callUI.activeCallId,
          candidate,
          sdp_mid: ev.candidate.sdpMid,
          sdp_m_line_index: ev.candidate.sdpMLineIndex,
          end_of_candidates: false,
      })));
      if (candidateLines.length > 1) {
        reportCallEvent("ice_local_numeric_candidate", {
          state: "augmented",
          count: candidateLines.length - 1,
        });
      }
    };
    pc.oniceconnectionstatechange = () => {
      // The Immune System reads connection state via vitals; emitted
      // as a metrics ping on the events WebSocket.
      reportCallMetricsOnce();
      addOneCallEvent(`Media route ${pc.iceConnectionState}.`);
      reportCallEvent("ice_state_changed", { state: pc.iceConnectionState });
      if (pc.iceConnectionState === "disconnected" || pc.iceConnectionState === "failed") {
        repairMediaPath("ice_state_changed").catch(() => {});
      } else if (pc.iceConnectionState === "connected" || pc.iceConnectionState === "completed") {
        callUI.qualityGoodTicks += 1;
      }
    };
    pc.onconnectionstatechange = () => {
      reportCallMetricsOnce();
      if (pc.connectionState === "disconnected" || pc.connectionState === "failed") {
        repairMediaPath("connection_state_changed").catch(() => {});
      } else if (pc.connectionState === "connected") {
        callUI.qualityGoodTicks += 1;
      }
    };
    media.pc = pc;
    ensureMediaTransceivers();
    return pc;
  }

