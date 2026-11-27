  async function createPeerConnection(opts) {
    assertWebRtcAvailable();
    opts = opts || {};
    // Resolve the daemon's disclosed STUN set before constructing the peer
    // connection. Creating an offer first and racing setConfiguration() made
    // cross-network QR/manual pairing silently host-candidate-only.
    const iceConfig = await loadPublicIceConfig();
    const iceServers = iceConfig.iceServers;
    const pc = new RTCPeerConnection({
      iceServers,
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
    });
    const session = {
      pc,
      control: null,
      bulk: null,
      signals: [],
      local_candidate_addresses: iceConfig.localCandidateAddresses,
      // The first verified remote offer/answer pins this session's Ed25519
      // signaling identity. Every subsequent answer, ICE candidate, and pair
      // hello must carry the same key before any WebRTC or roster mutation.
      remote_signal_signer_pubkey_b64u: null,
      remote_signal_signer_fingerprint: null,
      opened_ms: Date.now(),
      state: "starting",
    };
    const emitState = (label) => {
      session.state = label;
      if (opts.onState) opts.onState(label, session);
    };
    const wireChannel = (channel, kind) => {
      channel.binaryType = "arraybuffer";
      if (kind === "bulk") {
        channel.bufferedAmountLowThreshold = WEBRTC_BULK_BUFFER_LOW_BYTES;
      }
      let openNotified = false;
      const notifyOpen = () => {
        if (openNotified || channel.readyState !== "open") return;
        openNotified = true;
        emitState(`${kind}:open`);
      };
      channel.onopen = notifyOpen;
      channel.onclose = () => emitState(`${kind}:closed`);
      channel.onerror = () => emitState(`${kind}:error`);
      channel.onmessage = (event) => {
        // Received channels can already be open while their open event is
        // pending. Establish the session lifecycle before routing its first
        // frame, then ignore the delayed open event instead of restarting it.
        notifyOpen();
        if (opts.onMessage) opts.onMessage(kind, event.data, session);
      };
      return channel;
    };
    if (opts.initiator) {
      session.control = wireChannel(
        pc.createDataChannel(WEBRTC_CONTROL_LABEL, { ordered: true }),
        "control",
      );
      session.bulk = wireChannel(
        pc.createDataChannel(WEBRTC_BULK_LABEL, {
          ordered: false,
          maxRetransmits: 0,
        }),
        "bulk",
      );
    } else {
      pc.ondatachannel = (event) => {
        if (event.channel.label === WEBRTC_CONTROL_LABEL) {
          session.control = wireChannel(event.channel, "control");
        } else if (event.channel.label === WEBRTC_BULK_LABEL) {
          session.bulk = wireChannel(event.channel, "bulk");
        }
      };
    }
    pc.onicecandidate = async (event) => {
      if (!event.candidate) return;
      const signal = await _signSignal(
        "ice",
        _candidateForSignal(
          event.candidate,
          session.local_candidate_addresses[0] || null,
        ),
      );
      session.signals.push(signal);
      if (opts.onSignal) opts.onSignal(signal, session);
    };
    pc.onconnectionstatechange = () => emitState(pc.connectionState || "unknown");
    pc.oniceconnectionstatechange = () => emitState(`ice:${pc.iceConnectionState}`);
    return session;
  }

  function _waitForIceGatheringComplete(pc, timeoutMs = 10_000) {
    if (!pc || pc.iceGatheringState === "complete") return Promise.resolve(true);
    return new Promise((resolve) => {
      let timer = null;
      const cleanup = () => {
        if (timer !== null) clearTimeout(timer);
        pc.removeEventListener("icegatheringstatechange", onStateChange);
      };
      const onStateChange = () => {
        if (pc.iceGatheringState !== "complete") return;
        cleanup();
        resolve(true);
      };
      pc.addEventListener("icegatheringstatechange", onStateChange);
      timer = setTimeout(() => {
        cleanup();
        // Preserve already-gathered host candidates so an unreachable optional
        // STUN server cannot break a same-network session.
        resolve(false);
      }, timeoutMs);
    });
  }

  async function createOfferSignal(opts) {
    const session = await createPeerConnection(Object.assign({}, opts, { initiator: true }));
    // Data-channel-only negotiation needs no legacy offerToReceive* hints.
    // WebKit rejects those deprecated dictionary members on some releases.
    const offer = await session.pc.createOffer();
    await session.pc.setLocalDescription(offer);
    const iceComplete = await _waitForIceGatheringComplete(session.pc);
    const signal = await _signSignal("offer", _descriptionForSignal(session));
    session.signals.push(signal);
    return { session, signal, ice_complete: iceComplete };
  }

  async function acceptOfferSignal(envelope, opts) {
    const binding = await _verifiedSignalBinding(envelope, "offer");
    const session = await createPeerConnection(Object.assign({}, opts, { initiator: false }));
    await session.pc.setRemoteDescription(new RTCSessionDescription(envelope.body));
    _commitSignalSigner(session, binding);
    const answer = await session.pc.createAnswer();
    await session.pc.setLocalDescription(answer);
    const iceComplete = await _waitForIceGatheringComplete(session.pc);
    const signal = await _signSignal("answer", _descriptionForSignal(session));
    session.signals.push(signal);
    return { session, signal, ice_complete: iceComplete };
  }

  async function acceptAnswerSignal(session, envelope) {
    if (!session || !session.pc) throw new Error("missing session");
    const binding = await _verifiedSignalBinding(envelope, "answer");
    _assertSignalSignerContinuity(session, binding);
    await session.pc.setRemoteDescription(new RTCSessionDescription(envelope.body));
    _commitSignalSigner(session, binding);
    return session;
  }

  async function addIceSignal(session, envelope) {
    if (!session || !session.pc) throw new Error("missing session");
    const binding = await _verifiedSignalBinding(envelope, "ice");
    _assertSignalSignerContinuity(session, binding);
    await session.pc.addIceCandidate(envelope.body);
    _commitSignalSigner(session, binding);
    return session;
  }

  function sendControl(session, obj) {
    if (!session || !session.control || session.control.readyState !== "open") {
      throw new Error("control channel not open");
    }
    session.control.send(JSON.stringify(obj));
  }

  async function sendBulk(session, data) {
    if (!session || !session.bulk || session.bulk.readyState !== "open") {
      throw new Error("bulk channel not open");
    }
    while (session.bulk.bufferedAmount > WEBRTC_BULK_BUFFER_MAX_BYTES) {
      await new Promise((resolve) => {
        session.bulk.onbufferedamountlow = resolve;
      });
    }
    session.bulk.send(data);
  }

