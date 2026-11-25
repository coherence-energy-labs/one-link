  // ── hook pair handshake into existing WebRTC session lifecycle ────
  // Wrap createOfferSignal + acceptOfferSignal so they install our
  // onState + onMessage handlers. This way pair handshake fires
  // automatically the moment the control channel opens; no extra
  // user action.
  const _origCreateOffer = createOfferSignal;
  // eslint-disable-next-line no-func-assign
  createOfferSignal = async function (opts) {
    const userOpts = opts || {};
    const wrapped = Object.assign({}, userOpts, {
      onState: (label, session) => {
        if (userOpts.onState) userOpts.onState(label, session);
        if (label === "control:open") _onControlChannelOpen(session);
      },
      onMessage: (kind, data, session) => {
        if (userOpts.onMessage) userOpts.onMessage(kind, data, session);
        _routeControlMessage(session, kind, data);
      },
    });
    return _origCreateOffer(wrapped);
  };

  const _origAcceptOffer = acceptOfferSignal;
  // eslint-disable-next-line no-func-assign
  acceptOfferSignal = async function (envelope, opts) {
    const userOpts = opts || {};
    const wrapped = Object.assign({}, userOpts, {
      onState: (label, session) => {
        if (userOpts.onState) userOpts.onState(label, session);
        if (label === "control:open") _onControlChannelOpen(session);
      },
      onMessage: (kind, data, session) => {
        if (userOpts.onMessage) userOpts.onMessage(kind, data, session);
        _routeControlMessage(session, kind, data);
      },
    });
    return _origAcceptOffer(envelope, wrapped);
  };

  // Show the rdz card once identity is loaded. Hook into the card
  // renderer to surface the affordance after unlock.
  const _origRenderIdentityCard = _renderIdentityCard;
  // eslint-disable-next-line no-func-assign
  _renderIdentityCard = function (rec) {
    _origRenderIdentityCard(rec);
    _showRdzCard();
    _showWebRtcCard();
    _refreshPeersCard();
  };

  // Expose internals for tests + future-ship reuse. Keep the surface
  // tight — only readers / observers, no setters.
  window.__oneLinkPeer = {
    version: "0.22.1",
    state,
    bytesToHex,
    bytesToB64Url,
    b64UrlToBytes,
    fingerprintOf,
    readIdentity,
    writeIdentity,
    deleteIdentity,
    identityStorageBackend: () => _usesOpfsIdentityBackend() ? "opfs" : "indexeddb",
    _identityTestReadRaw,
    _identityTestWriteRaw,
    _identityTestDeleteRaw,
    generateIdentity,
    wrapIdentity,
    unwrapIdentity,
    isWrappedEnvelope,
    _unlockWith,
    _canonicalJson,
    _signEd25519,
    _verifyEd25519,
    _buildSignedRegister,
    _normalizeRdzUrl,
    _parseRdzRegisterAck,
    _parseRdzLookupAck,
    registerWith,
    lookupAt,
    browserTransportCapabilities,
    loadPathStats,
    savePathStat,
    observePathResult,
    chooseTransportPath,
    pathScore,
    openWebTransport,
    selectTransportForPeer,
    assertWebRtcAvailable,
    loadPublicIceConfig,
    loadPublicIceServers,
    _validObservedCandidateAddress,
    _numericCandidateLine,
    _descriptionForSignal,
    createPeerConnection,
    _waitForIceGatheringComplete,
    createOfferSignal,
    acceptOfferSignal,
    acceptAnswerSignal,
    addIceSignal,
    sendControl,
    sendBulk,
    verifySignal,
    _verifiedSignalBinding,
    _assertSignalSignerContinuity,
    _validatePeerBinding,
    encodeSignal,
    decodeSignal,
    listPeers,
    savePeer,
    deletePeer,
    _peerFileName,
    _computeSas,
    _deriveSetupSas,
    _validateSetupClaim,
    _renderSasArt,
    _newPairing,
    _validatePairHello,
    _onPairHello,
    _onPairConfirm,
    _routeControlMessage,
    saveMessage,
    loadMessages,
    clearMessages,
    persistOutboundMessage,
    listChatOutbox,
    listChatOutboxQuarantine,
    clearChatOutboxForPeer,
    clearChatOutboxForOwner,
    drainChatOutbox,
    acknowledgeOutboundMessage,
    _normalizeChatOutboxRow,
    _activeChatBinding,
    sendChatMessage,
    _detectPairQuery,
    _runAutoPairFlow,
    _detectSelfMeshInviteQuery,
    _runSelfMeshInviteFlow,
    _registerDaemonDc,
    _handleDaemonIdentityChallenge,
    _handleDaemonIdentityVerified,
    _identityPossessionSigningBytes,
    _routeDaemonDcMessage,
    fetchDaemonPeers,
    fetchDaemonMessages,
    _daemonRequest,
    _refreshDaemonRoster,
  };

  // v0.20.3 — Advanced-surfaces toggle. The default user sees the
  // welcome card + (after pair) the daemon roster + chat. Power
  // users tap "Advanced surfaces" to reveal identity / rendezvous /
  // manual signaling / SAS art. Toggle persists per session via
  // localStorage so a page refresh keeps the user's preference.
