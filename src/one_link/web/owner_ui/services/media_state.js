// Isolated service: dependencies are explicit parameters; no owner closure access.
function createCallMediaState() {
  const media = {
    localStream: null,        // MediaStream from getUserMedia
    remoteStream: null,        // assembled from ontrack events
    pc: null,                  // RTCPeerConnection (when wired)
    iceConfigReady: null,      // Promise that resolves after STUN config is applied
    localCandidateAddresses: [], // daemon-observed, same-device/LAN numeric routes
    iceSignalChain: Promise.resolve(), // serialize candidates before end-of-candidates
    screenStream: null,
    cameraVideoTrack: null,
    screenSharing: false,
    backgroundBlur: false,
    // doctrine-ok: §3.2.a internal recovery state field; user copy stays calm.
    reconnecting: false,
    expectRemoteVideo: false,
    expectRemoteAudio: true,
    transceiversReady: false,
    held: false,
    captionsOn: false,
    captionsStarting: false,
    captionRecognizer: null,
    layoutMode: "focus",
    voiceProcessing: "smart",
    muted: false,
    cameraOff: false,
    selectedAudioInputId: "",
    selectedVideoInputId: "",
    selectedAudioOutputId: "",
    videoFit: "cover",
    iceHelperReady: false,
    iceRelayReady: false,
    routePolicy: "direct_first",
    routePolicyDetail: null,
    bestRelayHealth: "",
    bestRelayScore: null,
    turnCredentialExpiresAtMs: null,
    lastIceConfigRefreshMs: 0,
    lastRelayProbeMs: 0,
    forceRelayOnRepair: false,
    preferRelayNext: false,
  };
  return media;
}
