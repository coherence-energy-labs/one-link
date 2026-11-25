  function stopAllMedia() {
    stopAttestStream();
    if (media.localStream) {
      media.localStream.getTracks().forEach((t) => { try { t.stop(); } catch (_) {} });
      mediaState.set("localStream", null);
    }
    if (media.remoteStream) {
      // Don't stop tracks (peer owns them), just detach.
      mediaState.set("remoteStream", null);
    }
    const localV = $$("#call-local-video");
    if (localV) {
      localV.srcObject = null;
      localV.classList.remove("show");
    }
    const remoteV = $$("#call-remote-video");
    if (remoteV) {
      remoteV.srcObject = null;
      remoteV.classList.remove("show");
    }
    const remoteA = $$("#call-remote-audio");
    if (remoteA) remoteA.srcObject = null;
    const surface = $$("#call-active-surface");
    if (surface) surface.classList.remove("has-remote-video");
    if (media.pc) {
      try { media.pc.close(); } catch (_) {}
      mediaState.set("pc", null);
    }
    mediaState.resetRoute();
    // Negotiation, telemetry, quality, adaptation and repair state of the
    // finished media session (callState owns the exact field list).
    callState.resetMediaSession();
    // doctrine-ok: §3.2.a internal recovery state reset; user copy stays calm.
    mediaState.resetSessionControls();
    _setCaptionsEnabled(false);
    try { media.captionRecognizer?.abort(); } catch (_) {}
    mediaState.set("captionRecognizer", null);
    const captionsBtn = $$("#btn-call-captions");
    if (captionsBtn) captionsBtn.disabled = false;
    mediaState.resetPresentation();
    syncMuteCameraButtons();
  }

