  // ── WebRTC UI wiring ────────────────────────────────────────────────
  let _webrtcSession = null;
  function _showWebRtcCard() {
    show($("#webrtc-card"));
    try {
      assertWebRtcAvailable();
      text($("#webrtc-status"), "Ready for direct browser link.");
    } catch (e) {
      text($("#webrtc-status"), e && e.message ? e.message : String(e));
    }
  }
  function _writeLocalSignal(signal) {
    const out = $("#webrtc-local");
    if (out) out.value = encodeSignal(signal);
  }
  function _readRemoteSignal() {
    const input = $("#webrtc-remote");
    return decodeSignal(input ? input.value : "");
  }
  $("#btn-webrtc-offer")?.addEventListener("click", async () => {
    const btn = $("#btn-webrtc-offer");
    if (btn) btn.disabled = true;
    text($("#webrtc-status"), "Creating signed WebRTC offer…");
    try {
      const res = await createOfferSignal({
        onState: (label) => text($("#webrtc-status"), `WebRTC: ${label}`),
      });
      _webrtcSession = res.session;
      _writeLocalSignal(res.signal);
      text($("#webrtc-status"), res.ice_complete
        ? "Complete offer ready. Send this one local signal to the other peer."
        : "Offer ready with gathered direct candidates; optional STUN timed out. Same-network routes may still work.");
    } catch (e) {
      text($("#webrtc-status"), `Offer failed: ${e && e.message ? e.message : e}`);
    } finally {
      if (btn) btn.disabled = false;
    }
  });
  $("#btn-webrtc-accept")?.addEventListener("click", async () => {
    const btn = $("#btn-webrtc-accept");
    if (btn) btn.disabled = true;
    text($("#webrtc-status"), "Verifying remote signal…");
    try {
      const signal = _readRemoteSignal();
      if (signal.type === "offer") {
        const res = await acceptOfferSignal(signal, {
          onState: (label) => text($("#webrtc-status"), `WebRTC: ${label}`),
        });
        _webrtcSession = res.session;
        _writeLocalSignal(res.signal);
        text($("#webrtc-status"), res.ice_complete
          ? "Complete answer ready. Send this one local signal back."
          : "Answer ready with gathered direct candidates; optional STUN timed out. Same-network routes may still work.");
      } else if (signal.type === "answer") {
        await acceptAnswerSignal(_webrtcSession, signal);
        text($("#webrtc-status"), "Answer accepted. Waiting for channel open.");
      } else if (signal.type === "ice") {
        await addIceSignal(_webrtcSession, signal);
        text($("#webrtc-status"), "ICE candidate accepted.");
      } else {
        throw new Error(`unsupported signal type: ${signal.type}`);
      }
    } catch (e) {
      text($("#webrtc-status"), `Signal failed: ${e && e.message ? e.message : e}`);
    } finally {
      if (btn) btn.disabled = false;
    }
  });
  $("#btn-webrtc-copy")?.addEventListener("click", async () => {
    const out = $("#webrtc-local");
    if (!out || !out.value) {
      text($("#webrtc-status"), "No local signal yet.");
      return;
    }
    try {
      await navigator.clipboard.writeText(out.value);
      text($("#webrtc-status"), "Local signal copied.");
    } catch {
      out.focus();
      out.select();
      text($("#webrtc-status"), "Select the local signal and copy it.");
    }
  });

