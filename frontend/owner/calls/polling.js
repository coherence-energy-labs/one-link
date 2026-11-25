  // WebSocket call_event messages are the low-latency path. This loop is a
  // reconciliation backstop for missed events, so its cadence can adapt to
  // actual urgency instead of hitting /api/v1/calls 40 times per idle minute.
  let _callBackfillTimer = null;
  let _callBackfillRunning = false;
  let _callBackfillStopped = false;
  function callBackfillDelayMs() {
    if (document.hidden) return callUI.activeCallId || callUI.inboundCallId ? 5000 : 30000;
    if (callUI.activeCallId || callUI.inboundCallId) return 1000;
    const peerCount = Number(document.getElementById("peers-count")?.textContent || 0);
    return peerCount > 0 ? 5000 : 10000;
  }
  function scheduleCallBackfill(delayMs = callBackfillDelayMs()) {
    if (_callBackfillStopped) return;
    if (_callBackfillTimer !== null) clearTimeout(_callBackfillTimer);
    _callBackfillTimer = setTimeout(runCallBackfill, Math.max(0, delayMs));
  }
  async function runCallBackfill() {
    _callBackfillTimer = null;
    if (_callBackfillRunning) return;
    _callBackfillRunning = true;
    try {
      await backfillLivingPresenceCalls();
    } catch (error) {
      console.warn("Call reconciliation failed", error);
    } finally {
      _callBackfillRunning = false;
      if (!_callBackfillStopped) scheduleCallBackfill();
    }
  }
  scheduleCallBackfill(250);
  document.addEventListener("visibilitychange", () => {
    scheduleCallBackfill(document.hidden ? callBackfillDelayMs() : 0);
  });
  if (typeof window.addEventListener === "function") {
    window.addEventListener("pagehide", () => {
      _callBackfillStopped = true;
      if (_callBackfillTimer !== null) clearTimeout(_callBackfillTimer);
      _callBackfillTimer = null;
    });
    window.addEventListener("pageshow", () => {
      _callBackfillStopped = false;
      scheduleCallBackfill(0);
    });
  }
