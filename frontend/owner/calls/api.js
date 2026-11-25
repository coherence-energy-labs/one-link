  async function callApiPost(body) {
    try {
      const r = await fetch("/api/v1/calls", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "same-origin",
      });
      return await r.json();
    } catch (_) {
      return { ok: false, user_message: "Couldn't reach the daemon." };
    }
  }

  async function callApiList() {
    try {
      const r = await fetch("/api/v1/calls", {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
      });
      return await r.json();
    } catch (_) {
      return { calls: [] };
    }
  }

  async function captureAutoCallTrace(reason, extra) {
    const callId = callUI.activeCallId;
    if (!callId) return null;
    const cleanReason = String(reason || "auto_trace").replace(/[^a-z0-9_-]/gi, "_").toLowerCase().slice(0, 64);
    const key = `${callId}:${cleanReason}`;
    const now = Date.now();
    if (callUI.lastAutoTraceKey === key && now - Number(callUI.lastAutoTraceMs || 0) < 15000) return null;
    callState.update({
      lastAutoTraceKey: key,
      lastAutoTraceMs: now,
    });
    try {
      const [traceResp, localDebug] = await Promise.all([
        fetch(`/api/v1/calls/${encodeURIComponent(callId)}/trace`, {
          credentials: "include", cache: "no-store",
        }),
        window._oneLinkCallDebug?.().catch(() => null),
      ]);
      const trace = await traceResp.json();
      const payload = {
        captured_at_ms: now,
        reason: cleanReason,
        call_id: callId,
        backend_trace: trace,
        local_debug: localDebug || null,
        extra: extra || null,
      };
      callState.recordAutoTrace(payload);
      try {
        localStorage.setItem(
          "one_link_auto_call_traces",
          JSON.stringify(callUI.autoTraceBuffer.slice(0, 6)),
        );
      } catch (_) {}
      reportCallEvent("auto_call_trace_captured", {
        reason: cleanReason,
        ok: true,
      });
      return payload;
    } catch (_) {
      reportCallEvent("auto_call_trace_failed", {
        reason: cleanReason,
      });
      return null;
    }
  }

