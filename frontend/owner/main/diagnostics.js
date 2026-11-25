  // ── Sidebar toggles ────────────────────────────────────────────────
  document.querySelectorAll(".pane-tabs .btn").forEach(b => {
    b.onclick = () => {
      document.querySelectorAll(".pane-tabs .btn").forEach(x => x.classList.remove("active"));
      b.classList.add("active");
      const pane = b.dataset.pane;
      state.activePane = pane;
      $("#files-panel").style.display = "none";
      $("#folders-panel").style.display = "none";
      $("#mesh-panel").style.display = "none";
      if (pane === "files") {
        $("#files-panel").style.display = "flex";
        $("#main").classList.add("with-files");
        refreshFiles();
      } else if (pane === "folders") {
        $("#folders-panel").style.display = "flex";
        $("#main").classList.add("with-files");
        refreshFolders();
      } else if (pane === "mesh") {
        $("#mesh-panel").style.display = "flex";
        $("#main").classList.add("with-files");
        // v0.9.1: load merged activity feed (transfers stay in
        // state for legacy callers; the mesh-panel now shows the
        // cross-peer event timeline).
        refreshActivityFeed();
        refreshTransfers();
      } else {
        $("#main").classList.remove("with-files");
      }
    };
  });

  // v0.8.1.1: Diagnostics overlay open/close - accessible only via
  // Ctrl+Shift+D OR the Settings modal's "Open diagnostics" button.
  // Intentionally hidden from the chat surface (chat-first, debug
  // when you need it).
  function openDebugOverlay() {
    const bd = $("#debug-backdrop");
    if (!bd) return;
    // Refresh the log + version sub on every open so the user sees
    // current state (instead of a snapshot from when the page loaded).
    if (state.me?.app_version) {
      $("#debug-version-sub").textContent = `daemon v${state.me.app_version}`;
    }
    bd.classList.add("show");
    refreshDebugLog();
  }
  function closeDebugOverlay() {
    $("#debug-backdrop")?.classList.remove("show");
  }
  $("#debug-close")?.addEventListener("click", closeDebugOverlay);
  $("#settings-open-diagnostics")?.addEventListener("click", () => {
    // Close the settings modal underneath so the user isn't
    // stacking two backdrops.
    $("#settings-backdrop")?.classList.remove("show");
    openDebugOverlay();
  });

  // Diagnostic exports intentionally never contain freeform log text. Regex
  // redaction cannot prove that every email, hostname, IPv6 literal, Unicode
  // name, URL, token, or future identifier shape was removed. Instead, map
  // internal entries into fixed categories and export numeric counters only.
  function _diagnosticEventCategory(entry) {
    const shape = `${entry?.source || ""} ${entry?.code || ""}`.toLowerCase();
    if (/call|media|webrtc|rtc|ice|audio|video/.test(shape)) return "call";
    if (/transfer|file|chunk|blob|upload|download/.test(shape)) return "transfer";
    if (/pair|identity|trust|capabil|auth|permission/.test(shape)) return "trust";
    if (/storage|sqlite|database|disk|wal|lockbox|seed|keychain/.test(shape)) return "storage";
    if (/update|upgrade|release/.test(shape)) return "update";
    if (/relay|rendezvous|network|socket|connect|offline|timeout|dns/.test(shape)) return "network";
    return "other";
  }

  function _diagnosticEventSummary(entries) {
    const summary = {
      total: 0,
      by_severity: { info: 0, warn: 0, error: 0 },
      by_category: {
        call: 0,
        transfer: 0,
        trust: 0,
        storage: 0,
        update: 0,
        network: 0,
        other: 0,
      },
    };
    for (const entry of (Array.isArray(entries) ? entries : []).slice(-50)) {
      const severity = entry?.severity;
      const safeSeverity = severity === "info" || severity === "warn" || severity === "error"
        ? severity
        : "error";
      const category = _diagnosticEventCategory(entry);
      summary.total += 1;
      summary.by_severity[safeSeverity] += 1;
      summary.by_category[category] += 1;
    }
    return summary;
  }

  async function _buildDiagnosticReport() {
    const report = {
      kind: "one_link_diagnostic_report_v2",
      app_version: state.me?.app_version || PAGE_BUILT_FOR || "unknown",
      page_version: PAGE_BUILT_FOR,
      peers: {
        count: state.peers.size,
        online: [...state.peers.values()].filter((p) => p.online).length,
        pinned: [...state.peers.values()].filter((p) => p.trust === "pinned").length,
        rejected: [...state.peers.values()].filter((p) => p.trust === "rejected").length,
      },
      groups: { count: state.groups?.size || 0 },
      messages_in_memory: state.messages.length,
      call_event_handler_failures: callEventHandlerFailures(),
      transfers: { active: state.transfers?.length || 0 },
      unread_total: state.totalUnread || 0,
      debug_event_summary: _diagnosticEventSummary(state.debugEntries || []),
      runtime_settings: (() => {
        const r = state.runtimeSettings || {};
        // Whitelist only known knob names; drop any user-supplied
        // strings (e.g. download_folder paths) that could identify.
        const allow = [
          "display_read_receipts", "send_read_receipts",
          "send_typing_indicators", "notification_sound",
          "show_message_preview",
          "voice_skip_preview", "dnd_enabled",
        ];
        const out = {};
        for (const k of allow) if (k in r) out[k] = r[k];
        return out;
      })(),
      status_summary: state.status ? {
        transfers_active: state.status.transfers?.active || 0,
        sessions_open: state.status.performance?.sessions?.open || 0,
        cdc_cache_bytes: state.status.performance?.cdc_cache?.bytes || 0,
        schema_version: state.status.schema_version || null,
        protocol_version: state.status.protocol_version || null,
      } : null,
    };
    return report;
  }
  function _diagnosticReportToText(report) {
    return JSON.stringify(report, null, 2);
  }
  // v0.21.x: replay welcome wizard. Resets the completion flags so
  // maybeShowOnboarding will render the wizard again on the next
  // /api/me call. Closes the settings modal first so the wizard
  // takes over the screen cleanly.
  $("#settings-replay-wizard")?.addEventListener("click", async () => {
    try { localStorage.removeItem(ONBOARDING_STORAGE_KEY); } catch {}
    try {
      // Best-effort: tell daemon to forget too, so a separate
      // browser tab also re-sees the wizard.
      await api.post("/api/settings", { onboarding_completed: false });
    } catch {}
    $("#settings-backdrop")?.classList.remove("show");
    document.body.classList.remove("settings-open");
    // Force-show step 1 of the wizard now.
    showOnboardingStep(1);
    $("#onboarding-backdrop").style.display = "flex";
  });

  $("#settings-export-diagnostics")?.addEventListener("click", async () => {
    const report = await _buildDiagnosticReport();
    const text = _diagnosticReportToText(report);
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `one-link-diagnostics-${new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast("Aggregate diagnostic report downloaded. Review it before sharing.", "good", 4500);
  });
  $("#settings-copy-diagnostics")?.addEventListener("click", async () => {
    const report = await _buildDiagnosticReport();
    const text = _diagnosticReportToText(report);
    try {
      await navigator.clipboard.writeText(text);
      toast("Diagnostic report copied to clipboard.", "good", 4000);
    } catch {
      toast("Couldn't copy — clipboard access denied.", "bad", 4500);
    }
  });
  // v0.21.x ES-35 (external audit 2026-05-18): Truth Dashboard.
  // The daemon is the single source of truth across all four axes.  Keeping
  // a second browser-side table made runtime-dependent native capabilities
  // and later hardening fixes drift from what the product displayed.
  // PI: primitive_proven; DW: daemon_wired; UE: UI_exposed; SP: soak_proven.
  // "✓" green, "~" partial/unqualified, "✗" absent or unproven.
  async function _renderTruthDashboard() {
    const host = document.getElementById("truth-grid");
    if (!host || host.dataset.painted === "1" || host.dataset.loading === "1") return;
    host.dataset.loading = "1";
    host.innerHTML = `<div class="doctor-empty">Loading current runtime truth…</div>`;
    let matrix;
    try {
      const audit = await api.get("/api/audit", { timeoutMs: 8000 });
      matrix = Array.isArray(audit?.feature_truth) ? audit.feature_truth : null;
      if (!matrix || matrix.length === 0) throw new Error("feature truth is unavailable");
    } catch (error) {
      host.innerHTML = `
        <div class="doctor-empty" role="status">
          Runtime truth unavailable. No capability status is being inferred in the browser.
        </div>
      `;
      host.dataset.painted = "1";
      delete host.dataset.loading;
      return;
    }
    host.innerHTML = `
      <div class="truth-head">
        <div></div>
        <div title="Primitive proven (implementation + automated gates)">PI</div>
        <div title="Daemon wired (current runtime path)">DW</div>
        <div title="UI exposed (driveable from this screen)">UE</div>
        <div title="Soak proven (archived physical multi-platform release evidence)">SP</div>
      </div>
    `;
    const stateMark = Object.freeze({ proven: "✓", partial: "~", absent: "✗" });
    const axes = ["primitive_proven", "daemon_wired", "ui_exposed", "soak_proven"];
    for (const row of matrix) {
      const marks = axes.map((axis) => stateMark[row?.[axis]] || "✗");
      const detail = [row?.evidence, row?.limitation].filter(Boolean).join(" ");
      const div = document.createElement("div");
      div.className = "truth-row";
      div.title = detail;
      div.innerHTML = `
        <div class="truth-name">${_escapeHtml(row?.name || "Unnamed capability")}</div>
        ${marks.map((m) => `<div class="truth-cell ${m === "✓" ? "ok" : m === "~" ? "partial" : "no"}">${m}</div>`).join("")}
      `;
      host.appendChild(div);
    }
    host.dataset.painted = "1";
    delete host.dataset.loading;
  }
  function _clickSettingsButton(id, unavailableMessage) {
    const btn = $(id);
    if (!btn) {
      toast(unavailableMessage || "That tool is not available in this build.", "bad", 4500);
      return false;
    }
    btn.click();
    return true;
  }
  $("#settings-advanced-doctor")?.addEventListener("click", () => {
    if (!_clickSettingsButton("#settings-run-doctor", "Doctor is not available in this build.")) return;
    $("#doctor-results")?.scrollIntoView({ block: "center", behavior: "smooth" });
  });
  $("#settings-advanced-bundle")?.addEventListener("click", () => {
    _clickSettingsButton("#settings-export-diagnostics", "Diagnostic export is not available in this build.");
  });
  $("#settings-advanced-truth")?.addEventListener("click", () => {
    switchSettingsPane("about");
    _renderTruthDashboard();
    const target = $("#truth-grid") || document.querySelector(".truth-dashboard");
    target?.scrollIntoView({ block: "center", behavior: "smooth" });
    toast("Opened feature truth status.", "info", 2600);
  });
  $("#settings-advanced-live")?.addEventListener("click", () => {
    _clickSettingsButton("#settings-open-diagnostics", "Live diagnostics are not available in this build.");
  });
  // Paint truth dashboard whenever the About pane becomes visible.
  document.addEventListener("DOMContentLoaded", () => {
    const aboutPane = document.querySelector('[data-settings-pane="about"]');
    if (!aboutPane) return;
    const obs = new MutationObserver(() => {
      if (aboutPane.classList.contains("active")) _renderTruthDashboard();
    });
    obs.observe(aboutPane, { attributes: true, attributeFilter: ["class"] });
  });

  // v0.21.x ES-20 (external audit 2026-05-18): One Link Doctor.
  // Runs ~12 checks against current state + browser capabilities +
  // recent daemon health. Each check returns
  // { id, label, status: "ok"|"warn"|"fail", hint }. Result rendered
  // into #doctor-results. No backend calls beyond the existing
  // /api/status that's already polled.
  async function _runOneLinkDoctor() {
    const out = [];
    function push(id, label, status, hint = "") { out.push({ id, label, status, hint }); }
    // Daemon reachable.
    let statusBody = null;
    try {
      statusBody = await api.get("/api/status", { timeoutMs: 5000 });
      push("daemon", "Daemon reachable", "ok",
        `Version ${statusBody?.app_version || statusBody?.version || "unknown"}`);
    } catch (e) {
      push("daemon", "Daemon reachable", "fail",
        `Can't reach the One Link daemon: ${e?.message || e}`);
      return out;
    }
    // UI token still valid (if api.get returned, it is).
    push("ui_token", "UI authentication", "ok",
      "Browser is authenticated to the local daemon.");
    // My version matches what the page expects.
    const myVer = state.me?.app_version || statusBody.app_version;
    if (myVer && PAGE_BUILT_FOR && myVer !== PAGE_BUILT_FOR) {
      push("page_drift", "Page / daemon version", "warn",
        `Page built for v${PAGE_BUILT_FOR}; daemon is v${myVer}. Hard-refresh the browser.`);
    } else {
      push("page_drift", "Page / daemon version", "ok",
        `Both on v${myVer || PAGE_BUILT_FOR}.`);
    }
    // Paired peers.
    const peers = [...state.peers.values()];
    const pinned = peers.filter((p) => p.trust === "pinned");
    if (pinned.length === 0) {
      push("peers", "Paired devices", "warn",
        "No paired devices. Pair another device to start chatting.");
    } else {
      const online = pinned.filter((p) => p.online).length;
      push("peers", "Paired devices", "ok",
        `${pinned.length} paired, ${online} online right now.`);
    }
    // Version compatibility with paired peers.
    const olderPeers = pinned.filter((p) => {
      const cmp = _compareAppVersion(p.app_version, myVer);
      return p.app_version && myVer && cmp < 0;
    });
    if (olderPeers.length > 0) {
      push("peer_version", "Peer versions", "warn",
        `${olderPeers.length} paired device${olderPeers.length === 1 ? " is" : "s are"} on older builds. Sends may queue until they update.`);
    } else if (pinned.length > 0) {
      push("peer_version", "Peer versions", "ok",
        "All paired devices match your build.");
    }
    // Incompatible peers.
    const broken = pinned.filter((p) =>
      p.compatibility && p.compatibility.compatible === false);
    if (broken.length > 0) {
      push("peer_compat", "Wire-path compatibility", "fail",
        `${broken.length} paired device${broken.length === 1 ? " can't" : "s can't"} negotiate a compatible wire path right now.`);
    }
    // Browser secure context (needed for getUserMedia / SW).
    if (window.isSecureContext) {
      push("secure_context", "Secure context", "ok",
        "Browser sees this as a secure context (mic / camera / SW work).");
    } else {
      push("secure_context", "Secure context", "fail",
        "Browser isn't in a secure context. Calls + service worker won't work. Use HTTPS or localhost.");
    }
    // WebRTC support.
    if (typeof RTCPeerConnection === "function") {
      push("webrtc", "WebRTC support", "ok",
        "Browser supports the call stack (RTCPeerConnection available).");
    } else {
      push("webrtc", "WebRTC support", "fail",
        "Browser doesn't expose RTCPeerConnection. Calls won't work in this browser.");
    }
    // Mic permission (cached from preflight or queried fresh).
    if (navigator.permissions?.query) {
      try {
        const mic = await navigator.permissions.query({ name: "microphone" });
        const micStatus = mic.state === "granted" ? "ok" : (mic.state === "denied" ? "fail" : "warn");
        push("mic", "Microphone permission",
          micStatus,
          `Currently ${mic.state}. ${mic.state === "denied" ? "Re-enable in browser site settings." : ""}`);
        const cam = await navigator.permissions.query({ name: "camera" });
        const camStatus = cam.state === "granted" ? "ok" : (cam.state === "denied" ? "fail" : "warn");
        push("cam", "Camera permission",
          camStatus,
          `Currently ${cam.state}. ${cam.state === "denied" ? "Re-enable in browser site settings." : ""}`);
      } catch (e) {
        push("media_perm", "Mic / camera permission", "warn",
          "Couldn't query permission status. Will be asked when you start a call.");
      }
    }
    // Notification permission.
    if ("Notification" in window) {
      const np = Notification.permission;
      push("notifications", "Desktop notifications",
        np === "granted" ? "ok" : (np === "denied" ? "warn" : "warn"),
        `Currently ${np}. ${np === "denied" ? "Re-enable in browser site settings to get incoming-call popups." : ""}`);
    }
    // Service Worker.
    if ("serviceWorker" in navigator) {
      const reg = await navigator.serviceWorker.getRegistration().catch(() => null);
      push("sw", "Service worker",
        reg ? "ok" : "warn",
        reg ? "Installed (offline + outbox queue work)." : "Not yet installed. Visit the page once over HTTPS to register it.");
    }
    // Online connectivity (navigator.onLine is unreliable but a useful coarse signal).
    push("online", "Network",
      navigator.onLine ? "ok" : "fail",
      navigator.onLine ? "Browser reports online." : "Browser reports offline. Messages will queue.");
    // Local storage / IDB usable.
    try {
      const k = "_doctor_check_" + Date.now();
      localStorage.setItem(k, "1");
      localStorage.removeItem(k);
      push("storage", "Local storage", "ok",
        "Browser can persist drafts + reaction history + onboarding state.");
    } catch (e) {
      push("storage", "Local storage", "fail",
        "Browser blocked localStorage. Drafts, pin/archive, and onboarding completion won't persist across reloads.");
    }
    // Outbox depth (from state).
    const queued = state.messages.filter((m) =>
      m._sendingState === "queued" || m._sendingState === "failed").length;
    if (queued > 0) {
      push("outbox", "Pending outbox", "warn",
        `${queued} message${queued === 1 ? " is" : "s are"} waiting to send. They'll retry automatically.`);
    } else {
      push("outbox", "Pending outbox", "ok", "Nothing queued.");
    }
    return out;
  }
  function _renderDoctorResults(results) {
    const host = $("#doctor-results");
    if (!host) return;
    host.innerHTML = "";
    if (!results || results.length === 0) {
      host.innerHTML = `<div class="doctor-empty">No checks ran.</div>`;
      return;
    }
    const counts = { ok: 0, warn: 0, fail: 0 };
    for (const r of results) counts[r.status] = (counts[r.status] || 0) + 1;
    const summary = el("div", "doctor-summary");
    summary.innerHTML = `
      <span class="doctor-tally"><span class="dot ok"></span> ${counts.ok} OK</span>
      <span class="doctor-tally"><span class="dot warn"></span> ${counts.warn} Warn</span>
      <span class="doctor-tally"><span class="dot fail"></span> ${counts.fail} Fail</span>
    `;
    host.appendChild(summary);
    for (const r of results) {
      const row = el("div", `doctor-row doctor-${r.status}`);
      row.innerHTML = `
        <span class="doctor-icon">${r.status === "ok" ? "✓" : r.status === "warn" ? "⚠" : "✕"}</span>
        <div class="doctor-body">
          <div class="doctor-label">${_escapeHtml(r.label)}</div>
          ${r.hint ? `<div class="doctor-hint">${_escapeHtml(r.hint)}</div>` : ""}
        </div>
      `;
      host.appendChild(row);
    }
  }
  $("#settings-run-doctor")?.addEventListener("click", async (ev) => {
    const btn = ev.currentTarget;
    btn.disabled = true;
    btn.textContent = "Running…";
    try {
      const results = await _runOneLinkDoctor();
      _renderDoctorResults(results);
    } catch (e) {
      _renderDoctorResults([{
        id: "exception",
        label: "Health check threw an exception",
        status: "fail",
        hint: String(e?.message || e),
      }]);
    } finally {
      btn.disabled = false;
      btn.textContent = "Run health check";
    }
  });

  $("#settings-open-bug-report")?.addEventListener("click", async () => {
    const report = await _buildDiagnosticReport();
    // Build a GitHub issue URL. The body is URL-encoded; GitHub
    // truncates at ~8K so we keep the report compact.
    const summary = `Bug: <short description here>`;
    const body = [
      "## What happened",
      "<describe what you did and what you expected vs what happened>",
      "",
      "## Steps to reproduce",
      "1. ",
      "2. ",
      "3. ",
      "",
      "## Diagnostic snapshot",
      "```json",
      _diagnosticReportToText(report).slice(0, 6000),
      "```",
      "",
      "_Generated by the in-app bug-report flow. Identifying info already stripped._",
    ].join("\n");
    const url = `https://github.com/coherence-energy-labs/one-link/issues/new?title=${encodeURIComponent(summary)}&body=${encodeURIComponent(body)}`;
    window.open(url, "_blank", "noopener,noreferrer");
    toast("GitHub opened in a new tab with the snapshot pre-filled.", "info", 4500);
  });

  // v0.15.0 - PWA install prompt handler. Browsers (Chrome, Edge,
