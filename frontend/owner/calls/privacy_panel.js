  // ── Privacy panel (May 15 2026) ──────────────────────────────────
  //
  // Surfaces sovereignty preset + per-feature state + the live
  // instrumented outbound-event log. Hidden by default; opens via
  // window.openPrivacyPanel() - wired to the lock icon in
  // Settings + the Ctrl+Shift+P shortcut.

  window.openPrivacyPanel = async function () {
    const overlay = document.getElementById("privacy-panel-overlay");
    if (!overlay) return;
    overlay.classList.add("show");
    await refreshPrivacyPanel();
  };

  function _hidePrivacyPanel() {
    const overlay = document.getElementById("privacy-panel-overlay");
    if (overlay) overlay.classList.remove("show");
    returnToOneHealthGuideIfPending();
  }

  async function refreshPrivacyPanel() {
    const body = document.getElementById("privacy-panel-body");
    if (!body) return;
    body.innerHTML = `<div class="privacy-panel-loading">Checking your privacy settings…</div>`;
    let status, presets, outbound;
    try {
      [status, presets, outbound] = await Promise.all([
        fetch("/api/sovereignty/status", { credentials: "include" }).then(r => r.json()),
        fetch("/api/sovereignty/preset", { credentials: "include" }).then(r => r.json()),
        fetch("/api/sovereignty/outbound?limit=50", { credentials: "include" }).then(r => r.json()),
      ]);
    } catch (e) {
      // 2026-05-21 audit T3-A: e.message is server-controlled; escape.
      const reason = _escapeHtml(String((e && e.message) || "network error"));
      body.innerHTML = `<div class="privacy-panel-loading">Couldn't load. (${reason})</div>`;
      return;
    }

    const active = (status && status.preset && status.preset.name) || "just_works";
    const presetCards = (presets.presets || []).map((p) => {
      const isActive = p.name === active;
      return `
        <div class="privacy-preset-card${isActive ? " active" : ""}"
             data-preset="${escapeAttr(p.name)}"
             role="button" tabindex="0">
          <div class="preset-name">${escapeText(p.label)}</div>
          <div class="preset-desc">${escapeText(p.description)}</div>
          <div class="preset-out">↗ ${escapeText(p.outbound_summary)}</div>
        </div>`;
    }).join("");

    const feat = (status && status.features) || {};
    const featRow = (label, on, source, extra) => `
      <div class="privacy-feature-row">
        <span class="feature-name">${escapeText(label)}</span>
        <span class="feature-state ${on ? "on" : "off"}">${
          on ? "ON" : "OFF"}${
          source ? ` · from ${escapeText(source)}` : ""}${
          extra ? ` · ${escapeText(extra)}` : ""}</span>
      </div>`;
    // Plain-English labels. Avoid jargon. Each row tells the user
    // "this thing is on/off, and that came from your mode (or you
    // explicitly changed it)."
    const featRowSimple = (label, on, source, extra) => `
      <div class="privacy-feature-row">
        <span class="feature-name">${escapeText(label)}</span>
        <span class="feature-state ${on ? "on" : "off"}">${
          on ? "ON" : "OFF"}${
          extra ? `, ${escapeText(extra)}` : ""}</span>
      </div>`;
    const featuresHtml = `
      ${featRowSimple(
        "Check for One Link updates",
        !!(feat.update_check && feat.update_check.enabled),
        feat.update_check && feat.update_check.source,
      )}
      ${featRowSimple(
        "STUN address discovery (not signaling or relay)",
        Array.isArray(feat.stun_servers && feat.stun_servers.list)
          && feat.stun_servers.list.length > 0,
        feat.stun_servers && feat.stun_servers.source,
        Array.isArray(feat.stun_servers && feat.stun_servers.list)
          && feat.stun_servers.list.length > 0
          ? `${feat.stun_servers.list.length} server${feat.stun_servers.list.length === 1 ? "" : "s"}`
          : "",
      )}
      ${featRowSimple(
        "Find devices on the same Wi-Fi",
        !!(feat.mdns_discovery && feat.mdns_discovery.enabled),
        feat.mdns_discovery && feat.mdns_discovery.source,
      )}
      ${featRowSimple(
        "Rendezvous client active (configured route required)",
        !!(feat.rendezvous && feat.rendezvous.active),
        feat.rendezvous && feat.rendezvous.source,
        feat.rendezvous && feat.rendezvous.configured
          ? `${feat.rendezvous.configured_url_count || 0} URL${feat.rendezvous.configured_url_count === 1 ? "" : "s"} configured${feat.rendezvous.active ? "" : ", client inactive"}`
          : "no URL configured",
      )}
      ${featRowSimple(
        "Stay signed in across daemon restarts (this browser origin only)",
        !!(feat.ui_session_persistence && feat.ui_session_persistence.enabled),
        feat.ui_session_persistence && feat.ui_session_persistence.source,
      )}
      ${featRowSimple(
        "Remember which browser is which (local label only)",
        !!(feat.ui_session_labels && feat.ui_session_labels.enabled),
        feat.ui_session_labels && feat.ui_session_labels.source,
      )}
      ${featRowSimple(
        "TURN relay route configured",
        !!(feat.turn_relay && feat.turn_relay.configured),
        feat.turn_relay && feat.turn_relay.source,
        feat.turn_relay && feat.turn_relay.configured
          ? `${(feat.turn_relay.urls || []).length} route${(feat.turn_relay.urls || []).length === 1 ? "" : "s"}`
          : "no relay configured",
      )}
      ${featRowSimple(
        "Adopt rendezvous URLs from devices on your Wi-Fi",
        !!(feat.inherit_rendezvous_from_mdns && feat.inherit_rendezvous_from_mdns.enabled),
        feat.inherit_rendezvous_from_mdns && feat.inherit_rendezvous_from_mdns.source,
      )}`;

    // Plain-English labels for the connection types so the user can
    // tell at a glance what each row is.
    const _kindLabel = (k) => {
      const m = {
        "update_check": "Update check",
        "stun": "Network helper",
        "rendezvous": "Outside relay",
        "external": "Outside",
      };
      return m[k] || k;
    };
    const entries = (outbound && outbound.entries) || [];
    const outboundHtml = entries.length === 0
      ? `<div class="privacy-empty">No instrumented outside-call events are recorded for this daemon session. This is not proof that no network connection occurred.</div>`
      : `<div class="privacy-outbound">${
          entries.map(e => `
            <div class="privacy-outbound-row">
              <span class="out-time">${escapeText(_fmtRelTime(e.ts_ms))}</span>
              <span class="out-dest">${escapeText(e.destination)}${
                e.note ? ` <span style="color:rgba(255,255,255,0.4)">(${
                  escapeText(e.note)})</span>` : ""}</span>
              <span class="out-kind">${escapeText(_kindLabel(e.kind))}</span>
            </div>`).join("")
        }</div>`;
    const outboundScope = (outbound && outbound.scope) || "";

    // May 16 2026 - paired-device update hint. When a paired device
    // is on a newer version, surface that. No call to any outside
    // server needed; the device itself told us.
    const hint = (status && status.peer_version_hint) || {};
    const versionHintHtml = hint.newer_available
      ? `
        <div class="privacy-section">
          <div class="privacy-section-h">A paired device has a newer version</div>
          <div class="privacy-feature-row" style="
              background:rgba(255,180,90,0.10);
              border:1px solid rgba(255,180,90,0.32);">
            <span class="feature-name">
              ${escapeText(hint.newest_peer || "Paired device")} is running version ${
                escapeText(hint.newest_version || "?")}
            </span>
            <span class="feature-state" style="color:rgba(255,180,90,1);">
              You're on ${escapeText(hint.local_version)}
            </span>
          </div>
          <div class="privacy-promise">
            We learned this directly from your paired device. No call to
            any outside server was made.
          </div>
        </div>`
      : "";

    body.innerHTML = `
      <div class="privacy-section">
        <div class="privacy-section-h">Privacy mode</div>
        <div class="privacy-preset-grid">${presetCards}</div>
      </div>
      ${versionHintHtml}
      <div class="privacy-section">
        <div class="privacy-section-h">What's turned on right now</div>
        <div class="privacy-features">${featuresHtml}</div>
      </div>
      <div class="privacy-section">
        <div class="privacy-section-h">Recent instrumented outside events (last ${
          entries.length || 0})</div>
        ${outboundHtml}
        <div class="privacy-promise">${escapeText(outboundScope)}</div>
      </div>`;

    // Wire preset cards.
    body.querySelectorAll(".privacy-preset-card").forEach((card) => {
      card.addEventListener("click", async () => {
        const name = card.getAttribute("data-preset");
        if (!name) return;
        try {
          // The daemon acknowledges this call only after the live network
          // subsystems have converged.  Use the common API wrapper so a
          // non-2xx rollback cannot be mistaken for a successful switch.
          await api.post("/api/sovereignty/preset", { name });
          await refreshPrivacyPanel();
          if (typeof toast === "function") {
            toast(`Sovereignty preset: ${name}`, "ok");
          }
        } catch (e) {
          // Re-render from daemon truth: a failed transition restores the
          // previous preset and runtime policy transactionally.
          await refreshPrivacyPanel().catch(() => {});
          if (typeof toast === "function") {
            toast(
              `Couldn't switch mode: ${errorToastBody(e)}`,
              "bad", 5000,
            );
          }
        }
      });
      card.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          card.click();
        }
      });
    });
  }

  function _fmtRelTime(ts_ms) {
    if (!ts_ms) return "-";
    const dt = Date.now() - ts_ms;
    if (dt < 60_000) return `${Math.round(dt / 1000)}s ago`;
    if (dt < 3600_000) return `${Math.round(dt / 60_000)}m ago`;
    if (dt < 86_400_000) return `${Math.round(dt / 3600_000)}h ago`;
    return `${Math.round(dt / 86_400_000)}d ago`;
  }

  function escapeText(s) {
    if (s == null) return "";
    const div = document.createElement("div");
    div.textContent = String(s);
    return div.innerHTML;
  }
  function escapeAttr(s) {
    return String(s == null ? "" : s).replace(/"/g, "&quot;");
  }

