  async function refreshBlockedDevicesList() {
    const host = $("#blocked-devices-list");
    if (!host) return;
    let rejected = [];
    try {
      const r = await api.get("/api/peers?include=rejected");
      const all = r.peers || [];
      rejected = all.filter((p) => p.trust === "rejected");
    } catch (e) {
      console.warn("refreshBlockedDevicesList:", e);
    }
    host.innerHTML = "";
    if (rejected.length === 0) {
      const empty = el("p", "settings-help blocked-empty",
        "No blocked devices.");
      host.appendChild(empty);
      return;
    }
    for (const p of rejected) {
      const row = el("div", "blocked-row");
      const meta = el("div", "name", p.display_name || p.hostname || p.short_id || p.fingerprint?.slice(0, 12) || "(unknown)");
      const sub = el("div", "sub", p.short_id || (p.fingerprint || "").slice(0, 8));
      const wrap = el("div");
      wrap.style.flex = "1";
      wrap.appendChild(meta);
      wrap.appendChild(sub);
      const unblock = el("button", "btn-ghost", "Unblock");
      unblock.onclick = async () => {
        try {
          await api.post(
            `/api/peers/${encodeURIComponent(p.fingerprint)}/trust`,
            { trust: "pinned" },
          );
          toast("Forgiveness granted.", "good");
          refreshBlockedDevicesList();
          refreshPeers();
        } catch (e) {
          toast(`Unblock didn't work: ${errorToastBody(e)}`, "bad");
        }
      };
      row.appendChild(wrap);
      row.appendChild(unblock);
      host.appendChild(row);
    }
  }

  // v0.21.x - Active browser sessions in Privacy pane.
  // Persistent UI sessions outlive daemon restarts through independently
  // revocable browser bearers; the user audits and revokes them here.
  async function refreshUiSessionsList() {
    const host = $("#ui-sessions-list");
    if (!host) return;
    let sessions = [];
    try {
      const r = await api.get("/api/auth/sessions");
      sessions = r.sessions || [];
    } catch (e) {
      host.innerHTML = "";
      const p = el("p", "settings-help");
      p.textContent = `Couldn't load sessions: ${e && e.message ? e.message : e}`;
      host.appendChild(p);
      return;
    }
    host.innerHTML = "";
    if (sessions.length === 0) {
      host.appendChild(el(
        "p", "settings-help",
        "No persistent sessions yet — open from the tray icon to mint one.",
      ));
      return;
    }
    for (const s of sessions) {
      const row = el("div", "blocked-row");
      const labelPrefix = s.is_this_browser ? "★ " : "";
      const meta = el(
        "div", "name",
        labelPrefix + (s.label || "Unknown browser"),
      );
      const sub = el(
        "div", "sub",
        `id ${s.session_uuid_prefix || "?"} · last used ${_humanRelMs(s.last_seen_ms)}`,
      );
      const wrap = el("div");
      wrap.style.flex = "1";
      wrap.appendChild(meta);
      wrap.appendChild(sub);
      const btn = el("button", "btn-ghost", "Revoke");
      btn.title = (
        s.is_this_browser
          ? "This is the browser you're using right now. Revoking will sign YOU out."
          : "Sign this browser out. It will need a fresh URL from the tray to come back."
      );
      btn.onclick = async () => {
        if (s.is_this_browser) {
          if (!confirm("Revoke THIS browser? You'll be signed out.")) return;
        }
        try {
          await api.post(
            `/api/auth/sessions/id-${encodeURIComponent(String(s.id))}/revoke`,
            {},
          );
          toast("Session revoked.", "good");
          if (s.is_this_browser) {
            _clearBrowserOwnerSession();
            // Give the toast a beat then reload with no browser authority.
            setTimeout(() => location.reload(), 600);
          } else {
            refreshUiSessionsList();
          }
        } catch (e) {
          toast(
            `Revoke didn't work: ${errorToastBody(e)}`,
            "bad", 5000,
          );
        }
      };
      row.appendChild(wrap);
      row.appendChild(btn);
      host.appendChild(row);
    }
  }
  // v0.21.x - load + apply the two Privacy toggles (persistence,
  // labels) so the user is in control of the trade-offs the
  // sessions feature makes for them. Toggles default ON; flipping
  // OFF triggers immediate side-effects (table wipe / label strip).
  async function refreshSessionSettings() {
    const persistEl = $("#set-session-persistence");
    const labelsEl = $("#set-session-labels");
    if (!persistEl || !labelsEl) return;
    try {
      const r = await api.get("/api/auth/sessions/settings");
      persistEl.checked = !!r.persistence_enabled;
      labelsEl.checked = !!r.labels_enabled;
    } catch (e) {
      console.warn("session settings load:", e);
    }
  }
  async function updateSessionSettings(patch) {
    try {
      const r = await api.post("/api/auth/sessions/settings", patch);
      if (r.wiped_sessions) {
        _clearBrowserOwnerSession();
        toast(
          `Wiped ${r.wiped_sessions} session${r.wiped_sessions === 1 ? "" : "s"}. `
          + `Reload to re-open from the tray.`,
          "info", 5000,
        );
      } else if (r.stripped_labels) {
        toast(
          `Cleared browser labels from ${r.stripped_labels} session${r.stripped_labels === 1 ? "" : "s"}.`,
          "info", 4000,
        );
      }
      refreshUiSessionsList();
    } catch (e) {
      toast(`Couldn't save: ${errorToastBody(e)}`, "bad", 5000);
      refreshSessionSettings();  // revert UI to actual state
    }
  }

  // v0.21.x: render the 3 sovereignty preset cards directly inside
  // Settings → Privacy so users find them without needing to hunt
  // for the 🔒 lock icon. Wires up click-to-switch — same backend
  // endpoint (/api/sovereignty/preset) as the lock-icon panel.
  async function refreshSettingsPrivacyPresets() {
    const host = $("#settings-privacy-preset-grid");
    if (!host) return;
    let status, presets;
    try {
      [status, presets] = await Promise.all([
        api.get("/api/sovereignty/status"),
        api.get("/api/sovereignty/preset"),
      ]);
    } catch (e) {
      host.innerHTML = "";
      const p = el("p", "settings-help");
      p.textContent = `Couldn't load privacy modes: ${e && e.message ? e.message : e}`;
      host.appendChild(p);
      return;
    }
    const active = (status && status.preset && status.preset.name) || "just_works";
    host.innerHTML = "";
    for (const preset of (presets.presets || [])) {
      const isActive = preset.name === active;
      const card = el(
        "div",
        "privacy-preset-card" + (isActive ? " active" : ""),
      );
      card.setAttribute("role", "radio");
      card.setAttribute("aria-checked", isActive ? "true" : "false");
      card.setAttribute("tabindex", "0");
      card.dataset.preset = preset.name;
      const name = el("div", "preset-name", preset.label);
      const desc = el("div", "preset-desc", preset.description);
      const out = el("div", "preset-out", "↗ " + (preset.outbound_summary || ""));
      card.appendChild(name);
      card.appendChild(desc);
      card.appendChild(out);
      const switchTo = async () => {
        if (preset.name === active) return;
        try {
          await api.post("/api/sovereignty/preset", { name: preset.name });
          toast(`Switched to ${preset.label}`, "good", 3500);
          // Refresh BOTH the preset cards (active state flip) AND
          // the per-feature toggles (session persistence / labels
          // may have flipped per the new preset's defaults).
          refreshSettingsPrivacyPresets();
          refreshSessionSettings();
          refreshUiSessionsList();
          refreshSettingsSecurityAudit();
        } catch (e) {
          toast(
            `Couldn't switch mode: ${errorToastBody(e)}`,
            "bad", 5000,
          );
        }
      };
      card.addEventListener("click", switchTo);
      card.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          switchTo();
        }
      });
      host.appendChild(card);
    }
  }

  // v0.21.x: live security audit findings inside Settings → Privacy.
  // Each finding shows category + severity + plain-English message;
  // re-runs every time the pane refreshes so the user always sees
  // current state.
  async function refreshSettingsSecurityAudit() {
    const host = $("#settings-security-audit");
    if (!host) return;
    let r;
    try {
      r = await api.get("/api/security/audit");
    } catch (e) {
      host.innerHTML = "";
      const p = el("p", "settings-help");
      p.textContent = `Couldn't run audit: ${e && e.message ? e.message : e}`;
      host.appendChild(p);
      return;
    }
    host.innerHTML = "";
    const findings = (r && r.findings) || [];
    if (findings.length === 0) {
      host.appendChild(el(
        "p", "settings-help",
        "No findings — nothing to report.",
      ));
      return;
    }
    const _sev = (s) => (s === "fail" ? "✗" : s === "warn" ? "!" : "✓");
    for (const f of findings) {
      const row = el("div", `security-audit-row sev-${f.severity || "info"}`);
      row.appendChild(el("div", "sa-icon", _sev(f.severity)));
      const body = el("div", "sa-body");
      body.appendChild(el(
        "div", "sa-category",
        String(f.category || "").replace(/_/g, " "),
      ));
      body.appendChild(el("div", "sa-message", f.message || ""));
      row.appendChild(body);
      host.appendChild(row);
    }
  }

  // Wire the "Sign out all browsers" button + auto-refresh when the
  // Privacy pane becomes visible. The button calls revoke-all then
  // reloads so the page resets to the unauth flow.
  document.addEventListener("DOMContentLoaded", () => {
    const persistEl = $("#set-session-persistence");
    if (persistEl) {
      persistEl.addEventListener("change", () => {
        if (!persistEl.checked) {
          if (!confirm(
            "Turn off Stay signed in?\n\n"
            + "This will wipe the sessions table NOW + every browser "
            + "will need to be re-opened from the tray on the next "
            + "daemon restart."
          )) {
            persistEl.checked = true;
            return;
          }
        }
        updateSessionSettings({ persistence_enabled: persistEl.checked });
      });
    }
    const labelsEl = $("#set-session-labels");
    if (labelsEl) {
      labelsEl.addEventListener("change", () => {
        updateSessionSettings({ labels_enabled: labelsEl.checked });
      });
    }
    const btnAll = $("#btn-sign-out-all");
    if (btnAll) {
      btnAll.addEventListener("click", async () => {
        if (!confirm(
          "Sign out EVERY browser, including this one? Each browser "
          + "will need to be re-opened from the tray icon to sign back in."
        )) return;
        try {
          const r = await api.post(
            "/api/auth/sessions/revoke-all", {},
          );
          toast(
            `Signed out ${r.revoked || 0} browser${r.revoked === 1 ? "" : "s"}.`,
            "good", 4000,
          );
          _clearBrowserOwnerSession();
          setTimeout(() => location.reload(), 600);
        } catch (e) {
          toast(
            `Sign-out didn't work: ${errorToastBody(e)}`,
            "bad", 5000,
          );
        }
      });
    }
  });

  // v0.15.4 - connect-another-device flow. Calls /api/connect-info,
  // renders either the QR + URL + Copy button (LAN mode) or a hint
  // telling the user to pass --lan (loopback mode). The QR SVG is
  // fetched separately so we don't double-encode the URL string.
  async function _refreshConnectInfo() {
    const host = $("#connect-info-body");
    if (!host) return;
    let info;
    try {
      info = await api.get("/api/connect-info");
    } catch (e) {
      host.innerHTML = "";
      const p = el("p", "settings-help");
      p.textContent = `Couldn't load connect info: ${e && e.message ? e.message : e}`;
      host.appendChild(p);
      return;
    }
    host.innerHTML = "";
    if (!info.lan_bound) {
      const hint = el("p", "settings-help");
      hint.innerHTML =
        "This daemon is bound to <code>127.0.0.1</code> only. " +
        "Restart with <code>one-link app --lan</code> to get a " +
        "scannable URL for your phone.";
      host.appendChild(hint);
      return;
    }
    const wrap = el("div", "connect-info-wrap");
    const imgWrap = el("div", "connect-info-qr");
    const img = document.createElement("img");
    img.src = `/api/connect-info/qr.svg?_=${Date.now()}`;
    img.alt = "QR code with the LAN URL";
    img.width = 240;
    img.height = 240;
    img.style.background = "#fff";
    img.style.padding = "12px";
    img.style.borderRadius = "8px";
    imgWrap.appendChild(img);
    wrap.appendChild(imgWrap);

    const right = el("div", "connect-info-text");
    const lab = el("p", "settings-help");
    lab.textContent =
      "Scan this from another device on the same Wi-Fi, or copy + paste the URL.";
    right.appendChild(lab);
    const urlBox = el("div", "connect-info-url-box");
    const urlEl = el("code", "connect-info-url");
    urlEl.textContent = info.lan_url;
    urlBox.appendChild(urlEl);
    const copyBtn = el("button", "btn-ghost connect-info-copy", "Copy URL");
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(info.lan_url);
        copyBtn.textContent = "Copied";
        setTimeout(() => { copyBtn.textContent = "Copy URL"; }, 1500);
      } catch (e) {
        toast(`Couldn't copy: ${e && e.message ? e.message : e}`, "bad");
      }
    };
    urlBox.appendChild(copyBtn);
    right.appendChild(urlBox);
    const warn = el("p", "settings-help");
    warn.textContent =
      "The URL contains your access token. Anyone on this Wi-Fi who has it can reach the UI; share with intent.";
    right.appendChild(warn);
    wrap.appendChild(right);
    host.appendChild(wrap);
  }

  function renderSettingsPrivacySummary() {
    const fp = state.me?.fingerprint || "";
    const shortEl = $("#privacy-identity-short");
    if (shortEl) shortEl.textContent = fp ? `${fp.slice(0, 12)}...${fp.slice(-8)}` : "Not loaded";
    const s = state.runtimeSettings || {};
    const receipts = s.send_read_receipts === false ? "receipts off" : "receipts on";
    const typing = s.send_typing_indicators === false ? "typing off" : "typing on";
    const summary = $("#privacy-sharing-summary");
    const detail = $("#privacy-sharing-detail");
    if (summary) summary.textContent = `${receipts}, ${typing}`;
    if (detail) {
      detail.textContent =
        `You ${s.send_read_receipts === false ? "do not send" : "send"} read receipts and ` +
        `${s.send_typing_indicators === false ? "hide" : "share"} typing indicators.`;
    }
  }

