  // ── Onboarding wizard (v0.9.4) ─────────────────────────────────────
  // First-run experience: 4-step modal that explains the app + sets
  // the user's display name. Gated by:
  //   - localStorage["onboarding_completed"] !== "1"
  //   - state.peers.size === 0 (heuristic: returning user already
  //     has paired devices, no need to re-onboard)
  // Persists completion to both localStorage AND the daemon's
  // settings table so a fresh browser tab on a paired daemon
  // doesn't re-pop the wizard.
  const ONBOARDING_STORAGE_KEY = "one_link.onboarding_completed";
  let _oneSetupInvite = null;
  let _oneSetupInviteTimer = null;

  async function refreshOneSetup() {
    try {
      state.oneSetup = await api.setup();
      renderOneSetup();
    } catch (e) {
      console.warn("setup status failed", e);
    }
    return state.oneSetup;
  }

  function _oneSetupFormatDuration(ms) {
    const total = Math.max(0, Math.round(Number(ms || 0) / 1000));
    const minutes = Math.floor(total / 60);
    const seconds = total % 60;
    return `${minutes}:${String(seconds).padStart(2, "0")}`;
  }

  function renderOneSetup() {
    const setup = state.oneSetup || {};
    const name = $("#onboarding-name")?.value || state.me?.display_name || state.me?.hostname || "This device";
    const current = $("#one-setup-current-device");
    if (current) current.textContent = name;
    const left = $("#one-setup-left-device");
    if (left) left.textContent = name;
    const counts = setup.counts || {};
    const identityState = $("#one-setup-identity-state");
    const identityDetail = $("#one-setup-identity-detail");
    if (identityState) identityState.textContent = counts.roots > 0 ? "Identity ready" : "Identity not created yet";
    if (identityDetail) identityDetail.textContent = counts.roots > 0
      ? "Your One identity is already available on this device."
      : "Create your One identity so your devices can belong to you without an account.";
    const rightState = $("#one-setup-right-state");
    if (rightState) rightState.textContent = counts.remote_devices > 0
      ? `${counts.remote_devices} trusted device${counts.remote_devices === 1 ? "" : "s"}`
      : "Waiting";
    const pending = Array.isArray(setup.pending_setup_devices)
      ? setup.pending_setup_devices[0]
      : null;
    const pendingBox = $("#one-setup-pending-device");
    if (pendingBox) pendingBox.style.display = pending ? "block" : "none";
    if (pending) {
      $("#one-setup-pending-label").textContent = `${pending.label || "New device"} is waiting`;
      $("#one-setup-trust-code").textContent = (
        pending.trust_phrase || pending.trust_code || "Waiting for phrase…"
      );
      const timing = $("#one-setup-pair-timing");
      if (timing) {
        const waited = _oneSetupFormatDuration(Number(pending.pair_elapsed_ms || 0));
        const left = _oneSetupFormatDuration(Number(pending.remaining_ms || 0));
        timing.textContent = `Waiting ${waited}. Invite expires in ${left}.`;
      }
      if (rightState) rightState.textContent = "Waiting for phrase match";
    }
    const list = $("#one-setup-checklist");
    if (list) {
      list.innerHTML = "";
      for (const item of (setup.checklist || []).slice(0, 8)) {
        const row = el("div", `setup-check-item ${item.status === "done" ? "done" : ""}`);
        row.appendChild(el("span", "status", item.status === "done" ? "OK" : "-"));
        const text = el("div", null);
        text.appendChild(el("strong", null, item.label || ""));
        text.appendChild(el("div", "size", item.human || ""));
        row.appendChild(text);
        row.appendChild(el("span", "tag", item.status || ""));
        list.appendChild(row);
      }
    }
    const panelTitle = $("#one-setup-panel-title");
    const panelSub = $("#one-setup-panel-sub");
    const panel = $("#one-setup-panel");
    if (panel) panel.classList.toggle("is-complete", !!setup.completed);
    if (panelTitle) panelTitle.textContent = setup.completed ? "One Setup complete" : "One Setup";
    if (panelSub) {
      panelSub.textContent = setup.next_action?.detail
        || "Pair devices, send once, and see privacy proof when you are ready.";
    }
    const panelList = $("#one-setup-panel-list");
    if (panelList) {
      panelList.innerHTML = "";
      for (const item of (setup.checklist || []).slice(0, 5)) {
        const row = el("div", `setup-mini-row ${item.status === "done" ? "done" : ""}`);
        row.appendChild(el("span", "dot", item.status === "done" ? "OK" : ""));
        row.appendChild(el("span", null, item.label || ""));
        row.appendChild(el("span", "tag", item.status || ""));
        panelList.appendChild(row);
      }
    }
    const settingsList = $("#settings-one-setup-list");
    if (settingsList) {
      settingsList.innerHTML = "";
      for (const item of (setup.checklist || []).slice(0, 8)) {
        const row = el("div", `setup-mini-row ${item.status === "done" ? "done" : ""}`);
        row.appendChild(el("span", "dot", item.status === "done" ? "OK" : ""));
        const text = el("span", null, item.label || "");
        text.title = item.human || "";
        row.appendChild(text);
        row.appendChild(el("span", "tag", item.status || ""));
        settingsList.appendChild(row);
      }
    }
    // v0.21.x: reflect recovery-track state on the settings sidebar
    // button. Once any track is configured the button shifts from
    // "Set recovery" to "Manage recovery" so it does not nag a user
    // who already shipped recovery.
    const recoveryBtn = $("#settings-one-setup-recovery");
    if (recoveryBtn) {
      const recoveryRow = (setup.checklist || []).find((it) => it.id === "recovery");
      const ready = recoveryRow && recoveryRow.status === "done";
      recoveryBtn.textContent = ready ? "Manage recovery" : "Set recovery";
    }
    const proof = setup.privacy_proof || {};
    const proofCopy = $("#settings-one-setup-proof-copy");
    if (proofCopy && proof.human) proofCopy.textContent = proof.human;
    const proofList = $("#settings-one-setup-proof-list");
    if (proofList) {
      proofList.innerHTML = "";
      for (const rowData of (proof.rows || []).slice(0, 8)) {
        const row = el("div", "setup-receipt-row");
        row.appendChild(el("b", null, rowData.label || ""));
        row.appendChild(el("span", null, rowData.value || ""));
        row.appendChild(el("span", "tag", rowData.status || ""));
        proofList.appendChild(row);
      }
      for (const event of (proof.audit_events || []).slice(0, 4)) {
        const row = el("div", "setup-receipt-row");
        row.appendChild(el("b", null, event.severity || "info"));
        row.appendChild(el("span", null, `${event.event || ""}${event.detail ? `: ${event.detail}` : ""}`));
        row.appendChild(el("span", "tag", "audit"));
        proofList.appendChild(row);
      }
    }
    const tech = $("#one-setup-technical-list");
    if (tech) {
      tech.innerHTML = "";
      for (const d of (setup.technical?.diagnostics || []).slice(0, 8)) {
        const row = el("div", null);
        row.appendChild(el("b", null, d.status || ""));
        row.appendChild(el("span", null, `${d.label || ""}: ${d.detail || ""}`));
        tech.appendChild(row);
      }
    }
    const panelTech = $("#one-setup-panel-technical-list");
    if (panelTech) {
      panelTech.innerHTML = "";
      for (const d of (setup.technical?.diagnostics || []).slice(0, 8)) {
        const row = el("div", null);
        row.appendChild(el("b", null, d.status || ""));
        row.appendChild(el("span", null, `${d.label || ""}: ${d.detail || ""}`));
        panelTech.appendChild(row);
      }
    }
    const settingsTech = $("#settings-one-setup-technical-list");
    if (settingsTech) {
      settingsTech.innerHTML = "";
      for (const d of (setup.technical?.diagnostics || []).slice(0, 8)) {
        const row = el("div", null);
        row.appendChild(el("b", null, d.status || ""));
        row.appendChild(el("span", null, `${d.label || ""}: ${d.detail || ""}`));
        settingsTech.appendChild(row);
      }
    }
  }

  async function maybeShowOnboarding() {
    const setup = state.oneSetup || await refreshOneSetup();
    try {
      if (localStorage.getItem(ONBOARDING_STORAGE_KEY) === "1") return;
    } catch { /* localStorage may be blocked - fall through */ }
    if (setup?.completed) {
      _markOnboardingComplete(/* persistRemote */ false);
      return;
    }
    if (setup?.skipped) return;
    // v0.9.4: also honor the daemon-persisted flag so a fresh
    // browser tab on a paired daemon doesn't re-pop the wizard
    // (no localStorage in that tab yet).
    if (state.me?.onboarding_completed) {
      _markOnboardingComplete(/* persistRemote */ false);
      return;
    }
    if (state.peers && state.peers.size > 0) {
      // Returning user with paired devices. Mark complete.
      _markOnboardingComplete(/* persistRemote */ true);
      return;
    }
    // Pre-fill the name field with whatever display_name the daemon
    // already has (might come from /api/me).
    const nameInput = $("#onboarding-name");
    if (nameInput && state.me?.display_name) {
      nameInput.value = state.me.display_name;
    } else if (nameInput && state.me?.hostname) {
      nameInput.value = state.me.hostname;
    }
    const stepFor = {
      identity: 3,
      add_device: 4,
      first_success: 5,
      privacy_proof: 6,
      safety: 6,
      finish: 6,
    };
    showOnboardingStep(stepFor[setup?.current_step] || 1);
    $("#onboarding-backdrop").style.display = "flex";
  }

  function showOnboardingStep(n) {
    const N = 6;
    document.querySelectorAll(".onboarding-step").forEach((step) => {
      const isThis = parseInt(step.dataset.step || "0", 10) === n;
      step.style.display = isThis ? "" : "none";
    });
    document.querySelectorAll("#onboarding-progress .dot").forEach((d, i) => {
      d.classList.toggle("active", i + 1 === n);
      d.classList.toggle("done", i + 1 < n);
    });
    if (n === 2) {
      // Focus the name input so the user can start typing.
      setTimeout(() => $("#onboarding-name")?.focus(), 50);
    }
  }

  function _markOnboardingComplete(persistRemote) {
    try { localStorage.setItem(ONBOARDING_STORAGE_KEY, "1"); } catch {}
    $("#onboarding-backdrop").style.display = "none";
    returnToOneHealthGuideIfPending();
    if (persistRemote) {
      // Best-effort: stash on the daemon so the next browser
      // session also skips. Failure is non-blocking.
      api.post("/api/settings", { onboarding_completed: true })
        .catch(() => {});
    }
  }

  async function skipOneSetup() {
    try { await api.setupAction("skip"); } catch {}
    $("#onboarding-backdrop").style.display = "none";
    returnToOneHealthGuideIfPending();
    toast("Setup is waiting in Activity whenever you want it.", "info", 3500);
  }

  async function finishOnboarding() {
    const nameInput = $("#onboarding-name");
    const newName = (nameInput?.value || "").trim();
    if (newName && newName !== state.me?.display_name) {
      try {
        await api.post("/api/settings", { display_name: newName });
        state.me = { ...(state.me || {}), display_name: newName };
        $("#me-host").textContent = newName;
      } catch (e) {
        toast(`Couldn't save name: ${e.message || e}`, "warn");
        // Don't bail - let the user finish onboarding anyway.
      }
    }
    try { await api.setupAction("complete"); } catch {}
    _markOnboardingComplete(/* persistRemote */ true);
  }

  async function createOneSetupIdentity() {
    const nameInput = $("#onboarding-name");
    const label = (nameInput?.value || state.me?.display_name || "My devices").trim();
    try {
      const result = await api.selfMeshRoot({ label });
      $("#one-setup-identity-state").textContent = "Identity ready";
      $("#one-setup-identity-detail").textContent = "Your One identity is ready. Now add your phone or laptop.";
      toast("One identity ready.", "good", 3000);
      await refreshSelfMesh();
      await refreshOneSetup();
      showOnboardingStep(4);
      return result;
    } catch (e) {
      toast(`Identity setup failed: ${e.message || e}`, "bad");
    }
  }

  function renderOneSetupInviteCountdown() {
    const hint = $("#one-setup-invite-hint");
    const btn = $("#one-setup-add-device");
    if (!_oneSetupInvite || !hint) return;
    const expiresMs = Number(_oneSetupInvite.expires_ms || 0);
    const remaining = Math.max(0, expiresMs - Date.now());
    const qr = $("#one-setup-invite-qr");
    const token = $("#one-setup-invite-token");
    if (remaining <= 0) {
      hint.textContent = "Invite expired. Create a fresh QR before adding another device.";
      hint.classList.add("setup-expired");
      if (btn) btn.textContent = "Refresh invite QR";
      if (qr) qr.style.opacity = ".45";
      if (token) token.classList.add("setup-expired");
      clearInterval(_oneSetupInviteTimer);
      _oneSetupInviteTimer = null;
      return;
    }
    const minutes = Math.floor(remaining / 60000);
    const seconds = Math.floor((remaining % 60000) / 1000);
    hint.textContent =
      `Scan this with the device you want to add. Expires in ${minutes}:${String(seconds).padStart(2, "0")}.`;
    hint.classList.remove("setup-expired");
    if (btn) btn.textContent = "Refresh invite QR";
    if (qr) qr.style.opacity = "1";
    if (token) token.classList.remove("setup-expired");
  }

  async function oneSetupAddDevice() {
    try {
      const invite = await api.setupDeviceInvite({
        label: state.me?.display_name || state.me?.hostname || "Add device",
      });
      _oneSetupInvite = invite;
      if (_oneSetupInviteTimer) clearInterval(_oneSetupInviteTimer);
      const qr = $("#one-setup-invite-qr");
      const token = $("#one-setup-invite-token");
      if (qr && invite.qr_url) {
        qr.src = `${invite.qr_url}&t=${Date.now()}`;
        qr.style.display = "block";
      }
      if (token) {
        token.value = invite.peer_url || invite.deep_link || invite.token || "";
        token.style.display = "block";
      }
      renderOneSetupInviteCountdown();
      _oneSetupInviteTimer = setInterval(async () => {
        renderOneSetupInviteCountdown();
        const setup = await refreshOneSetup();
        if (setup?.pending_setup_devices?.length) {
          showOnboardingStep(4);
        }
      }, 1500);
      await copyToClipboard(invite.peer_url || invite.deep_link || invite.token, "One Setup invite");
      await refreshOneSetup();
      toast("Invite ready and copied.", "good", 3500);
    } catch (e) {
      toast(`Invite failed: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  // v0.21.x recovery wizard. Replaces the self-attestation modal
  // (which asked the user to type "I have my recovery info" to
  // confirm something they had no in-app way to actually do) with
  // three real flows backed by /api/v1/recovery/*:
  //   1. Recovery phrase  - show the 24 words, verify 3 random
  //                         positions, record verified_at.
  //   2. Trusted contacts - pick guardians from pinned peers, mint
  //                         sealed Shamir shares, download each
  //                         share file for the user to deliver
  //                         through whatever medium they trust.
  //   3. Encrypted backup - stream a .olbak file the user keeps
  //                         somewhere safe.
  // The `oneSetupMarkRecoveryConfigured` symbol name stays for the
  // setup-action click router elsewhere.
  async function oneSetupMarkRecoveryConfigured() {
    await _showRecoveryWizard();
    await refreshOneSetup();
  }
