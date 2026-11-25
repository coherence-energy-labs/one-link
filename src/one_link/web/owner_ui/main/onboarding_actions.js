  async function openOneSetupFromState() {
    await refreshOneSetup();
    const setup = state.oneSetup || {};
    const stepFor = {
      identity: 3,
      add_device: 4,
      first_success: 5,
      privacy_proof: 6,
      safety: 6,
      finish: 6,
    };
    showOnboardingStep(stepFor[setup.current_step] || 1);
    $("#onboarding-backdrop").style.display = "flex";
  }

  async function oneSetupConfirmPendingDevice() {
    const pending = state.oneSetup?.pending_setup_devices?.[0];
    if (!pending?.token) return toast("No pending device is waiting.", "info", 3000);
    // 2026-05-23: /confirm requires the SAS in the body (audit
    // T1-L). Without it the server returns 400 "missing SAS
    // confirmation (sas required)" and the click silently fails.
    // Both devices independently derive and display the five-word phrase.
    const trustPhrase = pending.trust_phrase || pending.trust_code;
    if (!trustPhrase) {
      return toast("Pending device has no trust phrase yet — refresh and retry.", "warn", 4000);
    }
    const pairedLabel = pending.label || "Device";
    try {
      await api.confirmSetupDeviceInvite({
        token: pending.token,
        sas: trustPhrase,
      });
      // 2026-05-23 UX fix: previously this jumped to onboarding
      // step 5 ('Send something to yourself') which the user
      // experienced as a disconnected modal popping up RIGHT
      // after pair — "I just paired, why is this asking me to
      // send a test message?". Now: close the modal, surface a
      // toast that names the device that was paired, and refresh
      // the sidebar so the new device is visible. User can
      // immediately click into the chat with the device they
      // just paired.
      toast(
        `${pairedLabel} is paired and ready. Open it in the sidebar to chat.`,
        "good", 5000,
      );
      await refreshSelfMesh();
      await refreshOneSetup();
      try { await refreshPeers(); } catch (_e) {}
      // Close the onboarding modal — pair flow is done, user
      // should be back in the main app to use what they just paired.
      // The add-device milestone is tracked server-side by the device
      // count (state.list_self_mesh_devices), so we don't need an
      // explicit setupAction call here.
      const backdrop = $("#onboarding-backdrop");
      if (backdrop) backdrop.style.display = "none";
    } catch (e) {
      toast(`Couldn't trust ${pairedLabel}: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function oneSetupRejectPendingDevice() {
    const pending = state.oneSetup?.pending_setup_devices?.[0];
    if (!pending?.token) return toast("No pending device is waiting.", "info", 3000);
    try {
      await api.rejectSetupDeviceInvite({ token: pending.token, reason: "codes did not match" });
      toast("Stopped before trusting that device.", "warn", 4000);
      await refreshOneSetup();
    } catch (e) {
      toast(`Couldn't reject device: ${errorToastBody(e)}`, "bad", 6000);
    }
  }

  async function oneSetupReviewSafety() {
    await api.setupAction("safety_reviewed").catch(() => {});
    const meshBtn = document.querySelector('[data-pane="mesh"]');
    if (meshBtn) meshBtn.click();
    const safety = $("#self-mesh-safety-actions");
    if (safety) safety.open = true;
    $("#onboarding-backdrop").style.display = "none";
    $("#self-mesh-kit")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    toast("Device safety is open. Freeze is reversible; hard revoke is permanent.", "info", 5500);
    await refreshOneSetup();
  }

  async function oneSetupSendTest() {
    const peer = state.selectedPeer || Array.from(state.peers.keys())[0];
    if (!peer) {
      toast("Add or select a trusted device first.", "info", 3500);
      showOnboardingStep(4);
      return;
    }
    try {
      // v0.21.x bug fix: was `api.send(peer, body)` which doesn't
      // exist on the api object — TypeError at runtime. Every user
      // hit this on first run when they tried the wizard's flagship
      // "send a test message" action. The real send path is POST
      // /api/send with the same { peer, body } shape every other
      // call site uses (sendCurrent, retrySend, etc.).
      await api.post("/api/send", {
        peer,
        body: "Hello from One Link. This moved through your private fabric.",
      });
      await api.setupAction("first_message_sent").catch(() => {});
      $("#one-setup-first-success-state").textContent = "Sent privately";
      $("#one-setup-first-success-detail").textContent = "Your test message was sent to a trusted device.";
      await refreshOneSetup();
      showOnboardingStep(6);
    } catch (e) {
      toast(`Test message failed: ${errorToastBody(e)}`, "bad");
    }
  }

  let _oneSetupFileIntent = null;
  let _oneSetupFileSendInFlight = false;
  async function oneSetupSendFile() {
    if (_oneSetupFileSendInFlight) return;
    const peer = state.selectedPeer || Array.from(state.peers.keys())[0];
    if (!peer) {
      toast("Add or select a trusted device first.", "info", 3500);
      showOnboardingStep(4);
      return;
    }
    if (!_oneSetupFileIntent || _oneSetupFileIntent.peer !== peer) {
      const file = new File(
        ["This moved through your private One Link fabric.\n"],
        "hello-from-one-link.txt",
        { type: "text/plain" },
      );
      _oneSetupFileIntent = {
        peer,
        file,
        clientDeliveryId: _newClientMsgId(),
      };
    }
    const intent = _oneSetupFileIntent;
    _oneSetupFileSendInFlight = true;
    const setupFileButton = $("#one-setup-send-file");
    if (setupFileButton) setupFileButton.disabled = true;
    try {
      await api.upload(intent.peer, intent.file, {
        clientDeliveryId: intent.clientDeliveryId,
      });
      _oneSetupFileIntent = null;
      await api.setupAction("first_file_sent").catch(() => {});
      $("#one-setup-first-success-state").textContent = "File sent privately";
      $("#one-setup-first-success-detail").textContent = "One Link sent a tiny proof file through the real transfer path.";
      await refreshTransfers();
      await refreshOneSetup();
      showOnboardingStep(6);
    } catch (e) {
      toast(`Test file failed: ${e.message || e}`, "bad");
    } finally {
      _oneSetupFileSendInFlight = false;
      if (setupFileButton) setupFileButton.disabled = false;
    }
  }

  // Wire onboarding interactions.
  document.querySelectorAll("[data-onboarding-go]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const step = parseInt(btn.dataset.onboardingGo, 10);
      if (step >= 1 && step <= 6) showOnboardingStep(step);
    });
  });
  $("#onboarding-skip")?.addEventListener("click", () => {
    skipOneSetup();
  });
  $("#one-setup-skip-welcome")?.addEventListener("click", () => {
    skipOneSetup();
  });
  $("#onboarding-name-save")?.addEventListener("click", () => {
    showOnboardingStep(3);
  });
  $("#onboarding-finish")?.addEventListener("click", () => {
    finishOnboarding();
  });
  $("#one-setup-create-identity")?.addEventListener("click", createOneSetupIdentity);
  // v0.21.x: the "I already have one" button at onboarding step 3
  // used to silently skip forward to step 4 (Add device) without
  // doing anything useful. Now it opens the restore-from-phrase
  // modal so a user on a fresh install can actually bring back
  // their identity by typing their 24 words.
  $("#one-setup-restore-identity")?.addEventListener("click", openRecoveryRestoreModal);
  $("#one-setup-add-device")?.addEventListener("click", oneSetupAddDevice);
  $("#one-setup-copy-invite")?.addEventListener("click", () => {
    const token = $("#one-setup-invite-token")?.value || "";
    if (!token) return oneSetupAddDevice();
    copyToClipboard(token, "One Setup invite");
  });
  $("#one-setup-codes-yes")?.addEventListener("click", oneSetupConfirmPendingDevice);
  $("#one-setup-codes-no")?.addEventListener("click", oneSetupRejectPendingDevice);
  $("#one-setup-send-test")?.addEventListener("click", oneSetupSendTest);
  $("#one-setup-send-file")?.addEventListener("click", oneSetupSendFile);
  $("#one-setup-review-safety")?.addEventListener("click", oneSetupReviewSafety);
  $("#one-setup-resume")?.addEventListener("click", openOneSetupFromState);
  $("#one-setup-add-device-panel")?.addEventListener("click", async () => {
    await refreshOneSetup();
    showOnboardingStep(4);
    $("#onboarding-backdrop").style.display = "flex";
    await oneSetupAddDevice();
  });
  $("#one-setup-privacy-panel")?.addEventListener("click", async () => {
    await api.setupAction("privacy_proof_viewed").catch(() => {});
    $("#btn-privacy")?.click();
    await refreshOneSetup();
  });
  $("#one-setup-safety-panel")?.addEventListener("click", oneSetupReviewSafety);
  $("#settings-one-setup-resume")?.addEventListener("click", openOneSetupFromState);
  function openSettingsDeviceHub() {
    $("#btn-settings")?.click();
    switchSettingsPane("devices");
    setTimeout(() => {
      $("#pair-phone-section")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }, 40);
  }
  $("#settings-one-setup-add-device")?.addEventListener("click", () => {
    openSettingsDeviceHub();
  });
  $("#settings-one-setup-privacy")?.addEventListener("click", async () => {
    await api.setupAction("privacy_proof_viewed").catch(() => {});
    await refreshOneSetup();
    switchSettingsPane("setup");
    $("#settings-one-setup-proof-list")?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  });
  $("#settings-one-setup-recovery")?.addEventListener("click", oneSetupMarkRecoveryConfigured);
  // Enter on the name input → next step.
  $("#onboarding-name")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      showOnboardingStep(3);
    }
  });

