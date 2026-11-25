  // This is the unavailable unattended/background setting. The distinct manual
  // exact-signed one-click action is rendered in the update notice only when
  // /api/me proves that the frozen bundle and external helper qualify.
  async function _refreshAutoInstallToggle(settings = null) {
    const cb = document.getElementById("setting-auto-install-updates");
    if (!cb) return;
    void settings;
    cb.checked = false;
    cb.disabled = true;
  }
  document.getElementById("setting-auto-install-updates")
    ?.addEventListener("change", async (ev) => {
      ev.target.checked = false;
      ev.target.disabled = true;
      toast(
        "Background installation is unavailable. Use Install verified update when a qualifying frozen bundle offers it.",
        "info", 5500,
      );
    });

  // Settings -> About add-device QR. Uses the same One Setup device
  // invite as the primary pairing flow, and auto-opens confirmation
  // when the scanned device is waiting to be trusted.
  let _activePairToken = null;
  let _settingsPairPollTimer = null;
  function _resetPairPhoneCard() {
    _activePairToken = null;
    if (_settingsPairPollTimer) {
      clearInterval(_settingsPairPollTimer);
      _settingsPairPollTimer = null;
    }
    const wrap = $("#pair-phone-qr-wrap");
    if (wrap) {
      wrap.style.display = "none";
      wrap.innerHTML = "";
    }
    // v0.20.6 - also clear the iOS trust QR so a stale one
    // doesn't sit there pointing at a different cert if the
    // user re-mints after the daemon rotated certs.
    const trustWrap = $("#ios-trust-qr-wrap");
    if (trustWrap) trustWrap.innerHTML = "";
    const btnPrimary = $("#btn-mint-pair");
    const btnCancel = $("#btn-mint-pair-cancel");
    if (btnPrimary) {
      btnPrimary.disabled = false;
      btnPrimary.textContent = "Create device QR";
    }
    if (btnCancel) btnCancel.style.display = "none";
  }
  $("#btn-mint-pair")?.addEventListener("click", async () => {
    const btn = $("#btn-mint-pair");
    const cancel = $("#btn-mint-pair-cancel");
    const wrap = $("#pair-phone-qr-wrap");
    if (!btn || !wrap) return;
    btn.disabled = true;
    btn.textContent = "Creating device QR...";
    let info;
    try {
      info = await api.setupDeviceInvite({
        label: state.me?.display_name || state.me?.hostname || "Add device",
      });
    } catch (e) {
      btn.disabled = false;
      btn.textContent = "Create device QR";
      toast(`Couldn't create device QR: ${e && e.message ? e.message : e}`, "bad");
      return;
    }
    _activePairToken = info.token;
    btn.textContent = "Device QR ready";
    if (cancel) cancel.style.display = "";
    // Render the exact setup invite QR returned by the daemon.
    wrap.innerHTML = "";
    wrap.style.display = "block";
    const img = document.createElement("img");
    img.src = `${info.qr_url}&_=${Date.now()}`;
    img.alt = "One Setup device invite QR";
    img.width = 256;
    img.height = 256;
    img.style.background = "#fff";
    img.style.padding = "12px";
    img.style.borderRadius = "8px";
    img.style.display = "block";
    img.style.margin = "0 auto";
    wrap.appendChild(img);

    const ttlMin = Math.round((info.ttl_ms || 300_000) / 60_000);
    const note = document.createElement("p");
    note.className = "settings-help";
    note.style.marginTop = "10px";
    note.textContent =
      `Scan with your phone or laptop. The link expires in ${ttlMin} ` +
      `minute${ttlMin === 1 ? "" : "s"} and only works once. When ` +
      `the device asks to join, One Link will show a confirmation before trusting it.`;
    wrap.appendChild(note);

    const urlBox = document.createElement("div");
    urlBox.style.display = "flex";
    urlBox.style.gap = "8px";
    urlBox.style.alignItems = "center";
    urlBox.style.marginTop = "10px";
    const urlEl = document.createElement("code");
    urlEl.textContent = info.peer_url || info.deep_link || info.token || "";
    urlEl.style.flex = "1 1 auto";
    urlEl.style.minWidth = "0";
    urlEl.style.overflow = "hidden";
    urlEl.style.textOverflow = "ellipsis";
    urlEl.style.whiteSpace = "nowrap";
    urlEl.style.background = "var(--bg-3)";
    urlEl.style.color = "var(--text)";
    urlEl.style.padding = "6px 10px";
    urlEl.style.borderRadius = "6px";
    urlEl.style.fontSize = "11px";
    urlEl.style.fontFamily = "ui-monospace, SFMono-Regular, Consolas, monospace";
    const copyBtn = document.createElement("button");
    copyBtn.className = "btn-ghost";
    copyBtn.textContent = "Copy URL";
    copyBtn.onclick = async () => {
      try {
        await navigator.clipboard.writeText(info.peer_url || info.deep_link || info.token || "");
        copyBtn.textContent = "Copied";
        setTimeout(() => { copyBtn.textContent = "Copy URL"; }, 1500);
      } catch (e) {
        toast(`Couldn't copy: ${e && e.message ? e.message : e}`, "bad");
      }
    };
    urlBox.appendChild(urlEl);
    urlBox.appendChild(copyBtn);
    wrap.appendChild(urlBox);

    const openSetupBtn = document.createElement("button");
    openSetupBtn.className = "btn-ghost";
    openSetupBtn.style.marginTop = "10px";
    openSetupBtn.textContent = "Open pairing steps";
    openSetupBtn.onclick = async () => {
      await refreshOneSetup();
      showOnboardingStep(4);
      $("#onboarding-backdrop").style.display = "flex";
    };
    wrap.appendChild(openSetupBtn);

    if (_settingsPairPollTimer) clearInterval(_settingsPairPollTimer);
    _settingsPairPollTimer = setInterval(async () => {
      const setup = await refreshOneSetup();
      if (setup?.pending_setup_devices?.length) {
        clearInterval(_settingsPairPollTimer);
        _settingsPairPollTimer = null;
        showOnboardingStep(4);
        $("#onboarding-backdrop").style.display = "flex";
        toast("Device is waiting. Confirm it here to trust it.", "info", 5000);
      }
    }, 1500);

    toast("Device QR ready. You'll confirm before it becomes trusted.", "good", 3500);

    // v0.20.6 - render the iOS trust-profile QR alongside the
    // pair QR. iOS Safari refuses to bypass self-signed certs on
    // LAN IPs (no "visit anyway" link), so phones need the
    // removable .mobileconfig installed for the daemon's current,
    // endpoint-constrained authority. The trust profile URL is
    // HTTP (port 7117) so the download works BEFORE the cert is
    // trusted; after install + trust toggle, the pair QR (HTTPS)
    // works clean. We only render this when the daemon has an
    // HTTPS listener (otherwise no cert needs trusting).
    const trustWrap = $("#ios-trust-qr-wrap");
    if (trustWrap) {
      trustWrap.innerHTML = "";
      if (info.https_available && info.ios_profile_url) {
        const tImg = document.createElement("img");
        tImg.src =
          `/api/v1/peer-rtc/qr.svg?u=${encodeURIComponent(info.ios_profile_url)}` +
          `&_=${Date.now()}`;
        tImg.alt = "QR code for the iOS trust-profile install";
        tImg.width = 220;
        tImg.height = 220;
        tImg.style.background = "#fff";
        tImg.style.padding = "10px";
        tImg.style.borderRadius = "8px";
        tImg.style.display = "block";
        tImg.style.margin = "0 auto";
        trustWrap.appendChild(tImg);

        const tNote = document.createElement("p");
        tNote.className = "settings-help";
        tNote.style.marginTop = "10px";
        tNote.style.fontSize = "12px";
        tNote.textContent =
          "After install + trust toggle, the pair QR works for this " +
          "laptop's current constrained authority. Reinstall this " +
          "profile if One Link reports that the network endpoint changed.";
        trustWrap.appendChild(tNote);

        const tUrlBox = document.createElement("div");
        tUrlBox.style.display = "flex";
        tUrlBox.style.gap = "8px";
        tUrlBox.style.alignItems = "center";
        tUrlBox.style.marginTop = "8px";
        const tUrlEl = document.createElement("code");
        tUrlEl.textContent = info.ios_profile_url;
        tUrlEl.style.flex = "1 1 auto";
        tUrlEl.style.minWidth = "0";
        tUrlEl.style.overflow = "hidden";
        tUrlEl.style.textOverflow = "ellipsis";
        tUrlEl.style.whiteSpace = "nowrap";
        tUrlEl.style.background = "var(--bg-3)";
        tUrlEl.style.color = "var(--text)";
        tUrlEl.style.padding = "6px 10px";
        tUrlEl.style.borderRadius = "6px";
        tUrlEl.style.fontSize = "11px";
        tUrlEl.style.fontFamily = "ui-monospace, SFMono-Regular, Consolas, monospace";
        const tCopyBtn = document.createElement("button");
        tCopyBtn.className = "btn-ghost";
        tCopyBtn.textContent = "Copy URL";
        tCopyBtn.onclick = async () => {
          try {
            await navigator.clipboard.writeText(info.ios_profile_url);
            tCopyBtn.textContent = "Copied";
            setTimeout(() => { tCopyBtn.textContent = "Copy URL"; }, 1500);
          } catch (e) {
            toast(`Couldn't copy: ${e && e.message ? e.message : e}`, "bad");
          }
        };
        tUrlBox.appendChild(tUrlEl);
        tUrlBox.appendChild(tCopyBtn);
        trustWrap.appendChild(tUrlBox);
      } else {
        const tNote = document.createElement("p");
        tNote.className = "settings-help";
        tNote.style.fontSize = "12px";
        tNote.textContent =
          "This daemon isn't running an HTTPS listener, so no " +
          "trust profile is needed. (If iPhones can't open the " +
          "pair URL, restart the daemon with HTTPS enabled.)";
        trustWrap.appendChild(tNote);
      }
    }
  });
  $("#btn-mint-pair-cancel")?.addEventListener("click", _resetPairPhoneCard);

