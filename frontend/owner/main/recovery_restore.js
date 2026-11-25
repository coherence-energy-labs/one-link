  // ── recovery wizard: RESTORE-from-phrase modal ─────────────────
  // Symmetric counterpart to the SETUP wizard. Setup writes the 24
  // words; restore types them on a fresh install to bring the
  // identity back. The flow:
  //   1. Preflight: ask the daemon whether this install is "clean"
  //      (no peers/groups/messages) or "dirty" (would be replaced).
  //   2. Modal collects 24 words in a textarea. Validates locally:
  //      24 tokens, sane characters. The mnemonic checksum is
  //      verified server-side.
  //   3. If dirty: render a stern warning + explicit checkbox; submit
  //      passes force=true + confirmed_replace=true.
  //   4. On replacement, show "Restart One Link". The daemon journals
  //      protected inputs without changing live files; singleton-locked boot
  //      atomically converges seed/identity/DRK before State opens.
  // Both entry points (onboarding step 3 "I already have one" and
  // Settings -> Setup -> Set recovery -> Restore card) call the same
  // function below.
  async function openRecoveryRestoreModal() {
    _ensureRecoveryRestoreModal();
    const modal = document.getElementById("recovery-restore-modal");
    _recwizCaptureFocus(modal);
    modal.classList.add("show");
    document.body.classList.add("recwiz-open");
    // Reset to the input view + load preflight in parallel.
    const body = modal.querySelector(".recwiz-pane > .recwiz-restore-body");
    body.innerHTML = `<p class="recwiz-feedback">Checking install state...</p>`;
    let preflight;
    try {
      preflight = await api.recoveryRestorePreflight();
    } catch (e) {
      body.innerHTML = `<p class="recwiz-feedback bad">${escapeText("Could not check install state: " + errorToastBody(e))}</p>`;
      return;
    }
    _renderRecoveryRestoreInput(preflight);
    _recwizSetInitialFocus(modal);
  }

  function _closeRecoveryRestoreModal() {
    const modal = document.getElementById("recovery-restore-modal");
    if (modal) modal.classList.remove("show");
    document.body.classList.remove("recwiz-open");
    _recwizReturnFocus(modal);
  }

  function _ensureRecoveryRestoreModal() {
    if (document.getElementById("recovery-restore-modal")) return;
    const m = document.createElement("div");
    m.id = "recovery-restore-modal";
    m.className = "recwiz-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-label", "Restore identity from recovery phrase");
    m.innerHTML = `
      <div class="recwiz-backdrop" data-recwiz-close></div>
      <div class="recwiz-pane">
        <h2 class="recwiz-title">Restore from recovery phrase</h2>
        <p class="recwiz-lead">
          Type or paste the 24 words you wrote down when you set up
          One Link on your other device. Order matters; words are
          separated by spaces.
        </p>
        <details class="recwiz-help" style="margin-bottom:14px;">
          <summary>How does this work?</summary>
          <p>
            Your identity and backup-bundle key derive from the
            24-word phrase. Passphrase-mode application keys are kept
            portable through an authenticated seed-recovery wrap in
            current backups. The phrase restores your identity; the
            matching .olbak restores its saved data. The phrase itself
            never leaves this device.
          </p>
        </details>
        <p class="recwiz-card-meta" style="margin:0 0 8px;">
          Lost the paper but you set up trusted contacts?
          <a href="#" data-recwiz-restore-mode="shares"
             style="color:var(--accent);">Restore from guardian shares instead.</a>
        </p>
        <div class="recwiz-restore-body"></div>
      </div>
    `;
    document.body.appendChild(m);
    m.addEventListener("click", (ev) => {
      const t = ev.target;
      if (!(t instanceof Element)) return;
      if (t.hasAttribute("data-recwiz-close")) _closeRecoveryRestoreModal();
      if (t.getAttribute("data-recwiz-action") === "close-restore") {
        _closeRecoveryRestoreModal();
      }
      // Swap between phrase-restore and shares-restore inside the
      // same modal so users don't have to back out + pick a
      // different track. Preflight already loaded; just re-render.
      if (t.getAttribute("data-recwiz-restore-mode") === "shares") {
        ev.preventDefault();
        _renderRecoveryRestoreShares();
      }
      if (t.getAttribute("data-recwiz-restore-mode") === "phrase") {
        ev.preventDefault();
        api.recoveryRestorePreflight()
          .then(_renderRecoveryRestoreInput)
          .catch(() => { /* preflight already shown on open */ });
      }
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && m.classList.contains("show")) {
        _closeRecoveryRestoreModal();
      }
    });
  }

  // Shares-paste view inside the same restore modal. The recovering
  // user collects K share lines (format `index:base64_bytes`) from
  // K guardians and pastes them all into one textarea.
  async function _renderRecoveryRestoreShares() {
    const modal = document.getElementById("recovery-restore-modal");
    const body = modal.querySelector(".recwiz-restore-body");
    body.innerHTML = `<p class="recwiz-feedback">Checking install state...</p>`;
    let preflight;
    try {
      preflight = await api.recoveryRestorePreflight();
    } catch (e) {
      body.innerHTML = `<p class="recwiz-feedback bad">${escapeText("Could not check install state: " + errorToastBody(e))}</p>`;
      return;
    }
    const dirty = !!preflight.requires_force;
    const ev = preflight.evidence || {};
    const evParts = [];
    if (ev.pinned_peers) evParts.push(`${ev.pinned_peers} paired peer${ev.pinned_peers === 1 ? "" : "s"}`);
    if (ev.groups) evParts.push(`${ev.groups} group${ev.groups === 1 ? "" : "s"}`);
    if (ev.self_mesh_devices) evParts.push(`${ev.self_mesh_devices} self-mesh device${ev.self_mesh_devices === 1 ? "" : "s"}`);
    const evSummary = evParts.length
      ? `Current install: ${evParts.join(", ")}.`
      : "Current install has no identity state yet.";
    const dangerBlock = dirty ? `
      <div class="recwiz-danger-box">
        <strong>This will replace the current identity.</strong>
        ${escapeText(evSummary)}
        After restore, peers paired with this device will need to be
        re-paired.
      </div>
      <label class="recwiz-confirm-row">
        <input type="checkbox" id="recwiz-restore-shares-confirm" />
        <span>I understand my current identity will be replaced.</span>
      </label>` : `
      <p class="recwiz-card-meta">${escapeText(evSummary)}</p>`;
    body.innerHTML = `
      <p class="recwiz-lead">
        Paste the shares your guardians sent back. One per line, in
        the format <code>share_index:base64_bytes</code> (the format
        each guardian's Unwrap modal copies to clipboard). You need
        at least the threshold count the original split used (usually
        3 of 5).
      </p>
      <p class="recwiz-card-meta" style="margin:0 0 8px;">
        Have the 24-word phrase instead?
        <a href="#" data-recwiz-restore-mode="phrase"
           style="color:var(--accent);">Restore from phrase instead.</a>
      </p>
      <textarea class="recwiz-phrase-input" id="recwiz-restore-shares-input"
                aria-label="Guardian-delivered shares"
                autocomplete="off" spellcheck="false"
                style="min-height:140px;"
                placeholder="1:AAAA...
3:BBBB...
5:CCCC..."></textarea>
      <p class="recwiz-feedback" id="recwiz-restore-shares-fb"></p>
      ${dangerBlock}
      <div class="recwiz-card-actions" style="justify-content:flex-end;">
        <button type="button" class="recwiz-btn" data-recwiz-action="close-restore">Cancel</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-restore-shares-submit" disabled>
          ${dirty ? "Replace identity from shares" : "Restore identity from shares"}
        </button>
      </div>
    `;
    const ta = body.querySelector("#recwiz-restore-shares-input");
    const fb = body.querySelector("#recwiz-restore-shares-fb");
    const submit = body.querySelector("#recwiz-restore-shares-submit");
    const confirmBox = body.querySelector("#recwiz-restore-shares-confirm");
    function countLines() {
      return String(ta.value || "")
        .split("\n").map(l => l.trim()).filter(Boolean).length;
    }
    function check() {
      const n = countLines();
      const okShape = n >= 2;
      const okConfirm = !dirty || (confirmBox && confirmBox.checked);
      submit.disabled = !(okShape && okConfirm);
      if (n === 0) {
        fb.className = "recwiz-feedback";
        fb.textContent = "";
      } else if (n < 2) {
        fb.className = "recwiz-feedback";
        fb.textContent = "Need at least 2 share lines.";
      } else {
        fb.className = "recwiz-feedback";
        fb.textContent = `${n} share line${n === 1 ? "" : "s"} ready.`;
      }
    }
    ta.addEventListener("input", check);
    if (confirmBox) confirmBox.addEventListener("change", check);
    submit.addEventListener("click", async () => {
      submit.disabled = true;
      fb.className = "recwiz-feedback";
      fb.textContent = "Combining shares + restoring...";
      let res;
      try {
        res = await api.recoveryRestoreShares(ta.value, dirty, dirty);
      } catch (e) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = errorToastBody(e) || "Restore failed.";
        submit.disabled = false;
        return;
      }
      if (!res || !res.ok) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = (res && res.error) || "Restore failed.";
        submit.disabled = false;
        return;
      }
      body.innerHTML = `
        <div class="recwiz-restart-card">
          <strong>Identity restored from shares.</strong>
          ${res.shares_combined || 0} share${res.shares_combined === 1 ? "" : "s"}
          combined cleanly. Restart One Link to complete recovery;
          peers paired with the original device will recognize you
          again.
        </div>
        <div class="recwiz-card-actions" style="justify-content:flex-end;">
          <button type="button" class="recwiz-btn" id="recwiz-restore-shares-restart">Shut down One Link now</button>
          <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-action="close-restore">Close</button>
        </div>
      `;
      body.querySelector("#recwiz-restore-shares-restart")
        .addEventListener("click", () => _recwizShutdownDaemon("shares_restart"));
      toast("Identity restored from shares. Restart One Link to finish.", "good", 6000);
    });
    setTimeout(() => ta.focus(), 60);
  }

  function _renderRecoveryRestoreInput(preflight) {
    const modal = document.getElementById("recovery-restore-modal");
    const body = modal.querySelector(".recwiz-restore-body");
    const dirty = !!preflight.requires_force;
    const ev = preflight.evidence || {};
    const evParts = [];
    if (ev.pinned_peers) evParts.push(`${ev.pinned_peers} paired peer${ev.pinned_peers === 1 ? "" : "s"}`);
    if (ev.groups) evParts.push(`${ev.groups} group${ev.groups === 1 ? "" : "s"}`);
    if (ev.self_mesh_devices) evParts.push(`${ev.self_mesh_devices} self-mesh device${ev.self_mesh_devices === 1 ? "" : "s"}`);
    const evSummary = evParts.length
      ? `Current install: ${evParts.join(", ")}.`
      : "Current install has no identity state yet.";
    const dangerBlock = dirty ? `
      <div class="recwiz-danger-box">
        <strong>This will replace the current identity.</strong>
        ${escapeText(evSummary)}
        After restore, peers paired with this device will need to be
        re-paired. Messages encrypted to the old identity stay
        encrypted to that old key.
      </div>
      <label class="recwiz-confirm-row">
        <input type="checkbox" id="recwiz-restore-confirm" />
        <span>I understand my current identity will be replaced.</span>
      </label>` : `
      <p class="recwiz-card-meta">${escapeText(evSummary)}</p>`;
    body.innerHTML = `
      <textarea class="recwiz-phrase-input" id="recwiz-restore-phrase"
                aria-label="24 word recovery phrase"
                autocomplete="off" spellcheck="false"
                placeholder="abandon ability about ..."></textarea>
      <p class="recwiz-feedback" id="recwiz-restore-fb"></p>
      <div class="recwiz-card-meta" style="margin-top:14px;">
        <label class="recwiz-confirm-row" style="cursor:pointer;">
          <input type="checkbox" id="recwiz-restore-has-bundle" />
          <span>I also have an encrypted backup file (.olbak) to restore.</span>
        </label>
        <div id="recwiz-restore-bundle-row" hidden style="margin-top:8px;">
          <input type="file" id="recwiz-restore-bundle-file" accept=".olbak"
                 aria-label="Encrypted backup file" />
          <p class="recwiz-card-meta" id="recwiz-restore-bundle-info" style="margin-top:6px;"></p>
        </div>
      </div>
      ${dangerBlock}
      <div class="recwiz-card-actions" style="justify-content:flex-end;">
        <button type="button" class="recwiz-btn" data-recwiz-action="close-restore">Cancel</button>
        <button type="button" class="recwiz-btn recwiz-btn-primary" id="recwiz-restore-submit" disabled>
          ${dirty ? "Replace identity" : "Restore identity"}
        </button>
      </div>
    `;
    const ta = body.querySelector("#recwiz-restore-phrase");
    const fb = body.querySelector("#recwiz-restore-fb");
    const submit = body.querySelector("#recwiz-restore-submit");
    const confirmBox = body.querySelector("#recwiz-restore-confirm");
    const hasBundleBox = body.querySelector("#recwiz-restore-has-bundle");
    const bundleRow = body.querySelector("#recwiz-restore-bundle-row");
    const bundleFile = body.querySelector("#recwiz-restore-bundle-file");
    const bundleInfo = body.querySelector("#recwiz-restore-bundle-info");
    function tokenize(s) {
      return String(s || "").trim().split(/\s+/).filter(Boolean);
    }
    function check() {
      ta.classList.remove("bad");
      const tokens = tokenize(ta.value);
      const wantsBundle = hasBundleBox.checked;
      const hasBundleFile = bundleFile.files && bundleFile.files.length > 0;
      if (tokens.length === 0) {
        fb.className = "recwiz-feedback";
        fb.textContent = "";
        submit.disabled = true;
        return;
      }
      if (tokens.length < 24) {
        fb.className = "recwiz-feedback";
        fb.textContent = `${tokens.length} of 24 words.`;
        submit.disabled = true;
        return;
      }
      if (tokens.length > 24) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = `${tokens.length} words; expected exactly 24.`;
        ta.classList.add("bad");
        submit.disabled = true;
        return;
      }
      if (wantsBundle && !hasBundleFile) {
        fb.className = "recwiz-feedback";
        fb.textContent = "Pick your .olbak file to continue.";
        submit.disabled = true;
        return;
      }
      fb.className = "recwiz-feedback good";
      fb.textContent = wantsBundle
        ? "Ready to restore identity + backup."
        : "24 words detected. Checksum verifies on submit.";
      const okToSubmit = !dirty || (confirmBox && confirmBox.checked);
      submit.textContent = wantsBundle
        ? (dirty ? "Replace + restore backup" : "Restore identity + backup")
        : (dirty ? "Replace identity" : "Restore identity");
      submit.disabled = !okToSubmit;
    }
    ta.addEventListener("input", check);
    if (confirmBox) confirmBox.addEventListener("change", check);
    hasBundleBox.addEventListener("change", () => {
      bundleRow.hidden = !hasBundleBox.checked;
      if (!hasBundleBox.checked) {
        bundleFile.value = "";
        bundleInfo.textContent = "";
      }
      check();
    });
    bundleFile.addEventListener("change", () => {
      const f = bundleFile.files && bundleFile.files[0];
      if (f) {
        bundleInfo.textContent = `${f.name} (${_recwizHumanSize(f.size)})`;
      } else {
        bundleInfo.textContent = "";
      }
      check();
    });
    submit.addEventListener("click", () => _recoveryRestoreSubmit(dirty));
    setTimeout(() => ta.focus(), 60);
  }

  async function _recoveryRestoreSubmit(dirty) {
    const modal = document.getElementById("recovery-restore-modal");
    const body = modal.querySelector(".recwiz-restore-body");
    const ta = body.querySelector("#recwiz-restore-phrase");
    const fb = body.querySelector("#recwiz-restore-fb");
    const submit = body.querySelector("#recwiz-restore-submit");
    const hasBundleBox = body.querySelector("#recwiz-restore-has-bundle");
    const bundleFile = body.querySelector("#recwiz-restore-bundle-file");
    const tokens = String(ta.value || "").trim().split(/\s+/).filter(Boolean);
    if (tokens.length !== 24) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = "Need exactly 24 words.";
      ta.classList.add("bad");
      return;
    }
    const wantsBundle = hasBundleBox && hasBundleBox.checked;
    const file = bundleFile && bundleFile.files && bundleFile.files[0];
    if (wantsBundle && !file) {
      fb.className = "recwiz-feedback bad";
      fb.textContent = "Pick your .olbak file or untick the backup option.";
      return;
    }
    submit.disabled = true;
    fb.className = "recwiz-feedback";
    fb.textContent = wantsBundle
      ? "Reading backup file..."
      : "Verifying phrase and restoring...";

    if (wantsBundle) {
      if (file.size > 256 * 1024 * 1024) {
        fb.className = "recwiz-feedback bad";
        fb.textContent = "Backup exceeds the 256 MiB recovery limit.";
        submit.disabled = false;
        return;
      }
      fb.textContent = "Uploading, decrypting backup, and restoring...";
    }

    let res;
    try {
      if (wantsBundle) {
        res = await api.recoveryRestoreBundle(
          tokens.join(" "), file, dirty, dirty,
        );
      } else {
        res = await api.recoveryRestorePhrase(tokens.join(" "), dirty, dirty);
      }
    } catch (e) {
      ta.classList.add("bad");
      fb.className = "recwiz-feedback bad";
      fb.textContent = errorToastBody(e) || "Restore failed.";
      submit.disabled = false;
      return;
    }
    if (!res || !res.ok) {
      ta.classList.add("bad");
      fb.className = "recwiz-feedback bad";
      fb.textContent = (res && res.error) || "Restore failed.";
      submit.disabled = false;
      return;
    }
    // Destructive live restores are only staged here. Startup owns the
    // singleton lock and commits them before loading identity/state.
    const fromAge = wantsBundle && res.bundle_created_ms
      ? `from ${_recwizFormatRelative(res.bundle_created_ms)}`
      : "";
    const pending = !!res.recovery_pending || !!res.restart_required;
    const successMsg = pending
      ? wantsBundle
        ? `<strong>Recovery validated and staged safely.</strong> The phrase
           authenticated the backup ${escapeText(fromAge)} and
           ${res.file_count || 0} file${res.file_count === 1 ? "" : "s"}
           passed restore validation. Existing live files and keys are still
           unchanged. Shut down and start One Link once to commit the staged
           transaction before using the recovered identity.`
        : `<strong>Recovery staged safely.</strong> The phrase was accepted,
           but existing live keys are still unchanged. Shut down and start
           One Link once to commit the staged transaction before using the
           recovered identity.`
      : wantsBundle
        ? `<strong>Identity + backup restored and verified.</strong>
           ${res.file_count || 0} file${res.file_count === 1 ? "" : "s"}
           were restored from the backup ${escapeText(fromAge)}.`
        : `<strong>Identity restored and verified.</strong> Peers paired with
           the original device will recognize you again.`;
    body.innerHTML = `
      <div class="recwiz-restart-card">${successMsg}</div>
      <div class="recwiz-card-actions" style="justify-content:flex-end;">
        ${pending ? `<button type="button" class="recwiz-btn" id="recwiz-restore-restart">Shut down One Link now</button>` : ""}
        <button type="button" class="recwiz-btn recwiz-btn-primary" data-recwiz-action="close-restore">Close</button>
      </div>
    `;
    const restartBtn = body.querySelector("#recwiz-restore-restart");
    if (restartBtn) {
      restartBtn.addEventListener("click", () => _recwizShutdownDaemon("restore_restart"));
    }
    toast(
      pending
        ? "Recovery validated and staged. Restart One Link to commit it."
        : "Recovery restored and verified.",
      "good", 6000,
    );
  }

  // Small recovery-share imports retain the legacy textual base64 wire.
  // Full .olbak files use multipart Blob upload above so a 256 MiB backup
  // never expands into parallel ArrayBuffer + binary string + base64 + JSON
  // copies in the browser.
  function _recwizFileToB64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onerror = () => reject(reader.error || new Error("read failed"));
      reader.onload = () => {
        try {
          const buf = new Uint8Array(reader.result);
          let s = "";
          const CHUNK = 0x8000;
          for (let i = 0; i < buf.length; i += CHUNK) {
            s += String.fromCharCode.apply(null, buf.subarray(i, i + CHUNK));
          }
          resolve(btoa(s));
        } catch (e) { reject(e); }
      };
      reader.readAsArrayBuffer(file);
    });
  }

