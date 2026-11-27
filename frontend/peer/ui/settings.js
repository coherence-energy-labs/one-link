  // ── Phase 3b: phone Settings card ─────────────────────────────────
  // Surfaces device identity + paired daemon + sign-out. Reachable
  // from the ⚙ button on the chat roster.

  async function _openPhoneSettings() {
    _showOnly("#phone-settings-card");
    const labelEl = $("#phone-settings-device-label");
    const fpEl = $("#phone-settings-device-fp");
    const pairedEl = $("#phone-settings-device-paired");
    const daemonLabelEl = $("#phone-settings-daemon-label");
    const daemonFpEl = $("#phone-settings-daemon-fp");
    const daemonStatusEl = $("#phone-settings-daemon-status");
    const signoutStatusEl = $("#phone-settings-signout-status");
    if (signoutStatusEl) signoutStatusEl.textContent = "";

    // Device identity from in-memory state + localStorage cert.
    let cert = null;
    try {
      const raw = localStorage.getItem(SELF_MESH_CERT_KEY);
      if (raw) cert = JSON.parse(raw);
    } catch (_e) { cert = null; }
    const rec = state.rec || {};
    if (labelEl) {
      labelEl.textContent = (cert && cert.label) || rec.label || "This device";
    }
    if (fpEl) {
      fpEl.textContent = rec.fingerprint || (cert && cert.fingerprint) || "—";
    }
    if (pairedEl) {
      if (cert && cert.claimed_ms) {
        try {
          const when = new Date(cert.claimed_ms).toLocaleString();
          pairedEl.textContent = `Paired ${when}`;
        } catch {
          pairedEl.textContent = "Paired";
        }
      } else {
        pairedEl.textContent = "Not yet paired";
      }
    }

    // Daemon — pull a live fetch_self over the DC if registered,
    // else fall back to the cert's root_pub_b64 (less useful).
    if (daemonLabelEl) daemonLabelEl.textContent = "—";
    if (daemonFpEl) daemonFpEl.textContent = "—";
    if (daemonStatusEl) daemonStatusEl.textContent = "Checking link…";
    try {
      const selfReply = await _daemonRequest("fetch_self", {});
      if (daemonLabelEl) {
        daemonLabelEl.textContent =
          selfReply.hostname || selfReply.short_id || "Laptop";
      }
      if (daemonFpEl) {
        daemonFpEl.textContent = selfReply.fingerprint || "—";
      }
      if (daemonStatusEl) {
        daemonStatusEl.innerHTML =
          '<span style="color:#3a3;">● Connected</span>';
      }
    } catch (e) {
      if (daemonStatusEl) {
        daemonStatusEl.innerHTML =
          '<span style="color:#a44;">● Not connected</span> ' +
          `<span style="color:var(--text-dim);">— ${e && e.message ? e.message : e}</span>`;
      }
      if (cert && cert.root_pub_b64 && daemonFpEl) {
        daemonFpEl.textContent = `root: ${cert.root_pub_b64}`;
      }
    }
  }

  function _closePhoneSettings() {
    _showOnly("#daemon-roster-card");
  }

  async function _handlePhoneSignOut() {
    const statusEl = $("#phone-settings-signout-status");
    if (!confirm(
      "Sign out and re-pair?\n\n" +
      "This device's identity in this browser will be removed. " +
      "Other devices in your One identity will see this device " +
      "as offline until you re-pair."
    )) {
      return;
    }
    if (statusEl) statusEl.textContent = "Removing local identity…";
    try {
      // Drop OPFS keypair so identity boot starts from scratch
      // next visit.
      try { await deleteIdentity(); } catch (_e) { /* may not exist */ }
      // Drop pair-cert from localStorage so the welcome card shows
      // instead of trying to re-use a stale cert.
      try { localStorage.removeItem(SELF_MESH_CERT_KEY); } catch (_e) {}
      // Best-effort drop of any saved daemon peer entry in OPFS.
      try {
        if (typeof savePeer === "function" && state._pendingDaemonPubkey) {
          // No public deletePeer surface; OPFS cleanup will get the
          // peer entry on the next pair attempt (savePeer overwrites
          // by fingerprint).
        }
      } catch (_e) {}
      if (statusEl) statusEl.textContent = "Signed out. Reloading…";
      // Tiny pause so the user sees the confirmation, then hard
      // reload so every in-memory state (DC, peers, roster) is
      // dropped cleanly.
      setTimeout(() => { window.location.reload(); }, 400);
    } catch (e) {
      if (statusEl) {
        statusEl.textContent =
          `Sign out failed: ${e && e.message ? e.message : e}`;
      }
    }
  }

  $("#btn-phone-settings")?.addEventListener("click", _openPhoneSettings);
  $("#btn-phone-settings-back")?.addEventListener("click", _closePhoneSettings);
  $("#btn-phone-settings-signout")?.addEventListener("click", _handlePhoneSignOut);

  // 2026-05-23 phase A file-RECEIVE: chunked download from daemon.
  // Mirror of the upload protocol — server caps chunks at 16 KiB
  // (under aiortc's 64 KiB SCTP cap, same as send_file_chunk).
  // Phone polls fetch_blob_chunk until eof:true, assembles a Blob,
  // triggers a browser download.
