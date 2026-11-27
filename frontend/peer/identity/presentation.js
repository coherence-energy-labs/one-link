  function _renderIdentityCard(rec) {
    setPill("good", "ready");
    text($("#ident-status"), "Identity loaded.");
    text($("#ident-fp"), rec.fingerprint);
    text($("#ident-pub"), rec.public_key_b64u);
    show($("#ident-fp-wrap"));
    show($("#ident-pub-wrap"));
    show($("#actions-card"));
    const setBtn = $("#btn-set-passphrase");
    if (setBtn) setBtn.textContent = "Change passphrase";
    text($("#passphrase-help"),
      "Identity private-key material is encrypted on disk with Argon2id and " +
      "AES-256-GCM. Change the passphrase to rotate that encryption.");
  }

  function _showIdentitySetupGate(rec, currentAuthority) {
    peerIdentity.stagePending(rec, currentAuthority);
    hide($("#unlock-card"));
    hide($("#actions-card"));
    show($("#identity-setup-card"));
    setPill("warn", "protection required");
    text($("#ident-fp"), rec.fingerprint);
    text($("#ident-pub"), rec.public_key_b64u);
    show($("#ident-fp-wrap"));
    show($("#ident-pub-wrap"));
    if (currentAuthority === null) {
      text($("#ident-status"),
        "A fresh identity is ready in memory. Protect it before it is saved or used.");
      text($("#identity-setup-copy"),
        "Create a passphrase before this device can pair or connect. One Link " +
        "will encrypt the private identity before the first storage commit.");
      setDiag(`${_identityStorageLabel()} · generated in memory · awaiting encrypted commit`);
    } else {
      text($("#ident-status"),
        "A legacy plaintext identity is blocked until it is encrypted.");
      text($("#identity-setup-copy"),
        "This browser contains a legacy plaintext identity. Create a passphrase " +
        "to migrate it atomically before pairing or connecting.");
      setDiag(`${_identityStorageLabel()} · legacy plaintext blocked · awaiting encrypted migration`);
    }
    $("#identity-setup-passphrase")?.focus();
  }

  function _markIdentityReady(rec, envelope) {
    peerIdentity.unlock(rec, envelope);
    hide($("#identity-setup-card"));
    hide($("#unlock-card"));
    _renderIdentityCard(rec);
  }

  async function _showUnlockGate(envelope) {
    // Hide the actions card while locked — user can't export or
    // reset until unlocked. Reset is reachable via the unlock-failure
    // path (via prompt), which we'll route below.
    hide($("#actions-card"));
    show($("#unlock-card"));
    text($("#ident-status"),
      "Identity exists on disk but is encrypted. Enter your passphrase to unlock.");
    setPill("warn", "locked");
    text($("#ident-fp"), envelope.fingerprint);
    text($("#ident-pub"), envelope.public_key_b64u);
    show($("#ident-fp-wrap"));
    show($("#ident-pub-wrap"));
    setDiag(
      `${_identityStorageLabel()} · wrapped ` +
      `${envelope.wrapped_ms ? new Date(envelope.wrapped_ms).toLocaleString() : ""}`
    );
    // Auto-focus the passphrase input on phones too — the
    // virtual keyboard pops if focus + click; otherwise focus
    // alone is enough on desktop.
    const input = $("#unlock-passphrase");
    if (input) {
      try { input.focus(); } catch {}
    }
  }

  async function _unlockWith(passphrase) {
    if (!state.envelope) return;
    const expected = state.envelope;
    const rec = await unwrapIdentity(expected, passphrase);
    let committed = expected;
    if (expected.v === 1) {
      // Legacy PBKDF2 is decrypt-only. Do not expose the private identity to
      // networking until the Argon2id migration is durable and read back.
      const migrated = await _wrapIdentityV2(rec, passphrase, 1);
      committed = await _replaceIdentityAuthority(expected, migrated);
    }
    _markIdentityReady(rec, committed);
    _dispatchPostIdentityFlow();
  }

  async function _loadOrCreateIdentity() {
    return _withIdentityLock(async () => {
      const onDisk = await _readIdentityUnlocked();
      if (onDisk !== null) {
        return { record: onDisk, created: false };
      }

      // Absence is established while holding the cross-tab lock. Generate only
      // in memory: a private JWK is never newly published before the user has
      // supplied an encryption passphrase. Final publication uses CAS.
      setPill("warn", "generating");
      text($("#ident-status"), "Generating a fresh keypair…");
      setDiag("calling crypto.subtle.generateKey…");
      const rec = await generateIdentity();
      return { record: rec, created: true };
    });
  }

  function _showIdentityStorageFailure(error) {
    const message = error && error.message ? error.message : String(error);
    peerIdentity.failBoot(`identity storage blocked: ${message}`);
    setPill("bad", "identity blocked");
    setDiag(`${_identityStorageLabel()} blocked: ${message}`);
    text(
      $("#ident-status"),
      "An existing identity could not be verified. One Link did not replace " +
      "it or connect to peers. Restore a known-good backup, or explicitly " +
      "reset this device if you accept losing its current pairings.",
    );
    hide($("#unlock-card"));
    hide($("#ident-fp-wrap"));
    hide($("#ident-pub-wrap"));
    if (error instanceof IdentityCorruptionError) {
      show($("#actions-card"));
      hide($("#btn-export"));
      hide($("#btn-set-passphrase"));
      show($("#btn-reset"));
      text(
        $("#passphrase-help"),
        "Reset is destructive and never automatic. It removes the unreadable " +
        "identity only after your confirmation.",
      );
    } else {
      hide($("#actions-card"));
    }
  }

