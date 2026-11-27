  // ── reset / export wiring ───────────────────────────────────────────
  $("#btn-reset")?.addEventListener("click", async () => {
    if (!confirm(
      "Reset this device's identity? You'll lose access to anything paired " +
      "with the current keypair. There's no undo."
    )) return;
    try {
      await deleteIdentity();
    } catch (e) {
      alert(`Couldn't delete identity: ${e && e.message ? e.message : e}`);
      return;
    }
    location.reload();
  });
  $("#btn-export")?.addEventListener("click", async () => {
    let rec;
    try {
      rec = await readIdentity();
    } catch (e) {
      alert(`Couldn't read identity: ${e && e.message ? e.message : e}`);
      return;
    }
    if (!rec) {
      alert("No identity to export.");
      return;
    }
    const blob = new Blob(
      [JSON.stringify(rec, null, 2)],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `one-link-identity-${rec.fingerprint.slice(7, 19)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  });

  // ── unlock wiring ───────────────────────────────────────────────────
  async function _runUnlockFromInput() {
    const input = $("#unlock-passphrase");
    const status = $("#unlock-status");
    if (!input) return;
    const pass = input.value;
    if (!pass) {
      text(status, "Enter your passphrase.");
      show(status);
      return;
    }
    hide(status);
    text(status, "");
    const btn = $("#btn-unlock");
    if (btn) btn.disabled = true;
    setDiag("Unlocking. This takes a second.");
    try {
      await _unlockWith(pass);
      input.value = "";
      setDiag("identity unlocked and Argon2id envelope verified");
    } catch (e) {
      const detail = e instanceof IdentityStorageError &&
        !(e instanceof IdentityKdfError)
        ? "Unlock succeeded, but secure migration or storage verification failed. " +
          "The old identity was preserved; reload and try again."
        : "Wrong passphrase, authenticated data, or KDF integrity failure. Try again.";
      text(status, detail);
      show(status);
      input.select();
    } finally {
      if (btn) btn.disabled = false;
    }
  }
  $("#btn-unlock")?.addEventListener("click", _runUnlockFromInput);
  $("#unlock-passphrase")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") _runUnlockFromInput();
  });

  async function _runIdentitySetup() {
    const passInput = $("#identity-setup-passphrase");
    const confirmInput = $("#identity-setup-confirm");
    const status = $("#identity-setup-status");
    const button = $("#btn-identity-setup");
    if (!passInput || !confirmInput || !state.pending_rec) return;
    const passphrase = passInput.value;
    if (passphrase.length < IDENTITY_PASSPHRASE_MIN_CHARS) {
      text(status,
        `Use at least ${IDENTITY_PASSPHRASE_MIN_CHARS} characters.`);
      show(status);
      passInput.focus();
      return;
    }
    if (passphrase !== confirmInput.value) {
      text(status, "Passphrases do not match.");
      show(status);
      confirmInput.focus();
      return;
    }
    hide(status);
    button.disabled = true;
    setDiag("deriving Argon2id key and committing encrypted identity…");
    const rec = state.pending_rec;
    const expected = state.pending_authority;
    try {
      const envelope = await wrapIdentity(rec, passphrase);
      const committed = await _replaceIdentityAuthority(expected, envelope);
      passInput.value = "";
      confirmInput.value = "";
      _markIdentityReady(rec, committed);
      setDiag("encrypted identity committed and read back exactly");
      _dispatchPostIdentityFlow();
    } catch (error) {
      text(status,
        error && error.message
          ? `Identity protection failed closed: ${error.message}`
          : "Identity protection failed closed.");
      show(status);
      passInput.select();
    } finally {
      // DOM strings cannot be zeroized by JavaScript; clear both controls at
      // every terminal path so the browser does not retain visible secrets.
      confirmInput.value = "";
      button.disabled = false;
    }
  }

  $("#btn-identity-setup")?.addEventListener("click", _runIdentitySetup);
  $("#identity-setup-confirm")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") _runIdentitySetup();
  });

  // ── passphrase rotation wiring ──────────────────────────────────────
  $("#btn-set-passphrase")?.addEventListener("click", async () => {
    if (!state.rec || !state.envelope || state.envelope.v !== 2) {
      alert("Identity not loaded yet.");
      return;
    }
    const pass1 = prompt(
      `Enter a new passphrase (${IDENTITY_PASSPHRASE_MIN_CHARS}+ characters).`,
    );
    if (pass1 == null) return;
    if (pass1.length < IDENTITY_PASSPHRASE_MIN_CHARS) {
      alert(
        `Passphrase too short. Use at least ${IDENTITY_PASSPHRASE_MIN_CHARS} characters.`,
      );
      return;
    }
    const pass2 = prompt("Re-enter passphrase to confirm.");
    if (pass2 == null) return;
    if (pass2 !== pass1) {
      alert("Passphrases don't match. Try again.");
      return;
    }
    const expected = state.envelope;
    let replacement;
    try {
      replacement = await wrapIdentity(state.rec, pass1);
    } catch (e) {
      alert(`Couldn't wrap identity: ${e && e.message ? e.message : e}`);
      return;
    }
    try {
      const committed = await _replaceIdentityAuthority(expected, replacement);
      peerIdentity.setEnvelope(committed);
    } catch (e) {
      alert(`Couldn't persist wrapped identity: ${e && e.message ? e.message : e}`);
      return;
    }
    _renderIdentityCard(state.rec);
    alert("Passphrase changed. The Argon2id envelope was rotated atomically.");
  });

