  // ── boot ────────────────────────────────────────────────────────────
  async function boot() {
    // Quick-fail UX: detect missing platform features early so the
    // user gets a clear message instead of a JS console error.
    // v0.20.4 — also surface insecure-context as the FIRST check;
    // many phones land here with crypto.subtle present but
    // restricted, and "no web crypto" is misleading in that case.
    if (!window.isSecureContext) {
      state.boot_error_msg = "page loaded over plain HTTP; Web Crypto needs HTTPS";
      setPill("bad", "needs https");
      text($("#ident-status"),
        "This page needs to load over https://, not http://. " +
        "Open the QR code on your laptop again and scan it - the " +
        "fresh link will work.");
      return;
    }
    if (!window.crypto || !crypto.subtle) {
      state.boot_error_msg = "Web Crypto not exposed";
      setPill("bad", "browser too old");
      text($("#ident-status"),
        "Your browser is too old to run One Link safely. " +
        "Update Safari (iOS 17 or newer), Chrome, Edge, or " +
        "Firefox, then try again.");
      return;
    }
    if ((!navigator.storage || !navigator.storage.getDirectory) &&
        typeof indexedDB === "undefined") {
      state.boot_error_msg = "origin-private storage not exposed";
      setPill("bad", "browser too old");
      text($("#ident-status"),
        "Your browser doesn't support the origin-private storage One Link " +
        "uses to remember your identity. Update Safari, " +
        "Chrome (86+), Edge (86+), or Firefox (111+) and try again.");
      return;
    }

    setDiag(`checking ${_identityStorageLabel()}…`);
    let loaded;
    try {
      loaded = await _loadOrCreateIdentity();
    } catch (error) {
      _showIdentityStorageFailure(error);
      return;
    }
    const onDisk = loaded.record;

    // Wrapped envelope on disk -> show unlock gate. Boot stops here until the
    // authenticated private identity is available. Legacy PBKDF2 migrates
    // before this state can become ready.
    if (isWrappedEnvelope(onDisk)) {
      state.envelope = onDisk;
      await _showUnlockGate(onDisk);
      return;
    }

    // Fresh or legacy plaintext records are never network-capable. They remain
    // gated until an Argon2id envelope wins the storage CAS.
    if (onDisk) {
      _showIdentitySetupGate(onDisk, loaded.created ? null : onDisk);
      return;
    }
  }

