  async function _opfsRoot() {
    if (!navigator.storage || !navigator.storage.getDirectory) {
      throw new Error("OPFS unavailable in this browser");
    }
    return navigator.storage.getDirectory();
  }

  async function _identityDir(create = false) {
    const root = await _opfsRoot();
    const id = await root.getDirectoryHandle(ID_DIR_NAME, { create });
    return id.getDirectoryHandle(ID_VERSION_DIR, { create });
  }

  let _identityLocalLock = Promise.resolve();
  async function _withIdentityLock(operation) {
    if (_usesOpfsIdentityBackend()) {
      return navigator.locks.request(
        ID_LOCK_NAME, { mode: "exclusive" }, operation,
      );
    }
    // IDB compare-and-swap is the cross-tab commit authority. This promise
    // additionally serializes operations within one document.
    const run = _identityLocalLock.then(operation, operation);
    _identityLocalLock = run.catch(() => undefined);
    return run;
  }

  async function _readIdentityCandidate(dir, name) {
    let fileHandle;
    try {
      fileHandle = await dir.getFileHandle(name, { create: false });
    } catch (error) {
      if (_isNotFoundError(error)) return { status: "missing" };
      throw new IdentityStorageError(`could not open ${name}`, error);
    }

    let file;
    try {
      file = await fileHandle.getFile();
    } catch (error) {
      throw new IdentityStorageError(`could not read ${name}`, error);
    }
    if (!Number.isSafeInteger(file.size) || file.size <= 0 ||
        file.size > IDENTITY_FILE_MAX_BYTES) {
      throw new IdentityCorruptionError(`${name} has an invalid size`);
    }

    let raw;
    try {
      raw = new Uint8Array(await file.arrayBuffer());
    } catch (error) {
      throw new IdentityStorageError(`could not read ${name}`, error);
    }
    if (raw.byteLength !== file.size) {
      throw new IdentityCorruptionError(`${name} changed while it was read`);
    }

    let serialized;
    try {
      serialized = new TextDecoder("utf-8", { fatal: true }).decode(raw);
    } catch (error) {
      throw new IdentityCorruptionError(`${name} is not valid UTF-8`, error);
    }
    let record;
    try {
      record = JSON.parse(serialized);
    } catch (error) {
      throw new IdentityCorruptionError(`${name} is not valid JSON`, error);
    }
    await validateIdentityObject(record);
    return { status: "valid", record, serialized };
  }

  async function _probeIdentityCandidate(dir, name) {
    try {
      return await _readIdentityCandidate(dir, name);
    } catch (error) {
      if (error instanceof IdentityCorruptionError) {
        return { status: "corrupt", error };
      }
      throw error;
    }
  }

  async function _writeIdentityFile(dir, name, serialized) {
    let fileHandle;
    try {
      fileHandle = await dir.getFileHandle(name, { create: true });
    } catch (error) {
      throw new IdentityStorageError(`could not create ${name}`, error);
    }
    let writable;
    try {
      writable = await fileHandle.createWritable({ keepExistingData: false });
      await writable.write(serialized);
      await writable.close();
    } catch (error) {
      if (writable && typeof writable.abort === "function") {
        try { await writable.abort(); } catch {}
      }
      throw new IdentityStorageError(`could not commit ${name}`, error);
    }
    const readback = await _readIdentityCandidate(dir, name);
    if (readback.status !== "valid" || readback.serialized !== serialized) {
      throw new IdentityStorageError(`${name} failed exact read-back verification`);
    }
    return readback.record;
  }

  async function _removePendingIdentity(dir) {
    try {
      await dir.removeEntry(ID_PENDING_FILE);
    } catch (error) {
      if (!_isNotFoundError(error)) {
        // The committed authority is already exact and verified. A leftover
        // same-identity stage is harmless and will be reconciled next boot.
        console.warn("identity stage cleanup failed", error);
      }
    }
  }

  function _samePublicIdentity(left, right) {
    return left.fingerprint === right.fingerprint &&
      left.public_key_b64u === right.public_key_b64u &&
      left.created_ms === right.created_ms;
  }

  async function _recoverPendingIdentity(dir, pending) {
    const serialized = pending.serialized;
    await _writeIdentityFile(dir, ID_FILE, serialized);
    await _removePendingIdentity(dir);
    return pending.record;
  }

  async function _readIdentityUnlocked() {
    if (!_usesOpfsIdentityBackend()) {
      return _readIdentityIdb();
    }
    let dir;
    try {
      dir = await _identityDir(false);
    } catch (error) {
      if (_isNotFoundError(error)) return null;
      throw new IdentityStorageError("could not open browser identity directory", error);
    }

    const current = await _probeIdentityCandidate(dir, ID_FILE);
    const pending = await _probeIdentityCandidate(dir, ID_PENDING_FILE);

    if (current.status === "valid") {
      if (pending.status === "valid" &&
          !_samePublicIdentity(current.record, pending.record)) {
        throw new IdentityCorruptionError(
          "conflicting committed and staged browser identities exist",
        );
      }
      if (pending.status === "valid" &&
          pending.serialized === current.serialized) {
        await _removePendingIdentity(dir);
      } else if (pending.status === "valid") {
        // The committed name is authority. A same-key stage with different
        // envelope bytes is an interrupted mutation, not authorization to
        // finish that mutation after a crash.
        await _removePendingIdentity(dir);
      }
      return current.record;
    }

    // A staged key is self-consistent, not continuity-authorized. Never let an
    // unrelated valid stage replace a corrupt committed authority. Automatic
    // stage recovery is allowed only when the committed name is truly absent.
    if (current.status === "corrupt") {
      throw current.error;
    }
    if (pending.status === "corrupt") {
      throw pending.error;
    }
    if (pending.status === "valid") {
      return _recoverPendingIdentity(dir, pending);
    }
    return null;
  }

  async function readIdentity() {
    return _withIdentityLock(_readIdentityUnlocked);
  }

  async function _writeIdentityUnlocked(rec) {
    if (!_usesOpfsIdentityBackend()) {
      throw new IdentityStorageError(
        "IndexedDB identity writes require compare-and-swap",
      );
    }
    await validateIdentityObject(rec);
    const serialized = JSON.stringify(rec);
    if (new TextEncoder().encode(serialized).byteLength > IDENTITY_FILE_MAX_BYTES) {
      throw new IdentityStorageError("identity record exceeds the storage ceiling");
    }
    const dir = await _identityDir(true);
    await _writeIdentityFile(dir, ID_PENDING_FILE, serialized);
    await _writeIdentityFile(dir, ID_FILE, serialized);
    await _removePendingIdentity(dir);
    return rec;
  }

  async function writeIdentity(rec) {
    if (!isWrappedEnvelope(rec)) {
      throw new IdentityStorageError(
        "refusing to commit browser private-key material without encryption",
      );
    }
    return _withIdentityLock(async () => {
      if (!_usesOpfsIdentityBackend()) {
        return _compareAndSwapIdentityIdb(null, rec);
      }
      const current = await _readIdentityUnlocked();
      if (current !== null) {
        throw new IdentityStorageError(
          "identity authority already exists; use compare-and-swap rotation",
        );
      }
      return _writeIdentityUnlocked(rec);
    });
  }

  function _sameIdentityAuthority(left, right) {
    if (left === null || right === null) return left === right;
    try {
      return _canonicalJson(left) === _canonicalJson(right);
    } catch {
      return false;
    }
  }

  async function _replaceIdentityAuthority(expected, replacement) {
    if (!isWrappedEnvelope(replacement)) {
      throw new IdentityStorageError(
        "replacement identity must be an encrypted envelope",
      );
    }
    await validateWrappedIdentityEnvelope(replacement);
    return _withIdentityLock(async () => {
      if (!_usesOpfsIdentityBackend()) {
        return _compareAndSwapIdentityIdb(expected, replacement);
      }
      const current = await _readIdentityUnlocked();
      if (!_sameIdentityAuthority(current, expected)) {
        throw new IdentityStorageError(
          "identity changed in another tab; reload before continuing",
        );
      }
      await _writeIdentityUnlocked(replacement);
      const committed = await _readIdentityUnlocked();
      if (!_sameIdentityAuthority(committed, replacement)) {
        throw new IdentityStorageError(
          "encrypted identity did not survive exact commit verification",
        );
      }
      return committed;
    });
  }

  // Browser private keys are committed only inside a v2 AES-256-GCM
  // envelope. Its key is derived by the first-party, digest-pinned RustCrypto
  // Argon2id WASM worker using one exact production profile. Public identity
  // fields remain visible for locked-state diagnostics and are authenticated
  // as AES-GCM AAD. PBKDF2 v1 is decrypt-only for atomic migration.
