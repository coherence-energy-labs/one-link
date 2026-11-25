  function _usesOpfsIdentityBackend() {
    return !!(navigator.storage && navigator.storage.getDirectory &&
      navigator.locks && typeof navigator.locks.request === "function");
  }

  function _identityStorageLabel() {
    return _usesOpfsIdentityBackend()
      ? "opfs:identity/v1/keypair.json"
      : "indexeddb:one-link-browser-identity-v1/authority";
  }

  function _idbRequest(request, label) {
    return new Promise((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new IdentityStorageError(
        `${label} failed`, request.error,
      ));
    });
  }

  function _idbTransactionDone(transaction, label) {
    return new Promise((resolve, reject) => {
      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(new IdentityStorageError(
        `${label} failed`, transaction.error,
      ));
      transaction.onabort = () => reject(new IdentityStorageError(
        `${label} aborted`, transaction.error,
      ));
    });
  }

  function _openIdentityIdb() {
    if (typeof indexedDB === "undefined") {
      return Promise.reject(new IdentityStorageError(
        "this browser exposes neither coordinated OPFS nor IndexedDB",
      ));
    }
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(IDB_IDENTITY_DB, 1);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(IDB_IDENTITY_STORE)) {
          db.createObjectStore(IDB_IDENTITY_STORE);
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new IdentityStorageError(
        "could not open transactional browser identity storage", request.error,
      ));
      request.onblocked = () => reject(new IdentityStorageError(
        "browser identity storage upgrade is blocked by another tab",
      ));
    });
  }

  async function _parseIdentitySerialized(serialized, label) {
    if (typeof serialized !== "string") {
      throw new IdentityCorruptionError(`${label} is not serialized text`);
    }
    const size = new TextEncoder().encode(serialized).byteLength;
    if (size <= 0 || size > IDENTITY_FILE_MAX_BYTES) {
      throw new IdentityCorruptionError(`${label} has an invalid size`);
    }
    let record;
    try {
      record = JSON.parse(serialized);
    } catch (error) {
      throw new IdentityCorruptionError(`${label} is not valid JSON`, error);
    }
    await validateIdentityObject(record);
    return record;
  }

  async function _readIdentityIdb() {
    const db = await _openIdentityIdb();
    try {
      const tx = db.transaction(IDB_IDENTITY_STORE, "readonly");
      const done = _idbTransactionDone(tx, "browser identity read");
      const raw = await _idbRequest(
        tx.objectStore(IDB_IDENTITY_STORE).get(IDB_IDENTITY_KEY),
        "browser identity read",
      );
      await done;
      if (raw === undefined) return null;
      return _parseIdentitySerialized(raw, "browser identity authority");
    } finally {
      db.close();
    }
  }

  async function _compareAndSwapIdentityIdb(expected, replacement) {
    await validateWrappedIdentityEnvelope(replacement);
    const expectedRaw = expected === null ? undefined : JSON.stringify(expected);
    const replacementRaw = JSON.stringify(replacement);
    if (new TextEncoder().encode(replacementRaw).byteLength >
        IDENTITY_FILE_MAX_BYTES) {
      throw new IdentityStorageError("identity record exceeds the storage ceiling");
    }
    const db = await _openIdentityIdb();
    try {
      const tx = db.transaction(IDB_IDENTITY_STORE, "readwrite");
      const done = _idbTransactionDone(tx, "browser identity compare-and-swap");
      const store = tx.objectStore(IDB_IDENTITY_STORE);
      const currentRaw = await _idbRequest(
        store.get(IDB_IDENTITY_KEY), "browser identity authority read",
      );
      if (currentRaw !== expectedRaw) {
        tx.abort();
        try { await done; } catch {}
        throw new IdentityStorageError(
          "identity changed in another tab; reload before continuing",
        );
      }
      await _idbRequest(
        store.put(replacementRaw, IDB_IDENTITY_KEY),
        "browser identity authority write",
      );
      await done;
    } finally {
      db.close();
    }
    const committed = await _readIdentityIdb();
    if (!_sameIdentityAuthority(committed, replacement)) {
      throw new IdentityStorageError(
        "encrypted identity did not survive exact commit verification",
      );
    }
    return committed;
  }

  async function _deleteIdentityIdb() {
    const db = await _openIdentityIdb();
    try {
      const tx = db.transaction(IDB_IDENTITY_STORE, "readwrite");
      const done = _idbTransactionDone(tx, "browser identity deletion");
      await _idbRequest(
        tx.objectStore(IDB_IDENTITY_STORE).delete(IDB_IDENTITY_KEY),
        "browser identity deletion",
      );
      await done;
    } finally {
      db.close();
    }
  }

