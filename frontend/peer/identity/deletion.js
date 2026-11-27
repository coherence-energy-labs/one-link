  async function _deleteIdentityUnlocked() {
    if (!_usesOpfsIdentityBackend()) {
      return _deleteIdentityIdb();
    }
    const root = await _opfsRoot();
    try {
      await root.getDirectoryHandle(ID_DIR_NAME, { create: false });
    } catch (error) {
      if (_isNotFoundError(error)) return;
      throw new IdentityStorageError("could not inspect browser identity", error);
    }
    try {
      await root.removeEntry(ID_DIR_NAME, { recursive: true });
    } catch (error) {
      throw new IdentityStorageError("could not reset browser identity", error);
    }
  }

  async function deleteIdentity() {
    const ownerFp = state && state.rec ? state.rec.fingerprint : null;
    const result = await _withIdentityLock(_deleteIdentityUnlocked);
    if (ownerFp) await clearChatOutboxForOwner(ownerFp);
    return result;
  }

  // Narrow raw authority hooks for executable storage-failure tests. Same-
  // origin script already has direct OPFS/IDB access; these add no privilege.
  async function _identityTestReadRaw(slot = "primary") {
    if (slot !== "primary" && slot !== "pending") {
      throw new Error("invalid identity test slot");
    }
    if (_usesOpfsIdentityBackend()) {
      const dir = await _identityDir(false);
      const name = slot === "primary" ? ID_FILE : ID_PENDING_FILE;
      try {
        return await (await (await dir.getFileHandle(name)).getFile()).text();
      } catch (error) {
        if (_isNotFoundError(error)) return null;
        throw error;
      }
    }
    const db = await _openIdentityIdb();
    try {
      const tx = db.transaction(IDB_IDENTITY_STORE, "readonly");
      const done = _idbTransactionDone(tx, "identity test read");
      const key = slot === "primary" ? IDB_IDENTITY_KEY : "pending-test";
      const raw = await _idbRequest(
        tx.objectStore(IDB_IDENTITY_STORE).get(key), "identity test read",
      );
      await done;
      return raw === undefined ? null : raw;
    } finally {
      db.close();
    }
  }

  async function _identityTestWriteRaw(slot, raw) {
    if ((slot !== "primary" && slot !== "pending") || typeof raw !== "string") {
      throw new Error("invalid identity test write");
    }
    if (_usesOpfsIdentityBackend()) {
      const dir = await _identityDir(true);
      const name = slot === "primary" ? ID_FILE : ID_PENDING_FILE;
      const handle = await dir.getFileHandle(name, { create: true });
      const stream = await handle.createWritable();
      await stream.write(raw);
      await stream.close();
      return;
    }
    const db = await _openIdentityIdb();
    try {
      const tx = db.transaction(IDB_IDENTITY_STORE, "readwrite");
      const done = _idbTransactionDone(tx, "identity test write");
      const key = slot === "primary" ? IDB_IDENTITY_KEY : "pending-test";
      await _idbRequest(
        tx.objectStore(IDB_IDENTITY_STORE).put(raw, key), "identity test write",
      );
      await done;
    } finally {
      db.close();
    }
  }

  async function _identityTestDeleteRaw(slot) {
    if (slot !== "primary" && slot !== "pending") {
      throw new Error("invalid identity test delete");
    }
    if (_usesOpfsIdentityBackend()) {
      const dir = await _identityDir(false);
      const name = slot === "primary" ? ID_FILE : ID_PENDING_FILE;
      try { await dir.removeEntry(name); } catch (error) {
        if (!_isNotFoundError(error)) throw error;
      }
      return;
    }
    const db = await _openIdentityIdb();
    try {
      const tx = db.transaction(IDB_IDENTITY_STORE, "readwrite");
      const done = _idbTransactionDone(tx, "identity test delete");
      const key = slot === "primary" ? IDB_IDENTITY_KEY : "pending-test";
      await _idbRequest(
        tx.objectStore(IDB_IDENTITY_STORE).delete(key), "identity test delete",
      );
      await done;
    } finally {
      db.close();
    }
  }

