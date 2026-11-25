  async function _peersDir(create = false) {
    const root = await _opfsRoot();
    const peers = await root.getDirectoryHandle(PEERS_DIR_NAME, { create });
    return peers.getDirectoryHandle(PEERS_VERSION_DIR, { create });
  }

  async function _withPeersLock(mode, operation) {
    if (!navigator.locks || typeof navigator.locks.request !== "function") {
      throw new Error("Web Locks are required for collision-safe peer storage");
    }
    return navigator.locks.request(
      PEERS_LOCK_NAME, { mode }, operation,
    );
  }

  function _peerFileName(fingerprint, suffix = 0) {
    // Strip the `algo:` prefix and grab a hex prefix as the on-disk
    // filename. The prefix is never treated as identity: a collision
    // gets a numeric suffix under a cross-tab lock. Keeping the file name a hex
    // prefix means a casual filesystem peek doesn't reveal full
    // pubkeys.
    const canonical = _canonicalSha256Fingerprint(fingerprint);
    if (!Number.isSafeInteger(suffix) || suffix < 0 ||
        suffix > PEER_FILE_MAX_SUFFIX) {
      throw new Error("peer filename suffix is outside the storage bound");
    }
    const hex = canonical.split(":").pop();
    const stem = hex.slice(0, PEER_FILE_PREFIX_HEX_CHARS);
    return suffix === 0 ? `${stem}.json` : `${stem}-${suffix}.json`;
  }

  function _peerTimestamp(value, label) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer`);
    }
    return value;
  }

  async function _validatePeerRecord(rec) {
    _requireExactKeys(
      rec,
      ["fingerprint", "public_key_b64u", "v"],
      PEER_RECORD_KEYS.filter((key) =>
        key !== "fingerprint" && key !== "public_key_b64u" && key !== "v"
      ),
      "peer record",
    );
    if (rec.v !== 1) throw new Error("unsupported peer record version");
    const binding = await _validatePeerBinding(
      rec.fingerprint, rec.public_key_b64u, "peer record",
    );
    const alias = rec.alias === undefined ? "" : rec.alias;
    if (typeof alias !== "string" || alias.length > PAIR_ALIAS_MAX_CHARS ||
        /[\u0000-\u001f\u007f]/.test(alias)) {
      throw new Error("peer alias is invalid or too large");
    }
    const pairedMs = rec.paired_ms === undefined
      ? 0 : _peerTimestamp(rec.paired_ms, "paired_ms");
    const lastSeenMs = rec.last_seen_ms === undefined
      ? pairedMs : _peerTimestamp(rec.last_seen_ms, "last_seen_ms");
    if (rec.sas_digits !== undefined && rec.sas_digits !== null &&
        (typeof rec.sas_digits !== "string" || !/^\d{6}$/.test(rec.sas_digits))) {
      throw new Error("sas_digits must be six decimal digits or null");
    }
    if (rec.paired_via !== undefined &&
        (typeof rec.paired_via !== "string" ||
         !/^[a-z0-9_-]{1,32}$/.test(rec.paired_via))) {
      throw new Error("paired_via is invalid");
    }
    const normalized = {
      v: 1,
      fingerprint: binding.fingerprint,
      public_key_b64u: binding.public_key_b64u,
      alias,
      paired_ms: pairedMs,
      last_seen_ms: lastSeenMs,
    };
    if (Object.prototype.hasOwnProperty.call(rec, "sas_digits")) {
      normalized.sas_digits = rec.sas_digits;
    }
    if (Object.prototype.hasOwnProperty.call(rec, "paired_via")) {
      normalized.paired_via = rec.paired_via;
    }
    return normalized;
  }

  async function _readPeerEntry(name, handle) {
    const fileNamePattern = new RegExp(
      `^([0-9a-f]{${PEER_FILE_PREFIX_HEX_CHARS}})` +
      `(?:-([1-9][0-9]{0,4}))?\\.json$`,
    );
    const match = fileNamePattern.exec(name);
    if (!match) throw new Error(`unrecognized peer roster entry: ${name}`);
    const suffix = match[2] ? Number(match[2]) : 0;
    if (!Number.isSafeInteger(suffix) || suffix > PEER_FILE_MAX_SUFFIX) {
      throw new Error(`peer roster suffix is outside the bound: ${name}`);
    }
    const file = await handle.getFile();
    if (!Number.isSafeInteger(file.size) || file.size <= 0 ||
        file.size > PEER_RECORD_MAX_BYTES) {
      throw new Error(`peer roster entry has an invalid size: ${name}`);
    }
    const serialized = await file.text();
    if (new TextEncoder().encode(serialized).byteLength !== file.size) {
      throw new Error(`peer roster entry changed while being read: ${name}`);
    }
    let parsed;
    try {
      parsed = JSON.parse(serialized);
    } catch (_) {
      throw new Error(`peer roster entry is not valid JSON: ${name}`);
    }
    const record = await _validatePeerRecord(parsed);
    if (_peerFileName(record.fingerprint, suffix) !== name) {
      throw new Error(`peer roster filename does not match its fingerprint: ${name}`);
    }
    return { handle, name, record, serialized, suffix };
  }

  async function _readAllPeerEntries(dir) {
    const out = [];
    const byFingerprint = new Map();
    for await (const [name, handle] of dir.entries()) {
      if (handle.kind !== "file") {
        throw new Error(`unexpected non-file peer roster entry: ${name}`);
      }
      const entry = await _readPeerEntry(name, handle);
      if (byFingerprint.has(entry.record.fingerprint)) {
        throw new Error(
          `duplicate peer fingerprint authority: ${entry.record.fingerprint}`,
        );
      }
      byFingerprint.set(entry.record.fingerprint, entry);
      out.push(entry);
    }
    return out;
  }

  async function listPeers() {
    return _withPeersLock("shared", async () => {
      let dir;
      try {
        dir = await _peersDir(false);
      } catch (error) {
        if (_isNotFoundError(error)) return [];
        throw error;
      }
      const entries = await _readAllPeerEntries(dir);
      const out = entries.map((entry) => entry.record);
      out.sort((a, b) => Number(b.paired_ms || 0) - Number(a.paired_ms || 0));
      return out;
    });
  }

  async function _writePeerEntry(dir, fileName, record) {
    const serialized = JSON.stringify(record);
    if (new TextEncoder().encode(serialized).byteLength > PEER_RECORD_MAX_BYTES) {
      throw new Error("peer record exceeds the storage size limit");
    }
    const file = await dir.getFileHandle(fileName, { create: true });
    let writable;
    try {
      writable = await file.createWritable({ keepExistingData: false });
      await writable.write(serialized);
      await writable.close();
    } catch (error) {
      if (writable && typeof writable.abort === "function") {
        try { await writable.abort(); } catch (_) {}
      }
      throw error;
    }
    const readback = await _readPeerEntry(fileName, file);
    if (readback.serialized !== serialized ||
        readback.record.fingerprint !== record.fingerprint ||
        readback.record.public_key_b64u !== record.public_key_b64u) {
      throw new Error("peer record failed exact read-back verification");
    }
    return readback.record;
  }

  async function savePeer(rec) {
    const normalized = await _validatePeerRecord(rec);
    return _withPeersLock("exclusive", async () => {
      const dir = await _peersDir(true);
      const entries = await _readAllPeerEntries(dir);
      const sameFingerprint = entries.find(
        (entry) => entry.record.fingerprint === normalized.fingerprint,
      );
      if (sameFingerprint) {
        if (sameFingerprint.record.public_key_b64u !== normalized.public_key_b64u) {
          throw new Error("peer fingerprint is already bound to a different key");
        }
        // Idempotent same-binding update: reuse the exact authority filename;
        // never allocate a duplicate or overwrite a prefix-colliding peer.
        return _writePeerEntry(
          dir, sameFingerprint.name, normalized,
        );
      }

      const usedNames = new Set(entries.map((entry) => entry.name));
      let fileName = null;
      for (let suffix = 0; suffix <= PEER_FILE_MAX_SUFFIX; suffix += 1) {
        const candidate = _peerFileName(normalized.fingerprint, suffix);
        if (!usedNames.has(candidate)) {
          fileName = candidate;
          break;
        }
      }
      if (!fileName) throw new Error("peer fingerprint prefix namespace is exhausted");
      return _writePeerEntry(dir, fileName, normalized);
    });
  }

  async function deletePeer(fingerprint) {
    const canonical = _canonicalSha256Fingerprint(fingerprint);
    const removed = await _withPeersLock("exclusive", async () => {
      let dir;
      try {
        dir = await _peersDir(false);
      } catch (error) {
        if (_isNotFoundError(error)) return false;
        throw error;
      }
      const entries = await _readAllPeerEntries(dir);
      const target = entries.find(
        (entry) => entry.record.fingerprint === canonical,
      );
      if (!target) return false;
      await dir.removeEntry(target.name);
      return true;
    });
    if (removed) {
      // Forget is an authority revocation for this browser origin, not merely
      // the currently-unlocked identity. Remove every queued frame targeting
      // that fingerprint so an older local identity cannot replay it later.
      await clearChatOutboxForPeer(canonical);
    }
    return removed;
  }

  // SAS derivation: canonical bytes of {alice_pubkey, bob_pubkey,
  // alice_nonce, bob_nonce} where pubkeys + nonces are SORTED so
  // both sides hash the same input regardless of role. Hash with
