  const KDF_ITERATIONS_DEFAULT = 600000;

  function _randomBytes(n) {
    const u8 = new Uint8Array(n);
    crypto.getRandomValues(u8);
    return u8;
  }

  function _encodeIdentityPassphrase(passphrase, minimumChars) {
    if (typeof passphrase !== "string" || passphrase.length < minimumChars) {
      throw new IdentityKdfError(
        `passphrase must be at least ${minimumChars} characters`,
      );
    }
    const encoded = new TextEncoder().encode(passphrase);
    if (encoded.byteLength < 1 ||
        encoded.byteLength > IDENTITY_PASSPHRASE_MAX_BYTES) {
      encoded.fill(0);
      throw new IdentityKdfError(
        `passphrase must encode to at most ${IDENTITY_PASSPHRASE_MAX_BYTES} bytes`,
      );
    }
    return encoded;
  }

  async function _deriveLegacyAesKey(passphrase, salt, iterations) {
    const encoded = _encodeIdentityPassphrase(passphrase, 1);
    let baseKey;
    try {
      baseKey = await crypto.subtle.importKey(
        "raw",
        encoded,
        { name: "PBKDF2" },
        /*extractable=*/false,
        ["deriveKey"],
      );
    } finally {
      encoded.fill(0);
    }
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations,
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      /*extractable=*/false,
      ["decrypt"],
    );
  }

  async function _deriveArgonAesKey(passphrase, salt, minimumChars) {
    if (!(salt instanceof Uint8Array) || salt.byteLength !== IDENTITY_SALT_BYTES) {
      throw new IdentityKdfError("identity KDF salt is invalid");
    }
    if (typeof Worker !== "function") {
      throw new IdentityKdfError("this browser does not support identity KDF workers");
    }
    const password = _encodeIdentityPassphrase(passphrase, minimumChars);
    const workerSalt = new Uint8Array(salt);
    let worker;
    try {
      worker = new Worker(
        "/browser-crypto/argon2id-worker.js",
        { type: "classic", name: "one-link-identity-kdf" },
      );
    } catch (error) {
      password.fill(0);
      workerSalt.fill(0);
      throw new IdentityKdfError("could not start the identity KDF", error);
    }

    let reply;
    try {
      reply = await new Promise((resolve, reject) => {
        let settled = false;
        const finish = (callback, value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          callback(value);
        };
        const timer = setTimeout(
          () => finish(
            reject,
            new IdentityKdfError("identity KDF exceeded its time limit"),
          ),
          IDENTITY_KDF_TIMEOUT_MS,
        );
        worker.onmessage = (event) => finish(resolve, event.data);
        worker.onerror = (event) => {
          event.preventDefault?.();
          finish(reject, new IdentityKdfError("identity KDF worker failed"));
        };
        worker.onmessageerror = () => finish(
          reject, new IdentityKdfError("identity KDF returned an invalid message"),
        );
        try {
          worker.postMessage(
            {
              abiVersion: IDENTITY_ARGON_ABI_VERSION,
              memoryKiB: IDENTITY_ARGON_MEMORY_KIB,
              parallelism: IDENTITY_ARGON_PARALLELISM,
              password: password.buffer,
              salt: workerSalt.buffer,
              timeCost: IDENTITY_ARGON_TIME_COST,
            },
            [password.buffer, workerSalt.buffer],
          );
        } catch (error) {
          finish(
            reject,
            new IdentityKdfError("could not submit identity KDF work", error),
          );
        }
      });
    } finally {
      worker.terminate();
      if (password.byteLength) password.fill(0);
      if (workerSalt.byteLength) workerSalt.fill(0);
    }

    if (!_isPlainObject(reply) || reply.ok !== true ||
        reply.abiVersion !== IDENTITY_ARGON_ABI_VERSION ||
        reply.memoryKiB !== IDENTITY_ARGON_MEMORY_KIB ||
        reply.timeCost !== IDENTITY_ARGON_TIME_COST ||
        reply.parallelism !== IDENTITY_ARGON_PARALLELISM ||
        !(reply.key instanceof ArrayBuffer) || reply.key.byteLength !== 32 ||
        Object.keys(reply).sort().join(",") !==
          "abiVersion,key,memoryKiB,ok,parallelism,timeCost") {
      const code = _isPlainObject(reply) && typeof reply.code === "string"
        ? reply.code.slice(0, 64)
        : "invalid_reply";
      throw new IdentityKdfError(`identity KDF failed closed (${code})`);
    }
    const rawKey = new Uint8Array(reply.key);
    try {
      return await crypto.subtle.importKey(
        "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"],
      );
    } finally {
      rawKey.fill(0);
    }
  }

