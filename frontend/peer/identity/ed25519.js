  function _isEd25519Unsupported(error) {
    if (!error || typeof error !== "object") return false;
    if (error.name === "NotSupportedError") return true;
    return error.name === "OperationError" &&
      /^the operation is not supported\.?$/i.test(String(error.message || ""));
  }

  async function _loadEd25519Wasm() {
    if (_ed25519WasmPromise) return _ed25519WasmPromise;
    _ed25519WasmPromise = (async () => {
      const response = await fetch(ED25519_WASM_URL, {
        cache: "no-store",
        credentials: "same-origin",
        redirect: "error",
      });
      if (!response.ok || response.type === "opaque") {
        throw new IdentityStorageError("Ed25519 fallback artifact is unavailable");
      }
      const contentType = (response.headers.get("content-type") || "")
        .split(";", 1)[0].trim().toLowerCase();
      if (contentType !== "application/wasm") {
        throw new IdentityStorageError("Ed25519 fallback has an invalid media type");
      }
      const bytes = await response.arrayBuffer();
      if (bytes.byteLength < 8 || bytes.byteLength > ED25519_WASM_MAX_BYTES) {
        throw new IdentityStorageError("Ed25519 fallback size is outside its contract");
      }
      const digest = bytesToHex(await crypto.subtle.digest("SHA-256", bytes));
      if (digest !== ED25519_WASM_SHA256) {
        throw new IdentityStorageError("Ed25519 fallback integrity check failed");
      }
      let instantiated;
      try {
        instantiated = await WebAssembly.instantiate(bytes, {});
      } catch (error) {
        throw new IdentityStorageError("Ed25519 fallback could not start", error);
      }
      const exports = instantiated.instance.exports;
      const requiredFunctions = [
        "ol_ed25519_abi_version",
        "ol_ed25519_alloc",
        "ol_ed25519_zero_and_free",
        "ol_ed25519_public_from_seed",
        "ol_ed25519_validate_public",
        "ol_ed25519_sign",
        "ol_ed25519_verify",
        "ol_ed25519_self_test",
      ];
      if (!(exports.memory instanceof WebAssembly.Memory) ||
          requiredFunctions.some((name) => typeof exports[name] !== "function") ||
          exports.ol_ed25519_abi_version() !== ED25519_WASM_ABI_VERSION ||
          exports.ol_ed25519_self_test() !== 0) {
        throw new IdentityStorageError("Ed25519 fallback ABI self-test failed");
      }
      return exports;
    })();
    return _ed25519WasmPromise;
  }

  function _copyBoundedBytes(value, label, maximum, exact = null) {
    let source;
    if (value instanceof ArrayBuffer) source = new Uint8Array(value);
    else if (ArrayBuffer.isView(value)) {
      source = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    } else {
      throw new IdentityStorageError(`${label} must be bytes`);
    }
    if (source.byteLength > maximum ||
        (exact !== null && source.byteLength !== exact)) {
      throw new IdentityStorageError(`${label} length is outside its contract`);
    }
    return Uint8Array.from(source);
  }

  function _ed25519WasmAlloc(exports, length, label) {
    const allocationLength = Math.max(1, length);
    const pointer = exports.ol_ed25519_alloc(allocationLength);
    if (!Number.isSafeInteger(pointer) || pointer <= 0) {
      throw new IdentityStorageError(`${label} allocation failed`);
    }
    return { pointer, length: allocationLength };
  }

  function _ed25519WasmFree(exports, allocation, label) {
    if (!allocation) return;
    if (exports.ol_ed25519_zero_and_free(
      allocation.pointer, allocation.length,
    ) !== 0) {
      throw new IdentityStorageError(`${label} zeroization failed`);
    }
  }

  async function _wasmEd25519PublicFromSeed(seedValue) {
    const seed = _copyBoundedBytes(seedValue, "Ed25519 seed", 32, 32);
    let exports;
    let seedAllocation;
    let publicAllocation;
    try {
      exports = await _loadEd25519Wasm();
      seedAllocation = _ed25519WasmAlloc(exports, seed.length, "Ed25519 seed");
      publicAllocation = _ed25519WasmAlloc(exports, 32, "Ed25519 public key");
      new Uint8Array(
        exports.memory.buffer, seedAllocation.pointer, seed.length,
      ).set(seed);
      const code = exports.ol_ed25519_public_from_seed(
        seedAllocation.pointer, seed.length, publicAllocation.pointer, 32,
      );
      if (code !== 0) {
        throw new IdentityStorageError(`Ed25519 public derivation failed (${code})`);
      }
      return Uint8Array.from(new Uint8Array(
        exports.memory.buffer, publicAllocation.pointer, 32,
      ));
    } finally {
      seed.fill(0);
      if (exports) {
        _ed25519WasmFree(exports, publicAllocation, "Ed25519 public key");
        _ed25519WasmFree(exports, seedAllocation, "Ed25519 seed");
      }
    }
  }

  async function _wasmEd25519ValidatePublic(publicValue) {
    const publicKey = _copyBoundedBytes(
      publicValue, "Ed25519 public key", 32, 32,
    );
    let exports;
    let allocation;
    try {
      exports = await _loadEd25519Wasm();
      allocation = _ed25519WasmAlloc(exports, publicKey.length, "Ed25519 public key");
      new Uint8Array(
        exports.memory.buffer, allocation.pointer, publicKey.length,
      ).set(publicKey);
      return exports.ol_ed25519_validate_public(
        allocation.pointer, publicKey.length,
      ) === 0;
    } finally {
      publicKey.fill(0);
      if (exports) _ed25519WasmFree(exports, allocation, "Ed25519 public key");
    }
  }

  async function _wasmEd25519Sign(seedValue, messageValue) {
    const seed = _copyBoundedBytes(seedValue, "Ed25519 seed", 32, 32);
    const message = _copyBoundedBytes(
      messageValue, "Ed25519 message", ED25519_WASM_MAX_MESSAGE_BYTES,
    );
    let exports;
    let seedAllocation;
    let messageAllocation;
    let signatureAllocation;
    try {
      exports = await _loadEd25519Wasm();
      seedAllocation = _ed25519WasmAlloc(exports, seed.length, "Ed25519 seed");
      messageAllocation = _ed25519WasmAlloc(
        exports, message.length, "Ed25519 message",
      );
      signatureAllocation = _ed25519WasmAlloc(exports, 64, "Ed25519 signature");
      new Uint8Array(
        exports.memory.buffer, seedAllocation.pointer, seed.length,
      ).set(seed);
      if (message.length) {
        new Uint8Array(
          exports.memory.buffer, messageAllocation.pointer, message.length,
        ).set(message);
      }
      const code = exports.ol_ed25519_sign(
        seedAllocation.pointer, seed.length,
        messageAllocation.pointer, message.length,
        signatureAllocation.pointer, 64,
      );
      if (code !== 0) {
        throw new IdentityStorageError(`Ed25519 signing failed (${code})`);
      }
      return Uint8Array.from(new Uint8Array(
        exports.memory.buffer, signatureAllocation.pointer, 64,
      ));
    } finally {
      seed.fill(0);
      message.fill(0);
      if (exports) {
        _ed25519WasmFree(exports, signatureAllocation, "Ed25519 signature");
        _ed25519WasmFree(exports, messageAllocation, "Ed25519 message");
        _ed25519WasmFree(exports, seedAllocation, "Ed25519 seed");
      }
    }
  }

  async function _wasmEd25519Verify(publicValue, signatureValue, messageValue) {
    const publicKey = _copyBoundedBytes(
      publicValue, "Ed25519 public key", 32, 32,
    );
    const signature = _copyBoundedBytes(
      signatureValue, "Ed25519 signature", 64, 64,
    );
    const message = _copyBoundedBytes(
      messageValue, "Ed25519 message", ED25519_WASM_MAX_MESSAGE_BYTES,
    );
    let exports;
    let publicAllocation;
    let messageAllocation;
    let signatureAllocation;
    try {
      exports = await _loadEd25519Wasm();
      publicAllocation = _ed25519WasmAlloc(exports, 32, "Ed25519 public key");
      messageAllocation = _ed25519WasmAlloc(
        exports, message.length, "Ed25519 message",
      );
      signatureAllocation = _ed25519WasmAlloc(exports, 64, "Ed25519 signature");
      new Uint8Array(exports.memory.buffer, publicAllocation.pointer, 32)
        .set(publicKey);
      if (message.length) {
        new Uint8Array(
          exports.memory.buffer, messageAllocation.pointer, message.length,
        ).set(message);
      }
      new Uint8Array(exports.memory.buffer, signatureAllocation.pointer, 64)
        .set(signature);
      const code = exports.ol_ed25519_verify(
        publicAllocation.pointer, 32,
        messageAllocation.pointer, message.length,
        signatureAllocation.pointer, 64,
      );
      if (code === 0) return true;
      if (code === 4 || code === 5) return false;
      throw new IdentityStorageError(`Ed25519 verification failed (${code})`);
    } finally {
      publicKey.fill(0);
      signature.fill(0);
      message.fill(0);
      if (exports) {
        _ed25519WasmFree(exports, signatureAllocation, "Ed25519 signature");
        _ed25519WasmFree(exports, messageAllocation, "Ed25519 message");
        _ed25519WasmFree(exports, publicAllocation, "Ed25519 public key");
      }
    }
  }

