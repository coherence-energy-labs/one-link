  // ── OPFS persistence ────────────────────────────────────────────────
  // Identity layout (v0.16.0):
  //   /identity/v1/keypair.json
  //     {
  //       "v": 1,
  //       "alg": "Ed25519",
  //       "created_ms": <int>,
  //       "private_key_jwk": { ... },
  //       "public_key_b64u": "<43 chars base64url>",
  //       "fingerprint": "sha256:<hex>"
  //     }
  // Private identity material is never newly committed in plaintext. Legacy
  // v1 plaintext/PBKDF2 records remain readable only long enough to migrate
  // atomically to the v2 Argon2id envelope.
  const ID_DIR_NAME = "identity";
  const ID_VERSION_DIR = "v1";
  const ID_FILE = "keypair.json";
  const ID_PENDING_FILE = "keypair.pending.json";
  const ID_LOCK_NAME = "one-link.browser-identity.v1";
  const IDB_IDENTITY_DB = "one-link-browser-identity-v1";
  const IDB_IDENTITY_STORE = "identity";
  const IDB_IDENTITY_KEY = "authority";
  const IDENTITY_FILE_MAX_BYTES = 1024 * 1024;
  const IDENTITY_CLOCK_MAX_MS = Number.MAX_SAFE_INTEGER;
  const IDENTITY_PASSPHRASE_MIN_CHARS = 12;
  const IDENTITY_PASSPHRASE_MAX_BYTES = 1024;
  const IDENTITY_SALT_BYTES = 16;
  const IDENTITY_IV_BYTES = 12;
  const IDENTITY_ARGON_MEMORY_KIB = 256 * 1024;
  const IDENTITY_ARGON_TIME_COST = 3;
  const IDENTITY_ARGON_PARALLELISM = 1;
  const IDENTITY_ARGON_ABI_VERSION = 1;
  const IDENTITY_KDF_TIMEOUT_MS = 120 * 1000;
  const ED25519_WASM_URL = "/browser-crypto/ed25519-v1.wasm";
  const ED25519_WASM_SHA256 =
    "b112d5518115ac2a8dd923836f6f5eecf413a4d2ba97183e6809c863927fb9c7";
  const ED25519_WASM_ABI_VERSION = 1;
  const ED25519_WASM_MAX_BYTES = 256 * 1024;
  const ED25519_WASM_MAX_MESSAGE_BYTES = 1024 * 1024;

  class IdentityStorageError extends Error {
    constructor(message, cause) {
      super(message, cause === undefined ? undefined : { cause });
      this.name = "IdentityStorageError";
    }
  }

  class IdentityCorruptionError extends IdentityStorageError {
    constructor(message, cause) {
      super(message, cause);
      this.name = "IdentityCorruptionError";
    }
  }

  class IdentityKdfError extends IdentityStorageError {
    constructor(message, cause) {
      super(message, cause);
      this.name = "IdentityKdfError";
    }
  }

