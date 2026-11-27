  // ── v0.19.1 — SAS pairing over the control DataChannel ────────────
  //
  // Wire protocol over the control channel:
  //
  //   {"v":"OL-PAIR-1", "t":"hello", "pubkey":"<b64u>",
  //    "fingerprint":"<algo>:<hex>", "nonce":"<b64u 16B>", "ts": <ms>,
  //    "alias":"<optional display name>"}
  //
  //   {"v":"OL-PAIR-1", "t":"confirm",
  //    "fingerprint":"<algo>:<hex>", "matched": true|false,
  //    "ts": <ms>}
  //
  // Both sides send hello on control:open. Both compute the five-word SAS
  // independently from canonical(SortedPubkeyPair, SortedNoncePair).
  // Thirty digest bits select five words from the same curated 64-word
  // dictionary as the native pair-by-QR primitive. The prior 6-digit value
  // remains visible only for mixed-version compatibility. SHA-256 of the
  // same bytes also powers the 6-cell visual art.
  //
  // Match path: each side sends `confirm matched=true`. Only when
  // BOTH sides have local-confirmed AND received remote-confirmed
  // do we persist the peer record. Either side answering false →
  // tear down + close, no persistence.
  //
  // Replay defense: nonces are fresh per session; a captured
  // hello/confirm pair from an old session won't match the new
  // SAS computed against fresh nonces.

  const PAIR_PROTOCOL_VERSION = "OL-PAIR-1";
  const PAIR_NONCE_BYTES = 16;
  const PAIR_HELLO_TIMEOUT_MS = 30_000;
  const PAIR_MESSAGE_MAX_CHARS = 4096;
  const PAIR_ALIAS_MAX_CHARS = 128;
  const PAIR_CLOCK_SKEW_MS = 5 * 60 * 1000;
  // Mirrored from ol_pair_qr::sas_words and one_link.pairing. A repository
  // parity test locks every spelling and position across Rust/Python/JS.
  const PAIR_SAS_WORDS = Object.freeze([
    "agile","amuse","apple","basil","blaze","brick","cargo","cedar",
    "chess","climb","copper","crane","daisy","decoy","drift","eagle",
    "ember","exile","fable","flame","frost","globe","gravy","gusto",
    "happy","hover","igloo","indigo","ivory","jolly","juice","kindly",
    "koala","lemon","lunar","mango","melon","motor","north","nudge",
    "ocean","olive","panda","plume","quiet","rebel","ridge","saber",
    "sleek","sushi","tiger","trove","ultra","umbra","vapor","vivid",
    "wagon","winter","xenon","xylo","yacht","yodel","zebra","zinc",
  ]);
  const PAIR_SAS_WORD_COUNT = 5;
  const PAIR_SAS_BITS = 30;
  const SETUP_SAS_VERSION = "setup-words-v1";
  const SETUP_SAS_DOMAIN = "OL/setup-sas-words/v1\0";

  // OPFS peers store. One file per peer at /peers/v1/<short>.json. Every
  // read validates filename, full fingerprint, and Ed25519 key as one
  // authority. Corrupt or ambiguous rows fail closed instead of being hidden
  // and later overwritten; a future recovery UI can quarantine them explicitly.
  const PEERS_DIR_NAME = "peers";
  const PEERS_VERSION_DIR = "v1";
  const PEERS_LOCK_NAME = "one-link.browser-peers.v1";
  const PEER_FILE_PREFIX_HEX_CHARS = 24;
  const PEER_FILE_MAX_SUFFIX = 99_999;
  const PEER_RECORD_MAX_BYTES = 16 * 1024;
  const PEER_RECORD_KEYS = Object.freeze([
    "alias", "fingerprint", "last_seen_ms", "paired_ms", "paired_via",
    "public_key_b64u", "sas_digits", "v",
  ]);

