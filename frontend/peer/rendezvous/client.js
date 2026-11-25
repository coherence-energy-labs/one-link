  function _normalizeRdzUrl(url) {
    if (!url) return null;
    let value = String(url).trim();
    if (!value) return null;
    if (!/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(value)) value = "https://" + value;
    let parsed;
    try { parsed = new URL(value); } catch (_) {
      throw new Error("rendezvous URL is invalid");
    }
    if (parsed.protocol !== "https:") {
      throw new Error("rendezvous requires https:// (browser CSP forbids insecure cross-origin HTTP)");
    }
    if (parsed.username || parsed.password || parsed.search || parsed.hash) {
      throw new Error("rendezvous URL cannot contain credentials, a query, or a fragment");
    }
    if (parsed.pathname !== "/") {
      throw new Error("rendezvous URL must be an origin without a path");
    }
    return parsed.origin;
  }

  function _rdzExactObject(value, expectedKeys, label) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`${label} must be an object`);
    }
    const actual = Object.keys(value).sort();
    const expected = expectedKeys.slice().sort();
    if (actual.length !== expected.length || actual.some((key, i) => key !== expected[i])) {
      throw new Error(`${label} fields do not match ${RDZ_PROTOCOL_VERSION}`);
    }
    return value;
  }

  function _rdzTimestamp(value, label) {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error(`${label} must be a non-negative safe integer`);
    }
    return value;
  }

  function _rdzEndpoint(value, label) {
    _rdzExactObject(value, ["host", "port"], label);
    if (typeof value.host !== "string" || !value.host || value.host.length > 253 ||
        value.host.trim() !== value.host || !/^[\x21-\x7e]+$/.test(value.host)) {
      throw new Error(`${label}.host is invalid`);
    }
    if (!Number.isInteger(value.port) || value.port < 1 || value.port > 65535) {
      throw new Error(`${label}.port is invalid`);
    }
    return { host: value.host, port: value.port };
  }

  function _rdzCanonicalPubkey(value, label) {
    if (typeof value !== "string" || value.length !== 43 || value.includes("=")) {
      throw new Error(`${label} is not a canonical Ed25519 public key`);
    }
    let decoded;
    try { decoded = b64UrlToBytes(value); } catch (_) { decoded = null; }
    if (!decoded || decoded.length !== 32 || bytesToB64Url(decoded) !== value) {
      throw new Error(`${label} is not a canonical Ed25519 public key`);
    }
    return value;
  }

  function _parseRdzRegisterAck(value) {
    const ack = _rdzExactObject(value, RDZ_REGISTER_ACK_KEYS, "register_ack");
    if (ack.v !== RDZ_PROTOCOL_VERSION || ack.type !== "register_ack") {
      throw new Error("rendezvous returned the wrong register protocol response");
    }
    const observed = _rdzEndpoint(
      { host: ack.observed_host, port: ack.observed_port },
      "register_ack.observed",
    );
    const serverTime = _rdzTimestamp(ack.server_time_ms, "register_ack.server_time_ms");
    const expiresAt = _rdzTimestamp(ack.expires_at_ms, "register_ack.expires_at_ms");
    const lifetime = expiresAt - serverTime;
    if (lifetime <= 0 || lifetime > RDZ_MAX_TTL_MS) {
      throw new Error("register_ack lifetime is outside the protocol bound");
    }
    return Object.freeze({
      v: ack.v,
      type: ack.type,
      observed_host: observed.host,
      observed_port: observed.port,
      server_time_ms: serverTime,
      expires_at_ms: expiresAt,
    });
  }

  function _parseRdzLookupAck(value, expectedPubkey) {
    const ack = _rdzExactObject(value, RDZ_LOOKUP_ACK_KEYS, "lookup_ack");
    if (ack.v !== RDZ_PROTOCOL_VERSION || ack.type !== "lookup_ack") {
      throw new Error("rendezvous returned the wrong lookup protocol response");
    }
    const pubkey = _rdzCanonicalPubkey(ack.pubkey_b64, "lookup_ack.pubkey_b64");
    if (pubkey !== expectedPubkey) throw new Error("lookup_ack identity does not match request");
    const serverTime = _rdzTimestamp(ack.server_time_ms, "lookup_ack.server_time_ms");
    const expiresAt = _rdzTimestamp(ack.expires_at_ms, "lookup_ack.expires_at_ms");
    const lifetime = expiresAt - serverTime;
    if (lifetime <= 0 || lifetime > RDZ_MAX_TTL_MS) {
      throw new Error("lookup_ack lifetime is outside the protocol bound");
    }
    const observed = ack.observed_endpoint === null
      ? null
      : _rdzEndpoint(ack.observed_endpoint, "lookup_ack.observed_endpoint");
    if (!Array.isArray(ack.advertised_endpoints) || ack.advertised_endpoints.length > 8) {
      throw new Error("lookup_ack advertised_endpoints is invalid");
    }
    const endpoints = ack.advertised_endpoints.map((endpoint, index) =>
      _rdzEndpoint(endpoint, `lookup_ack.advertised_endpoints[${index}]`)
    );
    if (!["open", "restricted", "symmetric", "unknown"].includes(ack.nat_type)) {
      throw new Error("lookup_ack nat_type is invalid");
    }
    if (!Array.isArray(ack.capabilities) || ack.capabilities.length > 128 ||
        !ack.capabilities.every((capability) =>
          typeof capability === "string" &&
          /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(capability)
        )) {
      throw new Error("lookup_ack capabilities is invalid");
    }
    return Object.freeze({
      v: ack.v,
      type: ack.type,
      pubkey_b64: pubkey,
      observed_endpoint: observed,
      advertised_endpoints: Object.freeze(endpoints),
      nat_type: ack.nat_type,
      capabilities: Object.freeze(ack.capabilities.slice()),
      expires_at_ms: expiresAt,
      server_time_ms: serverTime,
    });
  }

  async function _readRdzResponseText(response) {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > RDZ_RESPONSE_MAX_BYTES) {
      throw new Error("rendezvous response is too large");
    }
    if (!response.body || typeof response.body.getReader !== "function") {
      throw new Error("browser cannot safely stream the rendezvous response");
    }
    const reader = response.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > RDZ_RESPONSE_MAX_BYTES) {
          await reader.cancel("response too large");
          throw new Error("rendezvous response is too large");
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const joined = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      joined.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      return new TextDecoder("utf-8", { fatal: true }).decode(joined);
    } catch (_) {
      throw new Error("rendezvous response is not valid UTF-8");
    }
  }

  async function _rdzFetch(url, init) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), RDZ_FETCH_TIMEOUT_MS);
    try {
      const response = await fetch(url, Object.assign({}, init || {}, {
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: controller.signal,
      }));
      const textValue = await _readRdzResponseText(response);
      let body = null;
      const contentType = String(response.headers.get("content-type") || "").toLowerCase();
      if (contentType.startsWith("application/json")) {
        try { body = JSON.parse(textValue); } catch (_) {
          throw new Error("rendezvous returned malformed JSON");
        }
      } else if (response.ok) {
        throw new Error("rendezvous success response is not JSON");
      }
      return { response, body, text: textValue };
    } catch (error) {
      if (controller.signal.aborted) throw new Error("rendezvous request timed out");
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  function _rdzHttpError(result) {
    const structured = result.body && typeof result.body.error === "string"
      ? result.body.error.trim()
      : "";
    const plain = String(result.text || "").trim();
    return (structured || plain || `HTTP ${result.response.status}`).slice(0, 300);
  }

  async function registerWith(rdzUrl, opts) {
    if (!state.rec) throw new Error("identity not unlocked");
    const base = _normalizeRdzUrl(rdzUrl);
    if (!base) throw new Error("rendezvous URL required");
    const wire = await _buildSignedRegister(state.rec, opts);
    const result = await _rdzFetch(`${base}/api/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(wire),
    });
    if (!result.response.ok) throw new Error(_rdzHttpError(result));
    return _parseRdzRegisterAck(result.body);
  }

  async function lookupAt(rdzUrl, peerPubkeyB64u) {
    const base = _normalizeRdzUrl(rdzUrl);
    if (!base) throw new Error("rendezvous URL required");
    const canonicalPubkey = _rdzCanonicalPubkey(peerPubkeyB64u, "lookup pubkey");
    // Daemon's _handle_lookup decodes via urlsafe_b64decode, so the
    // URL path takes base64url. Identity already stores keys in
    // base64url; pass through. encodeURIComponent is a belt-and-
    // suspenders safety in case a future-ship key encoding sneaks
    // in a non-URL-safe char.
    const enc = encodeURIComponent(canonicalPubkey);
    const result = await _rdzFetch(`${base}/api/v1/lookup/${enc}`);
    if (result.response.status === 404) return null;
    if (!result.response.ok) throw new Error(_rdzHttpError(result));
    return _parseRdzLookupAck(result.body, canonicalPubkey);
  }

