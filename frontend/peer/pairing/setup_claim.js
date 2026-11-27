  function _compareByteArrays(left, right) {
    if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) {
      throw new Error("SAS inputs must be byte arrays");
    }
    const limit = Math.min(left.byteLength, right.byteLength);
    for (let index = 0; index < limit; index += 1) {
      if (left[index] !== right[index]) return left[index] - right[index];
    }
    return left.byteLength - right.byteLength;
  }

  function _concatBytes(parts) {
    const total = parts.reduce((sum, part) => {
      if (!(part instanceof Uint8Array)) {
        throw new Error("SAS transcript parts must be byte arrays");
      }
      return sum + part.byteLength;
    }, 0);
    const joined = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      joined.set(part, offset);
      offset += part.byteLength;
    }
    return joined;
  }

  async function _deriveSetupSas(inviteToken, ownerPubB64u, devicePubB64u) {
    const secret = _canonicalB64UrlBytes(inviteToken, 32, "setup invite token");
    const owner = _canonicalB64UrlBytes(ownerPubB64u, 32, "setup owner public key");
    const device = _canonicalB64UrlBytes(devicePubB64u, 32, "setup device public key");
    const ordered = [owner, device].sort(_compareByteArrays);
    const transcript = _concatBytes([
      new TextEncoder().encode(SETUP_SAS_DOMAIN),
      secret,
      ordered[0],
      ordered[1],
    ]);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", transcript),
    );
    const words = _sasWordsFromDigest(digest);
    return { words, phrase: words.join(" "), digest };
  }

  async function _validateSetupClaim(query, identity, body) {
    _requirePlainObject(query, "setup invite query");
    _requirePlainObject(identity, "local device identity");
    _requirePlainObject(body, "setup invite claim");
    if (body.sas_version !== SETUP_SAS_VERSION) {
      throw new Error("setup invite did not negotiate the required five-word SAS");
    }
    if (body.device_pub_b64 !== identity.public_key_b64u) {
      throw new Error("setup claim is bound to a different device key");
    }
    const derived = await _deriveSetupSas(
      query.token, body.root_pub_b64, identity.public_key_b64u,
    );
    if (typeof body.trust_phrase !== "string" ||
        body.trust_phrase !== derived.phrase ||
        typeof body.trust_code !== "string" ||
        body.trust_code !== derived.phrase) {
      throw new Error("setup five-word phrase failed independent verification");
    }
    if (!Array.isArray(body.trust_words) ||
        body.trust_words.length !== PAIR_SAS_WORD_COUNT ||
        body.trust_words.some((word, index) => word !== derived.words[index])) {
      throw new Error("setup word vector does not match the verified phrase");
    }
    return derived;
  }

