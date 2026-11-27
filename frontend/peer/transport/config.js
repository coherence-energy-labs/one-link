  const { _validPublicIceServer, _validObservedCandidateAddress, loadPublicIceConfig, loadPublicIceServers } = createPeerIceConfig({
    fetch: (...args) => fetch(...args),
    AbortController: window.AbortController, setTimeout, clearTimeout,
  });

  function _numericCandidateLine(line, candidateAddress, ordinal) {
    if (typeof line !== "string") return null;
    const address = _validObservedCandidateAddress(candidateAddress);
    if (!address) return null;
    const withAttributePrefix = line.startsWith("a=");
    const body = withAttributePrefix ? line.slice(2) : line;
    const parts = body.trim().split(/\s+/);
    if (parts.length < 8 || !parts[0].startsWith("candidate:")) return null;
    const currentAddress = parts[4] || "";
    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+local$/i.test(currentAddress)) {
      return null;
    }
    if (parts[1] !== "1" || String(parts[2]).toUpperCase() !== "UDP") return null;
    if (!/^[0-9]{1,10}$/.test(parts[3]) || !/^[0-9]{1,5}$/.test(parts[5])) return null;
    const port = Number(parts[5]);
    if (port < 1 || port > 65535 || parts[6] !== "typ" || parts[7] !== "host") {
      return null;
    }
    // A distinct deterministic foundation prevents the synthetic numeric
    // candidate from collapsing into the original mDNS candidate. The socket
    // port, priority, ICE ufrag, and every extension remain browser-authored.
    parts[0] = `candidate:ol${Number(ordinal || 0).toString(36)}`;
    parts[4] = address;
    return `${withAttributePrefix ? "a=" : ""}${parts.join(" ")}`;
  }

  function _descriptionForSignal(session) {
    if (!session || !session.pc || !session.pc.localDescription) {
      throw new Error("missing local WebRTC description");
    }
    const description = session.pc.localDescription.toJSON();
    const addresses = Array.isArray(session.local_candidate_addresses)
      ? session.local_candidate_addresses
          .slice(0, 8)
          .map(_validObservedCandidateAddress)
          .filter((address, index, all) => address && all.indexOf(address) === index)
      : [];
    if (!addresses.length || typeof description.sdp !== "string") return description;
    const newline = description.sdp.includes("\r\n") ? "\r\n" : "\n";
    const output = [];
    let ordinal = 0;
    for (const line of description.sdp.split(/\r?\n/)) {
      output.push(line);
      for (const address of addresses) {
        const numeric = _numericCandidateLine(line, address, ordinal);
        if (numeric) {
          output.push(numeric);
          ordinal += 1;
        }
      }
    }
    return { type: description.type, sdp: output.join(newline) };
  }

  function _candidateForSignal(candidate, candidateAddress) {
    const body = candidate.toJSON();
    const numeric = _numericCandidateLine(body.candidate, candidateAddress, 0);
    if (numeric) body.candidate = numeric;
    return body;
  }

