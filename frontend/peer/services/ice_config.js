// Isolated service: collaborators cross the factory parameter boundary.
function createPeerIceConfig({
  fetch,
  AbortController,
  setTimeout,
  clearTimeout,
}) {
  function _validPublicIceServer(entry) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
    // This unauthenticated endpoint is deliberately STUN-only. Never accept
    // TURN credentials or a non-STUN URL through the public browser surface.
    if ("username" in entry || "credential" in entry) return false;
    const urls = Array.isArray(entry.urls) ? entry.urls : [entry.urls];
    return urls.length > 0 && urls.length <= 8 && urls.every((url) =>
      typeof url === "string" && url.length <= 2048 && /^stuns?:/i.test(url)
    );
  }

  function _validObservedCandidateAddress(value) {
    if (typeof value !== "string" || value !== value.trim() || value.length > 45) {
      return null;
    }
    const ipv4 = value.split(".");
    if (ipv4.length === 4 && ipv4.every((part) =>
      /^(?:0|[1-9][0-9]{0,2})$/.test(part) && Number(part) <= 255
    )) {
      const first = Number(ipv4[0]);
      if (first === 0 || first >= 224) return null;
      return value;
    }
    if (!value.includes(":") || !/^[0-9A-Fa-f:]+$/.test(value) || value.includes(":::")) {
      return null;
    }
    const compression = value.indexOf("::");
    if (compression !== -1 && compression !== value.lastIndexOf("::")) return null;
    const groups = value.split(":").filter(Boolean);
    if (groups.some((group) => group.length > 4)) return null;
    if (compression === -1 ? groups.length !== 8 : groups.length >= 8) return null;
    const lowered = value.toLowerCase();
    if (lowered === "::" || lowered.startsWith("ff")) return null;
    return lowered;
  }

  async function loadPublicIceConfig() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8_000);
    try {
      const response = await fetch("/api/v1/peer-rtc/ice-config", {
        cache: "no-store",
        credentials: "same-origin",
        signal: controller.signal,
      });
      if (!response.ok) return { iceServers: [], localCandidateAddresses: [] };
      const config = await response.json();
      if (!config || !Array.isArray(config.iceServers)) {
        return { iceServers: [], localCandidateAddresses: [] };
      }
      const assist = config.local_address_discovery;
      const rawCandidateAddresses = (
        assist && assist.enabled === true && assist.external === false &&
        assist.scope === "same-device-or-lan"
      ) ? (
        Array.isArray(assist.candidate_addresses)
          ? assist.candidate_addresses.slice(0, 8)
          : [assist.candidate_address]
      ) : [];
      const localCandidateAddresses = rawCandidateAddresses
        .map(_validObservedCandidateAddress)
        .filter((address, index, all) => address && all.indexOf(address) === index);
      return {
        iceServers: config.iceServers.slice(0, 16).filter(_validPublicIceServer),
        localCandidateAddresses,
      };
    } catch (_) {
      // Host-only ICE is the intentional sovereignty/failure fallback.
      return { iceServers: [], localCandidateAddresses: [] };
    } finally {
      clearTimeout(timer);
    }
  }

  async function loadPublicIceServers() {
    return (await loadPublicIceConfig()).iceServers;
  }

  return { _validPublicIceServer, _validObservedCandidateAddress, loadPublicIceConfig, loadPublicIceServers };
}
