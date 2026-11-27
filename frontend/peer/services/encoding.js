// Isolated service: collaborators cross the factory parameter boundary.
function createPeerEncoding({
  btoa,
  atob,
}) {
  // ── encoding helpers ────────────────────────────────────────────────
  const HEX = "0123456789abcdef";
  function bytesToHex(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < u8.length; i++) {
      const b = u8[i];
      out += HEX[b >> 4] + HEX[b & 0xf];
    }
    return out;
  }
  function bytesToB64Url(buf) {
    const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
    return btoa(bin)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  function b64UrlToBytes(s) {
    const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 ? "=".repeat(4 - (b64.length % 4)) : "";
    const bin = atob(b64 + pad);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }

  return { bytesToHex, bytesToB64Url, b64UrlToBytes };
}
