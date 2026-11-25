  // ── v0.5.3: connection-regime classifier ───────────────────────────
  // Tells users where a peer's connection is coming from. Pure
  // client-side: based on the address octet pattern of peer.address,
  // which the server already gives us. No extra API roundtrip needed.
  function isPrivateAddress(addr) {
    if (!addr || typeof addr !== "string") return false;
    if (addr === "127.0.0.1" || addr.startsWith("127.")) return true;
    if (addr === "::1") return true;
    if (addr.startsWith("169.254.")) return true;          // link-local
    if (addr.startsWith("10.")) return true;                // RFC 1918
    if (addr.startsWith("192.168.")) return true;           // RFC 1918
    if (addr.startsWith("fe80:") || addr.startsWith("FE80:")) return true; // IPv6 LL
    if (addr.startsWith("fc") || addr.startsWith("fd")) return true;       // IPv6 ULA
    // 172.16.0.0 – 172.31.255.255
    const m = /^172\.(\d+)\./.exec(addr);
    if (m) {
      const oct = parseInt(m[1], 10);
      if (oct >= 16 && oct <= 31) return true;
    }
    // 100.64.0.0/10 carrier-grade NAT
    const m2 = /^100\.(\d+)\./.exec(addr);
    if (m2) {
      const oct = parseInt(m2[1], 10);
      if (oct >= 64 && oct <= 127) return true;
    }
    return false;
  }

  // v0.7.3: pretty-print the compact `<os>-<kind>` mDNS tag.
  // Maps to a short label + an emoji icon. Returns "" when the
  // peer is on a pre-v0.7.3 build that didn't advertise.
  const _DEVICE_KIND_LABELS = {
    "windows-desktop": { label: "Windows desktop", icon: "🖥️" },
    "windows-laptop":  { label: "Windows laptop",  icon: "💻" },
    "windows-server":  { label: "Windows server",  icon: "🗄️" },
    "macos-desktop":   { label: "Mac desktop",     icon: "🖥️" },
    "macos-laptop":    { label: "MacBook",         icon: "💻" },
    "linux-desktop":   { label: "Linux desktop",   icon: "🖥️" },
    "linux-laptop":    { label: "Linux laptop",    icon: "💻" },
    "linux-server":    { label: "Linux server",    icon: "🗄️" },
    "linux-embedded":  { label: "Linux embedded",  icon: "🔌" },
    "linux-mobile":    { label: "Linux mobile",    icon: "📱" },
    "linux-tablet":    { label: "Linux tablet",    icon: "📱" },
    "ios-mobile":      { label: "iPhone",          icon: "📱" },
    "ios-tablet":      { label: "iPad",            icon: "📱" },
    "android-mobile":  { label: "Android phone",   icon: "📱" },
    "android-tablet":  { label: "Android tablet",  icon: "📱" },
    "bsd-desktop":     { label: "BSD",             icon: "🖥️" },
  };
  function deviceKindLabel(p) {
    const k = (p && p.device_kind) || "";
    if (!k) return null;
    if (_DEVICE_KIND_LABELS[k]) return _DEVICE_KIND_LABELS[k];
    // Generic fallback for unknown OS/kind combos.
    const [osPart, kindPart] = k.split("-");
    const icon =
      kindPart === "laptop"   ? "💻" :
      kindPart === "desktop"  ? "🖥️" :
      kindPart === "server"   ? "🗄️" :
      kindPart === "mobile"   ? "📱" :
      kindPart === "tablet"   ? "📱" :
      kindPart === "embedded" ? "🔌" : "❔";
    const niceOs = ({
      windows: "Windows", macos: "macOS", linux: "Linux",
      bsd: "BSD", ios: "iOS", android: "Android",
    })[osPart] || (osPart || "Device");
    return { label: `${niceOs} ${kindPart || ""}`.trim(), icon };
  }

  function reachLabel(p) {
    // v0.5.6: server-side regime is authoritative when present -
    // it knows whether the actual transport went through the relay.
    // Fall back to client-side classification if the server didn't
    // stamp one (offline DB peers, older builds).
    if (p.regime === "relay") return "via relay";
    if (p.regime === "lan") return "on Wi-Fi"; // doctrine-ok: §3.6.c grandfathered legacy surface (ADR-PENDING-doctrine-sweep-v0.21); replace with "Local network" in Tier α-pre legacy sweep.
    if (p.regime === "internet") return "via internet";
    if (p.regime === "offline" || !p.online) return "offline";
    if (isPrivateAddress(p.address)) return "on Wi-Fi"; // doctrine-ok: §3.6.c grandfathered legacy surface (ADR-PENDING-doctrine-sweep-v0.21); replace with "Local network" in Tier α-pre legacy sweep.
    return "via internet";
  }

  // Pick a class name for the latency dot based on rolling RTT.
  // Thresholds match what users intuitively call "snappy" vs "laggy".
  // v0.21.x: the dot now reflects CHANNEL HEALTH, not just RTT.
  // Presence (avatar dot) tells you whether the peer is reachable on
  // the network (mDNS sees them). The channel-health dot tells you
  // whether the actual wire path can deliver right now. Five states:
  //   null      — offline / unknown; no dot rendered
  //   "fast"    — recent bytes (<60s) + RTT <80ms; green
  //   "medium"  — recent bytes (<60s) + RTT <250ms; yellow
  //   "slow"    — recent bytes (<60s) + RTT >=250ms; red-ish
  //   "stale"   — no bytes in 60s+; gray-yellow ("channel idle")
  //   "broken"  — paired+online but compatibility negotiation failed;
  //               same red as "slow" with an exclamation cue.
  // This is what makes the "queued while online" symptom legible at
  // a glance — a stale or broken channel paints differently from a
  // fast one, even though presence says online either way.
  function latencyClass(p) {
    if (!p.online) return null;
    if (p.compatibility && p.compatibility.compatible === false) return "broken";
    const ms = p.health?.latency_ewma_ms;
    const lastAlive = p.health?.last_alive_ms;
    const stale = lastAlive != null
      && lastAlive > 0
      && (Date.now() - lastAlive) > 60_000;
    if (ms == null && stale) return "stale";
    if (ms == null) return null;
    if (stale) return "stale";
    if (ms < 80) return "fast";
    if (ms < 250) return "medium";
    return "slow";
  }
  function latencyTitle(p) {
    if (!p.online) return "";
    const ms = p.health?.latency_ewma_ms;
    const lastAlive = p.health?.last_alive_ms;
    const parts = [];
    const cls = latencyClass(p);
    if (cls === "broken") {
      parts.push("Channel needs renegotiation. Sends will queue until both sides catch up.");
    } else if (cls === "stale") {
      const ago = lastAlive ? Math.round((Date.now() - lastAlive) / 1000) : null;
      parts.push(
        ago != null
          ? `Channel idle (last bytes ${_fmtAgo(ago)})`
          : "Channel idle (no recent bytes)",
      );
    } else if (cls === "fast") {
      parts.push("Channel healthy");
    } else if (cls === "medium") {
      parts.push("Channel OK");
    } else if (cls === "slow") {
      parts.push("Channel slow");
    }
    if (ms != null) parts.push(`${Math.round(ms)} ms round-trip`);
    return parts.join(" - ");
  }
  function renderConversationPeerStatus(peer) {
    const subEl = $("#convo-sub");
    if (!subEl || !peer) return;
    subEl.innerHTML = "";
    subEl.classList.remove("copyable");
    subEl.title = "";
    subEl.onclick = null;
    if (peer.trust === "rejected") {
      subEl.appendChild(document.createTextNode("Device chat - blocked"));
      return;
    }
    subEl.appendChild(document.createTextNode("Device chat - "));
    const lc = latencyClass(peer);
    if (lc) {
      const dot = el("span", `lat-dot ${lc}`);
      dot.title = latencyTitle(peer);
      subEl.appendChild(dot);
    }
    subEl.appendChild(document.createTextNode(reachLabel(peer)));
    const ms = peer.health?.latency_ewma_ms;
    if (ms != null) {
      subEl.appendChild(document.createTextNode(` - ${Math.round(ms)} ms`));
    }
    const verBadge = renderPeerVersionBadge(peer);
    if (verBadge) {
      subEl.appendChild(document.createTextNode(" "));
      subEl.appendChild(verBadge);
    }
  }

  function _fmtAgo(seconds) {
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)}h ago`;
    return `${Math.round(seconds / 86400)}d ago`;
  }

