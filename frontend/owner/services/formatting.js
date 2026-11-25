// Isolated service: dependencies are explicit parameters; no owner closure access.
function createOwnerFormatting({
  document,
  getSettings,
}) {
  const $ = (sel) => document.querySelector(sel);
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const fmtBytes = (n) => {
    if (n == null) return "?";
    const u = ["B","KB","MB","GB","TB"]; let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
  };
  // v0.8.8: bytes/sec → human string for chat-bubble rate display.
  const fmtRate = (bps) => {
    if (!bps || bps < 1) return "-";
    return fmtBytes(bps) + "/s";
  };
  const fmtMbps = (bytesPerSecond) => {
    if (!bytesPerSecond || bytesPerSecond < 1) return "0 Mbps";
    const mbps = (bytesPerSecond * 8) / 1_000_000;
    return `${mbps >= 100 ? mbps.toFixed(0) : mbps >= 10 ? mbps.toFixed(1) : mbps.toFixed(2)} Mbps`;
  };
  // v0.8.8: bytes-remaining ÷ bps → "12s" or "3m 04s".
  const fmtEta = (remainingBytes, bps) => {
    if (!bps || bps < 1 || remainingBytes <= 0) return "-";
    const sec = Math.round(remainingBytes / bps);
    if (sec < 60) return `${sec}s`;
    const m = Math.floor(sec / 60);
    const s = sec - m * 60;
    if (m < 60) return `${m}m ${String(s).padStart(2, "0")}s`;
    const h = Math.floor(m / 60);
    return `${h}h ${m - h * 60}m`;
  };
  const fmtTime = (ms) => {
    const d = new Date(ms);
    const opts = { hour: "numeric", minute: "2-digit" };
    if (getSettings()?.show_message_seconds === true) {
      opts.second = "2-digit";
    }
    return d.toLocaleTimeString([], opts);
  };
  const sameDay = (a, b) => {
    const da = new Date(a), db = new Date(b);
    return da.getFullYear() === db.getFullYear() && da.getMonth() === db.getMonth() && da.getDate() === db.getDate();
  };
  const dayLabel = (ms) => {
    const d = new Date(ms);
    const now = new Date();
    const yest = new Date(); yest.setDate(now.getDate() - 1);
    if (sameDay(ms, now.getTime())) return "Today";
    if (sameDay(ms, yest.getTime())) return "Yesterday";
    // v0.10.5 bonus: smart relative labels for the recent past.
    // 2-7 days ago → weekday name (helps read the chat without
    // doing date math). >7 days but same year → "Apr 30". Older
    // years → "Apr 30, 2024".
    const ageMs = now.getTime() - ms;
    if (ageMs > 0 && ageMs < 7 * 24 * 60 * 60 * 1000) {
      const dayName = d.toLocaleDateString([], { weekday: "long" });
      return dayName;
    }
    if (d.getFullYear() === now.getFullYear()) {
      return d.toLocaleDateString([], { month: "short", day: "numeric" });
    }
    return d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });
  };
  const initials = (name) => {
    if (!name) return "?";
    const parts = name.replace(/[^a-zA-Z0-9 _-]/g, " ").split(/[ _-]+/).filter(Boolean);
    return (parts[0]?.[0] || "?").toUpperCase() + (parts[1]?.[0] || "").toUpperCase();
  };
  // v0.21.x: strip the internal collision-prefix from filenames
  // before displaying them. The daemon prefixes every inbox file
  // with `<13-digit-timestamp>_<16-hex-hash>_` to guarantee
  // uniqueness when two peers send the same filename. That prefix
  // is useful on disk but ugly in a chat bubble - users want to
  // see 'paper1.pdf', not '1779676087532_0d1e262c1c60b45f_paper1.pdf'.
  function displayFileName(name) {
    if (!name) return name;
    // Strip the daemon's staging prefix(es): 13 digits + _ + 16 hex
    // chars + _. APPLY RECURSIVELY — a forwarded file can accumulate
    // multiple stacked prefixes (e.g. ts1_hex1_ts2_hex2_IMG.jpeg)
    // when the same image bounces between machines. Bounded loop so
    // a pathological name can't spin.
    let out = String(name);
    for (let i = 0; i < 4; i += 1) {
      const m = out.match(/^\d{13}_[0-9a-fA-F]{16}_(.+)$/);
      if (!m) break;
      out = m[1];
    }
    return out;
  }
  // v0.21.x: middle-truncate a long path for display so the start
  // (root anchor like C:\Users\you) AND the meaningful end (the
  // actual folder leaf) stay visible. The whole path goes in the
  // element's title= so hovering still reveals it. Splits on the
  // path separator first to keep segment boundaries clean; falls
  // back to raw char split for paths that don't contain `\` or `/`.
  function _middleTruncatePath(p, maxChars) {
    const s = String(p || "");
    if (s.length <= maxChars) return s;
    // Try to keep complete leading + trailing segments.
    const sep = s.includes("\\") ? "\\" : "/";
    const parts = s.split(sep);
    if (parts.length >= 4) {
      // Always show drive/root + last 2 segments.
      const head = parts.slice(0, 2).join(sep);
      const tail = parts.slice(-2).join(sep);
      const candidate = head + sep + "…" + sep + tail;
      if (candidate.length <= maxChars) return candidate;
      // Last 2 alone if even head + tail is too long.
      const candidate2 = "…" + sep + tail;
      if (candidate2.length <= maxChars) return candidate2;
    }
    // Generic char-based middle elision.
    const keep = Math.max(8, Math.floor((maxChars - 1) / 2));
    return s.slice(0, keep) + "…" + s.slice(-keep);
  }
  const fileIcon = (name) => {
    const ext = (name.split(".").pop() || "").toLowerCase();
    if (["png","jpg","jpeg","gif","webp","bmp"].includes(ext)) return "🖼";
    if (["mp4","mov","mkv","webm","avi"].includes(ext)) return "🎬";
    if (["mp3","wav","flac","ogg","m4a"].includes(ext)) return "🎵";
    if (["pdf"].includes(ext)) return "📄";
    if (["zip","tar","gz","7z","rar"].includes(ext)) return "🗜";
    if (["doc","docx","odt","rtf"].includes(ext)) return "📝";
    if (["xls","xlsx","ods","csv"].includes(ext)) return "📊";
    return "📎";
  };

  return {
    $,
    el,
    fmtBytes,
    fmtRate,
    fmtMbps,
    fmtEta,
    fmtTime,
    sameDay,
    dayLabel,
    initials,
    displayFileName,
    _middleTruncatePath,
    fileIcon,
  };
}
