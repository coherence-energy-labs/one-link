  function populateNotifSettings() {
    const btn = $("#set-notif");
    if (!btn) return;
    if (!notifySupported()) {
      btn.textContent = "Not supported";
      btn.disabled = true;
      return;
    }
    btn.disabled = false;
    if (Notification.permission === "granted") {
      btn.textContent = "Enabled ✓";
      btn.classList.add("on");
    } else if (Notification.permission === "denied") {
      btn.textContent = "Blocked by browser";
      btn.disabled = true;
    } else {
      btn.textContent = "Enable";
      btn.classList.remove("on");
    }
  }
  // v0.10.0 - runtime settings cache populated when settings load.
  // Defaults are sane so notifyIncoming + soundOnIncoming work even
  // before /api/settings has been fetched.
  state.runtimeSettings = {
    theme: "dark",
    ui_density: "comfortable",
    message_bubble_style: "gradient",
    font_scale: "normal",
    motion_level: "full",
    accent_color: "#7c5cff",
    chat_wallpaper: "soft",
    enter_to_send: true,
    compact_message_list: false,
    show_message_seconds: false,
    auto_scroll_new_messages: true,
    send_link_previews: true,
    dnd_enabled: false,
    dnd_start: "22:00",
    dnd_end: "07:00",
    notification_sound: true,
    pair_default_allow_all: true,
  };

  // v0.10.0: live theme apply. Sets <html data-theme="..."> which
  // CSS variable overrides key off of. No element-by-element repaint.
  // v0.10.0: pull settings + flip the theme + cache runtime values.
  // Called on init() so a theme set in a prior session takes effect
  // before the user sees anything.
  async function loadAndApplySettings() {
    try {
      const r = await api.get("/api/settings");
      applyTheme(r.theme || "dark");
      applyAppearanceSettings(r);
      // v0.11.1: apply saved avatar color so the user's chosen tint
      // sticks across reloads, not just the session they picked it.
      if (r.avatar_color) {
        document.documentElement.style.setProperty(
          "--my-avatar", r.avatar_color,
        );
      }
      state.runtimeSettings = {
        theme: r.theme || "dark",
        ui_density: r.ui_density || "comfortable",
        message_bubble_style: r.message_bubble_style || "gradient",
        font_scale: r.font_scale || "normal",
        motion_level: r.motion_level || "full",
        accent_color: r.accent_color || "#7c5cff",
        chat_wallpaper: r.chat_wallpaper || "soft",
        enter_to_send: r.enter_to_send !== false,
        compact_message_list: r.compact_message_list === true,
        show_message_seconds: r.show_message_seconds === true,
        auto_scroll_new_messages: r.auto_scroll_new_messages !== false,
        send_link_previews: r.send_link_previews !== false,
        dnd_enabled: !!r.dnd_enabled,
        dnd_start: r.dnd_start || "22:00",
        dnd_end: r.dnd_end || "07:00",
        notification_sound: r.notification_sound !== false,
        pair_default_allow_all: r.pair_default_allow_all !== false,
        bio: r.bio || "",
        avatar_color: r.avatar_color || "#7c4dff",
        // v0.12.2 read-receipt privacy.
        send_read_receipts: r.send_read_receipts !== false,
        display_read_receipts: r.display_read_receipts !== false,
        // v0.12.3 typing-indicator privacy.
        send_typing_indicators: r.send_typing_indicators !== false,
        display_typing_indicators: r.display_typing_indicators !== false,
      };
      // Reuse this settings snapshot for the update toggle. The previous
      // DOMContentLoaded hook issued a second /api/settings request during
      // every boot solely to read this one field.
      await _refreshAutoInstallToggle(r);
    } catch {
      // Daemon unreachable / fresh install - default theme stays.
      await _refreshAutoInstallToggle({});
    }
  }

  function applyTheme(theme) {
    const t = (theme || "dark").toLowerCase();
    const html = document.documentElement;
    if (t === "light") html.setAttribute("data-theme", "light");
    else if (t === "auto") html.setAttribute("data-theme", "auto");
    else html.removeAttribute("data-theme");  // dark = default
  }

  function _validAppearanceValue(value, allowed, fallback) {
    const v = String(value || "").toLowerCase();
    return allowed.includes(v) ? v : fallback;
  }

  function applyAppearanceSettings(settings = {}) {
    const html = document.documentElement;
    const density = _validAppearanceValue(
      settings.ui_density, ["comfortable", "compact", "spacious"], "comfortable",
    );
    const bubbleStyle = _validAppearanceValue(
      settings.message_bubble_style, ["gradient", "solid", "minimal"], "gradient",
    );
    const fontScale = _validAppearanceValue(
      settings.font_scale, ["small", "normal", "large"], "normal",
    );
    const motion = _validAppearanceValue(
      settings.motion_level, ["full", "reduced", "off"], "full",
    );
    const wallpaper = _validAppearanceValue(
      settings.chat_wallpaper, ["soft", "none", "field", "midnight"], "soft",
    );
    html.dataset.density = density;
    html.dataset.bubbleStyle = bubbleStyle;
    html.dataset.fontScale = fontScale;
    html.dataset.motion = motion;
    html.dataset.wallpaper = wallpaper;
    html.dataset.compactMessages = settings.compact_message_list === true ? "1" : "0";
    const accent = String(settings.accent_color || "#7c5cff");
    if (/^#[0-9a-fA-F]{6}$/.test(accent)) {
      html.style.setProperty("--accent", accent);
      html.style.setProperty("--bubble-out", `linear-gradient(135deg, ${accent} 0%, var(--accent-2) 100%)`);
    }
  }

  // v0.10.0: do-not-disturb check. Compares current local time
  // against the user's window. Wraps around midnight when start
  // > end (e.g. 22:00 → 07:00 means "any time between 22:00 and
  // 07:00 the next morning").
  function isQuietHoursActive() {
    const rs = state.runtimeSettings;
    if (!rs?.dnd_enabled) return false;
    const parse = (s) => {
      const m = (s || "").match(/^(\d{1,2}):(\d{2})$/);
      if (!m) return null;
      return parseInt(m[1], 10) * 60 + parseInt(m[2], 10);
    };
    const start = parse(rs.dnd_start);
    const end = parse(rs.dnd_end);
    if (start == null || end == null) return false;
    const now = new Date();
    const minutes = now.getHours() * 60 + now.getMinutes();
    if (start === end) return false;  // zero-width window
    if (start < end) return minutes >= start && minutes < end;
    // Wrap-around (e.g. 22:00 → 07:00).
    return minutes >= start || minutes < end;
  }

  // v0.10.0: notification chime via Web Audio API. Two-tone synth,
  // ~250ms total, gentle decay. No vendored audio file. Respects
  // the master setting + DND + per-peer mute.
