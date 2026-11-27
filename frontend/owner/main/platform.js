  try {
    if ("scrollRestoration" in history) history.scrollRestoration = "manual";
  } catch (_) {}

  // ── v0.14.2 - Phone-tier foundation ─────────────────────────────────
  // Detect form-factor at boot, set data-form-factor on <html>, and
  // re-evaluate on debounced resize. CSS in the page reads the
  // attribute via `html[data-form-factor="phone"] .desktop-only` and
  // `html[data-form-factor="phone"] [data-tier="advanced"]`.
  // Subsequent v0.14.3 → v0.14.8 ships tag elements; this ship only
  // ships the mechanism.
  function _detectFormFactor() {
    const w = Math.min(window.innerWidth, window.innerHeight);
    const touch = ("ontouchstart" in window) || (navigator.maxTouchPoints || 0) > 0;
    const ua = (navigator.userAgent || "").toLowerCase();
    const uaMobile = /iphone|ipod|android.+mobile|windows phone/.test(ua);
    if (w <= 480 || uaMobile) return "phone";
    if (w <= 900 && touch) return "tablet";
    return "desktop";
  }
  function _applyFormFactor() {
    const ff = _detectFormFactor();
    document.documentElement.setAttribute("data-form-factor", ff);
    return ff;
  }
  // Apply BEFORE first paint so CSS rules don't flicker.
  _applyFormFactor();
  // Debounced resize re-eval. 250ms keeps a phone rotated to landscape
  // from instantly flipping into desktop tier; the user genuinely has
  // to resize a window past the threshold.
  let _ffResizeTimer = null;
  window.addEventListener("resize", () => {
    if (_ffResizeTimer) clearTimeout(_ffResizeTimer);
    _ffResizeTimer = setTimeout(_applyFormFactor, 250);
  });

