  const FIRST_SEND_KEY = "one_link.first_send_celebrated";
  function _maybeCelebrateFirstSend(msg) {
    if (!msg?.peer || !msg?.id) return;
    let seen = {};
    try { seen = JSON.parse(localStorage.getItem(FIRST_SEND_KEY) || "{}"); }
    catch {}
    if (seen[msg.peer]) return;
    seen[msg.peer] = Date.now();
    try { localStorage.setItem(FIRST_SEND_KEY, JSON.stringify(seen)); } catch {}
    // Defer one frame so the bubble has been added to the DOM.
    requestAnimationFrame(() => {
      const node = document.querySelector(`[data-msg-id="${CSS.escape(msg.id)}"]`);
      if (!node) return;
      node.classList.add("first-send-glow");
      // Remove the class after the animation completes so the bubble
      // settles into its normal style without manual cleanup elsewhere.
      setTimeout(() => node.classList.remove("first-send-glow"), 2200);
    });
  }

  // v0.21.x: "What's new" modal. Keyed by daemon's app_version in
  // localStorage; on a fresh install the first run is consumed by
  // the welcome wizard, so we seed the key on first observation
  // and only surface the modal when a subsequent run sees a new
  // version. Highlights are baked-in per release; the doc link
  // points at the GitHub repo's CHANGELOG.
  const WHATS_NEW_KEY = "one_link.last_seen_version";
  const WHATS_NEW_HIGHLIGHTS = {
    "0.21.0": {
      headline: "v0.21 · reliability, polish, and a self-updating One Link",
      items: [
        "One Link now updates itself: one click hands the exact signed release to an external updater that verifies Sigstore signatures, checksums, and the SBOM, swaps A/B with automatic rollback, and only commits after the new build proves healthy.",
        "Send button never silently hangs — every outbound message gets a status pill (Sending → Queued → Failed → Retry) and a 25s hard timeout that falls into the offline queue.",
        "Click any photo to open a fullscreen lightbox. Arrow keys / swipe move between every photo in this conversation.",
        "Long pasted messages collapse to a preview with a Show more toggle so the chat stays readable.",
        "Calls now have audible ringback + ringtone, a permission preflight, and leave a missed-call entry with Call back if no one answers.",
        "Voice messages: listen back before you send, play at 1.5x / 2x, with a waveform on every bubble.",
        "Unread count surfaces in the tab title, OS dock badge, and per-peer sidebar.",
        "Photos are re-encoded to strip EXIF before they can be attached; if stripping fails, the image is blocked. Edit before sending: crop, draw, blur a face.",
      ],
    },
  };
  function _maybeShowWhatsNew(currentVersion) {
    if (!currentVersion) return;
    let lastSeen = "";
    try { lastSeen = localStorage.getItem(WHATS_NEW_KEY) || ""; } catch {}
    if (lastSeen === currentVersion) return;
    // First-launch ever path: the welcome wizard handles the user.
    // Seed the key without showing the modal so the next version
    // bump shows it correctly.
    const onboardingDone = (() => {
      try { return localStorage.getItem(ONBOARDING_STORAGE_KEY) === "1"; }
      catch { return false; }
    })();
    if (!lastSeen && !onboardingDone) {
      try { localStorage.setItem(WHATS_NEW_KEY, currentVersion); } catch {}
      return;
    }
    const highlights = WHATS_NEW_HIGHLIGHTS[currentVersion]
      || _autoGenericWhatsNew(currentVersion);
    _showWhatsNewModal(highlights, currentVersion);
  }
  function _autoGenericWhatsNew(version) {
    return {
      headline: `Updated to v${version}`,
      items: [
        "Bug fixes and improvements across the chat surface.",
        "See the project changelog for the full list of changes.",
      ],
    };
  }
  function _showWhatsNewModal(highlights, version) {
    _ensureWhatsNewModal();
    const modal = document.getElementById("whatsnew-modal");
    modal.querySelector(".wnm-title").textContent = highlights.headline;
    const list = modal.querySelector(".wnm-items");
    list.innerHTML = "";
    for (const it of highlights.items) {
      const li = document.createElement("li");
      li.textContent = it;
      list.appendChild(li);
    }
    const dismiss = () => {
      try { localStorage.setItem(WHATS_NEW_KEY, version); } catch {}
      modal.classList.remove("show");
      document.body.classList.remove("wnm-open");
    };
    modal.querySelector(".wnm-dismiss").onclick = dismiss;
    modal.addEventListener("click", (ev) => {
      const t = ev.target;
      if (t && t instanceof Element && t.hasAttribute("data-wnm-close")) dismiss();
    }, { once: false });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape" && modal.classList.contains("show")) dismiss();
    }, { once: true });
    modal.classList.add("show");
    document.body.classList.add("wnm-open");
  }
  function _ensureWhatsNewModal() {
    if (document.getElementById("whatsnew-modal")) return;
    const m = document.createElement("div");
    m.id = "whatsnew-modal";
    m.className = "wnm-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-labelledby", "wnm-title-id");
    m.innerHTML = `
      <div class="wnm-backdrop" data-wnm-close></div>
      <div class="wnm-pane">
        <h2 class="wnm-title" id="wnm-title-id">What's new</h2>
        <ul class="wnm-items"></ul>
        <div class="wnm-actions">
          <button type="button" class="wnm-dismiss">Start using it</button>
        </div>
      </div>
    `;
    document.body.appendChild(m);
  }

  function handleLocalVersionDrift(daemonVer, pageVer, reason) {
    console.warn(
      `One Link page/backend drift: page=${pageVer}, daemon=${daemonVer}, reason=${reason || "version"}`,
    );
    // Hand off to LiveRefresh: it schedules a soft reload as soon as
    // the user is idle (no draft text, no open modal, no recent typing)
    // so the UI quietly upgrades itself without disrupting work.
    if (typeof LiveRefresh !== "undefined" && LiveRefresh.scheduleSoftReload) {
      LiveRefresh.scheduleSoftReload(daemonVer, reason || "boot");
    } else {
      // Fallback: should never fire because LiveRefresh is defined
      // earlier in this file. Keeps behavior safe if init order
      // changes someday.
      const key = `ol_local_version_drift:${daemonVer}:vs:${pageVer}`;
      if (sessionStorage.getItem(key) === "1") return;
      sessionStorage.setItem(key, "1");
      toast("One Link refreshed itself in the background. If anything feels off, reopen it.", "info", 5000);
    }
  }

  // v0.8.0.1: the version the page's HTML+JS was built against.
  // Compared at startup against the daemon's /api/me.app_version
  // so we surface a clear "restart One Link" banner instead of
  // letting the user smack into mysterious 404s on endpoints the
  // running daemon doesn't have yet. Bump on every release.
  const PAGE_BUILT_FOR = "0.22.1";
  const PAGE_SOURCE_FINGERPRINT = "__ONE_LINK_SOURCE_FINGERPRINT__";

  // v0.21.x: silent-retry helper for boot-time API calls. The
  // initial /api/me fetch races with the cookie that _index just
  // set (especially when the daemon was just restarted and the
  // browser is replaying a stale-cookie cache); a single failure
  // shouldn't fire the "Can't reach One Link" toast. Try 3 times
  // over ~3s with a small backoff before treating it as a real
  // outage. Returns the parsed body or rethrows the LAST error
  // so callers can decide what to do.
  async function _bootApiGetWithRetry(path, attempts = 3, baseDelayMs = 350) {
    let lastErr = null;
    for (let i = 0; i < attempts; i++) {
      try {
        return await api.get(path);
      } catch (e) {
        lastErr = e;
        if (i < attempts - 1) {
          // Linear backoff: 350ms, 700ms, 1050ms — total under 3s.
          await new Promise((r) => setTimeout(r, baseDelayMs * (i + 1)));
        }
      }
    }
    throw lastErr;
  }

