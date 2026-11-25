  // ── Pair modal ─────────────────────────────────────────────────────
  const pairBackdrop = $("#pair-backdrop");
  const pairTitle    = $("#pair-title");
  const pairExplain  = $("#pair-explain");
  const pairAvatar   = $("#pair-peer-avatar");
  const pairName     = $("#pair-peer-name");
  const pairSub      = $("#pair-peer-sub");
  const pairSasEl    = $("#pair-sas");
  const pairSasCompatEl = $("#pair-sas-compat");
  const pairMatch    = $("#pair-match");
  const pairMismatch = $("#pair-mismatch");
  const pairCancel   = $("#pair-cancel");

  function _formatSas(s) {
    s = (s || "").toString();
    if (/^\d{8}$/.test(s)) return `${s.slice(0, 2)} ${s.slice(2, 5)} ${s.slice(5)}`;
    s = s.padStart(6, "0").slice(-6);
    return s.slice(0, 3) + " " + s.slice(3);
  }

  // Protocol constant mirrored from one_link.pairing and ol_pair_qr. A
  // parity regression test locks all three representations together.
  const PAIR_SAS_WORDS = new Set([
    "agile","amuse","apple","basil","blaze","brick","cargo","cedar",
    "chess","climb","copper","crane","daisy","decoy","drift","eagle",
    "ember","exile","fable","flame","frost","globe","gravy","gusto",
    "happy","hover","igloo","indigo","ivory","jolly","juice","kindly",
    "koala","lemon","lunar","mango","melon","motor","north","nudge",
    "ocean","olive","panda","plume","quiet","rebel","ridge","saber",
    "sleek","sushi","tiger","trove","ultra","umbra","vapor","vivid",
    "wagon","winter","xenon","xylo","yacht","yodel","zebra","zinc",
  ]);

  function _canonicalPairSasPhrase(value) {
    const source = Array.isArray(value) ? value.join(" ") : String(value || "");
    const phrase = source.trim().toLowerCase().replace(/\s+/g, " ");
    const words = phrase ? phrase.split(" ") : [];
    if (words.length !== 5 || words.some((word) => !PAIR_SAS_WORDS.has(word))) {
      return "";
    }
    return words.join(" ");
  }

  function _showPairSas({ sas, sasPhrase }) {
    const phrase = _canonicalPairSasPhrase(sasPhrase);
    state.pairing.sas = sas || null;
    state.pairing.sasPhrase = phrase;
    pairSasEl.textContent = phrase || _formatSas(sas);
    if (pairSasCompatEl) {
      pairSasCompatEl.hidden = !phrase || !sas;
      pairSasCompatEl.textContent = phrase && sas
        ? `Older-client compatibility code: ${_formatSas(sas)}`
        : "";
    }
    renderSasArt($("#pair-sas-art"), sas);
    return phrase;
  }

  // v0.7.9 multi-modal SAS verification helpers.
  //
  // The transcript-bound five-word phrase is the current authority.
  // Numeric art stays available solely for mixed-version pairing with
  // an older client. Audio reads the phrase when present and falls back
  // to spelling the compatibility digits when it is not. The phrase is
  // daemon-derived independently on each side; the browser never invents it.

  // 24 distinct, easy-to-distinguish emoji. Avoid skin-tone
  // variants and culturally-loaded symbols. Each maps to a digit
  // pair so a 6-digit SAS yields 6 cells (one per digit, with the
  // symbol selected from `digit*2` mod table.length plus an offset
  // derived from neighbours so two equal digits produce different
  // cells).
  const SAS_ART_EMOJI = [
    "🐶","🐱","🦊","🐼","🐯","🐸",
    "🦋","🌸","🌳","🌈","🌊","🌙",
    "🍎","🍊","🍋","🍇","🍒","🥑",
    "🚀","🛸","⚓","🎵","🔔","⚡",
  ];
  const SAS_ART_BG = [
    "#5b3aa8","#3a6fa8","#3aa87f","#a87f3a","#a83a5b","#5ba83a",
    "#6a3aa8","#3a4aa8","#3aa897","#a8a23a","#a83a8b","#3aa83a",
  ];

  function sasArtCells(sas) {
    const s = String(sas || "").padStart(6, "0").slice(0, 6);
    const cells = [];
    for (let i = 0; i < 6; i++) {
      const d = parseInt(s[i], 10) || 0;
      // Mix neighboring digits so two adjacent identical digits
      // don't produce identical cells.
      const left = parseInt(s[(i + 5) % 6], 10) || 0;
      const right = parseInt(s[(i + 1) % 6], 10) || 0;
      const emojiIdx = (d * 7 + left * 3 + i * 11) % SAS_ART_EMOJI.length;
      const bgIdx = (d * 5 + right * 3 + i * 13) % SAS_ART_BG.length;
      cells.push({
        emoji: SAS_ART_EMOJI[emojiIdx],
        bg: SAS_ART_BG[bgIdx],
        digit: s[i],
      });
    }
    return cells;
  }

  function renderSasArt(host, sas) {
    if (!host) return;
    host.innerHTML = "";
    if (!sas) {
      host.classList.add("empty");
      return;
    }
    host.classList.remove("empty");
    for (const c of sasArtCells(sas)) {
      const cell = el("div", "cell", c.emoji);
      cell.style.backgroundColor = c.bg;
      cell.title = `digit ${c.digit}`;
      host.appendChild(cell);
    }
  }

  function speakSas(sasPhrase, sas) {
    if (!("speechSynthesis" in window)) {
      toast("This browser doesn't support speech.", "warn");
      return;
    }
    const phrase = _canonicalPairSasPhrase(sasPhrase);
    const rawDigits = String(sas || "");
    const s = /^\d{8}$/.test(rawDigits)
      ? rawDigits
      : rawDigits.padStart(6, "0").slice(-6);
    if (!phrase && (!s || /^0+$/.test(s))) {
      toast("Pair code isn't ready yet.", "info");
      return;
    }
    // Cancel any in-flight readback so rapid clicks don't queue.
    window.speechSynthesis.cancel();
    // Spell digit-by-digit with a pause every 3 digits - matches
    // the "043 192" formatting and makes phone-call confirmation
    // bulletproof.
    const words = ["zero","one","two","three","four","five","six","seven","eight","nine"];
    const digitSpoken = s.split("").map((d, i) => {
      const word = words[parseInt(d, 10)] || d;
      const pause = s.length === 8 ? (i === 2 || i === 5) : i === 3;
      return pause ? `, ${word}` : word;
    }).join(" ");
    const spoken = phrase ? phrase.split(" ").join(", ") : digitSpoken;
    const u = new SpeechSynthesisUtterance(spoken);
    u.rate = 0.85;
    u.pitch = 1.0;
    window.speechSynthesis.speak(u);
  }

  // v0.14.7 - phone pair flow: SAS-art primary + shorter button
  // copy. Reading 6 digits twice on a phone screen is fiddly; the
  // 6-cell visual grid is faster to glance-compare. Buttons get a
  // direct "Match" / "Don't match" framing matching what the user
  // is actually being asked.
  function _applyPhonePairFlow() {
    if (document.documentElement.getAttribute("data-form-factor") !== "phone") return;
    const art = document.querySelector("#pair-sas-art");
    if (art) art.style.display = "grid";
    const toggle = document.querySelector("#pair-sas-art-toggle");
    if (toggle) toggle.classList.add("on");
    const m = document.querySelector("#pair-match");
    if (m) m.textContent = "Match";
    const x = document.querySelector("#pair-mismatch");
    if (x) x.textContent = "Don't match";
  }

  async function openPairModal(peer) {
    state.pairing = {
      peerFp: peer.fingerprint, sas: null, sasPhrase: "", weConfirmed: false,
    };
    pairTitle.textContent = "Pair this device";
    pairExplain.textContent = "Compare all five words with the other device. They must be identical and in the same order.";
    pairAvatar.textContent = initials(peer.hostname || peer.short_id);
    pairName.textContent = peer.hostname || "(unknown)";
    pairSub.textContent = peer.short_id;
    pairSasEl.textContent = "…";
    if (pairSasCompatEl) {
      pairSasCompatEl.hidden = true;
      pairSasCompatEl.textContent = "";
    }
    renderSasArt($("#pair-sas-art"), null);
    showPairStage("compare");  // v0.8.7
    _applyPhonePairFlow();
    pairBackdrop.classList.add("show");
    // UX audit P0-4: 60s watchdog. If the other device doesn't
    // respond, surface a clear "didn't confirm yet" message
    // instead of hanging silently forever.
    _startPairWatchdog(peer.fingerprint);
    try {
      const res = await api.post(`/api/peers/${peer.fingerprint}/pair`, {});
      const phrase = _showPairSas({
        sas: res.sas,
        sasPhrase: res.sas_phrase || res.sas_words || "",
      });
      pairExplain.textContent = phrase
        ? "Compare all five words with the other device. They must be identical and in the same order."
        : "This peer only supports the older numeric ceremony. Compare the full compatibility code on both devices.";
    } catch (e) {
      pairSasEl.textContent = "";
      _clearPairWatchdog();
      toast(`Couldn't start pairing. ${e.message || e}`, "bad");
    }
  }

  // UX audit P0-4 helper. Watches the pair flow for inactivity.
  // After 60s with the modal still open and pairing not complete,
  // surface a visible "didn't respond" message. closePairModal()
  // also clears this so a successful pair doesn't trigger it.
  let _pairWatchdogTimer = null;
  function _startPairWatchdog(peerFp) {
    _clearPairWatchdog();
    _pairWatchdogTimer = setTimeout(() => {
      if (!state.pairing || state.pairing.peerFp !== peerFp) return;
      if (!pairBackdrop.classList.contains("show")) return;
      pairExplain.textContent = (
        "The other device hasn't confirmed yet. Open One Link on "
        + "that device and look for a matching code, or close this "
        + "and try again."
      );
      try { toast("The other device hasn't responded. You can wait or close and try again.", "warn", 6000); }
      catch (_) {}
    }, 60_000);
  }
  function _clearPairWatchdog() {
    if (_pairWatchdogTimer) {
      clearTimeout(_pairWatchdogTimer);
      _pairWatchdogTimer = null;
    }
  }

  function openPairModalIncoming(peer, sas) {
    const sasPhrase = arguments.length > 2 && typeof arguments[2] === "string"
      ? arguments[2]
      : "";
    state.pairing = {
      peerFp: peer.fingerprint, sas, sasPhrase, weConfirmed: false,
    };
    showPairStage("compare");  // Never retain the prior ceremony's stage.
    pairTitle.textContent = "Pair this device";
    pairExplain.textContent = "The other device asked to pair. Verify all five words match in the same order.";
    pairAvatar.textContent = initials(peer.hostname || peer.short_id);
    pairName.textContent = peer.hostname || "(unknown)";
    pairSub.textContent = peer.short_id;
    const phrase = _showPairSas({ sas, sasPhrase });
    if (!phrase) {
      pairExplain.textContent = "The other device uses the older numeric ceremony. Compare the full compatibility code on both devices.";
    }
    _applyPhonePairFlow();
    pairBackdrop.classList.add("show");
  }

  function closePairModal(succeeded) {
    pairBackdrop.classList.remove("show");
    state.pairing = {
      peerFp: null, sas: null, sasPhrase: "", weConfirmed: false,
    };
    // UX audit P0-4: clear watchdog so we don't fire a stale
    // "the other device didn't respond" message after a successful
    // pair (or after user cancels).
    _clearPairWatchdog();
    // v0.7.9: stop any in-flight readback so a closed modal isn't
    // chattering "five six" from the speaker.
    try { window.speechSynthesis?.cancel(); } catch {}
    const art = $("#pair-sas-art");
    if (art) art.style.display = "none";
  }

  // v0.8.7: switch the pair modal between the two stages.
  function showPairStage(stage) {
    const compare = $("#pair-stage-compare");
    const verified = $("#pair-stage-verified");
    if (!compare || !verified) return;
    compare.style.display = stage === "compare" ? "" : "none";
    verified.style.display = stage === "verified" ? "" : "none";
  }

  // v0.8.7: when both devices confirm SAS match, slide to stage 2
  // ('paired - also verify in person?') instead of closing outright.
  // Closing the modal still happens - just from the new stage's
  // explicit Skip / Verify button.
  function enterPairVerifyStage() {
    pairTitle.textContent = "Paired successfully";
    pairExplain.textContent = "";
    showPairStage("verified");
  }

  pairMatch.onclick = async () => {
    if (!state.pairing.peerFp) return;
    pairMatch.disabled = true;
    try {
      const res = await api.post(`/api/peers/${state.pairing.peerFp}/pair-confirm`, {});
      state.pairing.weConfirmed = true;
      if (res.both_confirmed) {
        // v0.8.7: do NOT close the modal - pivot to the verify-now
        // stage. Toast still fires so the user knows pairing succeeded.
        toast("Paired", "good");
        enterPairVerifyStage();
      } else {
        pairExplain.textContent = "Waiting for the other device to confirm…";
      }
    } catch (e) {
      toast(`Pair confirm failed: ${e.message || e}`, "bad");
    } finally {
      pairMatch.disabled = false;
    }
  };

  // v0.8.7: the verify-now stage exposes two CTAs.
  $("#pair-verify-now")?.addEventListener("click", async () => {
    const fp = state.pairing.peerFp;
    if (!fp) { closePairModal(true); return; }
    try {
      await api.post(`/api/peers/${fp}/verify`, {
        method: state.pairing.sasPhrase ? "sas-words-v3" : "sas-digits",
        note: "Confirmed during pair flow",
      });
      toast("Verified in person. Hard to fake that.", "good");
    } catch (e) {
      toast(`Verify didn't work: ${errorToastBody(e)}`, "bad");
    } finally {
      closePairModal(true);
      // Refresh peers so the green ✓ shows up on the sidebar
      // immediately. WS broadcast also fires server-side, but a
      // direct refresh removes any visible lag.
      refreshPeers();
    }
  });
  $("#pair-skip-verify")?.addEventListener("click", () => {
    closePairModal(true);
  });
  pairMismatch.onclick = async () => {
    if (!state.pairing.peerFp) return;
    try {
      await api.post(`/api/peers/${state.pairing.peerFp}/pair-reject`, {});
    } catch (e) { /* ignore */ }
    closePairModal(false);
    toast("Pairing rejected - possible MITM", "bad", 6000);
    refreshPeers();
  };
  pairCancel.onclick = () => closePairModal(false);
  pairSasEl.onclick = () => {
    const phrase = _canonicalPairSasPhrase(state.pairing?.sasPhrase);
    const txt = phrase || String(state.pairing?.sas || "");
    if (txt) {
      copyToClipboard(txt, phrase ? "verification phrase" : "compatibility code");
    }
  };
  // v0.7.9 multi-modal SAS - wire pair-modal helpers.
  $("#pair-sas-speak")?.addEventListener("click", () => {
    speakSas(state.pairing?.sasPhrase, state.pairing?.sas);
  });
  $("#pair-sas-art-toggle")?.addEventListener("click", (e) => {
    const art = $("#pair-sas-art");
    if (!art) return;
    const showing = art.style.display !== "none";
    art.style.display = showing ? "none" : "grid";
    e.currentTarget.classList.toggle("on", !showing);
  });
  $("#pair-sas-copy")?.addEventListener("click", () => {
    const phrase = _canonicalPairSasPhrase(state.pairing?.sasPhrase);
    const sas = state.pairing?.sas;
    if (!phrase && !sas) { toast("Pair phrase isn't ready yet.", "info"); return; }
    copyToClipboard(
      phrase || String(sas).padStart(6, "0"),
      phrase ? "verification phrase" : "compatibility code",
    );
  });

