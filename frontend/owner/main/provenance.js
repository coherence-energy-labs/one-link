  // ── Living Presence Tier α-pre: Reality dot rendering ─────────────
  // Renders a single calm indicator on a media bubble showing the
  // cryptographically-verified provenance state of that media: who
  // produced it, on what kind of source, over what path, with what
  // recording state. Tap to reveal the trust pane.
  //
  // Doctrine compliance:
  //   §4.c - calm provenance indicator is REQUIRED on every verified
  //          media bubble.
  //   §3.5.c - no surreptitious indicators. The dot is visible
  //            but unobtrusive at 14px; the detail pane is full text.
  //   §3.9.a - no raw fingerprint hex anywhere in the detail pane.
  //   §3.6.c - no network-technology jargon ("on Wi-Fi"); we use the
  //            plain-language labels from frame_provenance.py.
  //
  // The provenance state is provided by frame_provenance.to_ui_dict:
  //   { kind: "Original" | "Repaired" | "Predicted" | "Reconstructed" | "Blank",
  //     path: "Local network" | "Direct" | "Via relay" | ...,
  //     recording: "Not recording" | "You are recording" | ...,
  //     verified: bool,
  //     produced_at_us: int }
  //
  // Returns a {dot, detail} DOM pair the caller appends to the
  // bubble; OR null if no provenance is known (calm hidden state -
  // we never show a dot for unknown).
  function renderRealityDot(blobHex) {
    if (!blobHex) return null;
    const state_ = state.provenanceByBlob.get(blobHex);
    if (!state_) return null;

    const dot = el("span", "reality-dot");
    dot.classList.add(state_.verified ? "verified" : "unverified");
    // Title attribute on hover for quick reference. Plain language
    // only - never hex, never network type names.
    dot.title = state_.verified
      ? `${state_.kind} · ${state_.path} · ${state_.recording}`
      : "Unverified sender - tap for details";
    dot.setAttribute("aria-label", dot.title);
    dot.setAttribute("role", "button");

    const detail = el("div", "reality-detail");
    const addRow = (label, value) => {
      const row = el("div", "reality-row");
      row.appendChild(el("span", "reality-label", label));
      row.appendChild(el("span", "reality-value", value));
      detail.appendChild(row);
    };
    addRow("Source", state_.kind);
    addRow("Path", state_.path);
    addRow("Recording", state_.recording);
    addRow("Signature", state_.verification || (state_.verified ? "Sender signature confirmed" : "Sender not confirmed"));
    addRow("Scope", state_.scope || "Confirms sender and bytes, not physical truth");

    dot.addEventListener("click", (ev) => {
      ev.stopPropagation();
      detail.classList.toggle("show");
    });
    dot.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter" || ev.key === " ") {
        ev.preventDefault();
        detail.classList.toggle("show");
      }
    });
    dot.setAttribute("tabindex", "0");

    return { dot, detail };
  }

