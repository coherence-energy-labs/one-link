  // ── Composer: text + staged files share one Send button ───────────
  const input = $("#input");
  const sendBtn = $("#btn-send");
  const tray = $("#attach-tray");

  function refreshSendEnabled() {
    const hasText = input.value.trim().length > 0;
    const hasFiles = state.staged.length > 0;
    sendBtn.disabled = state.composerSendInFlight
      || (!hasText && !hasFiles)
      || (!state.selectedPeer && !state.selectedGroup);
  }
  input.addEventListener("input", () => {
    refreshSendEnabled();
    saveActiveDraft();
    input.style.height = "auto";
    input.style.height = Math.min(160, input.scrollHeight) + "px";
  });
  input.addEventListener("keydown", (e) => {
    const enterSends = state.runtimeSettings?.enter_to_send !== false;
    const shouldSend = e.key === "Enter"
      && ((enterSends && !e.shiftKey) || (!enterSends && e.ctrlKey));
    if (shouldSend) {
      e.preventDefault();
      sendCurrent();
    }
  });
  sendBtn.addEventListener("click", sendCurrent);

  // ── Staging tray (paste/drop/attach all stage instead of auto-send) ─
  function readDataUrl(file) {
    return new Promise((resolve) => {
      if (!file.type?.startsWith("image/")) { resolve(null); return; }
      const r = new FileReader();
      r.onload = () => resolve(r.result);
      r.onerror = () => resolve(null);
      r.readAsDataURL(file);
    });
  }
  async function stageFile(file, relPath = null) {
    if (!file) return false;
    // Mint before any image processing/read await so this user intent has one
    // cryptographically random identity for its entire staged lifetime.
    const clientDeliveryId = _newClientMsgId();
    // v0.21.x: EXIF / metadata stripping for images. Camera photos
    // carry GPS coords + camera model + timestamp by default; sending
    // those reveals where and how a photo was taken. We re-encode
    // through canvas (which discards all EXIF).  This privacy boundary is
    // deliberately fail-closed: an image that cannot be decoded and
    // re-encoded is not staged as its metadata-bearing original.
    let workingFile = file;
    if (_isImageFileForStrip(file)) {
      try {
        workingFile = await _stripImageMetadata(file);
      } catch (e) {
        console.warn("Image metadata removal failed; attachment blocked:", e);
        toast(
          "This image was not attached because One Link could not safely remove its location and camera metadata. Convert it to JPEG, PNG, or WebP and try again.",
          "bad",
          8000,
        );
        return false;
      }
    }
    const id = ++state.stagedSeq;
    const dataUrl = await readDataUrl(workingFile);
    // v0.21.x: relPath carries the original folder-relative path when
    // the file came in from a drag-folder drop. The send pipeline
    // forwards it as the rel_path multipart field so the recipient
    // mirrors the folder tree under inbox/<rel_path> instead of
    // dropping every file flat. null for ordinary single-file stages.
    state.staged.push({ id, clientDeliveryId, file: workingFile, dataUrl, relPath });
    renderStaging();
    refreshSendEnabled();
    return true;
  }
  function _isImageFileForStrip(file) {
    const type = (file?.type || "").toLowerCase();
    if (type === "image/jpeg" || type === "image/jpg" || type === "image/png" || type === "image/webp") return true;
    // Some browsers leave file.type empty — sniff by extension.
    const ext = (file?.name || "").split(".").pop()?.toLowerCase() || "";
    return ext === "jpg" || ext === "jpeg" || ext === "png" || ext === "webp";
  }
  async function _stripImageMetadata(file) {
    const url = URL.createObjectURL(file);
    try {
      const img = await new Promise((res, rej) => {
        const i = new Image();
        i.onload = () => res(i);
        i.onerror = rej;
        i.src = url;
      });
      const canvas = document.createElement("canvas");
      canvas.width = img.naturalWidth;
      canvas.height = img.naturalHeight;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("2D canvas is unavailable");
      ctx.drawImage(img, 0, 0);
      const declaredType = (file.type || "").toLowerCase();
      const extension = (file.name || "").split(".").pop()?.toLowerCase() || "";
      const outType = declaredType === "image/png" || (!declaredType && extension === "png")
        ? "image/png"
        : declaredType === "image/webp" || (!declaredType && extension === "webp")
          ? "image/webp"
          : "image/jpeg";
      const quality = outType === "image/jpeg" ? 0.92 : undefined;
      const blob = await new Promise((resolve, reject) => {
        canvas.toBlob((value) => {
          if (!value || value.size === 0) {
            reject(new Error("canvas produced no sanitized image"));
            return;
          }
          resolve(value);
        }, outType, quality);
      });
      if (blob.type !== outType) {
        throw new Error(`browser did not honor sanitized image type ${outType}`);
      }
      return new File([blob], file.name, {
        type: outType,
        lastModified: file.lastModified,
      });
    } finally {
      URL.revokeObjectURL(url);
    }
  }
  function removeStaged(id) {
    state.staged = state.staged.filter(s => s.id !== id);
    renderStaging();
    refreshSendEnabled();
  }
  function renderStaging() {
    tray.innerHTML = "";
    if (state.staged.length === 0) {
      tray.classList.remove("show");
      return;
    }
    tray.classList.add("show");
    for (const s of state.staged) {
      const chip = el("div", "chip");
      const thumb = el("div", "thumb");
      if (s.dataUrl) {
        const img = document.createElement("img");
        img.src = s.dataUrl;
        thumb.appendChild(img);
        // v0.21.x: edit affordance on image chips. Click thumb edge
        // pencil OR double-click thumb itself opens the markup
        // editor. Crop / pen / blur + undo + save replaces the
        // staged file with the edited version.
        if (_isImageFileForStrip(s.file)) {
          const editBtn = document.createElement("button");
          editBtn.type = "button";
          editBtn.className = "chip-edit-btn";
          editBtn.title = "Edit image (crop, draw, blur)";
          editBtn.textContent = "✎";
          editBtn.onclick = (ev) => { ev.stopPropagation(); openImageEditor(s); };
          thumb.appendChild(editBtn);
          thumb.ondblclick = (ev) => { ev.stopPropagation(); openImageEditor(s); };
        }
      } else {
        thumb.textContent = fileIcon(s.file.name);
      }
      const meta = el("div", "meta");
      // v0.21.x: inline-editable filename. Click → contenteditable
      // → blur or Enter commits. Keeps "1779063202010_*.png"-style
      // ugly names out of the receiver's chat history. Updates the
      // File object on commit (browser File constructor preserves
      // content + type; new instance gets the friendlier name).
      const nameEl = el("div", "name editable", s.file.name);
      nameEl.title = "Click to rename before sending";
      nameEl.tabIndex = 0;
      nameEl.addEventListener("click", (ev) => {
        ev.stopPropagation();
        _beginRenameStaged(nameEl, s);
      });
      nameEl.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          _beginRenameStaged(nameEl, s);
        }
      });
      meta.appendChild(nameEl);
      meta.appendChild(el("div", "size", fmtBytes(s.file.size)));
      const x = el("button", "x", "×");
      x.title = "Remove";
      x.onclick = () => removeStaged(s.id);
      chip.appendChild(thumb);
      chip.appendChild(meta);
      chip.appendChild(x);
      tray.appendChild(chip);
    }
  }
  // v0.21.x: image markup editor for staged photos. Pen / blur /
  // crop with undo. Output replaces the staged File so the receiver
  // sees the edited version. Pure Canvas2D — no external deps.
  //
  // Op model: each user action pushes onto an `ops` stack. Render =
  // baseImage → apply each op in order → render live stroke on top.
  // Save flattens to a JPEG / PNG depending on source type.
