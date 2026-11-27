  const _editorState = {
    chipId: null,
    baseImage: null,
    width: 0,
    height: 0,
    ops: [],
    activeOp: null,
    tool: "pen",
    color: "#ff4d4d",
    penSize: 4,
    blurRadius: 14,
    scale: 1,
    pointer: null,
  };
  async function openImageEditor(staged) {
    _ensureImageEditorModal();
    const modal = document.getElementById("image-editor-modal");
    const canvas = modal.querySelector(".iem-canvas");
    const ctx = canvas.getContext("2d");
    const stageUrl = URL.createObjectURL(staged.file);
    const img = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = rej;
      i.src = stageUrl;
    });
    _editorState.chipId = staged.id;
    _editorState.baseImage = img;
    _editorState.width = img.naturalWidth;
    _editorState.height = img.naturalHeight;
    _editorState.ops = [];
    _editorState.activeOp = null;
    _editorState.tool = "pen";
    _editorState.color = "#ff4d4d";
    _editorState.penSize = 4;
    _editorState.blurRadius = 14;
    _resizeEditorCanvas(canvas);
    _redrawEditor();
    URL.revokeObjectURL(stageUrl);
    _attachEditorHandlers(canvas);
    modal.classList.add("show");
    document.body.classList.add("iem-open");
  }
  function _resizeEditorCanvas(canvas) {
    const maxW = Math.min(window.innerWidth * 0.92, 1100);
    const maxH = Math.min(window.innerHeight * 0.78, 720);
    const aspect = _editorState.width / _editorState.height;
    let w = _editorState.width;
    let h = _editorState.height;
    if (w > maxW) { w = maxW; h = w / aspect; }
    if (h > maxH) { h = maxH; w = h * aspect; }
    _editorState.scale = w / _editorState.width;
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;
    canvas.width = _editorState.width;
    canvas.height = _editorState.height;
  }
  function _redrawEditor() {
    const canvas = document.querySelector("#image-editor-modal .iem-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(_editorState.baseImage, 0, 0, canvas.width, canvas.height);
    for (const op of _editorState.ops) _applyOp(ctx, op, canvas);
    if (_editorState.activeOp) _applyOp(ctx, _editorState.activeOp, canvas);
    // Crop preview rectangle (active crop op is rendered as a marquee)
    if (_editorState.tool === "crop" && _editorState.activeOp?.type === "crop-marquee") {
      const r = _editorState.activeOp.rect;
      ctx.save();
      ctx.strokeStyle = "rgba(255,255,255,.9)";
      ctx.lineWidth = 2 / _editorState.scale;
      ctx.setLineDash([6 / _editorState.scale, 4 / _editorState.scale]);
      ctx.strokeRect(r.x, r.y, r.w, r.h);
      ctx.restore();
    }
  }
  function _applyOp(ctx, op, canvas) {
    if (op.type === "pen") {
      if (!op.points || op.points.length === 0) return;
      ctx.save();
      ctx.strokeStyle = op.color;
      ctx.lineWidth = op.size;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      ctx.moveTo(op.points[0].x, op.points[0].y);
      for (let i = 1; i < op.points.length; i++) {
        ctx.lineTo(op.points[i].x, op.points[i].y);
      }
      ctx.stroke();
      ctx.restore();
    } else if (op.type === "blur") {
      if (!op.points || op.points.length === 0) return;
      // Draw a blurred copy of the canvas region into an off-screen
      // canvas, then composite back through a path mask. Two passes
      // keep the live preview cheap.
      const off = document.createElement("canvas");
      off.width = canvas.width;
      off.height = canvas.height;
      const octx = off.getContext("2d");
      octx.filter = `blur(${op.radius}px)`;
      octx.drawImage(canvas, 0, 0);
      ctx.save();
      ctx.beginPath();
      for (const p of op.points) {
        ctx.moveTo(p.x + op.radius * 1.6, p.y);
        ctx.arc(p.x, p.y, op.radius * 1.6, 0, Math.PI * 2);
      }
      ctx.clip();
      ctx.drawImage(off, 0, 0);
      ctx.restore();
    } else if (op.type === "crop") {
      // Crop is destructive — applied at apply-crop time, not in
      // the live op stack. Handled by _applyCrop().
    }
  }
  function _attachEditorHandlers(canvas) {
    if (canvas._handlersAttached) return;
    canvas._handlersAttached = true;
    function ptFromEvent(ev) {
      const rect = canvas.getBoundingClientRect();
      const x = (ev.clientX - rect.left) / rect.width * canvas.width;
      const y = (ev.clientY - rect.top) / rect.height * canvas.height;
      return { x, y };
    }
    canvas.addEventListener("pointerdown", (ev) => {
      canvas.setPointerCapture(ev.pointerId);
      const p = ptFromEvent(ev);
      const t = _editorState.tool;
      if (t === "pen") {
        _editorState.activeOp = {
          type: "pen",
          color: _editorState.color,
          size: _editorState.penSize / _editorState.scale,
          points: [p],
        };
      } else if (t === "blur") {
        _editorState.activeOp = {
          type: "blur",
          radius: _editorState.blurRadius / _editorState.scale,
          points: [p],
        };
      } else if (t === "crop") {
        _editorState.activeOp = {
          type: "crop-marquee",
          rect: { x: p.x, y: p.y, w: 0, h: 0 },
          startX: p.x,
          startY: p.y,
        };
      }
      _redrawEditor();
    });
    canvas.addEventListener("pointermove", (ev) => {
      if (!_editorState.activeOp) return;
      const p = ptFromEvent(ev);
      const op = _editorState.activeOp;
      if (op.type === "pen" || op.type === "blur") {
        op.points.push(p);
      } else if (op.type === "crop-marquee") {
        op.rect.x = Math.min(op.startX, p.x);
        op.rect.y = Math.min(op.startY, p.y);
        op.rect.w = Math.abs(p.x - op.startX);
        op.rect.h = Math.abs(p.y - op.startY);
      }
      _redrawEditor();
    });
    function endStroke() {
      const op = _editorState.activeOp;
      if (op) {
        if (op.type === "pen" || op.type === "blur") {
          _editorState.ops.push(op);
        }
        // crop-marquee stays as activeOp until user clicks Apply crop
        if (op.type !== "crop-marquee") _editorState.activeOp = null;
      }
      _redrawEditor();
      _refreshEditorToolbarState();
    }
    canvas.addEventListener("pointerup", endStroke);
    canvas.addEventListener("pointerleave", () => {
      // Don't end strokes when pointer briefly leaves; only on up.
    });
    canvas.addEventListener("pointercancel", endStroke);
  }
  function _refreshEditorToolbarState() {
    const modal = document.getElementById("image-editor-modal");
    if (!modal) return;
    const undoBtn = modal.querySelector(".iem-undo");
    const applyCropBtn = modal.querySelector(".iem-apply-crop");
    undoBtn.disabled = _editorState.ops.length === 0;
    const hasCrop = _editorState.activeOp?.type === "crop-marquee"
      && _editorState.activeOp.rect.w > 4
      && _editorState.activeOp.rect.h > 4;
    applyCropBtn.style.display = hasCrop ? "" : "none";
  }
  function _undoEditorOp() {
    if (_editorState.ops.length === 0) return;
    _editorState.ops.pop();
    _redrawEditor();
    _refreshEditorToolbarState();
  }
  function _applyCrop() {
    const op = _editorState.activeOp;
    if (op?.type !== "crop-marquee" || op.rect.w < 4 || op.rect.h < 4) return;
    // Bake current state into a new baseImage at the crop rect.
    const canvas = document.querySelector("#image-editor-modal .iem-canvas");
    const off = document.createElement("canvas");
    off.width = Math.max(1, Math.round(op.rect.w));
    off.height = Math.max(1, Math.round(op.rect.h));
    const octx = off.getContext("2d");
    octx.drawImage(canvas, op.rect.x, op.rect.y, op.rect.w, op.rect.h,
                   0, 0, off.width, off.height);
    const dataUrl = off.toDataURL("image/png");
    const img = new Image();
    img.onload = () => {
      _editorState.baseImage = img;
      _editorState.width = img.naturalWidth;
      _editorState.height = img.naturalHeight;
      _editorState.ops = [];
      _editorState.activeOp = null;
      _resizeEditorCanvas(canvas);
      _redrawEditor();
      _refreshEditorToolbarState();
    };
    img.src = dataUrl;
  }
  function _saveEditor() {
    const canvas = document.querySelector("#image-editor-modal .iem-canvas");
    if (!canvas) return;
    // Discard any active crop marquee before save.
    if (_editorState.activeOp?.type === "crop-marquee") {
      _editorState.activeOp = null;
      _redrawEditor();
    }
    canvas.toBlob((blob) => {
      if (!blob) return;
      const staged = state.staged.find((s) => s.id === _editorState.chipId);
      if (!staged) { _closeEditor(); return; }
      const newName = staged.file.name.replace(/\.(png|jpe?g|webp)$/i, ".png")
                      || `edited-${Date.now()}.png`;
      try {
        staged.file = new File([blob], newName, {
          type: "image/png",
          lastModified: Date.now(),
        });
      } catch {
        staged.displayName = newName;
      }
      readDataUrl(staged.file).then((du) => {
        staged.dataUrl = du;
        renderStaging();
      });
      _closeEditor();
      toast("Image updated. Click Send when ready.", "good", 3000);
    }, "image/png");
  }
  function _closeEditor() {
    const modal = document.getElementById("image-editor-modal");
    if (modal) {
      modal.classList.remove("show");
      document.body.classList.remove("iem-open");
    }
    _editorState.baseImage = null;
    _editorState.ops = [];
    _editorState.activeOp = null;
  }
  function _ensureImageEditorModal() {
    if (document.getElementById("image-editor-modal")) return;
    const m = document.createElement("div");
    m.id = "image-editor-modal";
    m.className = "iem-modal";
    m.setAttribute("role", "dialog");
    m.setAttribute("aria-modal", "true");
    m.setAttribute("aria-label", "Edit image");
    m.innerHTML = `
      <div class="iem-backdrop"></div>
      <div class="iem-pane">
        <div class="iem-toolbar">
          <div class="iem-tools">
            <button type="button" class="iem-tool" data-tool="pen" title="Draw">✏️ Pen</button>
            <button type="button" class="iem-tool" data-tool="blur" title="Blur a region">⬜ Blur</button>
            <button type="button" class="iem-tool" data-tool="crop" title="Crop">✂ Crop</button>
          </div>
          <div class="iem-color-row" data-color-row>
            <button type="button" class="iem-color" data-color="#ff4d4d" style="background:#ff4d4d"></button>
            <button type="button" class="iem-color" data-color="#ffd83b" style="background:#ffd83b"></button>
            <button type="button" class="iem-color" data-color="#46d39a" style="background:#46d39a"></button>
            <button type="button" class="iem-color" data-color="#5b9bff" style="background:#5b9bff"></button>
            <button type="button" class="iem-color" data-color="#ffffff" style="background:#ffffff"></button>
          </div>
          <div class="iem-actions">
            <button type="button" class="iem-undo" disabled>Undo</button>
            <button type="button" class="iem-apply-crop" style="display:none">Apply crop</button>
            <button type="button" class="iem-cancel">Cancel</button>
            <button type="button" class="iem-save">Save</button>
          </div>
        </div>
        <div class="iem-canvas-wrap">
          <canvas class="iem-canvas"></canvas>
        </div>
      </div>
    `;
    document.body.appendChild(m);
    // Wire toolbar handlers.
    m.querySelectorAll(".iem-tool").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        const tool = btn.dataset.tool;
        _editorState.tool = tool;
        m.querySelectorAll(".iem-tool").forEach((x) =>
          x.classList.toggle("active", x === btn));
        const colorRow = m.querySelector("[data-color-row]");
        if (colorRow) colorRow.style.display = tool === "pen" ? "" : "none";
        // Cancel any in-flight crop marquee when switching tools.
        if (tool !== "crop" && _editorState.activeOp?.type === "crop-marquee") {
          _editorState.activeOp = null;
          _redrawEditor();
        }
        _refreshEditorToolbarState();
      });
    });
    m.querySelectorAll(".iem-color").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        _editorState.color = btn.dataset.color;
        m.querySelectorAll(".iem-color").forEach((x) =>
          x.classList.toggle("active", x === btn));
      });
    });
    m.querySelector(".iem-undo").addEventListener("click", _undoEditorOp);
    m.querySelector(".iem-apply-crop").addEventListener("click", _applyCrop);
    m.querySelector(".iem-cancel").addEventListener("click", _closeEditor);
    m.querySelector(".iem-save").addEventListener("click", _saveEditor);
    // Default tool + color visual state.
    m.querySelector(".iem-tool[data-tool='pen']").classList.add("active");
    m.querySelector(".iem-color[data-color='#ff4d4d']").classList.add("active");
    document.addEventListener("keydown", (ev) => {
      if (!m.classList.contains("show")) return;
      if (ev.key === "Escape") _closeEditor();
      else if (ev.key === "z" && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); _undoEditorOp(); }
    });
  }

  // v0.21.x: inline rename for staged files. Replaces the static
  // filename label with a focused input; commits on blur/Enter,
  // cancels on Escape. Sanitises to drop path-separator chars +
  // disallow empty + cap at 255 chars.
  function _beginRenameStaged(nameEl, s) {
    const original = s.file.name;
    const input = document.createElement("input");
    input.type = "text";
    input.className = "name-edit";
    input.value = original;
    input.maxLength = 255;
    input.setAttribute("aria-label", "Rename staged file");
    nameEl.replaceWith(input);
    input.focus();
    input.select();
    const commit = () => {
      const raw = input.value.trim();
      const sanitised = raw.replace(/[\\\/]/g, "_").slice(0, 255);
      const next = sanitised || original;
      if (next !== original) {
        try {
          s.file = new File([s.file], next, {
            type: s.file.type,
            lastModified: s.file.lastModified,
          });
        } catch {
          // Older browsers without File-renaming support: best-effort
          // overlay name so the chip + send-time receiver still see
          // the friendlier label.
          s.displayName = next;
        }
      }
      renderStaging();
    };
    input.addEventListener("blur", commit);
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); input.blur(); }
      else if (ev.key === "Escape") { ev.preventDefault(); renderStaging(); }
    });
  }

