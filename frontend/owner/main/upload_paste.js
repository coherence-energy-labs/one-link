  async function uploadFile(file, opts = {}) {
    // A composer send captures its target before awaiting text/file requests.
    // Use that immutable peer instead of whichever conversation happens to be
    // selected when this upload eventually starts.
    const targetPeerId = opts.peerId || state.selectedPeer;
    if (!targetPeerId) {
      toast("Pick a device on the left to start.", "info");
      return {_uploadFailed: true, error: "missing peer"};
    }
    const peer = state.peers.get(targetPeerId);
    if (peer?.trust === "rejected") {
      toast("This device is blocked. Use Allow device first.", "bad");
      return {_uploadFailed: true, error: "peer rejected"};
    }
    // v0.21.x: keep the File object so the sender's bubble can open
    // the photo / file on click. The daemon stages then deletes the
    // upload, so without this cache the outbound bubble would
    // dead-end. Cached by name+size, so a same-name+size resend
    // refreshes the entry.
    rememberOutboundFile(file);
    // v0.21.x: when this file came from a drag-folder drop, opts.relPath
    // is the folder-relative path. Show the original tree position in
    // the sending toast so users see what they're sending.
    const displayName = opts.relPath || file.name;
    const sendingToast = toast(`Sending ${displayName}...`, "info", 30000);
    try {
      const result = await api.upload(
        targetPeerId, file, {
          ...(opts.relPath ? { relPath: opts.relPath } : {}),
          ...(opts.clientDeliveryId
            ? { clientDeliveryId: opts.clientDeliveryId }
            : {}),
        },
      );
      sendingToast?.remove();
      if (result?.background && result?.accepted) {
        toast(`${displayName} is securely staged and sending in the background.`, "info", 5000);
      } else if (result?.queued || result?.paused) {
        toast(`${displayName} will send when they're back online.`, "info", 5000);
      }
      return result;
    } catch (e) {
      sendingToast?.remove();
      toast(`${file.name}: ${errorToastBody(e)}. One Link will keep anything already staged and retry when it can.`, "bad", 9000);
      return {_uploadFailed: true, error: e};
    }
  }

  // 2026-06-04: HTML-to-markdown converter for rich-text paste.
  //
  // When the user pastes from a rendered web page (ChatGPT, Claude,
  // GitHub, docs) the clipboard contains BOTH ``text/plain`` (which
  // the browser hands the textarea by default) and ``text/html``
  // (the source's actual DOM). The plain-text serialisation loses
  // a lot of structure: bullets become inline, headings lose their
  // weight, code blocks merge with prose. We grab the HTML version
  // when present and walk it into clean markdown text — bullets
  // become "- ", headings become "# ", code stays fenced — so the
  // chat renderer's markdown path (see ``_renderChatBody``) can
  // restore the original look on the receiver's side.
  //
  // Deliberately conservative: drops scripts/styles, ignores
  // unknown tags (default case = recurse into children, no
  // formatting), no inline-style introspection. Anything we
  // don't recognise degrades to plain text, never to broken HTML.
  function _htmlToMarkdown(html) {
    let scratch;
    try {
      scratch = document.createElement("div");
      scratch.innerHTML = html;
    } catch (_) {
      return "";
    }
    // Strip dangerous / noisy elements before walking.
    scratch.querySelectorAll(
      "script, style, link, meta, iframe, noscript, head, title, svg"
    ).forEach((n) => n.remove());
    const out = _walkToMd(scratch).trim();
    // Collapse runs of >2 blank lines (paste from Word / Google Docs
    // tends to spam blank <p>s); keep at most one blank line between
    // blocks.
    return out.replace(/\n{3,}/g, "\n\n");
  }
  function _walkToMd(node) {
    if (!node) return "";
    if (node.nodeType === Node.TEXT_NODE) {
      // Collapse whitespace inside text nodes — HTML inline text
      // is whitespace-insensitive, and preserving the original
      // newlines would inject random hard breaks inside paragraphs.
      // The structural newlines come from block-element wrappers
      // (p / h* / li / pre).
      return (node.textContent || "").replace(/\s+/g, " ");
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return "";
    const tag = node.tagName.toLowerCase();
    const kids = () => Array.from(node.childNodes).map(_walkToMd).join("");
    switch (tag) {
      case "br": return "\n";
      case "p": case "div": case "section": case "article": case "header":
      case "footer": case "main": case "aside":
        return "\n" + kids().trim() + "\n";
      case "h1": return "\n\n# "      + kids().trim() + "\n\n";
      case "h2": return "\n\n## "     + kids().trim() + "\n\n";
      case "h3": return "\n\n### "    + kids().trim() + "\n\n";
      case "h4": return "\n\n#### "   + kids().trim() + "\n\n";
      case "h5": return "\n\n##### "  + kids().trim() + "\n\n";
      case "h6": return "\n\n###### " + kids().trim() + "\n\n";
      case "strong": case "b": {
        const t = kids().trim();
        return t ? "**" + t + "**" : "";
      }
      case "em": case "i": {
        const t = kids().trim();
        return t ? "_" + t + "_" : "";
      }
      case "code": {
        // Inline code only; <pre><code> is handled by the <pre> arm.
        if (node.parentElement && node.parentElement.tagName.toLowerCase() === "pre") {
          return kids();
        }
        return "`" + (node.textContent || "") + "`";
      }
      case "pre": {
        // Use raw textContent so leading whitespace + newlines inside
        // the code block survive. The text-node collapser would
        // otherwise flatten the indentation.
        const raw = (node.textContent || "").replace(/\n+$/, "");
        return "\n\n```\n" + raw + "\n```\n\n";
      }
      case "blockquote": {
        // 2026-06-04: do NOT emit "> " line prefixes. The composer
        // textarea can't render markdown, so users see literal ">"
        // characters and read it as garbage — especially when the
        // source is an email reply whose entire body is wrapped in
        // <blockquote> for quoting. Preserve the text as plain
        // paragraphs; if the user genuinely wants a blockquote on
        // the receiver side they can type "> " themselves.
        return "\n\n" + kids().trim() + "\n\n";
      }
      case "ul": {
        const items = Array.from(node.children).filter((c) => c.tagName === "LI");
        const lines = items.map((li) => "- " + _walkToMd(li).trim().replace(/\n+/g, " "));
        return "\n\n" + lines.join("\n") + "\n\n";
      }
      case "ol": {
        const items = Array.from(node.children).filter((c) => c.tagName === "LI");
        const lines = items.map((li, idx) =>
          (idx + 1) + ". " + _walkToMd(li).trim().replace(/\n+/g, " ")
        );
        return "\n\n" + lines.join("\n") + "\n\n";
      }
      case "li": return kids();
      case "a": {
        const href = (node.getAttribute("href") || "").trim();
        const txt = kids().trim();
        if (!href || href === txt) return txt;
        // Skip in-page anchors and pure javascript: links.
        if (/^(javascript:|#)/i.test(href)) return txt;
        return "[" + txt + "](" + href + ")";
      }
      case "hr": return "\n\n---\n\n";
      case "img": {
        const alt = (node.getAttribute("alt") || "").trim();
        return alt ? "[image: " + alt + "]" : "";
      }
      case "table": {
        const rows = Array.from(node.querySelectorAll("tr"));
        if (!rows.length) return "";
        const cellsOf = (tr) =>
          Array.from(tr.children)
            .filter((c) => c.tagName === "TD" || c.tagName === "TH")
            .map((td) => _walkToMd(td).trim().replace(/\n+/g, " ").replace(/\|/g, "\\|"));
        const lines = rows.map((tr) => "| " + cellsOf(tr).join(" | ") + " |");
        if (lines.length >= 2) {
          const ncols = cellsOf(rows[0]).length;
          lines.splice(1, 0, "|" + " --- |".repeat(ncols));
        }
        return "\n\n" + lines.join("\n") + "\n\n";
      }
      case "del": case "s": case "strike": {
        const t = kids().trim();
        return t ? "~~" + t + "~~" : "";
      }
      default: return kids();
    }
  }

  // Paste - stage files OR convert rich-text HTML to markdown text.
  function handlePasteImage(e) {
    if (!state.selectedPeer) return false;
    const cd = e.clipboardData;
    if (!cd) return false;
    const items = cd.items;
    // Files first (existing behaviour: paste an image → stage attachment).
    let attached = false;
    if (items) {
      for (const item of items) {
        if (item.kind !== "file") continue;
        const file = item.getAsFile();
        if (!file) continue;
        const ext = (file.type || "image/png").split("/")[1] || "png";
        const named = file.name && file.name.length > 0
          ? file
          : new File([file], `pasted-${Date.now()}.${ext}`, { type: file.type });
        stageFile(named);
        attached = true;
      }
    }
    if (attached) {
      e.preventDefault();
      return true;
    }
    // 2026-06-04: rich-text → markdown. Only fires when the paste
    // target is OUR composer (avoid hijacking other inputs). The
    // clipboard may have a text/html version (we walk it to clean
    // markdown) or only text/plain. EITHER way we run a final
    // ``_cleanPastedText`` pass that strips email-style ">" quote
    // prefixes — they're never wanted in the composer because the
    // textarea can't render markdown. If the source had both HTML
    // and a richer-than-plain conversion, prefer the HTML output;
    // otherwise fall through to a cleaned-plain rewrite.
    const target = e.target;
    if (target !== $("#input")) return false;
    let html = "";
    try { html = cd.getData("text/html") || ""; } catch (_) {}
    let plain = "";
    try { plain = cd.getData("text/plain") || ""; } catch (_) {}
    let insertText = "";
    if (html) {
      const md = _htmlToMarkdown(html);
      // If the HTML version produced something distinct from the
      // plain version, use the HTML walk; otherwise fall through to
      // the plain-text path so the email-quote cleanup runs on it.
      if (md && md.trim() !== plain.trim()) {
        insertText = _cleanPastedText(md);
      }
    }
    if (!insertText && plain) {
      const cleaned = _cleanPastedText(plain);
      // Only intercept the plain-text path if the cleanup actually
      // changed anything — otherwise let the browser do its native
      // paste (faster, preserves IME state on mobile).
      if (cleaned !== plain) insertText = cleaned;
    }
    if (!insertText) return false;
    // Insert at the cursor instead of replacing the whole field.
    const ta = target;
    const start = ta.selectionStart ?? ta.value.length;
    const end   = ta.selectionEnd   ?? ta.value.length;
    const before = ta.value.slice(0, start);
    const after  = ta.value.slice(end);
    ta.value = before + insertText + after;
    const cursor = start + insertText.length;
    ta.selectionStart = ta.selectionEnd = cursor;
    // Notify any input-event listeners (autosize, send-button enable,
    // typing-indicator debounce) so the composer state updates.
    ta.dispatchEvent(new Event("input", { bubbles: true }));
    e.preventDefault();
    return true;
  }
  // 2026-06-04: strip artifacts users never want to read in a
  // composer textarea. Today: email-style ">" / ">>" quote prefixes,
  // and runs of empty ">"-only lines collapsing to a single blank.
  // Conservative: only acts when the marker is at line start AND a
  // meaningful fraction of lines have them (so a one-off "> note"
  // in casual prose is preserved, but a 50-line reply quote chain
  // is flattened).
  function _cleanPastedText(text) {
    if (!text) return text;
    const lines = text.split(/\r?\n/);
    // Count lines that look like email-quote markers. Accept any
    // depth of nesting ("> >>>>") because mailing lists chain them.
    const QUOTE_RE = /^\s*(?:>\s*)+/;
    let quoted = 0;
    let nonEmpty = 0;
    for (const ln of lines) {
      if (!ln.trim()) continue;
      nonEmpty += 1;
      if (QUOTE_RE.test(ln)) quoted += 1;
    }
    if (nonEmpty === 0) return text;
    // 30% threshold: a real quote-reply block is overwhelmingly
    // quoted; casual prose almost never starts a line with ">".
    if (quoted / nonEmpty < 0.30) return text;
    // Strip the prefix; collapse empty-quote-only lines ("> ") into
    // a single empty line; squeeze 3+ blank lines down to 2.
    const cleaned = lines
      .map((ln) => ln.replace(QUOTE_RE, ""))
      .join("\n")
      .replace(/[ \t]+$/gm, "")
      .replace(/\n{3,}/g, "\n\n");
    return cleaned;
  }
  $("#input").addEventListener("paste", handlePasteImage);
  // v0.12.3: typing indicator. Fires on every non-empty input
  // event; daemon-side debounces to once per 2.5s/peer so a fast
  // typer doesn't flood the wire. Privacy gate is enforced
  // server-side too - we don't bother shipping the API call when
  // the user has opted out, because we know we'll get
  // skipped='privacy' back.
  const _lastTypingFiredAt = new Map();
  $("#input").addEventListener("input", () => {
    const text = $("#input").value || "";
    if (!text.trim()) return;
    if (state.runtimeSettings?.send_typing_indicators === false) return;
    let targetKey = null;
    let endpoint = null;
    if (state.selectedPeer) {
      const peer = state.peers.get(state.selectedPeer);
      if (peer?.fingerprint && peer.trust === "pinned") {
        targetKey = `peer:${peer.fingerprint}`;
        endpoint = `/api/peers/${peer.fingerprint}/typing`;
      }
    } else if (state.selectedGroup) {
      targetKey = `group:${state.selectedGroup}`;
      endpoint = `/api/groups/${state.selectedGroup}/typing`;
    }
    if (!targetKey || !endpoint) return;
    const now = Date.now();
    // Client-side debounce mirrors the server-side 2.5s debounce
    // so we don't even make the round trip while typing fast.
    if (now - (_lastTypingFiredAt.get(targetKey) || 0) < 2500) return;
    _lastTypingFiredAt.set(targetKey, now);
    api.post(endpoint, {}).catch(() => { /* best-effort */ });
  });
  document.addEventListener("paste", (e) => {
    const t = e.target;
    const isOurInput = t && t.id === "input";
    const isAnyInput = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA");
    // Skip when focus is in some OTHER input (don't hijack their paste).
    if (isAnyInput && !isOurInput) return;
    // v0.21.x: also skip when focus IS in our composer textarea. The
    // `#input`-scoped paste listener registered above already handled
    // it. Without this guard both listeners fire and stageFile()
    // gets called twice, doubling the attach-tray entries.
    if (isOurInput) return;
    handlePasteImage(e);
  });

  // Drag-drop - stage instead of auto-send.
  let dragCounter = 0;
  document.addEventListener("dragenter", (e) => {
    if (e.dataTransfer && Array.from(e.dataTransfer.types).includes("Files")) {
      dragCounter++;
      $("#drop-overlay").classList.add("show");
    }
  });
  document.addEventListener("dragover", (e) => { e.preventDefault(); });
  document.addEventListener("dragleave", () => {
    dragCounter--;
    if (dragCounter <= 0) { dragCounter = 0; $("#drop-overlay").classList.remove("show"); }
  });
  // Recursively walk a DirectoryEntry, returning {file, relPath}[].
  // Browsers paginate readEntries() in batches of ~100, so we loop until
  // empty. Path is included so we can show 'subdir/file.txt' in chips.
  async function readAllEntries(reader) {
    const out = [];
    while (true) {
      const batch = await new Promise((resolve, reject) =>
        reader.readEntries(resolve, reject));
      if (!batch.length) break;
      out.push(...batch);
    }
    return out;
  }
  async function collectFromEntry(entry, prefix = "") {
    const collected = [];
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) =>
        entry.file(resolve, reject));
      collected.push({ file, relPath: prefix + file.name });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const children = await readAllEntries(reader);
      for (const child of children) {
        const sub = await collectFromEntry(child, prefix + entry.name + "/");
        collected.push(...sub);
      }
    }
    return collected;
  }

  document.addEventListener("drop", async (e) => {
    e.preventDefault();
    dragCounter = 0;
    $("#drop-overlay").classList.remove("show");
    if (!state.selectedPeer) { toast("Pick a device on the left to start.", "info"); return; }
    const items = e.dataTransfer?.items;
    let collected = [];
    if (items && items.length && items[0].webkitGetAsEntry) {
      // Use entries API to detect folders. This is what makes folder
      // drops actually work.
      const entries = [];
      for (const item of items) {
        const entry = item.webkitGetAsEntry?.();
        if (entry) entries.push(entry);
      }
      try {
        for (const entry of entries) {
          const sub = await collectFromEntry(entry);
          collected.push(...sub);
        }
      } catch (err) {
        toast(`Folder read failed: ${err.message || err}`, "bad");
      }
    }
    if (!collected.length) {
      // Fallback: dataTransfer.files (works for plain file drops).
      const files = Array.from(e.dataTransfer?.files || []);
      collected = files.map(f => ({ file: f, relPath: f.name }));
    }
    if (collected.length === 0) return;
    if (collected.length > 1) {
      toast(`Staging ${collected.length} files`, "info", 2000);
    }
    for (const { file, relPath } of collected) {
      // v0.21.x: preserve the folder tree on send. The wire protocol
      // now carries a sanitized rel_path field on FILE_OFFER, so the
      // recipient ends up with inbox/<rel_path> instead of a flat
      // inbox/<basename>. Pass relPath as a second arg to stageFile
      // so it gets bundled into the multipart upload. The file.name
      // stays the bare leaf so the staging chip + outbound bubble
      // show the user-meaningful name (not the full nested path).
      await stageFile(file, relPath !== file.name ? relPath : null);
    }
  });

