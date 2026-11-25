  const _PHONE_DOWNLOAD_CHUNK_SIZE = 16 * 1024;

  function _b64UrlToBytes(b64) {
    // Server emits URL-safe base64 with stripped padding. atob needs
    // standard alphabet + correct padding, so normalize first.
    const std = b64.replace(/-/g, "+").replace(/_/g, "/");
    const pad = std + "=".repeat((4 - std.length % 4) % 4);
    const bin = atob(pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function _renderFileBubbleBody(bubble, m) {
    const file = m.file || {};
    const name = file.name || "file";
    const size = file.size || 0;
    const blobHash = file.blob_hash || "";
    const mime = file.mime || "";
    const isOutbound = (m.direction === "out" || m.direction === "outbound");

    // Filename + size header.
    const head = document.createElement("div");
    head.style.display = "flex";
    head.style.alignItems = "center";
    head.style.gap = "10px";
    head.style.fontSize = "14px";

    const icon = document.createElement("div");
    icon.textContent = "📎";
    icon.style.fontSize = "20px";
    icon.style.flex = "0 0 auto";
    head.appendChild(icon);

    const info = document.createElement("div");
    info.style.flex = "1 1 auto";
    info.style.minWidth = "0";
    const nameEl = document.createElement("div");
    nameEl.textContent = name;
    nameEl.style.fontWeight = "600";
    nameEl.style.overflow = "hidden";
    nameEl.style.textOverflow = "ellipsis";
    nameEl.style.whiteSpace = "nowrap";
    info.appendChild(nameEl);
    const sizeEl = document.createElement("div");
    sizeEl.style.fontSize = "11px";
    sizeEl.style.opacity = "0.75";
    sizeEl.textContent = _formatBytes(size);
    info.appendChild(sizeEl);
    head.appendChild(info);
    bubble.appendChild(head);

    // Action row: download button (inbound) or send-status (outbound).
    if (!blobHash) {
      // Transfer not complete yet — show status, no download.
      const status = document.createElement("div");
      status.style.fontSize = "12px";
      status.style.marginTop = "6px";
      status.style.opacity = "0.7";
      status.textContent = isOutbound ? "Sending…" : "Waiting for content…";
      bubble.appendChild(status);
      return;
    }
    if (isOutbound) {
      const status = document.createElement("div");
      status.style.fontSize = "12px";
      status.style.marginTop = "6px";
      status.style.opacity = "0.7";
      status.textContent = "Sent";
      bubble.appendChild(status);
      return;
    }
    // Inbound + has blob_hash → render download button.
    const btn = document.createElement("button");
    btn.className = "btn";
    btn.textContent = "Download";
    btn.style.marginTop = "8px";
    btn.style.padding = "8px 14px";
    btn.style.fontSize = "13px";
    btn.style.background = "var(--bg-3)";
    btn.style.color = "var(--text)";
    btn.style.border = "1px solid var(--line)";
    btn.style.borderRadius = "8px";
    btn.style.cursor = "pointer";
    btn.style.minHeight = "36px";
    btn.setAttribute("aria-label", `Download ${name}`);
    const progress = document.createElement("div");
    progress.style.fontSize = "11px";
    progress.style.marginTop = "6px";
    progress.style.opacity = "0.75";
    progress.style.minHeight = "1em";
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        await _downloadFileFromDaemon({
          blob_hash: blobHash,
          name, size, mime,
          onProgress: (got, total) => {
            const pct = total > 0 ? Math.floor((got / total) * 100) : 0;
            progress.textContent =
              `${_formatBytes(got)} / ${_formatBytes(total)} · ${pct}%`;
          },
        });
        progress.textContent = "Saved.";
      } catch (e) {
        progress.textContent =
          `Couldn't download: ${e && e.message ? e.message : e}`;
        btn.disabled = false;
      }
    });
    bubble.appendChild(btn);
    bubble.appendChild(progress);
  }

  async function _downloadFileFromDaemon(opts) {
    const { blob_hash, name, size, mime, onProgress } = opts;
    const chunks = [];
    let offset = 0;
    let total = size || 0;
    let eof = false;
    while (!eof) {
      const reply = await _daemonRequest("fetch_blob_chunk", {
        blob_hash,
        offset,
        length: _PHONE_DOWNLOAD_CHUNK_SIZE,
      });
      if (reply.data_b64) {
        const bytes = _b64UrlToBytes(reply.data_b64);
        chunks.push(bytes);
        offset += bytes.length;
      }
      if (typeof reply.total_size === "number" && reply.total_size > 0) {
        total = reply.total_size;
      }
      if (onProgress) onProgress(offset, total);
      eof = !!reply.eof;
      if (!reply.data_b64 && !eof) {
        // Defensive guard: server returned no bytes but didn't
        // signal eof. Bail rather than spinning.
        throw new Error("server returned empty chunk without eof");
      }
    }
    // Assemble + trigger browser download.
    const blob = new Blob(chunks, {
      type: mime || "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name || "download";
    document.body.appendChild(a);
    a.click();
    setTimeout(() => {
      URL.revokeObjectURL(url);
      a.remove();
    }, 1000);
  }

