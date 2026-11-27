  // SHA-256, take 30 bits → five curated words. The retained first-four-byte
  // decimal mapping is an older-client compatibility code. The same hash
  // powers the visual art: bytes 4..10 each map to a (hue, shape) cell.
  function _sasWordsFromDigest(digest) {
    if (!(digest instanceof Uint8Array) || digest.byteLength < 4) {
      throw new Error("SAS digest must contain at least four bytes");
    }
    const big =
      ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
    const rawBits = big & ((2 ** PAIR_SAS_BITS) - 1);
    const words = [];
    for (let index = 0; index < PAIR_SAS_WORD_COUNT; index += 1) {
      const shift = PAIR_SAS_BITS - 6 * (index + 1);
      words.push(PAIR_SAS_WORDS[(rawBits >>> shift) & 0x3f]);
    }
    return words;
  }

  async function _computeSas(localPub, localNonce, remotePub, remoteNonce) {
    const pubs = [localPub, remotePub].slice().sort();
    const nonces = [localNonce, remoteNonce].slice().sort();
    const dict = {
      v: PAIR_PROTOCOL_VERSION,
      pubkeys: pubs,
      nonces,
    };
    const enc = new TextEncoder();
    const bytes = enc.encode(_canonicalJson(dict));
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    // 4-byte unsigned int → mod 10^6 → zero-padded to 6 digits.
    const big =
      ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
    const six = (big % 1_000_000).toString().padStart(6, "0");
    const display = six.slice(0, 3) + " " + six.slice(3);
    const words = _sasWordsFromDigest(digest);
    const artBytes = digest.slice(4, 10); // 6 cells
    return {
      digits: six,
      display,
      words,
      phrase: words.join(" "),
      art: Array.from(artBytes),
      digest,
    };
  }

  function _renderSasArt(host, artBytes) {
    if (!host) return;
    host.innerHTML = "";
    const SHAPES = ["●", "■", "▲", "◆", "★", "✚", "✦", "◐"];
    for (const b of artBytes) {
      const hue = (b * 360) / 256;
      const shape = SHAPES[b & (SHAPES.length - 1)];
      const cell = document.createElement("div");
      cell.style.background = `hsl(${hue}deg 60% 28%)`;
      cell.style.color = `hsl(${hue}deg 90% 75%)`;
      cell.style.borderRadius = "8px";
      cell.style.padding = "10px";
      cell.style.textAlign = "center";
      cell.style.fontSize = "20px";
      cell.style.fontFamily = "ui-monospace, SFMono-Regular, Consolas, monospace";
      cell.textContent = shape;
      host.appendChild(cell);
    }
  }

