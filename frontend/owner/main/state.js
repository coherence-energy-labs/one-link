  // ── State ──────────────────────────────────────────────────────────
  const state = createOwnerState();

  // v0.7.5: fixed emoji palette for reactions. Custom picker
  // arrives in v0.7.5.1 - for now five universally-meaningful
  // reactions cover the 80% case.
  const REACTION_EMOJIS = ["👍", "❤️", "😂", "😮", "🎉"];

  const IMAGE_EXT = new Set(["png","jpg","jpeg","gif","webp","bmp","svg"]);
  const isImageName = (name) => IMAGE_EXT.has((name?.split(".").pop() || "").toLowerCase());
  // v0.9.2: audio extensions render as inline audio bubbles. webm
  // and ogg cover the MediaRecorder output across browsers; the
  // others handle inbound forwarded clips.
  const AUDIO_EXT = new Set([
    "webm", "ogg", "oga", "opus", "m4a", "mp3", "wav", "aac", "flac",
  ]);
  const isAudioName = (name) => AUDIO_EXT.has((name?.split(".").pop() || "").toLowerCase());

