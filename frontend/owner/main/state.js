  // ── State ──────────────────────────────────────────────────────────
  const state = createOwnerState();

  // Feature state owners (MNT-03). Each one keeps its fields private and
  // changes them only through its own functions; `state.<field>` stays the
  // page's read path. Writing a published field throws, naming its owner.
  // tests/js/ownership_baseline.json lists what each feature retired from
  // the shared bag; the ownership census fails if any of it is written again.
  const stateOwners = createStatePublisher(state);
  const messageStore = createMessageStore();
  const transferStore = createTransferStore({ now: () => Date.now() });
  const settingsStore = createSettingsStore();
  const identityStore = createIdentityStore();
  const pollingCluster = createPollingCluster({
    setInterval: (fn, ms) => setInterval(fn, ms),
    clearInterval: (id) => clearInterval(id),
  });
  stateOwners.publish("messageStore", {
    messages: messageStore.direct,
    groupMessages: messageStore.group,
  });
  stateOwners.publish("transferStore", {
    transfers: transferStore.list,
    transfersById: transferStore.byId,
    transferByDirBlob: transferStore.dirBlobIndex,
    transferRates: transferStore.rates,
  });
  stateOwners.publish("settingsStore", {
    runtimeSettings: settingsStore.runtime,
    rendezvousUrls: settingsStore.rendezvousUrls,
    chatPrefs: settingsStore.chatPrefs,
  });
  stateOwners.publish("identityStore", {
    me: identityStore.me,
    selfMesh: identityStore.selfMesh,
  });

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

