// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of the owner page's settings state:
//   - the runtime settings cache that DND, sound, theme, receipts and the
//     composer consult between /api/settings loads;
//   - the settings editor's hydration and unsaved-changes flags;
//   - the cached rendezvous URL list;
//   - the per-chat preference cache (color, wallpaper, archived), which the
//     server owns and chat_pref events keep in sync.
// Readers see the cache through `state.runtimeSettings`,
// `state.rendezvousUrls` and `state.chatPrefs`.
function createSettingsStore() {
  let runtime;          // undefined until the page installs its defaults
  let rendezvousUrls;   // undefined until the first status/settings load
  let chatPrefs;        // undefined until the chat preference cache starts
  let hydrating = false;
  let dirty = false;

  function replaceRuntime(settings) {
    if (!settings || typeof settings !== "object") throw new TypeError("runtime settings must be an object");
    runtime = settings;
    return runtime;
  }

  // Kept as the daemon returned it (callers already default to []).
  function setRendezvousUrls(urls) {
    rendezvousUrls = urls;
    return rendezvousUrls;
  }

  // The cache starts empty (but present) when the chat feature loads.
  function startChatPrefs() {
    chatPrefs = chatPrefs || { peer: {}, group: {} };
    return chatPrefs;
  }

  // The server is the authority: a fresh GET replaces the cache.
  function replaceChatPrefs(peer, group) {
    chatPrefs = { peer: peer || {}, group: group || {} };
    return chatPrefs;
  }

  // One preference. null/undefined clears it. Returns false (and changes
  // nothing) while the cache has not started, as the live event did.
  function setChatPref(scope, id, kind, value) {
    if (!chatPrefs) return false;
    if (!chatPrefs[scope]) chatPrefs[scope] = {};
    if (!chatPrefs[scope][id]) chatPrefs[scope][id] = {};
    if (value === null || value === undefined) delete chatPrefs[scope][id][kind];
    else chatPrefs[scope][id][kind] = value;
    return true;
  }

  // Settings editor lifecycle. While hydrating, programmatic control
  // updates must not mark the form dirty.
  function beginHydration() { hydrating = true; }
  function endHydration() { hydrating = false; }
  // Returns whether the change counted (false while hydrating).
  function markDirty() {
    if (hydrating) return false;
    dirty = true;
    return true;
  }
  function markClean() { dirty = false; }

  // Lifecycle: back to the state of a freshly loaded page.
  function reset() {
    runtime = undefined;
    rendezvousUrls = undefined;
    chatPrefs = undefined;
    hydrating = false;
    dirty = false;
  }

  return Object.freeze({
    runtime: () => runtime,
    rendezvousUrls: () => rendezvousUrls,
    chatPrefs: () => chatPrefs,
    isHydrating: () => hydrating,
    isDirty: () => dirty,
    replaceRuntime,
    setRendezvousUrls,
    startChatPrefs,
    replaceChatPrefs,
    setChatPref,
    beginHydration,
    endHydration,
    markDirty,
    markClean,
    reset,
  });
}
