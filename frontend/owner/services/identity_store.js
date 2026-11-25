// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of this device's identity snapshot on the owner page: `me` (from
// GET /api/me: fingerprint, display name, onboarding and update flags) and
// the personal device mesh that lists the devices that are also "me".
// Readers see them through `state.me` and `state.selfMesh`.
function createIdentityStore() {
  let me = null;
  let selfMesh = null;

  function replaceMe(snapshot) {
    me = snapshot;
    return me;
  }

  // A local rename, reflected before the next /api/me snapshot.
  function rename(displayName) {
    me = { ...(me || {}), display_name: displayName };
    return me;
  }

  function replaceSelfMesh(mesh) {
    selfMesh = mesh;
    return selfMesh;
  }

  // Lifecycle: no identity known yet.
  function reset() {
    me = null;
    selfMesh = null;
  }

  return Object.freeze({
    me: () => me,
    selfMesh: () => selfMesh,
    replaceMe,
    rename,
    replaceSelfMesh,
    reset,
  });
}
