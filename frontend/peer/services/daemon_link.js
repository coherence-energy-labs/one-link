// Isolated service: collaborators cross the factory parameter boundary.
//
// Owner of the peer page's transport state toward the daemon: the one
// authenticated DataChannel, the daemon fingerprint it was opened for, the
// in-flight requests keyed by rid, and the browser identity-possession
// handshake on that channel. Request/response correlation is scoped to one
// channel: replacing or closing the channel rejects every request that was
// in flight on it, and a stale channel can never settle the current one's
// handshake. Fields (read through `state.<name>`): daemon_dc,
// daemon_dc_fingerprint, daemon_pending, daemon_identity_ready,
// daemon_identity_context.
function createDaemonLink({ clearTimeout }) {
  if (typeof clearTimeout !== "function") throw new TypeError("createDaemonLink needs clearTimeout");
  let dc = null;
  let fingerprint = null;
  const pending = new Map(); // rid -> { resolve, reject, timer }
  let identityReady = null;  // { dc, promise, resolve, reject, settled, verified }
  let identityContext = null; // { dc, challenge }

  function rejectAllPending(message) {
    for (const [, entry] of pending) {
      clearTimeout(entry.timer);
      entry.reject(new Error(message));
    }
    pending.clear();
  }

  // Settle the handshake with a rejection, if it belongs to `channel` and
  // has not settled yet. Returns whether it did.
  function failIdentity(channel, error) {
    const ready = identityReady;
    if (!ready || ready.dc !== channel || ready.settled) return false;
    ready.settled = true;
    ready.reject(error instanceof Error ? error : new Error(String(error)));
    return true;
  }

  // Make `channel` the daemon transport. A different previous channel's
  // requests and unsettled handshake are rejected with `replacedMessage`.
  // Returns the previous channel (the caller closes it) and the new
  // handshake promise.
  function attach(channel, daemonFingerprint, replacedMessage) {
    const previous = dc;
    if (previous && previous !== channel) {
      rejectAllPending(replacedMessage);
      failIdentity(previous, new Error(replacedMessage));
    }
    dc = channel;
    fingerprint = daemonFingerprint;
    identityContext = null;
    let resolveIdentity;
    let rejectIdentity;
    const promise = new Promise((resolve, reject) => {
      resolveIdentity = resolve;
      rejectIdentity = reject;
    });
    identityReady = {
      dc: channel,
      promise,
      resolve: resolveIdentity,
      reject: rejectIdentity,
      settled: false,
      verified: false,
    };
    return { previous, identityPromise: promise };
  }

  // `channel` closed. A close from an older channel after a newer one took
  // over owns no current state: returns null and changes nothing.
  // Otherwise settles the handshake, clears the channel, rejects every
  // in-flight request with `closedMessage`, and reports whether the
  // channel had been verified (the caller may reconnect).
  function detach(channel, handshakeMessage, closedMessage) {
    if (dc !== channel) return null;
    const ready = identityReady;
    const wasVerified = Boolean(ready && ready.dc === channel && ready.verified);
    failIdentity(channel, new Error(handshakeMessage));
    dc = null;
    fingerprint = null;
    identityContext = null;
    rejectAllPending(closedMessage);
    return { wasVerified };
  }

  // The challenge this browser signed on `channel`.
  function setIdentityContext(channel, challenge) {
    identityContext = { dc: channel, challenge };
  }

  // The daemon verified possession on `channel`. Returns whether the
  // handshake was open and is now resolved.
  function verifyIdentity(channel, result) {
    const ready = identityReady;
    if (!ready || ready.dc !== channel || ready.settled) return false;
    ready.settled = true;
    ready.verified = true;
    ready.resolve(result);
    return true;
  }

  function addPending(rid, entry) {
    pending.set(rid, entry);
  }

  // Remove and return the request waiting on `rid`, or null.
  function takePending(rid) {
    if (!pending.has(rid)) return null;
    const entry = pending.get(rid);
    pending.delete(rid);
    return entry;
  }

  function dropPending(rid) {
    return pending.delete(rid);
  }

  // Lifecycle: release every request timer and settle every waiter.
  function dispose(message = "daemon link disposed") {
    rejectAllPending(message);
    if (dc) failIdentity(dc, new Error(message));
    dc = null;
    fingerprint = null;
    identityContext = null;
  }

  return Object.freeze({
    dc: () => dc,
    fingerprint: () => fingerprint,
    pending: () => pending,
    identityReady: () => identityReady,
    identityContext: () => identityContext,
    attach,
    detach,
    failIdentity,
    setIdentityContext,
    verifyIdentity,
    addPending,
    takePending,
    dropPending,
    rejectAllPending,
    dispose,
  });
}
