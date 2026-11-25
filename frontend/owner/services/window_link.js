// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of this window's link to its daemon, and of the ONE status line that
// reports it. Three facts decide what the line says, and only this service
// holds them:
//
//   session     "ok" | "recovering" | "signed_out"
//   socketDown  the live event socket is closed
//   offline     the operating system reports no network
//
// Why one owner. Before this, the event socket wrote "Restoring One Link…"
// into one element and the session handler created a second, fixed-position
// element for "access key expired". Each was correct alone; shown together
// they printed over each other, and neither knew the other existed. One
// owner means one line, so two messages cannot overlap or contradict.
//
// Why recovery never gives up. A daemon restart is a routine event (an
// update restarts it), and a window that needs a person to notice a banner
// and click it has not recovered. So while the credential has not been
// disproved the service keeps probing, with backoff, for as long as it
// takes, and resumes the page by itself when a probe succeeds or the
// daemon greets the event socket.
//
// Why a rejection is confirmed before the credential is forgotten.
// Forgetting it strands the window until it is reopened from the launcher,
// so it takes two consecutive rejections, CONFIRM_REJECTION_MS apart. A
// probe that could not get an answer ("unavailable": no response, a 5xx, a
// rate limit) says nothing about the credential and resets the count.
function createWindowLink({
  probe,
  forgetCredential,
  suspend,
  resume,
  render,
  setTimeout,
  clearTimeout,
  random,
}) {
  for (const [name, value] of Object.entries({
    probe, forgetCredential, suspend, resume, render, setTimeout, clearTimeout, random,
  })) {
    if (typeof value !== "function") {
      throw new TypeError(`createWindowLink needs ${name}`);
    }
  }

  // A restart that completes inside this window passes without a word.
  const QUIET_MS = 4000;
  const CONFIRM_REJECTION_MS = 2000;
  const REJECTIONS_TO_SIGN_OUT = 2;
  const BACKOFF_BASE_MS = 1000;
  const BACKOFF_CAP_MS = 30000;

  let session = "ok";
  let socketDown = false;
  let offline = false;
  let troubleVisible = false;
  let quietTimer = null;
  let probeTimer = null;
  let probeInFlight = false;
  let failures = 0;
  let rejections = 0;
  let disposed = false;
  let rendered;

  function status() {
    if (session === "signed_out") return "signed_out";
    if (troubleVisible) return "restoring";
    if (offline) return "offline";
    return null;
  }

  function publish() {
    const next = status();
    if (next === rendered) return;
    rendered = next;
    render(next);
  }

  // "Trouble" is the recoverable condition: the page cannot currently talk
  // to its daemon. It becomes visible only after QUIET_MS without recovery.
  function reconcileTrouble() {
    const inTrouble = session === "recovering" || socketDown;
    if (!inTrouble) {
      if (quietTimer !== null) { clearTimeout(quietTimer); quietTimer = null; }
      troubleVisible = false;
    } else if (!troubleVisible && quietTimer === null) {
      quietTimer = setTimeout(() => {
        quietTimer = null;
        troubleVisible = true;
        publish();
      }, QUIET_MS);
    }
    publish();
  }

  function cancelProbe() {
    if (probeTimer !== null) { clearTimeout(probeTimer); probeTimer = null; }
  }

  function backoffMs() {
    // 1 s, 2 s, 4 s ... capped at 30 s, with a quarter of jitter either way
    // so several windows restoring together do not probe in step.
    const base = Math.min(BACKOFF_CAP_MS, BACKOFF_BASE_MS * Math.pow(2, Math.max(0, failures - 1)));
    return Math.floor(base + (random() - 0.5) * 0.5 * base);
  }

  function scheduleProbe(delayMs) {
    cancelProbe();
    probeTimer = setTimeout(() => {
      probeTimer = null;
      runProbe();
    }, delayMs);
  }

  function recover() {
    const wasSuspended = session !== "ok";
    session = "ok";
    failures = 0;
    rejections = 0;
    cancelProbe();
    reconcileTrouble();
    if (wasSuspended) resume();
  }

  function signOut() {
    session = "signed_out";
    cancelProbe();
    forgetCredential();
    reconcileTrouble();
  }

  function runProbe() {
    if (disposed || probeInFlight || session !== "recovering") return;
    cancelProbe();
    probeInFlight = true;
    let outcome;
    try {
      outcome = Promise.resolve(probe());
    } catch (_) {
      outcome = Promise.resolve("unavailable");
    }
    outcome.catch(() => "unavailable").then((result) => {
      probeInFlight = false;
      // The event socket may have recovered the session while this probe
      // was in flight; its answer is then about a state that is gone.
      if (disposed || session !== "recovering") return;
      if (result === "ok") {
        recover();
        return;
      }
      if (result === "rejected") {
        rejections += 1;
        if (rejections >= REJECTIONS_TO_SIGN_OUT) {
          signOut();
          return;
        }
        scheduleProbe(CONFIRM_REJECTION_MS);
        return;
      }
      rejections = 0;
      failures += 1;
      scheduleProbe(backoffMs());
    });
  }

  // An API call was answered 401. Stop the polls (each would repeat the
  // same answer) and find out whether the credential is really gone.
  function unauthorized() {
    if (disposed || session !== "ok") return;
    session = "recovering";
    failures = 0;
    rejections = 0;
    suspend();
    reconcileTrouble();
    runProbe();
  }

  // The daemon greeted the event socket (its first message, "hello"). The
  // handshake carries the same credential the probe would validate, and the
  // daemon greets only a socket it has authenticated, so a greeting is proof
  // the session works.
  //
  // The browser's `open` event is NOT that proof. The daemon accepts an
  // unauthenticated socket and then closes it with code 4401, so `open`
  // fires for a refused credential too. Treating `open` as recovery made the
  // window resume its polls, collect a burst of 401s, and start over, about
  // once a second, until the daemon rate-limited it.
  function socketGreeted() {
    if (disposed) return;
    socketDown = false;
    if (session !== "ok") {
      recover();
      return;
    }
    reconcileTrouble();
  }

  function socketClosed() {
    if (disposed) return;
    socketDown = true;
    reconcileTrouble();
  }

  function setOffline(value) {
    if (disposed) return;
    offline = !!value;
    publish();
  }

  // The person asked (or the window came back to the foreground): probe now
  // instead of waiting out the backoff. Returns whether there was anything
  // to retry.
  function retryNow() {
    if (disposed || session !== "recovering") return false;
    failures = 0;
    runProbe();
    return true;
  }

  function dispose() {
    disposed = true;
    cancelProbe();
    if (quietTimer !== null) { clearTimeout(quietTimer); quietTimer = null; }
  }

  return Object.freeze({
    unauthorized,
    socketGreeted,
    socketClosed,
    setOffline,
    retryNow,
    dispose,
    session: () => session,
    status,
    // A signed-out window has no credential to present, so reconnecting the
    // event socket would only add failed sign-in attempts.
    shouldReconnectSocket: () => !disposed && session !== "signed_out",
  });
}
