// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// Owner of the owner page's background polling transport: the cluster of
// interval timers that refresh peers, transfers, status, health, fabric
// truth and groups alongside the WebSocket (2026-05-21 audit T3-P). A 401
// burst pauses the whole cluster so it cannot keep re-firing session
// recovery; explicit recovery resumes it with fresh intervals. dispose()
// releases every timer the cluster holds.
function createPollingCluster({ setInterval, clearInterval }) {
  if (typeof setInterval !== "function" || typeof clearInterval !== "function") {
    throw new TypeError("createPollingCluster needs interval timers");
  }
  let timers = [];
  let paused = false;

  function schedule(tasks) {
    return tasks.map(([fn, ms]) => setInterval(fn, ms));
  }

  // Boot: add the polls to whatever the cluster already holds.
  function start(tasks) {
    timers.push(...schedule(tasks));
  }

  // Stop every poll and remember that the cluster is paused. An empty
  // cluster has nothing to pause and stays unpaused.
  function pause() {
    if (!timers.length) return false;
    for (const id of timers) {
      try { clearInterval(id); } catch (_) {}
    }
    timers = [];
    paused = true;
    return true;
  }

  // Re-schedule fresh intervals, only after a pause, so a partial
  // pause/resume cycle can never double-fire.
  function resume(tasks) {
    if (!paused) return false;
    paused = false;
    timers = schedule(tasks);
    return true;
  }

  function dispose() {
    for (const id of timers) {
      try { clearInterval(id); } catch (_) {}
    }
    timers = [];
    paused = false;
  }

  return Object.freeze({
    start,
    pause,
    resume,
    dispose,
    isPaused: () => paused,
    timerIds: () => timers.slice(),
  });
}
