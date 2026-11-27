// Isolated service: collaborators cross the factory parameter boundary.
function createPeerProgress({
  state,
  performance,
}) {
  function _pairingProgress() {
    const started = performance.now();
    const record = { phase: "starting", elapsed_ms: 0, history: [] };
    state.autopair_diagnostics = record;
    // Local bounded diagnostics contain stage names and standard connection
    // states only. Never retain tokens, SDP, addresses, keys or signed messages.
    return (phase, pc, dc) => {
      const event = {
        phase, elapsed_ms: Math.round(performance.now() - started),
        connection: pc?.connectionState || null,
        ice: pc?.iceConnectionState || null,
        gathering: pc?.iceGatheringState || null,
        channel: dc?.readyState || null,
      };
      Object.assign(record, event);
      record.history.push(event);
      if (record.history.length > 32) record.history.shift();
    };
  }

  return { _pairingProgress };
}
