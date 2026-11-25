"""Execute shipped pairing setup, deadline and diagnostic behavior in Node."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _section(start: str, end: str) -> str:
    source = Path("src/one_link/web/peer.html").read_text(encoding="utf-8")
    first = source.index(start)
    return source[first:source.index(end, first)]


def _run(script: str) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for executable pairing lifecycle checks")
    result = subprocess.run(
        [node, "--input-type=commonjs"], input=script, text=True,
        capture_output=True, timeout=15, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_ice_config_request_is_aborted_and_releases_its_timer() -> None:
    loader = _section("async function loadPublicIceConfig()", "async function loadPublicIceServers()")
    _run("""
const assert = require('node:assert/strict');
let callback, cleared = false, signal;
const setTimeout = (fn, ms) => { assert.equal(ms, 8000); callback = fn; return 42; };
const clearTimeout = (id) => { assert.equal(id, 42); cleared = true; };
const fetch = async (url, options) => {
  assert.equal(url, '/api/v1/peer-rtc/ice-config');
  signal = options.signal;
  return new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(new Error('aborted'))));
};
""" + loader + """
(async () => {
  const pending = loadPublicIceConfig();
  callback();
  assert.deepEqual(await pending, {iceServers: [], localCandidateAddresses: []});
  assert.equal(signal.aborted, true);
  assert.equal(cleared, true);
})().catch(error => { console.error(error); process.exitCode = 1; });
""")


def test_progress_keeps_bounded_connection_states_without_session_payloads() -> None:
    progress = _section("function _pairingProgress()", "async function _runAutoPairFlow(pair)")
    _run("""
const assert = require('node:assert/strict');
const state = {};
""" + progress + """
const mark = _pairingProgress();
for (let i = 0; i < 40; i++) {
  mark('gathering_ice', {
    connectionState: 'connecting', iceConnectionState: 'checking',
    iceGatheringState: 'gathering', localDescription: 'must not be retained',
  }, {readyState: 'connecting', label: 'must not be retained'});
}
assert.equal(state.autopair_diagnostics.history.length, 32);
for (const row of state.autopair_diagnostics.history) {
  assert.deepEqual(Object.keys(row).sort(), ['channel', 'connection', 'elapsed_ms', 'gathering', 'ice', 'phase']);
  assert.ok(row.elapsed_ms >= 0);
}
assert.equal(JSON.stringify(state.autopair_diagnostics).includes('must not be retained'), false);
""")


@pytest.mark.parametrize("scenario", ["channel_error", "deadline_during_config", "cancel_during_config"])
def test_pairing_setup_failure_always_settles_and_cleans_up(scenario: str) -> None:
    flow = _section("function _pairingProgress()", "// ── v0.20.2 — daemon DataChannel router")
    _run("""
const assert = require('node:assert/strict');
const state = {rec: {public_key_b64u: 'fixture', fingerprint: 'fixture'}};
let timer, timerCleared = false, cancelHandler, pcClosed = false, status;
let resolveConfig, configStarted;
const configWasStarted = new Promise(resolve => { configStarted = resolve; });
const config = new Promise(resolve => { resolveConfig = resolve; });
const button = {
  addEventListener: (name, fn) => { cancelHandler = fn; },
  removeEventListener: (name, fn) => { assert.equal(fn, cancelHandler); cancelHandler = null; },
};
const $ = () => button;
const show = () => {};
const hide = () => {};
const _showOnly = () => {};
const _autopairShowHost = () => {};
const _autopairSetState = (...args) => { status = args; };
const _autopairPreflight = () => null;
const _waitForIdentity = async () => state.rec;
const loadPublicIceConfig = () => { configStarted(); return config; };
const setTimeout = (fn, ms) => { assert.equal(ms, 90000); timer = fn; return 5; };
const clearTimeout = id => { assert.equal(id, 5); timerCleared = true; };
const AUTOPAIR_DAEMON_CONTROL_LABEL = 'control';
class RTCPeerConnection {
  constructor() { this.connectionState = 'new'; }
  createDataChannel() { throw new Error('browser channel construction failed'); }
  close() { pcClosed = true; this.connectionState = 'closed'; }
}
""" + flow + f"""
(async () => {{
  const result = _runAutoPairFlow({{daemon_fingerprint: 'fixture'}});
  const rejection = assert.rejects(result);
  await configWasStarted;
  if ('{scenario}' === 'deadline_during_config') timer();
  if ('{scenario}' === 'cancel_during_config') cancelHandler();
  resolveConfig({{iceServers: [], localCandidateAddresses: []}});
  await rejection;
  assert.equal(timerCleared, true);
  assert.equal(cancelHandler, null);
  assert.equal(state.autopair_diagnostics.phase, 'failed');
  if ('{scenario}' === 'channel_error') {{
    assert.equal(pcClosed, true);
    assert.equal(status[1], 'pairing failed');
  }} else {{
    assert.equal(pcClosed, false, 'settled setup must not create a connection later');
    assert.equal(status[1], '{scenario}' === 'cancel_during_config' ? 'cancelled' : 'timed out');
  }}
}})().catch(error => {{ console.error(error); process.exitCode = 1; }});
""")
