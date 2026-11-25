"""Executable adversarial proofs for browser pairing identity authority.

The browser implementation is intentionally inline in ``peer.html``. These
tests execute the shipped JavaScript functions in the repository-pinned Node
runtime instead of asserting only source strings. OPFS is represented by a
transactional in-memory handle with the same methods the production code uses.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


PEER_HTML = Path("src/one_link/web/peer.html")
NODE = shutil.which("node")


def _section(source: str, start: str, end: str) -> str:
    start_index = source.index(start)
    end_index = source.index(end, start_index)
    return source[start_index:end_index]


def _run_node(script: str) -> str:
    if NODE is None:
        pytest.skip("Node is required for executable browser-peer JavaScript proofs")
    result = subprocess.run(  # noqa: S603 - fixed local executable, no shell
        [NODE, "--input-type=commonjs"],
        input=script,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"Node proof failed ({result.returncode})\nstdout:\n{result.stdout}\n"
        f"stderr:\n{result.stderr}"
    )
    return result.stdout.strip()


@pytest.fixture(scope="module")
def peer_source() -> str:
    return PEER_HTML.read_text(encoding="utf-8")


def _encoding_and_crypto_source(source: str) -> str:
    # The generated service has a real lexical boundary. Instantiate its
    # shipped factory rather than slicing its private locals out of that scope.
    encoding = (
        _section(source, "function createPeerEncoding(", "\n}\n") + "\n}\n"
        + "const { bytesToHex, bytesToB64Url, b64UrlToBytes } = createPeerEncoding({ btoa, atob });\n"
    )
    fingerprint = _section(
        source,
        "async function fingerprintOf(pubBytes)",
        "// ── OPFS persistence",
    )
    identity_crypto = _section(
        source,
        'const ED25519_WASM_URL = "/browser-crypto/ed25519-v1.wasm";',
        "function _isNotFoundError(error)",
    )
    canonical_b64 = _section(
        source,
        "function _decodeCanonicalB64Url(value, label, expectedLength = null)",
        "function _assertIdentityTimestamp(value, label)",
    )
    canonical_and_signing = _section(
        source,
        "function _canonicalJson(obj)",
        "// v0.20.7 (security audit C1): pull the DTLS-SRTP fingerprint",
    )
    return (
        encoding
        + fingerprint
        + identity_crypto
        + canonical_b64
        + canonical_and_signing
    )


def _pinned_ed25519_fetch_source() -> str:
    """Serve the shipped integrity-pinned fallback to extracted browser code."""
    return r"""
const { readFileSync } = require("node:fs");
const ed25519WasmArtifact = readFileSync(
  "src/one_link/web/assets/ed25519-v1.wasm",
);
globalThis.fetch = async (url) => {
  assert.equal(url, "/browser-crypto/ed25519-v1.wasm");
  return new Response(ed25519WasmArtifact, {
    status: 200,
    headers: { "content-type": "application/wasm" },
  });
};
"""


def test_peer_roster_is_collision_safe_and_fail_closed(peer_source: str) -> None:
    roster = _section(
        peer_source,
        'const PAIR_PROTOCOL_VERSION = "OL-PAIR-1";',
        "// SAS derivation:",
    )
    # A real 96-bit prefix collision is deliberately infeasible. Shrinking only
    # the filename prefix in this harness exercises the exact production
    # allocation/readback algorithm with real Ed25519 keys and fingerprints.
    roster = roster.replace(
        "const PEER_FILE_PREFIX_HEX_CHARS = 24;",
        "const PEER_FILE_PREFIX_HEX_CHARS = 1;",
    )
    binding_helpers = _section(
        peer_source,
        'const WRTC_PROTOCOL_VERSION = "OL-WRTC-1";',
        "async function _signSignal(type, body)",
    )
    script = f"""
const assert = require("node:assert/strict");
const {{ webcrypto }} = require("node:crypto");
Object.defineProperty(globalThis, "crypto", {{ value: webcrypto }});

{_encoding_and_crypto_source(peer_source)}
{_pinned_ed25519_fetch_source()}
{binding_helpers}

class MockFileHandle {{
  constructor() {{ this.kind = "file"; this.data = ""; }}
  async getFile() {{
    const data = this.data;
    return {{
      size: new TextEncoder().encode(data).byteLength,
      text: async () => data,
    }};
  }}
  async createWritable() {{
    let staged = "";
    return {{
      write: async (value) => {{ staged = String(value); }},
      close: async () => {{ this.data = staged; }},
      abort: async () => {{ staged = ""; }},
    }};
  }}
}}

class MockDirectory {{
  constructor() {{ this.files = new Map(); }}
  async getFileHandle(name, options = {{}}) {{
    if (!this.files.has(name)) {{
      if (!options.create) {{
        const error = new Error("not found");
        error.name = "NotFoundError";
        throw error;
      }}
      this.files.set(name, new MockFileHandle());
    }}
    return this.files.get(name);
  }}
  async removeEntry(name) {{
    if (!this.files.delete(name)) throw new Error("not found");
  }}
  async *entries() {{
    for (const entry of [...this.files.entries()].sort()) yield entry;
  }}
}}

const rosterDirectory = new MockDirectory();
const peersDirectory = {{
  getDirectoryHandle: async (name) => {{
    assert.equal(name, "v1");
    return rosterDirectory;
  }},
}};
const rootDirectory = {{
  getDirectoryHandle: async (name) => {{
    assert.equal(name, "peers");
    return peersDirectory;
  }},
}};
async function _opfsRoot() {{ return rootDirectory; }}
function _isNotFoundError(error) {{ return error && error.name === "NotFoundError"; }}
Object.defineProperty(globalThis, "navigator", {{
  value: {{ locks: {{ request: async (_name, _options, operation) => operation() }} }},
}});
const purgedPeers = [];
async function clearChatOutboxForPeer(fingerprint) {{
  purgedPeers.push(fingerprint);
  return 1;
}}

{roster}

async function makeRecord(alias) {{
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {{
    v: 1,
    fingerprint: await fingerprintOf(raw),
    public_key_b64u: bytesToB64Url(raw),
    alias,
    paired_ms: 1,
    last_seen_ms: 1,
  }};
}}

(async () => {{
  const firstByNibble = new Map();
  let first;
  let second;
  for (let attempt = 0; attempt < 64 && !second; attempt += 1) {{
    const candidate = await makeRecord(`peer-${{attempt}}`);
    const nibble = candidate.fingerprint.slice("sha256:".length, 8);
    if (firstByNibble.has(nibble)) {{
      first = firstByNibble.get(nibble);
      second = candidate;
    }} else {{
      firstByNibble.set(nibble, candidate);
    }}
  }}
  assert.ok(first && second, "expected a one-hex-character prefix collision");

  await savePeer(first);
  await savePeer(second);
  const collisionNames = [...rosterDirectory.files.keys()].sort();
  assert.equal(collisionNames.length, 2);
  assert.ok(collisionNames.some((name) => /^[0-9a-f]\\.json$/.test(name)));
  assert.ok(collisionNames.some((name) => /^[0-9a-f]-1\\.json$/.test(name)));

  const firstUpdate = {{ ...first, alias: "same-binding-update", last_seen_ms: 2 }};
  await savePeer(firstUpdate);
  assert.deepEqual([...rosterDirectory.files.keys()].sort(), collisionNames);
  const listed = await listPeers();
  assert.equal(listed.length, 2);
  assert.equal(
    listed.find((row) => row.fingerprint === first.fingerprint).alias,
    "same-binding-update",
  );

  const beforeMismatch = [...rosterDirectory.files.entries()].map(
    ([name, handle]) => [name, handle.data],
  );
  await assert.rejects(
    savePeer({{ ...first, public_key_b64u: second.public_key_b64u }}),
    /fingerprint does not match sha256\\(public key\\)/,
  );
  assert.deepEqual(
    [...rosterDirectory.files.entries()].map(([name, handle]) => [name, handle.data]),
    beforeMismatch,
  );

  for (const hostile of [
    {{ ...first, alias: "x".repeat(129) }},
    {{ ...first, public_key_b64u: first.public_key_b64u + "A" }},
    {{ ...first, fingerprint: first.fingerprint.toUpperCase() }},
    {{ ...first, unexpected: true }},
  ]) {{
    await assert.rejects(savePeer(hostile));
  }}
  assert.deepEqual(
    [...rosterDirectory.files.entries()].map(([name, handle]) => [name, handle.data]),
    beforeMismatch,
  );

  assert.equal(await deletePeer(second.fingerprint), true);
  assert.deepEqual(purgedPeers, [second.fingerprint]);
  assert.equal((await listPeers()).length, 1);
  assert.equal((await listPeers())[0].fingerprint, first.fingerprint);

  const occupiedStems = new Set(
    [...rosterDirectory.files.keys()].map((name) => name.slice(0, 1)),
  );
  const corruptStem = [..."0123456789abcdef"].find(
    (candidate) => !occupiedStems.has(candidate),
  );
  const corruptHandle = new MockFileHandle();
  corruptHandle.data = "{{broken-json";
  rosterDirectory.files.set(`${{corruptStem}}.json`, corruptHandle);
  await assert.rejects(listPeers(), /not valid JSON/);
  await assert.rejects(savePeer(await makeRecord("blocked-by-corruption")), /not valid JSON/);
  assert.equal(corruptHandle.data, "{{broken-json");
  process.stdout.write("roster-integrity-ok");
}})().catch((error) => {{
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
}});
"""
    assert _run_node(script) == "roster-integrity-ok"


def test_signed_session_and_pair_hello_reject_key_or_session_swap(
    peer_source: str,
) -> None:
    ice_config_factory = _section(peer_source, "function createPeerIceConfig(", "\n}\n") + "\n}\n"
    webrtc = _section(
        peer_source,
        'const WRTC_PROTOCOL_VERSION = "OL-WRTC-1";',
        "// ── rendezvous UI wiring",
    )
    pair_constants = _section(
        peer_source,
        'const PAIR_PROTOCOL_VERSION = "OL-PAIR-1";',
        "// OPFS peers store.",
    )
    pair_validators = _section(
        peer_source,
        "function _validatePairTimestamp(value, label)",
        "// Pair-session lifecycle.",
    )
    pair_hello = _section(
        peer_source,
        "async function _onPairHello(envelope)",
        "async function _sendPairConfirm(matched)",
    )
    pair_router = _section(
        peer_source,
        "function _routeControlMessage(session, kind, data)",
        "async function _onControlChannelOpen(session)",
    )
    chat_router = _section(
        peer_source,
        "const _origRouteControlMessage = _routeControlMessage;",
        "// Open the chat card automatically once finalize-pairing",
    )
    script = f"""
const assert = require("node:assert/strict");
const {{ webcrypto }} = require("node:crypto");
Object.defineProperty(globalThis, "crypto", {{ value: webcrypto }});
globalThis.window = {{
  RTCPeerConnection: class {{}},
  RTCSessionDescription: class {{}},
}};
globalThis.RTCSessionDescription = class {{
  constructor(value) {{ Object.assign(this, value); }}
}};

{_encoding_and_crypto_source(peer_source)}
{_pinned_ed25519_fetch_source()}
{ice_config_factory}
const state = {{ rec: null, pairing: null }};
{webrtc}
{pair_constants}
{pair_validators}

const $ = () => null;
const text = () => undefined;
const show = () => undefined;
const hide = () => undefined;
const _renderSasArt = () => undefined;
async function _computeSas() {{
  return {{ digits: "123456", display: "123 456", art: [1, 2, 3, 4, 5, 6] }};
}}
function _abortPairing(reason) {{
  if (!state.pairing || state.pairing.finished) return;
  state.pairing.finished = true;
  state.pairing.abort_reason = reason;
}}
async function _onPairConfirm() {{ state.confirm_calls = (state.confirm_calls || 0) + 1; }}
{pair_hello}
{pair_router}
const MSG_PROTOCOL_VERSION = "OL-MSG-1";
let chatTextCalls = 0;
let chatAckCalls = 0;
async function _onChatTextReceived() {{ chatTextCalls += 1; }}
async function _onChatAckReceived() {{ chatAckCalls += 1; }}
{chat_router}

async function makeSigner() {{
  const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return {{
    private_key_jwk: await crypto.subtle.exportKey("jwk", pair.privateKey),
    public_key_b64u: bytesToB64Url(raw),
    fingerprint: await fingerprintOf(raw),
  }};
}}

(async () => {{
  const signerA = await makeSigner();
  const signerB = await makeSigner();
  const local = await makeSigner();

  state.rec = signerA;
  const answerA = await _signSignal("answer", {{ type: "answer", sdp: "v=0\\r\\n" }});
  const applied = {{ descriptions: 0, candidates: 0 }};
  const session = {{
    pc: {{
      setRemoteDescription: async () => {{ applied.descriptions += 1; }},
      addIceCandidate: async () => {{ applied.candidates += 1; }},
    }},
    remote_signal_signer_pubkey_b64u: null,
    remote_signal_signer_fingerprint: null,
  }};
  await acceptAnswerSignal(session, answerA);
  assert.equal(session.remote_signal_signer_pubkey_b64u, signerA.public_key_b64u);
  assert.equal(session.remote_signal_signer_fingerprint, signerA.fingerprint);
  assert.equal(applied.descriptions, 1);

  state.rec = signerB;
  const iceB = await _signSignal("ice", {{
    candidate: "candidate:1 1 UDP 1 127.0.0.1 9 typ host",
    sdpMLineIndex: 0,
    sdpMid: "0",
    usernameFragment: "b",
  }});
  await assert.rejects(
    addIceSignal(session, iceB),
    /remote signaling signer changed/,
  );
  assert.equal(applied.candidates, 0);
  assert.equal(session.remote_signal_signer_pubkey_b64u, signerA.public_key_b64u);

  state.rec = signerA;
  const iceA = await _signSignal("ice", {{
    candidate: "candidate:2 1 UDP 1 127.0.0.1 10 typ host",
    sdpMLineIndex: 0,
    sdpMid: "0",
    usernameFragment: "a",
  }});
  await addIceSignal(session, iceA);
  assert.equal(applied.candidates, 1);

  await assert.rejects(
    verifySignal({{ ...answerA, unsigned_extra: true }}, "answer"),
    /fields do not match the protocol/,
  );
  await assert.rejects(
    _signSignal("offer", {{ type: "offer", sdp: "x".repeat(1024 * 1024 + 1) }}),
    /invalid offer session description/,
  );

  const nonce = bytesToB64Url(crypto.getRandomValues(new Uint8Array(16)));
  const helloB = {{
    v: PAIR_PROTOCOL_VERSION,
    t: "hello",
    pubkey: signerB.public_key_b64u,
    fingerprint: signerB.fingerprint,
    nonce,
    ts: Date.now(),
  }};
  state.rec = local;
  state.pairing = {{
    session,
    finished: false,
    remote_hello: null,
    local_nonce: crypto.getRandomValues(new Uint8Array(16)),
  }};
  await _onPairHello(helloB);
  assert.equal(state.pairing.remote_hello, null);
  assert.match(state.pairing.abort_reason, /verified signaling signer/);

  const activeSession = {{
    remote_signal_signer_pubkey_b64u: signerA.public_key_b64u,
    remote_signal_signer_fingerprint: signerA.fingerprint,
  }};
  const staleSession = {{
    remote_signal_signer_pubkey_b64u: signerA.public_key_b64u,
    remote_signal_signer_fingerprint: signerA.fingerprint,
  }};
  const helloA = {{
    v: PAIR_PROTOCOL_VERSION,
    t: "hello",
    pubkey: signerA.public_key_b64u,
    fingerprint: signerA.fingerprint,
    nonce,
    ts: Date.now(),
  }};
  state.pairing = {{
    session: activeSession,
    finished: false,
    remote_hello: null,
    local_nonce: crypto.getRandomValues(new Uint8Array(16)),
  }};
  _routeControlMessage(staleSession, "control", JSON.stringify(helloA));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(state.pairing.remote_hello, null);
  _routeControlMessage(activeSession, "control", JSON.stringify(helloA));
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(state.pairing.remote_hello.fingerprint, signerA.fingerprint);

  state.pairing.persisted = true;
  state.pairing.finished = true;
  state.pairing.local_confirm = true;
  state.pairing.remote_confirm = true;
  const ack = JSON.stringify({{
    v: MSG_PROTOCOL_VERSION,
    t: "ack",
    id: "outgoing-message-1",
    ts: Date.now(),
  }});
  _routeControlMessage(staleSession, "control", ack);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(chatAckCalls, 0, "stale session must not acknowledge active chat");
  _routeControlMessage(activeSession, "control", ack);
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(chatAckCalls, 1);
  assert.equal(chatTextCalls, 0);

  const oversizedHello = {{ ...helloA, alias: "x".repeat(4097) }};
  await assert.rejects(_validatePairHello(oversizedHello), /size limit/);
  const wrongFingerprint = {{ ...helloA, fingerprint: signerB.fingerprint }};
  await assert.rejects(
    _validatePairHello(wrongFingerprint),
    /fingerprint does not match sha256\\(public key\\)/,
  );
  process.stdout.write("session-binding-ok");
}})().catch((error) => {{
  console.error(error && error.stack ? error.stack : error);
  process.exitCode = 1;
}});
"""
    assert _run_node(script) == "session-binding-ok"
