"use strict";

// MNT-03 behavioural contracts for the peer page's feature state owners:
// identity, daemon transport and daemon-chat view state. Each runs from its
// canonical source module, in strict mode like the shipped peer closure.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "../..");
const peer = path.join(root, "frontend/peer");
const read = (rel) => fs.readFileSync(path.join(peer, rel), "utf8");

function scope(files, globals, epilogue) {
  const names = Object.keys(globals);
  const body = '"use strict";\n' + files.map(read).join("\n") + "\n" + epilogue;
  return new Function(...names, body)(...names.map((name) => globals[name]));
}
function load(files, globals = {}) {
  const factories = [...files.map(read).join("\n").matchAll(/^function (create[A-Za-z]+)\(/gm)].map((m) => m[1]);
  return scope(files, globals, `return { ${factories.join(", ")} };`);
}

test("the peer page's state publisher is the owner page's, byte for byte", () => {
  const owner = fs.readFileSync(path.join(root, "frontend/owner/services/state_publisher.js"), "utf8");
  const strip = (text) => text.replace(/\r\n/g, "\n");
  assert.equal(strip(read("services/state_publisher.js")), strip(owner),
    "the two pages cannot share a runtime module; their copies must not drift");
});

const PUBLISHED = {
  peerIdentity: ["rec", "envelope", "pending_rec", "pending_authority", "boot_error_msg", "post_identity_flow_started"],
};

test("every migrated peer identity field is read-only on `state` (strict mode) and names its owner", () => {
  const page = scope(
    ["services/state.js", "services/state_publisher.js", "services/identity.js", "ui/state.js"], {},
    "return { state, stateOwners, peerIdentity };",
  );
  for (const [owner, fields] of Object.entries(PUBLISHED)) {
    for (const field of fields) {
      assert.equal(page.stateOwners.ownerOf(field), owner);
      assert.throws(() => { page.state[field] = "raw"; }, (e) => e instanceof TypeError && e.message.includes(owner), field);
    }
  }
  assert.deepEqual(Object.keys(page.state), PUBLISHED.peerIdentity);
  page.peerIdentity.unlock({ fingerprint: "fp" }, { v: 2 });
  assert.equal(page.state.rec.fingerprint, "fp");
  assert.equal(page.state.envelope.v, 2);
  // Unpublished fields stay ordinary shared fields (pairing, diagnostics).
  page.state.pairing = { session: 1 };
  assert.equal(page.state.pairing.session, 1);
});

// ── Identity ────────────────────────────────────────────────────────────

test("identity: a pending commit is not usable, unlock clears it, boot failure is recorded", () => {
  const identity = load(["services/identity.js"]).createPeerIdentity();
  assert.deepEqual([identity.rec(), identity.envelope(), identity.pendingRec(), identity.pendingAuthority()], [null, null, null, null]);
  assert.equal(identity.bootError(), undefined, "absent until boot stops");
  identity.unlock({ fingerprint: "old" }, { v: 2 });
  identity.stagePending({ fingerprint: "fresh" }, null);
  assert.deepEqual([identity.rec(), identity.envelope(), identity.pendingRec().fingerprint, identity.pendingAuthority()],
    [null, null, "fresh", null], "a staged identity is held aside and nothing is usable");
  assert.equal(identity.beginPostIdentityFlow(), false, "no post-unlock flow without an unlocked identity");
  identity.unlock({ fingerprint: "fresh" }, { v: 2, committed: true });
  assert.deepEqual([identity.pendingRec(), identity.pendingAuthority(), identity.envelope().committed], [null, null, true]);
  identity.setEnvelope({ v: 2, rotated: true });
  assert.equal(identity.envelope().rotated, true);
  assert.equal(identity.beginPostIdentityFlow(), true);
  assert.equal(identity.beginPostIdentityFlow(), false, "the post-unlock flow runs once per page");
  assert.equal(identity.postIdentityFlowStarted(), true);
  identity.failBoot("Web Crypto not exposed");
  assert.equal(identity.bootError(), "Web Crypto not exposed");
  identity.reset();
  assert.deepEqual([identity.rec(), identity.envelope(), identity.bootError(), identity.postIdentityFlowStarted()],
    [null, null, undefined, false]);
});

// ── Daemon transport ────────────────────────────────────────────────────

function daemonLink() {
  const cleared = [];
  const link = load(["services/daemon_link.js"]).createDaemonLink({ clearTimeout: (id) => cleared.push(id) });
  return { link, cleared };
}

function pendingEntry(log, name) {
  return { timer: `${name}-timer`, resolve: (v) => log.push([name, "resolve", v]), reject: (e) => log.push([name, "reject", e.message]) };
}

test("daemon link: one current channel; replacing it rejects the old requests and handshake", async () => {
  const { link, cleared } = daemonLink();
  const dc1 = { id: 1 };
  const dc2 = { id: 2 };
  const first = link.attach(dc1, "fp1", "daemon channel replaced");
  assert.equal(first.previous, null);
  assert.deepEqual([link.dc(), link.fingerprint(), link.identityReady().dc, link.identityReady().settled], [dc1, "fp1", dc1, false]);
  const firstRejected = first.identityPromise.catch((e) => e.message);
  const log = [];
  link.addPending("r1", pendingEntry(log, "r1"));
  link.setIdentityContext(dc1, { challenge_id: "c" });
  const second = link.attach(dc2, "fp2", "daemon channel replaced");
  assert.equal(second.previous, dc1, "the caller closes the previous channel");
  assert.deepEqual(log, [["r1", "reject", "daemon channel replaced"]]);
  assert.deepEqual(cleared, ["r1-timer"]);
  assert.equal(link.pending().size, 0);
  assert.equal(await firstRejected, "daemon channel replaced");
  assert.deepEqual([link.identityContext(), link.identityReady().dc], [null, dc2]);
  const same = link.attach(dc2, "fp2", "daemon channel replaced");
  assert.equal(same.previous, dc2, "re-attaching the same channel rejects nothing");
});

test("daemon link: a stale close changes nothing; the current close fails requests and reports verification", async () => {
  const { link, cleared } = daemonLink();
  const dc1 = { id: 1 };
  const dc2 = { id: 2 };
  const replaced = link.attach(dc1, "fp", "replaced").identityPromise;
  const { identityPromise } = link.attach(dc2, "fp", "replaced");
  await assert.rejects(replaced, /replaced/);
  const log = [];
  link.addPending("r2", pendingEntry(log, "r2"));
  assert.equal(link.detach(dc1, "handshake closed", "daemon channel closed"), null, "an older channel's close owns nothing");
  assert.equal(link.dc(), dc2);
  assert.equal(link.pending().size, 1);
  assert.equal(link.verifyIdentity(dc1, { ok: true }), false, "a stale channel cannot verify the current handshake");
  assert.equal(link.verifyIdentity(dc2, { verified_ms: 5 }), true);
  assert.deepEqual(await identityPromise, { verified_ms: 5 });
  assert.equal(link.verifyIdentity(dc2, { verified_ms: 6 }), false, "a handshake settles once");
  const closed = link.detach(dc2, "handshake closed", "daemon channel closed");
  assert.deepEqual(closed, { wasVerified: true });
  assert.deepEqual(log, [["r2", "reject", "daemon channel closed"]]);
  assert.deepEqual(cleared, ["r2-timer"]);
  assert.deepEqual([link.dc(), link.fingerprint(), link.identityContext(), link.pending().size], [null, null, null, 0]);
});

test("daemon link: an unverified close rejects the handshake; failIdentity only settles the matching channel", async () => {
  const { link } = daemonLink();
  const dc = { id: 1 };
  const { identityPromise } = link.attach(dc, "fp", "replaced");
  assert.equal(link.failIdentity({ id: "other" }, new Error("x")), false);
  const closed = link.detach(dc, "identity-possession channel closed", "daemon channel closed");
  assert.deepEqual(closed, { wasVerified: false });
  await assert.rejects(identityPromise, /identity-possession channel closed/);
  const again = link.attach(dc, "fp", "replaced");
  assert.equal(link.failIdentity(dc, "not an error object"), true);
  await assert.rejects(again.identityPromise, /not an error object/);
  assert.equal(link.failIdentity(dc, new Error("twice")), false);
});

test("daemon link: request correlation by rid, and dispose releases every timer and waiter", async () => {
  const { link, cleared } = daemonLink();
  const log = [];
  link.addPending("a", pendingEntry(log, "a"));
  link.addPending("b", pendingEntry(log, "b"));
  const entry = link.takePending("a");
  assert.equal(entry.timer, "a-timer");
  assert.equal(link.takePending("a"), null, "a response settles its request once");
  assert.equal(link.dropPending("b"), true);
  assert.equal(link.dropPending("b"), false);
  const dc = { id: 1 };
  const { identityPromise } = link.attach(dc, "fp", "replaced");
  link.addPending("c", pendingEntry(log, "c"));
  link.dispose();
  assert.deepEqual(log, [["c", "reject", "daemon link disposed"]]);
  assert.deepEqual(cleared, ["c-timer"]);
  await assert.rejects(identityPromise, /daemon link disposed/);
  assert.deepEqual([link.dc(), link.pending().size], [null, 0]);
  assert.throws(() => load(["services/daemon_link.js"]).createDaemonLink({}), /clearTimeout/);
});

// ── Daemon-chat view state ──────────────────────────────────────────────

test("daemon conversation: a peer or a group is open, never both; replies are bounded; roster is copied", () => {
  const view = load(["services/daemon_conversation.js"]).createDaemonConversation();
  assert.deepEqual([view.activePeer(), view.activeGroup(), view.replyTo(), view.rosterPeers()], [null, null, null, undefined]);
  view.openGroup({ group_id: "g" });
  view.openPeer({ fingerprint: "p" });
  assert.deepEqual([view.activePeer().fingerprint, view.activeGroup()], ["p", null]);
  view.openGroup({ group_id: "g" });
  assert.deepEqual([view.activePeer(), view.activeGroup().group_id], [null, "g"]);
  view.leaveGroup();
  assert.equal(view.activeGroup(), null);
  view.openPeer({ fingerprint: "p" });
  view.close();
  assert.deepEqual([view.activePeer(), view.activeGroup()], [null, null]);
  const reply = view.setReplyTo({ id: 7, body: "x".repeat(400) });
  assert.deepEqual([reply.id, reply.body.length], ["7", 160]);
  assert.equal(view.setReplyTo({ file: { name: "photo.jpg" } }).body, "photo.jpg");
  assert.equal(view.setReplyTo({}).body, "(message)");
  view.clearReplyTo();
  assert.equal(view.replyTo(), null);
  const record = { fingerprint: "p", alias: "" };
  view.openPeer(record);
  assert.equal(view.updatePeer(record, { alias: "Desk", muted: true }), record, "the opened record itself changes");
  assert.deepEqual({ ...view.activePeer() }, { fingerprint: "p", alias: "Desk", muted: true });
  assert.throws(() => view.updatePeer(null, {}), /peer record/);
  const peers = [{ fingerprint: "a" }];
  view.replaceRoster(peers, []);
  peers.push({ fingerprint: "b" });
  assert.equal(view.rosterPeers().length, 1, "the roster keeps its own copy");
  view.reset();
  assert.deepEqual([view.rosterPeers(), view.rosterGroups(), view.replyTo()], [undefined, undefined, null]);
});

test("the identity owner holds the unwrapped record and envelope, never a passphrase", () => {
  const identity = load(["services/identity.js"]).createPeerIdentity();
  const source = read("services/identity.js");
  const fields = source.slice(source.indexOf("function createPeerIdentity() {"), source.indexOf("function stagePending"));
  assert.match(fields, /let rec = null;/);
  assert.match(fields, /let envelope = null;/);
  assert.doesNotMatch(fields.toLowerCase(), /passphrase|password|secret/);
  assert.doesNotMatch(Object.keys(identity).join(" ").toLowerCase(), /passphrase|password/);
});

test("the public test hook adopts an identity record through the owner, and raw writes stay refused", () => {
  const page = scope(
    ["services/state.js", "services/state_publisher.js", "services/identity.js", "ui/state.js"], {},
    "return { state, peerIdentity };",
  );
  const source = read("ui/public_api.js");
  const hook = source.match(/_identityTestUseRecord: (\(rec\) => \{[^}]*\}),/);
  assert(hook, "window.__oneLinkPeer exposes _identityTestUseRecord");
  const useRecord = new Function("peerIdentity", "state", `return ${hook[1]};`)(page.peerIdentity, page.state);
  page.peerIdentity.unlock({ fingerprint: "old" }, { v: 2, kept: true });
  useRecord({ fingerprint: "injected" });
  assert.equal(page.state.rec.fingerprint, "injected");
  assert.equal(page.state.envelope.kept, true, "the committed envelope is kept");
  assert.throws(() => { page.state.rec = { fingerprint: "raw" }; }, /owned by peerIdentity/);
});
