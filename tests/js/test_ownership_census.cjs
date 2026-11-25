"use strict";

// MNT-03 ownership census: the instrument's own contract, then the ratchet
// that binds the shipped owner and peer pages to the justified baseline.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const census = require("./ownership_census.js");

// A generated page in the builder's exact shape: a private services scope
// holding factories, then one feature closure whose modules are delimited by
// "// owner-ui module: <path>" markers.
function page(modules, services = "") {
  const parts = ["<html><body><script>\n(() => {\n"];
  if (services) parts.push("// owner-ui module: services/fixture_store.js\n", services, "\n");
  parts.push("(() => {\n");
  for (const [file, body] of Object.entries(modules)) parts.push(`// owner-ui module: ${file}\n`, body, "\n");
  parts.push("})();\n})();\n</script></body></html>\n");
  return { owner: { html: parts.join("") } };
}

function entries(pages) {
  return census.crossModuleEntries(census.runCensus(pages))
    .map((e) => `${e.target} <- ${e.writer} ${JSON.stringify(e.kinds)}`);
}

const STORE = `function createFixtureStore() {
  const items = [];
  return Object.freeze({ add(x) { items.push(x); }, clear() { items.length = 0; }, items: () => items });
}`;

test("the census reports a known cross-module write and nothing else", () => {
  const measured = entries(page({
    "main/a.js": "const shared = { count: 0, items: [] };\nlet flag = false;\nshared.count = 1;\nflag = true;",
    "main/b.js": "function touch() { shared.count += 1; }",
  }));
  assert.deepEqual(measured, ['shared.count <- main/b.js {"property":1}']);
});

test("every write form is detected, and every read form is not", () => {
  const cases = [
    ["flag = true;", 'flag <- main/b.js {"assign":1}'],
    ["flag ||= true;", 'flag <- main/b.js {"assign":1}'],
    ["counter++;", 'counter <- main/b.js {"update":1}'],
    ["--counter;", 'counter <- main/b.js {"update":1}'],
    ["[flag, counter] = [true, 2];", 'counter <- main/b.js {"assign":1}|flag <- main/b.js {"assign":1}'],
    ["({ flag } = { flag: 1 });", 'flag <- main/b.js {"assign":1}'],
    ["for (flag in shared) {}", 'flag <- main/b.js {"assign":1}'],
    ["shared.count = 2;", 'shared.count <- main/b.js {"property":1}'],
    ["shared.count *= 2;", 'shared.count <- main/b.js {"property":1}'],
    ['shared["count"] = 2;', 'shared.count <- main/b.js {"property":1}'],
    ["shared[key] = 2;", 'shared.[] <- main/b.js {"property":1}'],
    ["shared.nested.deep = 2;", 'shared.nested <- main/b.js {"property":1}'],
    ["shared.count++;", 'shared.count <- main/b.js {"property":1}'],
    ["delete shared.count;", 'shared.count <- main/b.js {"property":1}'],
    ["[shared.count] = [3];", 'shared.count <- main/b.js {"property":1}'],
    ["shared.items.push(1);", 'shared.items <- main/b.js {"mutator":1}'],
    ["shared.byId.set('a', 1);", 'shared.byId <- main/b.js {"mutator":1}'],
    ["shared.byId?.delete('a');", 'shared.byId <- main/b.js {"mutator":1}'],
    ["shared.byId.get('a').status = 'x';", 'shared.byId <- main/b.js {"property":1}'],
    ["list.splice(0, 1);", 'list <- main/b.js {"mutator":1}'],
    ["Object.assign(shared, { count: 1 });", 'shared <- main/b.js {"mutator":1}'],
    ["Object.assign(shared.nested, { a: 1 });", 'shared.nested <- main/b.js {"mutator":1}'],
    ["Reflect.deleteProperty(shared, 'count');", 'shared <- main/b.js {"mutator":1}'],
    // Aliases, followed transitively.
    ["const items = shared.items; items.push(1);", 'shared.items <- main/b.js {"mutator":1}'],
    ["const { items } = shared; items.push(1);", 'shared.items <- main/b.js {"mutator":1}'],
    ["const s = shared; const i = s.items; i.length = 0;", 'shared.items <- main/b.js {"property":1}'],
    ["const row = shared.byId.get('a') || null; if (row) row.done = true;", 'shared.byId <- main/b.js {"property":1}'],
    ["let t; t = shared.items; t.pop();", 'shared.items <- main/b.js {"mutator":1}'],
    ["for (const item of shared.items) item.done = true;", 'shared.items <- main/b.js {"property":1}'],
    ["for (const [, v] of shared.byId) v.done = true;", 'shared.byId <- main/b.js {"property":1}'],
    ["shared.items.forEach((item) => { item.done = true; });", 'shared.items <- main/b.js {"property":1}'],
    ["shared.items.reduce((acc, item) => { item.n = 1; return acc; }, 0);", 'shared.items <- main/b.js {"property":1}'],
    // Service interfaces: a depth-one call is the interface; mutating what it
    // returns is not.
    ["store.clear();", ""],
    ["store.add(1);", ""],
    ["store.items().push(1);", 'store.items() <- main/b.js {"mutator":1}'],
    // Reads, shadowing, and copies are not writes into the shared binding.
    ["const n = shared.count + list.length; shared.items.includes(n);", ""],
    ["function f(shared) { shared.count = 1; }", ""],
    ["function f() { let flag = 1; flag = 2; }", ""],
    ["{ const shared = {}; shared.count = 1; }", ""],
    ["try { } catch (shared) { shared.count = 1; }", ""],
    ["const copy = shared.items.slice(); copy.push(1);", ""],
    ["const copy = { ...shared }; copy.count = 1;", ""],
    ["const o = { shared: 1 }; o.shared = 2;", ""],
  ];
  for (const [body, expected] of cases) {
    const measured = entries(page({
      "main/a.js": "const shared = { count: 0, items: [], byId: new Map(), nested: {} };\nlet flag = false;\nlet counter = 0;\nconst list = [];\nconst key = 'k';\nconst store = createFixtureStore();",
      "main/b.js": body,
    }, STORE));
    assert.equal(measured.join("|"), expected, body);
  }
});

test("writes inside the declaring module are not cross-module", () => {
  const measured = entries(page({
    "main/a.js": "const shared = { items: [] };\nfunction add(x) { shared.items.push(x); }",
    "main/b.js": "add(1);",
  }));
  assert.deepEqual(measured, []);
});

test("window bridges: the publisher owns the property, another module's write is reported", () => {
  const result = census.runCensus(page({
    "main/a.js": "window.bridge = { count: 0 };",
    "main/b.js": "window.bridge.count = 2; window.location.hash = '#x';",
  }));
  assert.deepEqual(census.globalBridgeEntries(result).map((e) => `${e.property} ${e.declaredIn} <- ${e.writer} ${JSON.stringify(e.kinds)}`),
    ['bridge main/a.js <- main/b.js {"property":1}']);
  assert.deepEqual(census.platformGlobalWrites(result).map((g) => g.property), ["location"]);
});

test("a page that is not in the builder's shape is refused, not under-counted", () => {
  assert.throws(() => census.runCensus({ owner: { html: "<script>const a = 1;</script>" } }), census.CensusError);
  assert.throws(() => census.runCensus({ owner: { html: "<script>\n(() => {\n// owner-ui module: main/a.js\nconst a = 1;\n})();\n</script>" } }),
    census.CensusError);
  assert.throws(() => census.runCensus({ owner: { html: "<script>\n(() => {\n// owner-ui module: main/a.js\n((\n})();\n</script>" } }),
    census.CensusError);
});

// ── The baseline comparison can fail in every direction ──────────────────

function fixtureBaseline(measured) {
  return {
    schema: 1,
    rationales: { R: "Fixture rationale long enough to be read as a real justification of the write." },
    entries: census.crossModuleEntries(measured).map((e) => ({ ...e, rationale: "R" })),
    globalBridges: [],
  };
}

test("the ratchet rejects an increase, a decrease, a new entry, a stale entry and a missing reason", () => {
  const two = census.runCensus(page({
    "main/a.js": "const shared = { count: 0 };",
    "main/b.js": "shared.count = 1; shared.count = 2;",
  }));
  const baseline = fixtureBaseline(two);
  assert.deepEqual(census.compareToBaseline(two, baseline), []);

  const three = census.runCensus(page({ "main/a.js": "const shared = { count: 0 };", "main/b.js": "shared.count = 1; shared.count = 2; shared.count = 3;" }));
  assert.match(census.compareToBaseline(three, baseline).join("\n"), /increased/);

  const one = census.runCensus(page({ "main/a.js": "const shared = { count: 0 };", "main/b.js": "shared.count = 1;" }));
  assert.match(census.compareToBaseline(one, baseline).join("\n"), /decreased; lower the baseline/);

  const none = census.runCensus(page({ "main/a.js": "const shared = { count: 0 };", "main/b.js": "" }));
  assert.match(census.compareToBaseline(none, baseline).join("\n"), /no longer measured; remove it/);

  const other = census.runCensus(page({ "main/a.js": "const shared = { count: 0, n: 0 };", "main/b.js": "shared.count = 1; shared.count = 2; shared.n = 1;" }));
  assert.match(census.compareToBaseline(other, baseline).join("\n"), /new cross-module write \(1\): owner \| owner \| shared\.n/);

  const unjustified = { ...baseline, entries: baseline.entries.map((e) => ({ ...e, rationale: "UNJUSTIFIED" })) };
  const errors = census.compareToBaseline(two, unjustified).join("\n");
  assert.match(errors, /has no justification/);
  assert.match(errors, /unused rationale: R/);

  const thin = { ...baseline, rationales: { R: "because" } };
  assert.match(census.compareToBaseline(two, thin).join("\n"), /too thin/);
});

test("a migrated feature fails the ratchet if its retired state or its owner is written", () => {
  const measured = census.runCensus(page({
    "main/a.js": "const state = { transfers: [] };\nconst transferStore = createFixtureStore();",
    "main/b.js": "state.transfers.push(1); transferStore.items().push(2);",
  }, STORE));
  const baseline = {
    ...fixtureBaseline(measured),
    migratedFeatures: [{
      name: "transfers", page: "owner", retiredTargets: ["state.transfers"],
      owners: [{ closure: "owner", binding: "transferStore" }, { closure: "owner", binding: "missingStore" }],
    }],
  };
  const errors = census.compareToBaseline(measured, baseline).join("\n");
  assert.match(errors, /retired transfers state is written again: state\.transfers in main\/b\.js/);
  assert.match(errors, /transfers state owner transferStore is written directly: transferStore\.items\(\) mutator in main\/b\.js/);
  assert.match(errors, /transfers state owner is missing: owner:missingStore/);
});

// ── The shipped pages ────────────────────────────────────────────────────

test("the shipped owner and peer pages match the justified ownership baseline exactly", () => {
  const measured = census.runCensus();
  const baseline = census.loadBaseline();
  const errors = census.compareToBaseline(measured, baseline);
  assert.deepEqual(errors, [], "run `node tests/js/ownership_census.js --check` for the differences");
  // The three closures are all analyzed; a page that silently lost its
  // module markers would otherwise read as zero coupling.
  const closures = new Set(measured.bindings.map((b) => `${b.page}:${b.closure}`));
  assert.deepEqual([...closures].sort(), ["owner:calls", "owner:owner", "peer:peer"]);
  // The six MNT-03 features each have an explicit state owner on the page
  // that carries them, and each owner is a declared binding the ratchet
  // checks for direct writes.
  const covered = new Set(baseline.migratedFeatures.map((f) => f.name));
  for (const name of ["message rendering", "transfers", "calls", "settings", "identity", "transport"]) {
    assert(covered.has(name), `${name} has no state owner in the baseline`);
  }
  for (const feature of baseline.migratedFeatures) {
    assert(feature.owners.length > 0, `${feature.name} names no state owner`);
    for (const owner of feature.owners) {
      assert(measured.bindings.some((b) => b.page === feature.page && b.closure === owner.closure && b.name === owner.binding),
        `${feature.name} owner ${owner.binding} is not a top-level binding`);
    }
    assert((feature.retiredTargets || []).length + (feature.moduleOwned || []).length > 0 || feature.name === "calls",
      `${feature.name} names no retired shared state`);
  }
  // The call driver's read paths are the owners' read-only views.
  const calls = baseline.migratedFeatures.find((f) => f.name === "calls");
  assert.deepEqual(calls.owners.map((o) => o.binding).sort(), ["callState", "callUI", "media", "mediaState"]);
  assert.deepEqual(measured.crossClosure, [], "no closure names another closure's top-level binding");
});

test("cross-closure references are reported, typeof probes included, published names excluded", () => {
  const html = "<script>\n(() => {\n(() => {\n// owner-ui module: main/a.js\nconst state = {};\nfunction toast() {}\n" +
    "function shared() {}\nwindow.shared = shared;\n})();\n})();\n</script>\n" +
    "<script>\n(() => {\n(function () {\n// owner-ui module: calls/b.js\n" +
    "function f() { state.messages.push(1); if (typeof toast === 'function') toast('x'); shared(); }\n" +
    "})();\n})();\n</script>\n";
  const measured = census.runCensus({ owner: { html } });
  assert.deepEqual(measured.crossClosure.map((r) => `${r.closure} ${r.name} -> ${r.declaredClosure}:${r.declaredIn}`),
    ["calls state -> owner:main/a.js", "calls toast -> owner:main/a.js"]);
  const errors = census.compareToBaseline(measured, { schema: 1, rationales: {}, entries: [], globalBridges: [] });
  assert.match(errors.join("\n"), /cross-closure reference: owner calls calls\/b\.js:1 names state/);
});

test("a Git CRLF checkout of the page measures exactly what the LF build measures", () => {
  const lf = page({ "main/a.js": "const shared = { n: 0 };", "main/b.js": "function f() {\n  shared.n = 1;\n}" });
  const crlf = { owner: { html: lf.owner.html.split("\n").join("\r\n") } };
  const strip = (m) => m.writes.map((w) => `${w.path} ${w.writer}:${w.line}`);
  assert.deepEqual(strip(census.runCensus(crlf)), strip(census.runCensus(lf)));
  assert.deepEqual(strip(census.runCensus(lf)), ["shared.n main/b.js:2"]);
});

test("the baseline file is in canonical form", () => {
  const text = fs.readFileSync(census.BASELINE_PATH, "utf8");
  const baseline = JSON.parse(text);
  const keys = baseline.entries.map(census.entryKey);
  assert.deepEqual(keys, [...keys].sort((a, b) => {
    const [x, y] = [a.split(" | "), b.split(" | ")];
    return [0, 1, 2, 4].map((i) => (x[i] < y[i] ? -1 : x[i] > y[i] ? 1 : 0)).find((v) => v !== 0) || 0;
  }));
  assert(text.endsWith("\n") && !text.includes("\r"), "baseline must be LF-terminated JSON");
  assert.equal(path.basename(census.BASELINE_PATH), "ownership_baseline.json");
});

test("--write-baseline on an unchanged census reproduces the committed baseline, reasons included", () => {
  const os = require("node:os");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "one-link-census-"));
  const copy = path.join(dir, "baseline.json");
  try {
    fs.copyFileSync(census.BASELINE_PATH, copy);
    census.writeBaseline(census.runCensus(), copy);
    assert.equal(fs.readFileSync(copy, "utf8"), fs.readFileSync(census.BASELINE_PATH, "utf8").replace(/\r\n/g, "\n"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
