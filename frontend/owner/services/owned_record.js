// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// A closed-schema state record for one feature state owner. The fields that
// exist are fixed when the record is created. Every write goes through
// set / update / increment, which refuse a field the schema does not declare.
// Readers get `view`: its properties are live getters, and any assignment,
// definition or deletion through it throws a TypeError naming the owner.
// That holds in sloppy code too (a frozen object would fail silently there),
// so a write that bypasses the owner fails at the write, not later.
//
// The owning service keeps `fields` private for its named transitions and
// hands out only the view and the write functions it chooses to expose.
function createOwnedRecord(owner, initial) {
  if (typeof owner !== "string" || !owner) throw new TypeError("an owned record needs a named owner");
  const fields = { ...initial };
  const known = new Set(Object.keys(fields));

  function refuse(key) {
    throw new TypeError(`${owner}.${String(key)} is owned state; change it through the ${owner} owner`);
  }
  function requireKnown(key) {
    if (!known.has(key)) throw new TypeError(`${owner} has no field ${String(key)}`);
  }

  const target = {};
  for (const key of known) {
    Object.defineProperty(target, key, {
      enumerable: true,
      configurable: false,
      get: () => fields[key],
      set: () => refuse(key),
    });
  }
  const view = new Proxy(target, {
    set: (_target, key) => refuse(key),
    defineProperty: (_target, key) => refuse(key),
    deleteProperty: (_target, key) => refuse(key),
    setPrototypeOf: () => refuse("[[Prototype]]"),
    preventExtensions: () => refuse("[[Extensible]]"),
  });

  function set(key, value) {
    requireKnown(key);
    fields[key] = value;
    return value;
  }

  // Several fields in one step. Every key is checked before any is written.
  function update(patch) {
    const keys = Object.keys(patch);
    for (const key of keys) requireKnown(key);
    for (const key of keys) fields[key] = patch[key];
    return view;
  }

  function increment(key, by = 1) {
    requireKnown(key);
    fields[key] += by;
    return fields[key];
  }

  return Object.freeze({ view, fields, set, update, increment, has: (key) => known.has(key) });
}
