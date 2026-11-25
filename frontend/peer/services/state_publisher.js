// Isolated service: dependencies are explicit parameters; no owner closure access.
//
// A feature state owner keeps its fields private and changes them only
// through its own functions. The page still reads that state through the
// shared namespace (`state.transfers`, `state.messages`, ...), so this
// publisher installs a read-only accessor per field. Assigning one throws a
// TypeError that names the owner: a missed migration fails loudly instead of
// silently forking the owner's copy. A field is published once, by one owner.
function createStatePublisher(target, label = "state") {
  if (!target || typeof target !== "object") throw new TypeError(`${label} must be an object`);
  const ownerOf = new Map();
  function publish(owner, readers) {
    if (typeof owner !== "string" || !owner) throw new TypeError("a published field needs a named owner");
    for (const [field, read] of Object.entries(readers)) {
      if (typeof read !== "function") throw new TypeError(`${label}.${field} needs a reader function`);
      if (ownerOf.has(field) || Object.prototype.hasOwnProperty.call(target, field)) {
        throw new TypeError(`${label}.${field} already has an owner (${ownerOf.get(field) || "a plain field"})`);
      }
      ownerOf.set(field, owner);
      Object.defineProperty(target, field, {
        enumerable: true,
        configurable: false,
        get: read,
        set() {
          throw new TypeError(`${label}.${field} is owned by ${owner}; change it through ${owner}`);
        },
      });
    }
  }
  return Object.freeze({
    publish,
    ownerOf: (field) => ownerOf.get(field) || null,
    fields: () => [...ownerOf.keys()],
  });
}
