# Offline courier service boundaries

Offline courier operations now have independent persistence, filesystem and
use-case boundaries. `UIServer` retains authentication, request parsing, HTTP
status translation, removable-drive selection and WebSocket event delivery.
The services can be imported and used without the server, daemon or `aiohttp`.

| Component | Dependencies | Owns | Does not own |
| --- | --- | --- | --- |
| `CourierReplayLedger` | One explicit ledger path, event bound, clock | Replay IDs, bounded recent events, loading and validating durable authority, atomic publication and read-back | Chunk cache, identity, requests, network |
| `CourierFileCatalog` | Explicit courier root and size/list bounds | Drop/outbox paths, newest-file catalog, opaque file-ID resolution, staging and temporary-file cleanup, selected removable path containment | Drive discovery, authorization, replay admission, decryption |
| `CourierDirectoryMonitor` | Catalog and clock | Last directory signatures, scan time and change count | Poll scheduling, WebSocket clients, notifications |
| `CourierService` | Ledger, catalog, immutable identity, two-query `CourierChunkIndex`, chunk read/write callbacks, hash/name validation and inbox-path callbacks | Export selection, signed bundle creation, import admission ordering, cache insertion, verified assembly | HTTP, arbitrary daemon/state access, peer/session management, online delivery |

## Composition and compatibility

Each `UIServer` owns one ledger, catalog and directory monitor. Their roots are
bound at construction instead of consulting process-wide path configuration
again for every operation. The server creates a lightweight `CourierService`
with the current identity and cache/index dependencies for each operation.
Identity rotation or daemon state attachment therefore does not leave a stale
identity in a long-lived use-case object.

`CourierChunkIndex` exposes only `get_transfer` and `list_chunks_for_blob`.
Chunk cache insertion has its own typed callable, including the optional blob
identity and chunk index. No service receives the daemon, imports the server,
reflects over unrelated state, or obtains its caller's global namespace.
Return payloads have explicit `TypedDict` contracts. Domain failures identify
invalid input, missing resources, conflicts, unavailable authority and operation
failure; the HTTP adapter preserves the existing 400, 404, 409, 503 and 500
responses respectively.

Export-file now calls the export use case directly. It no longer constructs a
fake HTTP request, calls another HTTP handler, serializes a response, and parses
that response back into an internal result. The persisted courier file still
contains the encrypted bundle and manifest only; the separate unlock token is
returned to the caller, never embedded in that file.

Existing private helper names used by integrations remain small compatibility
adapters. The ledger's old read views still expose its current replay set,
events and error state. HTTP route registration, authentication, browser peer
dispatch, upload admission and the audit endpoint are unchanged.

## Failure and ownership contracts

- Import validates/decrypts the bundle and checks replay before cache insertion.
  Successful durable replay admission must precede the first chunk write. A
  failed sync admits zero chunks. A later cache failure leaves admission intact
  so retry cannot repeat an uncertain side effect after restart.
- Existing corrupt or unreadable ledger files remain preserved and block
  replay-sensitive import. Event history is bounded independently of replay
  IDs, so trimming old events never forgets a previously admitted bundle.
- Assembly streams cached chunks to an exclusively created output and checks
  the complete content hash. A failed assembly removes only the output it
  created. A pre-existing destination survives exclusive-create failure.
- Temporary export/copy files are removed when writing, copying or publication
  fails. A drive disappearing during directory iteration yields an unavailable
  (empty) inventory rather than a partial list.
- The catalog retains at most 64 candidate records by default while scanning,
  and applies the existing file-size bounds. Per-file reads and encrypted bundle
  construction retain the existing bundle memory limits; this refactor is not
  a claim that every courier operation has constant memory usage.

## Verification and remaining scope

Direct service tests use a two-method read-only index, ordinary dictionary
cache and explicit filesystem roots. They verify durable admission before any
cache write, behavior across reconstruction, failed-sync and partial-cache
outcomes, separate token handling, ordered assembly, rollback ownership,
bounded catalog behavior, temporary-file cleanup and independent monitor
state. Handler tests verify malformed JSON rejection before a service is
constructed and preserve the original domain error/status contracts. Existing
courier API, bundle, removable-media, performance and server tests continue to
exercise the production adapters.

At baseline `5344ee9`, `server.py` had 29,931 physical lines. This change removes
870 lines and adds 216 lines of service composition and adapters, leaving
29,277 lines. The preceding daemon preparation/commit extraction removed a
further 556 lines from `daemon.py`. These are actual responsibility boundaries,
not a completed decomposition of either large orchestration class. Browser
peer dispatch, recovery handlers, outbound transfers and other domains remain
future candidates for similarly bounded extractions.

Courier operations remain synchronous within their caller's event loop, as
before. The HTTP adapter does not offload imports to concurrent worker threads:
the replay check/admission sequence depends on the existing serialized call
lifecycle. Adding concurrent import workers requires a separate synchronization
design and tests. Private ledger publication retains the existing filesystem
durability semantics; the removable copy path is not a transactional removable
media protocol.
