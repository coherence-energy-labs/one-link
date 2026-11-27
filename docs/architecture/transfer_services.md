# Transfer runtime service boundaries

The daemon still coordinates peer/session state and transport. Three modules
now own cohesive filesystem, preparation and retry-accounting responsibilities.
They can be imported and tested without constructing or importing the daemon
or HTTP server.

| Boundary | Inputs / dependencies | Owned behavior | Excluded responsibilities |
| --- | --- | --- | --- |
| `DescriptorFileSource` (`file_source.py`) | A regular-file path, an explicit no-follow opener, platform identity probe | Descriptor/path identity agreement, Windows file-ID/change time, stable open/read lifetime, before/after mutation checks | Peers, sessions, transfer queue, database, network |
| `FilePreparationService` (`file_preparation.py`) | `FileSource`, `FileIndexCache`, `FileIndexers`, immutable `FileIndexPolicy` and `PeerIndexProfile`, optional cadence callback | Manifest mode selection, peer-compatible fixed sizes, exact explicit retry boundaries, cache integrity checks, descriptor-bound indexing, cache/source recording | Session discovery, trust changes, delivery, receipts, UI |
| `RemoteCommitGuard` (`transfer_commit_guard.py`) | Read-only `TransferCommitLedger`, durable replace and parent-directory sync functions | Offer/receipt-bound retry decision, private marker publication, marker removal, malformed/unknown accounting refusal | Sending, observer callbacks, trust, arbitrary ledger writes |

## Composition and compatibility

`Daemon.prepare_file_for_transfer` adapts live peer capabilities and delegates
preparation. A fresh service receives the current dependency snapshot for each
operation because the state store is attached during boot and test/measurement
indexers may be deliberately replaced. No service holds or reflects over the
daemon. No module copies its global namespace or dynamically binds its methods.

The cadence callback is evaluated only for automatic fixed-size preparation of
large files. Small-file CDC and explicitly requested retry boundaries never
perform an unnecessary field lookup. Automatic tuning may reuse smaller proven
chunks; an explicit retry size must match its recorded boundary mode exactly.
The existing Gear-CDC and fixed wire formats are preserved.

Existing daemon entry points and the private helper names used by integrations
remain compatibility adapters. Native payload-route accounting, offer/receipt
orchestration, and the public `send_file` interface are unchanged. Existing
instrumentation of `daemon.index_file` / `daemon.fixed_index_file` continues to
observe real preparation through explicitly supplied indexer ports.

## Failure and ownership contracts

- Source identity and read errors propagate. A cache hit never authorizes a
  different path/inode/change-time identity. Missing strong identity disables
  persistent reuse; it does not skip source checks.
- Cache lookup/decode/write failures remain best effort: preparation can rebuild
  from the verified descriptor, but an indexing failure cannot publish a cache
  entry. Cache hashes must be exactly 64 lowercase hexadecimal characters.
- Filesystem descriptors remain held through each scan/read operation. POSIX
  metadata checks and Windows share-mode restrictions retain their existing
  guarantees; caller lifecycle ownership still matters for mutable sources.
- The commit guard reads one ledger snapshot for a retry decision. Only an
  outbound record with the exact modern receipt-capable delivery contract can
  receive an unknown-outcome retry grant. A missing record, a mismatched marker,
  an explicit invalid boundary, or a proven receipt blocks automatic resend.
- The guard does not acquire transfer locks. The daemon's per-transfer gate
  still serializes attempts. Its filesystem publication callback runs before
  parent synchronization; any durability error propagates and temporary files
  are removed. A published failure marker remains conservative evidence.

## Verification and remaining scope

Direct service tests instantiate minimal three-operation cache and read-only
ledger implementations, exercise cache corruption/rebuild, weak identity,
resource cleanup, explicit-versus-automatic sizing, cadence laziness, contract
drift and durable marker ordering. Existing daemon cache/transfer/receipt/
resume tests continue to exercise the compatibility path and integration.

At the extraction baseline (`8b42802`) `daemon.py` had 39,796 physical lines.
This change removes 640 lines of owned logic and introduces 84 lines of adapters
and composition (39,240 lines afterward). It reduces coupling and isolates
responsibilities, but the remaining large peer dispatcher, outbound transfer
state machine and other daemon services still warrant incremental extraction.
File count or smaller modules alone are not a claim of complete maintainability
remediation. Further changes should use these explicit ports and preserve the
established behavioral tests rather than copying the daemon into mixins.
