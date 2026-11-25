# Peer browser source architecture

This directory is the canonical source for `src/one_link/web/peer.html`.
The generated page stays self-contained for offline distribution. Authoring
files are outside the installed/served runtime assets.

```sh
python scripts/build_owner_ui.py --page peer
python scripts/build_owner_ui.py --check
python -m pytest -q tests/test_peer_ui_build.py tests/test_peer_pairing_progress.py
node --test tests/js/test_peer_ui_services.cjs
```

The build check retains its historical name and validates both owner and peer
artifacts by default. It rejects stale artifacts, incomplete module inventories,
duplicate modules, misplaced lifecycle modules, invalid service declarations,
and unresolved template markers. Output has no machine paths, timestamps, or
random values. `--check` does not write files.

## Domain ownership

`manifest.json` names each module's responsibility and its execution order.
Feature boundaries contain complete functions and event bindings. The original
peer lifecycle remains a strict JavaScript closure; its initialization order
and existing `window.__oneLinkPeer` interface remain intact.

| Directory | Owns | Main collaborators |
| --- | --- | --- |
| `identity/` | Identity envelope validation, Ed25519 adapter, KDF, OPFS/IndexedDB authority, boot and setup controls | Encoding helpers, peer state, DOM presentation |
| `rendezvous/` | Canonical signing, signed daemon answer checks, bounded rendezvous requests | Identity, transport capability observations |
| `transport/` | Signal contracts, signer continuity, RTC setup, candidate projection and control/bulk sends | Public ICE service, identity, pairing callbacks |
| `pairing/` | Peer-record persistence, SAS handshake, setup invites, auto-pair cancellation/deadlines and handoff | Identity state, transport, progress service, daemon channel registration |
| `messages/` | Direct peer message history, durable outbox contract, persistence, draining and ACK handling | Bound paired channel, identity and UI rendering |
| `daemon_chat/` | Browser possession handshake, daemon request routing, roster/chat, upload/download and group operations | Current daemon channel, peer state, presentation helpers |
| `ui/` | DOM helpers, identity/chat surfaces, settings, existing public API, returning-device flow and boot dispatch | Domain functions and service bindings |

The transport selector remains explicitly experimental. Modularization does
not activate WebTransport or change which transport the product advertises.
Cryptographic/envelope formats, storage transactions, possession checks,
retry budgets, and pairing deadlines remain owned by their existing domains
and their source/executable contract tests.

## Isolated service interfaces

Service factories are defined in an outer private strict scope. Feature code
runs in the inner peer closure, so a service cannot capture its lexical state
accidentally. Each service receives dependencies explicitly, and factory names
are not added to `window`.

| Factory | Inputs | Output and ownership |
| --- | --- | --- |
| `createPeerEncoding({ btoa, atob })` | Platform base64 codecs | Exact byte/hex/base64url conversion helpers. Fingerprint calculation remains in its existing feature domain. |
| `createPeerState()` | None | Fresh in-memory identity/session fields for one page. Identity material is not copied into a second global store. |
| `createPeerIceConfig({ fetch, AbortController, setTimeout, clearTimeout })` | HTTP, abort controller, timer lifecycle | Public ICE loading, STUN filtering and explicitly enabled local-address selection. Owns its 8-second request timer and host-only failure fallback. |
| `createPeerProgress({ state, performance })` | The owning peer state and monotonic clock | A per-attempt progress recorder with the existing bounded 32-entry history. It records phases and standard connection states, with no signaling payloads. |

The service tests instantiate these factories independently of the page. The
pairing lifecycle tests instantiate the generated progress service and execute
the actual generated auto-pair function, retaining checks that cancellation,
configuration timeout, and channel setup errors settle and clean up.

## Editing rules

Edit the relevant source module and rebuild the page. Keep the two service and
feature scopes distinct: pass collaborators into a factory instead of reaching
into another module's mutable lexical state. Feature modules still share their
original closure, which preserves deliberate function hooks and state observers.
Their remaining coupling is explicit in the domain table and manifest; they are
not presented as independently loadable ES modules.

Markup/CSS belong in `peer.template.html`. The template marker is expanded at
build time; no browser module loader or extra HTTP source route is introduced.
For protocol or identity changes, extend the existing behavior tests rather
than treating a successful build as runtime qualification.
