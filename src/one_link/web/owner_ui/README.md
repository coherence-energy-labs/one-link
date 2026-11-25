# Owner browser source architecture

The shipped owner page is `../index.html`. It is generated from the markup/CSS
template and the JavaScript modules in this directory. Edit the canonical
sources, then commit both those sources and the generated page:

```sh
python scripts/build_owner_ui.py
python scripts/build_owner_ui.py --check
python -m pytest -q tests/test_owner_ui_build.py
node --test tests/js/test_owner_ui_services.cjs
```

Run commands from the repository root. The builder uses only Python's standard
library. It does not fetch packages, transpile JavaScript, or add a runtime
loader. Browsers and frozen distributions continue to receive the complete
offline HTML page. Existing HTML readers and executable JavaScript tests use
that actual shipped artifact.

## Ownership and composition

`manifest.json` is the ordered ownership map. Every JavaScript source has a
named responsibility and belongs to one of two lifecycle groups:

| Source area | Responsibility and collaborators |
| --- | --- |
| `main/state.js` and `services/owner_state.js` | Construct the owner page's mutable state. Feature modules consume that same page instance. |
| `main/session.js`, `main/api_errors.js`, `main/api.js`, `services/api_client.js` | Session lifecycle and server-error presentation stay in the owner feature layer. The injected HTTP service owns concurrent GET requests and immutable file-upload intent caches. |
| `main/messages.js`, `main/message_actions.js`, `main/rich_text_files.js`, `main/previews.js` | Message rendering, user actions, and typed file presentation. Rendering uses shared formatting helpers and current owner state. |
| `main/transfer_facts.js`, `main/transfers.js`, `main/transfer_header.js`, `main/file_offers.js` | Transfer status, progress, prompts, and reconciliation. The daemon remains the source of transfer truth; sending uses the API service. |
| `main/composer_staging.js`, `main/composer_send.js`, `main/upload_paste.js`, `main/attachments.js`, `main/voice.js`, `main/outbox.js` | Capture a user's send intent, preserve its target and retry identity, and reconcile its result. These modules share the owner state and API service. |
| `main/discovery.js`, `main/pairing.js`, `main/onboarding*.js`, `main/recovery_*.js` | Pairing/setup and the separate recovery workflows. Each workflow keeps its handlers and presentation together. |
| `main/settings_*.js`, `main/device_drawer.js`, `main/device_mesh.js` | Settings, per-device controls, and personal device views. |
| `main/bootstrap.js`, `main/live_refresh.js`, `main/events.js`, `main/lifecycle.js` | Startup snapshots, WebSocket reconciliation, reconnect/update lifecycle, and page-level handlers. |
| `calls/state.js`, `calls/capture.js`, `calls/cleanup.js` | Call state, browser media resources, and their cleanup. Media/call state are distinct injected objects. |
| `calls/ice.js`, `calls/negotiation.js`, `calls/remote_signaling.js`, `calls/recovery.js` | RTC setup, offer/answer roles, remote signaling, and backend-directed recovery. |
| `calls/health.js`, `services/call_health.js`, `calls/telemetry.js` | Health classification and adaptation decisions are isolated from the DOM and signaling. Telemetry supplies observations; injected callbacks apply presentation/capture changes. |
| `calls/surfaces.js`, `calls/presentation.js`, `calls/buttons.js`, `calls/events.js`, `calls/polling.js` | Call surfaces, actions, event reconciliation, and lifecycle-aware backfill. |

The manifest describes the remaining, smaller domains individually. Module
boundaries are whole functions, state declarations, and feature event bindings;
they are not generated slices chosen by a line-count threshold. The source
files are canonical and can be edited directly. No extraction step from the
generated page is needed or supported.

### Isolated services

The builder defines service factories in an **outer private scope**, then runs
the owner or call feature closure inside it. This is a real lexical boundary:
a service cannot capture variables declared inside the feature closure. It
receives collaborators through parameters and returns its interface. Neither
factory names nor new mutable state leak into `window`.

| Factory | Inputs | Returned interface and owned state |
| --- | --- | --- |
| `createOwnerState()` | None | A fresh owner-state object, including fresh maps, arrays, and pairing state. |
| `createOwnerFormatting({ document, getSettings })` | DOM access and a live settings accessor | DOM/text formatting functions. The accessor keeps timestamp settings current after edits. |
| `createOwnerApiClient(...)` | Fetch, constructors/timers, session-error callback, error translator, and intent-ID generator | Existing `api` methods. Its in-flight GET map and per-file intent WeakMap are private to that client. |
| `createCallState()` | None | A fresh call lifecycle, signaling, and telemetry state object. |
| `createCallMediaState()` | None | A fresh media/route state object. Capture and cleanup features own resource lifetime. |
| `createCallHealth(...)` | Call/media state, capture profile functions, and presentation/event callbacks | Health classification, quality hysteresis, selected-candidate extraction, and adaptive video functions. |

Platform primitives such as `Map`, `Date`, `Math`, and `Promise` retain their
normal JavaScript meaning. Services do not require the owner page to run. The
Node tests instantiate them in independent VM contexts with explicit inputs
and exercise lost-response retries, concurrency, cleanup callbacks, independent
state instances, and call health/adaptation.

### Feature lifecycle and remaining coupling

Feature files within `main/` still share the owner closure; feature files within
`calls/` still share the call closure. Their manifest order preserves existing
initialization and event registration order. Existing public `window` bridges
between the two lifecycles remain in their original features. This is an
incremental modular architecture, not a claim that every feature is already an
independent ES module.

For further isolation, move a coherent behavior into a service factory, give
it explicit collaborators, and add an independent runtime contract before
changing feature bindings. Do not copy state into services: pass the owning
instance so observers see current values. Avoid new implicit cross-feature
mutable variables. Keep state initialization, async ownership, and resource
cleanup in the relevant domain; the explicit service boundaries show the
preferred direction.

## Generated artifact contract

The builder rejects duplicate paths, unregistered or missing JavaScript files,
invalid/missing factory declarations, missing template markers, and removal of
the build-fingerprint declaration. Every generated module is labeled with its
canonical path. There are no timestamps, host paths, or random values in the
output. `--check` returns nonzero when the committed artifact is stale and never
rewrites it.

Keep `PAGE_SOURCE_FINGERPRINT`'s placeholder in `main/version.js`. Runtime build
identity continues to fingerprint the generated `web/index.html`; it therefore
covers all shipped browser code without a new `build_identity.py` file list or
runtime source discovery. Any canonical edit must be rebuilt before packaging.

Markup and CSS belong in `index.template.html`. The two script markers are
build-time insertion points, not browser requests. The call script remains
after its existing call-surface markup. Peer browser assets and server routes
are separate responsibilities and are not rewritten by this builder.
