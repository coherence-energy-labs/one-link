# Launch blockers — what's left, and how we solve it ourselves

One Link is for the people. No required hosted accounts. No corporate
gatekeepers. We build everything ourselves. This doc enumerates
what's left before launch and the sovereign-by-design path
through each one — not "go pay a corporation to bless us."

## The corporate-cert temptation, and why we refuse it

The obvious "fix" for SmartScreen / Gatekeeper warnings is to
buy a Windows code-signing certificate ($300-700/yr from
DigiCert / Sectigo / Comodo) and join the Apple Developer
Program ($99/yr) to notarize a macOS binary. We don't do this.

**Why:**
- A corporate CA can revoke our cert under government pressure.
  This has happened to other privacy tools.
- Apple can revoke Developer ID at will. Same with Microsoft.
- Either revocation kills the project's distribution overnight.
- The whole point of One Link is that no one can take it away
  from the people running it. Buying corporate blessing means
  someone can take it away.

**What we do instead:** treat the OS warning as the first
chance to teach the user that this is a deliberate
sovereignty stance, not an oversight.

---

## What's left

### 1. SmartScreen warning UX (Windows)

**Today:** Windows users see "Windows protected your PC" on
first launch. They click `More info → Run anyway` to proceed.
A non-technical user may close the dialog thinking it's malware.

**Our fix (build it ourselves):**

- **Website download page already explains the warning** —
  good. Audit found this is in place.
- **Add a 30-second screenshot walkthrough** of the
  click-through. Visual > text for non-technical users.
- ~~**First-launch in-app banner**~~ **SHIPPED (v0.21.x, verified 2026-08-07).**
  `index.html` carries `install-warning-banner` + its "read more" modal, with
  exactly this framing. It fires once per device (`one_link.install_warning_seen`),
  is dismissable, silently skips when `localStorage` is unavailable, and
  deliberately never competes with the key-rotation banner, which is urgent.
  What remains of this item is the **website** screenshot walkthrough below.
- **`one-link verify-this-install` command** ships as a fail-closed complete
  package inventory. It requires an independently authenticated expected
  rollup for comparison; `--inventory-only` is explicitly non-verifying.
  Artifact authenticity still requires the exact-tag Sigstore bundle path.

We accept the install-rate cost of the warning in exchange for
the property that no corporation can revoke our right to ship.

---

### 2. Gatekeeper warning UX (macOS)

**Today:** macOS users see "cannot be opened because the
developer cannot be verified." They right-click → Open to
proceed. Same friction shape as #1.

**Our fix:** same shape as Windows — better website copy +
in-app post-install confirmation + the verify-this-install
command. We will never buy an Apple Developer membership to
make this go away.

---

### 3. Android — `⚠️ untested` everywhere

**Today:** ROADMAP capability table marks every Android cell
`⚠️ untested`. Nobody has actually tested it.

**Our fix:** test it ourselves. An Android device (or AVD
emulator from android-studio, which is open-source) is the
only requirement. No Google Play account. No Play Store
listing. We distribute via:

- The website's download page (direct APK)
- F-Droid (community-run, sovereign)
- IPFS / Tor mirrors

No corporate distribution gate.

**Action:** 30 minutes on a device or emulator. Walk install
→ pair → message → photo → call. Update the ROADMAP table
with the actual `✅` / `⚠️` / `❌` per cell. Document the
real install path on the website.

---

### 4. Website meta-vs-reality mismatch — ~~P0~~ **RESOLVED (re-audited 2026-08-07)**

> **This is no longer a blocker, and the table below is a historical record.**
> Re-checked against the live site and the published releases rather than against
> this document, because a stale P0 costs attention every time someone reads it.
>
> | 2026-05-25 finding | 2026-08-07 reality |
> |---|---|
> | meta claims "Windows, macOS, Linux, Android, iOS" | no platform overclaim; copy leads on privacy |
> | Schema.org `operatingSystem` lists Android + iOS | `"Windows, macOS, Linux"` |
> | download page says only Windows + Linux ship | no such mismatch on the page |
> | "Last reviewed 2026-05-19" visible mid-page | not present |
>
> **And "macOS" is now TRUE, not aspirational:** `v0.21.0` publishes
> `one-link-macos-arm64.zip` with a Sigstore bundle, beside Linux (x86_64 + arm64)
> and Windows (x86_64 + arm64). The site's claim matches what a user can download.
>
> The site paths in the table are also gone — it was restructured into
> `content/` + `dist/` with six locales (de/es/fr/it/pt + en), which is why a
> find/replace against `/index.html` would have found nothing.
>
> **Only residual, minor:** user-facing copy on the builders and security pages
> still pins "lands v0.22". Accurate today (current release is 0.21.0) but it goes
> stale by itself; "coming in the next release" would not.

**Today (2026-05-25, historical):** Homepage meta description claims "Works on Windows,
macOS, Linux, Android, iOS" but the download page (correctly)
says "Windows + Linux ship today." First-impression damage
for users searching from a Mac.

**Our fix:** edit the website. These are website-repo edits,
not daemon-repo. Audit findings (2026-05-25):

  | File:Line | Current | Suggested |
  |---|---|---|
  | `/index.html` (meta description) | "Works on Windows, macOS, Linux, Android, iOS" | "Works on Windows and Linux today. macOS, Android, iOS coming soon." |
  | `/features/index.html:93–95` | "Voice and video calls" unqualified | Add "(Desktop only today)" |
  | `/features/index.html:98–99` | "Shared folders" unqualified | Add "(Desktop only today)" |
  | `/download/index.html:56` | "Detecting your device..." placeholder visible on load | Pre-detect or show a minimal spinner |
  | `/download/index.html:177, 241` | "ML-DSA-65 pending (lands v0.22)" | "Coming in next release" (no version pin in user copy) |
  | `/features/index.html:167` | "What lands in v0.22" header | "What lands next" |
  | `/features/index.html:186` | "Last reviewed 2026-05-19" visible mid-page | Move to footer, or drop |
  | `/index.html:54` | Schema.org `operatingSystem: "Windows, macOS, Linux, Android, iOS"` | `"Windows, Linux"` (matches reality) |
  | `/roadmap/index.html:250–280` | "Will not build" section uses negative framing | Reframe as "What One Link stays focused on" |

These are find/replace edits against `<repo-root>\Projects\One_link_Website\`. Bounded scope, ~1-2 hours.

---

### 5. Real human cold-install walk on each OS

**Today:** The codebase measures cold-install at 8 seconds
end-to-end. That's daemon-spawn-to-chat-pane. It does NOT
measure "download from website → SmartScreen warning →
click through → see UI → pair phone via QR → send message."
A real human on a fresh machine has never done this.

**Our fix:** us. A clean Windows VM (free; built into Win10/11
Pro via Hyper-V, or VirtualBox is free + open-source) + 30
minutes. Walk the full flow. Notes every place you had to
think, wait, or guess. We iterate until "non-technical
friend can do this without asking."

---

### 6. Crash / error reporting — sovereign, not Sentry

**Today:** Field failures surface only when users click "Copy
error report" + paste into a GitHub issue. High-friction; most
users won't bother.

**Our fix (build it ourselves):**

- **Self-hosted opt-in beacon.** A small endpoint in our own
  daemon-cluster (or a peer-to-peer aggregator — the project
  has CRDT primitives; an "anonymous error CRDT" is the
  sovereign shape). Users explicitly opt in. Sanitized data
  only. We never use Sentry / Datadog / Bugsnag / any
  third-party processor.
- **Until that ships:** the existing "Copy error report"
  button + the GitHub issues link in Settings → About are
  the path.

---

### 7. Localization — community-driven

**Today:** English only.

**Our fix:** community translations. The codebase doesn't ship
with i18n infrastructure yet; first step is to externalize all
user-facing strings into a message catalog (a one-time
refactor of `peer.html` + `index.html` + the server's HTML
templates). After that, native speakers submit translations as
PRs. No paid translation service. No corporate CMS. The
community owns the language coverage.

---

### 8. Accessibility — quick pass done, full audit needs human

**Today:** We did a quick a11y pass this session (icon-only
buttons + input aria-labels + modal a11y attrs + 4 new tests).
A full WCAG-2 audit needs a human with a screen reader.

**Our fix:** us, or a community member who uses a screen
reader daily. Walk every major flow with VoiceOver / NVDA /
Orca. File issues for everything that fails. No paid a11y
consultancy.

---

### 9. Group invite acceptance — **SCOPE WAS UNDERSTATED (re-audited 2026-08-07)**

**What this entry said:** the phone can copy invites but cannot ACCEPT an invite link
directly on the phone — implying the desktop can, and that this is a phone-UI gap of
~1-2 hours.

**What the code actually shows:** *nothing on any surface can redeem a group invite.*
The link is **mint-only**.

- It is generated in two places — `server.py:25168` (desktop API) and `server.py:7996`
  (the phone bridge) — as a signed, offline-verifiable
  `one-link://group-invite/<token>`, and `peer.html` offers a **Copy invite** button.
- `protocol_handler.peer_path_for_deep_link` accepts exactly **one** route,
  `self-mesh/enroll`. `one-link://group-invite/...` raises
  `unsupported one-link route: group-invite/...`.
- Nothing anywhere decodes that token, verifies its `signature_hex`, checks
  `expires_ms`, or turns it into a join request. `grep` for `one_link_group_invite`
  returns two hits, both minting it.

So a user can copy an invite and send it, and the person who receives it has no path
that consumes it — on the phone **or** the desktop.

**Why this is bigger than "~1-2 hours of UI".** The mint deliberately does not grant
membership: *"the token lets a paired device prove which group it is asking to join. A
group admin still signs the ADD_MEMBER event, preserving the group authority model
instead of turning links into ambient access."* Redemption therefore needs a
**join-request protocol** — verify the issuer's signature and expiry, present the group
to the invitee, carry a request to an admin, and have the admin sign `ADD_MEMBER` — and
that touches the group authority model directly. Building it hastily is how a link
becomes ambient access, which is the exact thing the design refuses.

**Our fix:** still code, and still ours — but scoped as a protocol increment with its
own threat review, not a button on a phone screen.

#### Landed 2026-08-07 — the verification half

`src/one_link/group_invite.py` is the consumer that never existed, and the deep-link
handler now accepts the URL the app has been minting all along:

- `verify_group_invite(token)` → `VerifiedInvite` **or raises**. There is deliberately no
  "probably fine" return value for a UI to render optimistically.
- **The binding that matters:** a signature made with the key named *inside* the token
  proves only that the token is self-consistent — anyone can mint that. The fingerprint
  is recomputed from the public key and required to match, which is what stops an
  attacker presenting a trusted contact's fingerprint over their own key. **Calibrated:**
  with that one check removed, the forged invite verifies clean and exactly one test
  catches it.
- Also refused: edited payloads, smuggled fields, expired invites, invites issued in the
  future (a clock wrong enough to fake `issued_ms` can fake `expires_ms`), wrong token
  types, future versions, bad key lengths, oversized tokens, and `True` where an integer
  belongs. 20 tests, written forgery-first.
- `one-link://group-invite/<token>` now routes to `/peer?group_invite=…` instead of
  `unsupported one-link route`.

#### What is still missing — the authority half

Verification produces an **introduction**, not membership, and must never be made to
produce membership. Still to build:

1. a **join-request** carried from the invitee to a group admin,
2. the admin's approve/decline surface, signing the existing `ADD_MEMBER` event,
3. the invitee-facing screen that shows the verified group, issuer and expiry.

**Do not read the Copy invite button — or `verify_group_invite` — as evidence a person
can join a group from a link yet.** The token is now trustworthy; nothing yet acts on it.

---

## What this list is NOT

It is not a list of "things you need to pay for." Every item
above is solvable with code, infrastructure we already control,
or our own time. Friction is acceptable. Corporate dependency
is not.

If a future contributor proposes "let's just buy a code-signing
cert / Apple Developer membership / Sentry account to make this
easier," the answer is no, and the reason is in
`docs/GOVERNANCE.md`: the structure that keeps One Link free of
corporate capture is the same structure that keeps users free.
We don't shortcut around it for our own convenience.

---

## Recommended next-action order

1. **Edit the website** (#4) — ~2 hours, biggest visible
   impression-cost win. Bounded, you already own the repo.
2. **Walk Windows cold-install on a fresh box** (#5) — ~30
   minutes, surfaces real bugs nothing else will.
3. **Test on an Android device or emulator** (#3) — ~30
   minutes, updates the capability table with truth.
4. **Walk macOS cold-install** (#5 again) — your call whether
   to fix observed bugs before or after Android.
5. **Soft launch** — 10-20 friends/family, week of bug
   intake, fix, broaden.
6. **#1 + #2 (SmartScreen / Gatekeeper UX polish)** —
   sequence into website work as you learn what real users
   ask about.
7. **#7 (localization)** + **#8 (full a11y)** + **#9 (phone
   group invite)** — post-soft-launch, prioritize by what
   users actually request.

The point is to ship, hear from users, iterate. Not to wait
for a fictional "everything perfect" state that corporations
sell you via paid blessings.
