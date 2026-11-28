# Operating a One Link Rendezvous

A One Link rendezvous is a small server that lets paired devices on
different networks find each other. It never receives plaintext or end-to-end
keys. It holds signed presence beacons and, when encrypted relay is enabled,
forwards opaque ciphertext while observing its sizes and timing.

> **Distribution status:** One Link does not currently publish a verified
> rendezvous container image. Do not pull `onelink/rendezvous:latest` or treat
> any similarly named registry image as project-authenticated. Check out a
> reviewed source commit and use `deploy/rendezvous/docker-compose.yml`; its
> external images, Python closure, and hashes are pinned and it builds locally.

---

## What it does, what it doesn't

**Does:**
- Holds, in memory, a small signed record per pubkey:
  `(pubkey, observed_public_IP, advertised_endpoints[], capabilities)`.
- Replies to lookups: "where is `pubkey X`?"
- Bounded resources: hard caps on registrations and each attacker-keyed map
  (20,000 each by default), plus finite request, connection, and relay-memory
  ceilings validated against the declared process memory budget at startup.
- Periodically evicts expired entries.
- All registers and revokes are Ed25519-signed by the device. The
  rendezvous cannot forge those device signatures or complete the separately
  authenticated peer handshake because it doesn't hold device private keys.

**Does NOT:**
- See chat or file plaintext. With relay enabled it forwards encrypted payload
  bytes, but end-to-end encryption keys stay between the paired devices.
- Persist anything to disk. A restart loses all current presence
  registrations — devices re-register within a few minutes.
- Authenticate operators or users. The protocol is symmetric. Trust
  comes from the cryptographic signatures, not the operator.

**Threat model summary:**
- A malicious or compromised rendezvous can:
  - Drop or refuse to forward presence (DoS — users notice immediately)
  - Lie about who is registered (clients verify nothing about lookup
    responses except shape; bad data just causes failed dial attempts)
  - Observe public-IP and availability metadata for registrations. Blinded
    lookup tokens reduce raw-pubkey exposure on the v2 lookup request, but do
    not make the service metadata-anonymous.
  - Observe both relay sockets, timing, byte counts, and rotating route-tag
    activity. Production v2 routing carries neither endpoint identity public
    key, and its bounded sealed first flights hide the channel HELLO/REPLY
    identities as well. The explicit v1 migration route exposes the destination
    public key and raw channel identities. Tag rotation is not unlinkability:
    the persistent listener socket and refresh sets remain correlatable by that
    relay, and route-set cardinality reveals an approximate paired-peer count.
    Because the same service also accepts signed presence, its operator can
    attempt to associate relay sockets with presence identities by IP address
    and timing even though the identity key is absent from v2 relay frames.
    Recorded sealed first flights can be opened after a later compromise of
    the recipient identity seed; this layer does not provide metadata forward
    secrecy against endpoint-key compromise.
    Neither mode resists traffic analysis by that relay.
- A malicious or compromised rendezvous **cannot**:
  - Read relay plaintext: relayed payload is end-to-end encrypted and the
    rendezvous never receives the decryption keys
  - Impersonate a device (no private keys)
  - Forge registrations under someone else's pubkey (signature check)
  - Complete an authenticated peer channel as another paired device. It can
    still replay otherwise-valid control data inside accepted protocol windows
    or redirect/drop lookup results; clients must retain channel authentication.

---

## Hardware requirements

The shipped 512 MiB profile caps registrations and each attacker-controlled
rate/nonce/replay map at 20,000 keys, concurrent handlers at 64, and the
pairwise relay routing table at 4,096 rotating tags; the optional relay payload
budget is 128 MiB. Each tag is charged as four Python container entries (global
route, listener set, epoch-auth key, and expiry). A hostile-state probe at the former
50,000-key shape increased RSS by 433,811,456 bytes before relay payloads or
meaningful connection load, so the old 200,000-registration default was not a
safe 512 MiB contract. Treat the new defaults as memory-safety ceilings, not
capacity SLOs:

The 64-handler ceiling is intentional: each handler's envelope includes one
maximum relay frame plus parser/task overhead, because aiohttp materializes a
WebSocket message before the application can acquire its relay-memory lease.

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 512 MB starting point | workload-tested value |
| CPU | 1 vCPU | 1 vCPU |
| Disk | image + bounded engine logs | operator retention policy |
| Bandwidth | workload-dependent | measured peak + headroom |

Compose enforces 1 CPU, 512 MiB RAM, 128 PIDs, and 65,536 file descriptors. It
also declares exactly 536,870,912 bytes to the server; startup fails closed if
the configured state, concurrency, and relay ceilings exceed that envelope.
Its 120-second stop grace period covers the relay's bounded, ordered connector
and listener teardown path before the runtime escalates to a forced kill.
Measure your endpoint mix, request rate, reverse proxy, and log driver under
failure/abuse before operating a public instance.
Per-source abuse quotas key IPv4 individually and aggregate native IPv6 by /64
so rotating interface identifiers cannot reset the quota or churn its key map;
the presence record still retains the full observed IPv6 endpoint. At the map
ceiling, unknown identities fail closed until inactive buckets expire; they do
not evict and reset an existing client's live quota.

---

## Deployment

### Option 1 — Docker (recommended)

`docker-compose.yml` ships in the repo at `deploy/rendezvous/`. It deliberately
omits `image:` so Compose builds reviewed local source rather than pulling a
mutable or unauthenticated registry name:

Use Docker Engine 28.3.3 or newer. Docker documents that versions older than
28.0.0 could expose localhost-published ports to peers on the same L2 network;
28.3.3 also fixed a firewalld-reload regression that re-exposed loopback
bindings. Host-local processes remain inside this topology's trust boundary.

```yaml
services:
  rendezvous:
    build:
      context: ../..
      dockerfile: deploy/rendezvous/Dockerfile
    restart: unless-stopped
    ports:
      - "127.0.0.1:7118:7118"
    environment:
      ONE_LINK_RDZ_HOST: "0.0.0.0"
      ONE_LINK_RDZ_PORT: "7118"
      ONE_LINK_RDZ_LOG_LEVEL: "INFO"
      ONE_LINK_RDZ_MAX_REGISTRATIONS: "20000"
      ONE_LINK_RDZ_MAX_ATTACKER_STATE_KEYS: "20000"
      ONE_LINK_RDZ_MAX_CONCURRENT_CONNECTIONS: "64"
      ONE_LINK_RDZ_MAX_CONCURRENT_PER_SOURCE: "16"
      ONE_LINK_RDZ_MEMORY_BUDGET_BYTES: "536870912"
```

Run:

```bash
# First check out the exact full commit SHA you reviewed.
cd deploy/rendezvous
ONE_LINK_VCS_REF="$(git rev-parse HEAD)" docker compose up -d --build
```

Logs:

```bash
docker compose logs -f rendezvous
```

### Option 2 — systemd (source deployment)

No verified PyPI production distribution is currently claimed. Build/install
from a reviewed checkout and a locked environment, then point `ExecStart` at
that environment; do not substitute an unverified `pip install one_link`.

```ini
# /etc/systemd/system/one-link-rendezvous.service
[Unit]
Description=One Link rendezvous
After=network.target

[Service]
Type=simple
User=onelink
Group=onelink
Environment=HOME=/nonexistent
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/opt/one-link/.venv/bin/python -m one_link.rendezvous_server \
    --host 127.0.0.1 --port 7118 --trust-proxy-headers \
    --memory-budget-bytes 536870912
Restart=always
RestartSec=2
TimeoutStopSec=120s
MemoryMax=512M
TasksMax=128
LimitNOFILE=65536
CPUQuota=100%
UMask=0077
# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin onelink
# From the reviewed repository checkout (example path /opt/one-link):
cd /opt/one-link
uv sync --frozen --no-dev
sudo systemctl daemon-reload
sudo systemctl enable --now one-link-rendezvous
```

### Option 3 — bare metal development run

```bash
uv sync --frozen --no-dev
uv run --frozen python -m one_link.rendezvous_server \
    --host 127.0.0.1 --port 7118
```

Use a process manager (supervisord, runit, pm2, …) to keep it up.

---

## TLS

**Always front the rendezvous with HTTPS.** Registration and revocation
authenticity is signature-checked, while TLS protects lookup/presence metadata
from passive network observers. A TLS endpoint necessarily sees the requests
it terminates; it does not receive One Link chat/file plaintext because that
traffic is outside the rendezvous protocol.

### nginx + Let's Encrypt

Use `deploy/rendezvous/nginx.conf.example` as the single reviewed vhost source;
do not copy an abbreviated proxy block from an old runbook. It preserves POST
with a literal-host 308 redirect, overwrites forwarding identity, strips
untrusted `Forwarded`/cookie metadata and upstream cookie/runtime headers,
separates WebSocket upgrades from ordinary HTTP, uses bounded per-source nginx
request/connection zones, disables secret-bearing access logs on both vhosts,
limits the non-redactable nginx error log to emergency process events, sends
no-store/security headers, keeps `/metrics` private, and gives the server's
30-second relay heartbeat a 75-second proxy window. The backend also disables
aiohttp's raw-request-target access logger.

The signed register/revoke and public lookup routes deliberately provide
credential-free CORS for browser peers. Preflights accept only their exact
methods and `Content-Type`; they are rate-limited. Metrics receives no CORS
permission, and relay WebSocket upgrades reject browser `Origin` headers.

The example references the final Let's Encrypt certificate paths, so provision
the certificate before enabling that TLS vhost (for example with Certbot's
standalone or webroot flow), replace every `rendezvous.example.com`, install the
file, then require `nginx -t` to pass before reload.

The standalone issuance example is only the initial certificate step while
port 80 is free; it does not establish unattended renewal after nginx starts.
Configure a DNS/webroot renewal method or explicit safe nginx service hooks for
your environment and require `certbot renew --dry-run` to pass.

### Cloudflare (alternative)

DNS-only Cloudflare records work with the shipped nginx baseline. Do not simply
enable orange-cloud proxying: nginx then sees Cloudflare edge addresses,
collapsing per-client rate limits and publishing the wrong observed address.
For orange-cloud operation, configure nginx's real-IP module using Cloudflare's
maintained IP ranges, restrict the origin firewall to those ranges, and only
then forward `$remote_addr`; use **Full (strict)** TLS. Never trust
`CF-Connecting-IP` from an origin that arbitrary clients can reach directly.

The rendezvous reads `X-Forwarded-For` only when
`--trust-proxy-headers`/`ONE_LINK_RDZ_TRUST_PROXY_HEADERS=true` is explicitly
enabled. The compose baseline enables it safely because port 7118 is published
on host-loopback for the directly connected proxy. Disable it for any directly
client-accessible listener so callers cannot spoof rate-limit identities.

---

## Verifying the deployment

### Health check

```bash
curl -sS https://rendezvous.example.com/health
# {"ok": true}
```

### Metrics

The shipped nginx vhost does **not** publish `/metrics`. Keep the collector on
the host/backend network and pass a high-entropy Bearer secret through a
mounted file, not a query string, command argument, or compose environment
value:

```bash
sudo install -d -m 700 /etc/one-link
openssl rand -hex 32 | sudo tee /etc/one-link/metrics-token >/dev/null
sudo chmod 600 /etc/one-link/metrics-token

# Add to the rendezvous process/container configuration:
# --metrics-token-file /etc/one-link/metrics-token
TOKEN="$(sudo cat /etc/one-link/metrics-token)"
curl -fsS -H "Authorization: Bearer ${TOKEN}" \
  http://127.0.0.1:7118/metrics
unset TOKEN
# {
#   "registers_total": 1234,
#   "lookups_total": 5678,
#   "lookup_misses_total": 12,
#   "rate_limit_rejects_total": 0,
#   ...
# }
```

Hook the private endpoint into Prometheus / Grafana / your monitoring of choice
— it returns JSON keys, not Prometheus exposition. If an operator deliberately
removes nginx's exact-match deny, the backend requires the token from every
effective non-loopback client. Under `--trust-proxy-headers`, a missing or
malformed `X-Forwarded-For` identity fails closed instead of inheriting the
proxy's loopback address.

### From a One Link client

In the One Link UI: **Settings → Connect across networks**, paste:

```
https://rendezvous.example.com
```

The status dot turns green and the panel shows your observed public
IP. If you're behind NAT, this is the IP your devices announce to
each other.

---

## Tuning for scale

The default registration ceiling and every attacker-keyed map ceiling are
20,000. Tune them as one memory envelope only after representative load, churn,
expiry-sweep, relay, and hostile distinct-key testing. The measured former
50,000-key state alone increased RSS by 433,811,456 bytes:

```bash
python -m one_link.rendezvous_server \
    --host 0.0.0.0 \
    --port 7118 \
    --max-registrations 40000 \
    --max-attacker-state-keys 40000 \
    --max-concurrent-connections 256 \
    --memory-budget-bytes 1073741824 \
    --rate-per-ip-per-min 600 \
    --rate-register-per-pubkey-per-min 60
```

That example declares a 1 GiB process envelope and is not valid under the
shipped 512 MiB container limit. Raise the external container or service limit
to at least the same value, repeat the hostile-state RSS probe, and leave room
for the configured relay payload budget, WebSocket/parser buffers, Python
baseline, and transient cryptographic work. The startup estimator is a
fail-closed floor derived from the measured hostile state with allocator
headroom, not a throughput guarantee or substitute for workload testing.

`--max-concurrent-connections` is a memory bound, and every relay listener
holds one slot for as long as its WebSocket is open, so it is also the number
of devices one process can serve at a time. `--max-concurrent-per-source`
(default 16) keeps one source address, or one IPv6 /64, from holding more than
its share; a request over that share is answered 429 while the server still
has room for everyone else. A household or office behind one NAT address
counts as one source: raise the per-source value if you expect more than 16
devices behind a single address. Behind a reverse proxy, pass
`--trust-proxy-headers`, otherwise every client appears to come from the
proxy and they all share one source's limits.

Do not place independent in-memory rendezvous processes behind an ordinary
load balancer: a registration and a later lookup can land on different state.
No shared-registry protocol is implemented. Scale/federate by publishing
multiple independent rendezvous URLs so clients register with and race each
one, or first implement and verify shared state plus globally coherent limits.

---

## Federation

Devices can register with multiple rendezvous in parallel, and
lookups race all configured rendezvous, returning the first hit. To
provide redundancy:

1. Run two or more rendezvous instances at independent operators.
2. Have your users add both URLs to **Settings → Connect across
   networks** (one per line).
3. Both will receive registrations; either can satisfy lookups.

There is no protocol-level sync between instances — by design.
Eventual consistency happens through clients re-registering on
their refresh schedule (every TTL/2, default 150 s).

---

## Privacy posture

The rendezvous learns:
- Which pubkeys are online and their public IPs (the metadata that
  TLS hides from network observers but the rendezvous itself sees).
- Lookup identifiers/tokens plus network and timing metadata. Blinded-token
  lookup reduces raw identifier disclosure but is not an anonymity proof.
- For v2 relay traffic: both socket addresses, timing, byte counts, and
  rotating pairwise-tag activity, but not either identity public key in the
  relay path or control frames. Enabling the explicit legacy migration route
  discloses the destination public key to the relay.
- Approximate device geo from IP (whatever IP geolocation lookup
  reveals).

The rendezvous does NOT learn:
- Anything about message content
- Anything about file content
- Group membership (groups are an end-to-end primitive on top of the
  rendezvous, not a rendezvous-side feature)

To minimize what the rendezvous sees:
- A Tor/onion deployment is not claimed by this runbook: it requires a tested
  client transport path and DNS/proxy-leak review that are not proven here.
- Self-host. Operating your own rendezvous means you trust nobody
  outside your house with this metadata.

---

## Incident response

If your rendezvous gets compromised:

1. **Rotate the host.** Bring up a new one at a different IP / domain.
2. **Tell your users to update their rendezvous URL.** They need a
   trusted out-of-band channel for this — exactly the same channel
   they use to bootstrap pairing.
3. **Don't worry about message confidentiality.** A compromised
   rendezvous can't decrypt anything. The cost of compromise is
   metadata + uptime.

A compromised rendezvous cannot complete an authenticated One Link channel as
a client because it doesn't hold that client's private keys. It can still
observe metadata, deny service, replay accepted control data inside protocol
windows, or direct lookup dials at the wrong public IP; the last case fails
peer authentication because the One Link channel verifies the peer's pubkey at
handshake.

---

## Why does this exist?

Most modern messaging apps need a centralized rendezvous service
operated by the app vendor — Signal, WhatsApp, iMessage — and you
have to trust that vendor's metadata posture. One Link's rendezvous
is the same architectural primitive but the operator can be:

- The user's home server.
- A friend's machine.
- A community-run instance.
- A commercial provider you choose.
- Any combination of the above.

There is no "official" rendezvous you must use. The protocol is
public, and operators can choose their own infrastructure. Cost, capacity, and
metadata exposure remain workload- and deployment-specific and must be
measured by each operator.
