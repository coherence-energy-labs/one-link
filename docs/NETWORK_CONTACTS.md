# What a default install contacts

One Link has no accounts and no telemetry. A default install still talks to a
small number of computers that are not yours, and to your local network. This
page lists all of them, what each one learns, and how to turn each off.

The default privacy preset is **Just Works**. Everything below describes that
preset. `tests/test_network_contacts_disclosure.py` compares this page with
the preset in the source, so the page cannot quietly fall behind the code.

## Outside your network

| Contact | When | What it learns | Turn it off |
|---|---|---|---|
| `api.github.com` (GitHub Releases for `coherence-energy-labs/one-link`) | Once every 6 hours while the daemon runs | Your public IP address, the time, and the fixed User-Agent `one-link-update-check/0.21`. No device ID, no version, no account. | Privacy panel → update notifications off, or choose the Quiet or Off-grid preset. |
| `stun.nextcloud.com:443` | When a call or a browser-peer link is being set up | Your public IP address and port, and the time. STUN cannot see or relay content. | Choose Quiet or Off-grid, or clear the STUN list in the Privacy panel. |
| `stun.sipgate.net:3478` | Same as above | Same as above | Same as above |
| `stun.antisip.com:3478` | Same as above | Same as above | Same as above |

Nothing else outside your network is contacted by default. In particular the
stock build ships **no rendezvous server and no TURN relay**; those are used
only after you configure one, and then that server learns your IP address,
your device's public key and which public keys you look up.

## On your local network

| Contact | When | What it reveals | Turn it off |
|---|---|---|---|
| mDNS multicast (`_onelink._tcp.local.`) | Continuously while the daemon runs | To every device on the same network: that One Link is running, its listening port, the device's short ID and public key, and, under Just Works only, your chosen display name, a device-kind tag such as `macos-laptop`, and any rendezvous URLs you configured. The operating-system hostname is never announced. | Off-grid stops the announcement. Quiet, or the `mdns_announce_details` setting, keeps discovery working but announces only the short ID and public key. |
| Direct connections to devices found that way | When you send, sync or pair | The peer learns your LAN address. Content is end-to-end encrypted. | Off-grid. |

## The three presets

| | Just Works (default) | Quiet | Off-grid |
|---|---|---|---|
| Update check (GitHub) | on | off | off |
| STUN | 3 community servers | none | none |
| mDNS announcement | on, with details | on, minimal | off |
| Rendezvous / TURN (if you configure one) | allowed | off | off |

## Checking it yourself

The Privacy panel lists recent outbound connections
(`/api/sovereignty/outbound`). To confirm from outside the program, watch the
machine's traffic with any packet capture tool while the daemon runs: with no
rendezvous server configured you should see only the hosts above plus
connections to your own paired devices.
