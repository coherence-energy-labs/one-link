#!/bin/sh
# Map the small set of ONE_LINK_RDZ_* env vars onto rendezvous_server flags.
# Operators who prefer flags can pass them as `docker run` arguments and
# this wrapper passes them through after the env-derived ones (later
# argparse occurrences win).
set -eu
umask 077

case "${ONE_LINK_RDZ_TRUST_PROXY_HEADERS:-false}" in
    1|true|TRUE|yes|YES)
        set -- --trust-proxy-headers "$@"
        ;;
    0|false|FALSE|no|NO)
        ;;
    *)
        echo "FATAL: ONE_LINK_RDZ_TRUST_PROXY_HEADERS must be true or false" >&2
        exit 64
        ;;
esac

case "${ONE_LINK_RDZ_ENABLE_RELAY:-false}" in
    1|true|TRUE|yes|YES)
        set -- --enable-relay "$@"
        ;;
    0|false|FALSE|no|NO)
        ;;
    *)
        echo "FATAL: ONE_LINK_RDZ_ENABLE_RELAY must be true or false" >&2
        exit 64
        ;;
esac

# Pass only the secret's file path on the process command line. The token
# itself stays in the mounted Docker/Kubernetes secret and never appears in a
# URL, argv, compose environment value, or shell expansion output.
if [ -n "${ONE_LINK_RDZ_METRICS_TOKEN_FILE:-}" ]; then
    set -- --metrics-token-file "${ONE_LINK_RDZ_METRICS_TOKEN_FILE}" "$@"
fi

# Environment-derived options precede explicit container command arguments,
# so an operator can still override numeric values with a final CLI flag.
exec /opt/rendezvous-venv/bin/python -m one_link.rendezvous_server \
    --host "${ONE_LINK_RDZ_HOST:-0.0.0.0}" \
    --port "${ONE_LINK_RDZ_PORT:-7118}" \
    --max-registrations "${ONE_LINK_RDZ_MAX_REGISTRATIONS:-20000}" \
    --max-attacker-state-keys "${ONE_LINK_RDZ_MAX_ATTACKER_STATE_KEYS:-20000}" \
    --rate-per-ip-per-min "${ONE_LINK_RDZ_RATE_PER_IP_PER_MIN:-120}" \
    --rate-register-per-pubkey-per-min "${ONE_LINK_RDZ_RATE_REGISTER_PER_PUBKEY_PER_MIN:-30}" \
    --rate-lookup-per-ip-per-min "${ONE_LINK_RDZ_RATE_LOOKUP_PER_IP_PER_MIN:-30}" \
    --rate-new-pubkey-register-per-ip-per-min "${ONE_LINK_RDZ_RATE_NEW_PUBKEY_PER_IP_PER_MIN:-10}" \
    --rate-listener-replace-per-pubkey-per-min "${ONE_LINK_RDZ_RATE_LISTENER_REPLACE_PER_PUBKEY_PER_MIN:-2}" \
    --max-concurrent-connections "${ONE_LINK_RDZ_MAX_CONCURRENT_CONNECTIONS:-64}" \
    --max-concurrent-per-source "${ONE_LINK_RDZ_MAX_CONCURRENT_PER_SOURCE:-16}" \
    --memory-budget-bytes "${ONE_LINK_RDZ_MEMORY_BUDGET_BYTES:-536870912}" \
    --relay-connect-per-ip-per-min "${ONE_LINK_RDZ_RELAY_CONNECT_PER_IP_PER_MIN:-60}" \
    --relay-max-sessions-per-listener "${ONE_LINK_RDZ_RELAY_MAX_SESSIONS_PER_LISTENER:-32}" \
    --relay-max-route-keys "${ONE_LINK_RDZ_RELAY_MAX_ROUTE_KEYS:-4096}" \
    --relay-session-idle-s "${ONE_LINK_RDZ_RELAY_SESSION_IDLE_S:-300}" \
    --relay-forward-timeout-s "${ONE_LINK_RDZ_RELAY_FORWARD_TIMEOUT_S:-30}" \
    --relay-forward-queue-limit-bytes "${ONE_LINK_RDZ_RELAY_QUEUE_LIMIT_BYTES:-4194340}" \
    --relay-forward-queue-max-items "${ONE_LINK_RDZ_RELAY_QUEUE_MAX_ITEMS:-64}" \
    --relay-forward-global-budget-bytes "${ONE_LINK_RDZ_RELAY_GLOBAL_BUDGET_BYTES:-134217728}" \
    --relay-forward-control-reserve-bytes "${ONE_LINK_RDZ_RELAY_CONTROL_RESERVE_BYTES:-4194304}" \
    --log-level "${ONE_LINK_RDZ_LOG_LEVEL:-INFO}" \
    "$@"
