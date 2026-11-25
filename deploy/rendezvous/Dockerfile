# One Link rendezvous container.
#
# Supply-chain boundary:
#   * every external image is immutable by OCI index digest;
#   * the rendezvous-only Python dependency closure is exact and hash-locked;
#   * source builds are forbidden, so a missing audited wheel fails the build;
#   * the final image contains neither uv/pip nor the desktop application's
#     unrelated dependency and source surface.

# uv 0.13.10. The tag documents the version; the digest is authoritative and
# preserves the multi-architecture index (linux/amd64 + linux/arm64 included).
FROM ghcr.io/astral-sh/uv:0.13.10@sha256:a3ea1357342c1a4bf9a0c53a3deb1b55379aefa037338d8113d5771efa01774f AS uv-bin

# CPython 3.12.14 on Debian bookworm-slim, official multi-architecture index.
FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS dependencies

COPY --from=uv-bin /uv /usr/local/bin/uv
COPY deploy/rendezvous/requirements.lock /tmp/requirements.lock

# A no-seed virtual environment avoids shipping pip/setuptools/wheel. uv checks
# every selected wheel against requirements.lock and refuses sdists/builds.
RUN uv venv \
      --no-project \
      --no-python-downloads \
      --python /usr/local/bin/python \
      /opt/rendezvous-venv \
 && uv pip install \
      --python /opt/rendezvous-venv/bin/python \
      --require-hashes \
      --no-build \
      --no-cache \
      --no-deps \
      --requirement /tmp/requirements.lock \
 && /opt/rendezvous-venv/bin/python -c \
      "import aiohttp, cryptography; print(aiohttp.__version__, cryptography.__version__)"


FROM python:3.12.14-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e AS runtime

ARG ONE_LINK_VERSION=0.22.1
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="One Link rendezvous" \
      org.opencontainers.image.description="Self-hosted One Link presence rendezvous" \
      org.opencontainers.image.source="https://github.com/coherence-energy-labs/one-link" \
      org.opencontainers.image.version="${ONE_LINK_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"

RUN groupadd --system --gid 10001 onelink \
 && useradd --system --uid 10001 --gid 10001 \
      --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin onelink

COPY --from=dependencies /opt/rendezvous-venv /opt/rendezvous-venv

# Copy only the import closure used by rendezvous_server. Adding an import to
# that server without updating this allowlist makes the image fail immediately
# instead of silently growing to the full desktop package.
COPY src/one_link/__init__.py \
     src/one_link/rdz_blind.py \
     src/one_link/relay_proto.py \
     src/one_link/relay_routing.py \
     src/one_link/rendezvous_proto.py \
     src/one_link/rendezvous_server.py \
     /opt/one-link/one_link/
COPY --chmod=0555 deploy/rendezvous/entrypoint.sh /usr/local/bin/one-link-rendezvous

ENV HOME=/nonexistent \
    PATH=/opt/rendezvous-venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/opt/one-link \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ONE_LINK_RDZ_HOST=0.0.0.0 \
    ONE_LINK_RDZ_PORT=7118 \
    ONE_LINK_RDZ_LOG_LEVEL=INFO \
    ONE_LINK_RDZ_MAX_REGISTRATIONS=20000 \
    ONE_LINK_RDZ_MAX_ATTACKER_STATE_KEYS=20000 \
    ONE_LINK_RDZ_RATE_PER_IP_PER_MIN=120 \
    ONE_LINK_RDZ_RATE_REGISTER_PER_PUBKEY_PER_MIN=30 \
    ONE_LINK_RDZ_RATE_LOOKUP_PER_IP_PER_MIN=30 \
    ONE_LINK_RDZ_RATE_NEW_PUBKEY_PER_IP_PER_MIN=10 \
    ONE_LINK_RDZ_RATE_LISTENER_REPLACE_PER_PUBKEY_PER_MIN=2 \
    ONE_LINK_RDZ_MAX_CONCURRENT_CONNECTIONS=64 \
    ONE_LINK_RDZ_MEMORY_BUDGET_BYTES=536870912 \
    ONE_LINK_RDZ_TRUST_PROXY_HEADERS=false \
    ONE_LINK_RDZ_METRICS_TOKEN_FILE= \
    ONE_LINK_RDZ_ENABLE_RELAY=false \
    ONE_LINK_RDZ_RELAY_CONNECT_PER_IP_PER_MIN=60 \
    ONE_LINK_RDZ_RELAY_MAX_SESSIONS_PER_LISTENER=32 \
    ONE_LINK_RDZ_RELAY_MAX_ROUTE_KEYS=4096 \
    ONE_LINK_RDZ_RELAY_SESSION_IDLE_S=300 \
    ONE_LINK_RDZ_RELAY_FORWARD_TIMEOUT_S=30 \
    ONE_LINK_RDZ_RELAY_QUEUE_LIMIT_BYTES=4194340 \
    ONE_LINK_RDZ_RELAY_QUEUE_MAX_ITEMS=64 \
    ONE_LINK_RDZ_RELAY_GLOBAL_BUDGET_BYTES=134217728 \
    ONE_LINK_RDZ_RELAY_CONTROL_RESERVE_BYTES=4194304

WORKDIR /opt/one-link
USER 10001:10001
EXPOSE 7118/tcp
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/one-link-rendezvous"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; r=urllib.request.urlopen('http://127.0.0.1:7118/health',timeout=2); sys.exit(0 if r.status == 200 else 1)"]
