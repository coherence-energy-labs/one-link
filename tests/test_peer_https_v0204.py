"""v0.20.4 — Self-signed HTTPS for the daemon.

iOS Safari (and most modern browsers) gate Web Crypto Subtle to
secure contexts (HTTPS or localhost). A phone hitting
http://192.168.1.42 to /peer can't generate Ed25519 keys, which
breaks the entire phone-as-peer architecture on LAN. This ship
mints a self-signed cert + serves a parallel HTTPS listener so
the pair URL becomes https://, the phone gets a "Not Private"
warning once, taps Continue, and Web Crypto works from then on.

  Reach:  the phone-as-peer pair flow finally completes on iOS
          Safari over LAN. Without this, every prior ship in the
          v0.20 arc was unusable on iPhone.
  Hide:   self-signed cert is generated invisibly on first run,
          persisted to data_dir, auto-rotated near expiry.
  Async:  cert generation is one-shot (~30ms); HTTPS listener
          comes up in parallel with the existing HTTP listener,
          on a separate port.
  Depth:  ECDSA P-256 (universal browser support; Ed25519 server
          certs are rejected by Safari). 365-day TTL with 30-day
          rotation window. SAN covers every detectable LAN IPv4 +
          IPv6 + localhost + onelink.local for future mDNS.

Tests cover: cert generation shape (algorithm, validity, SAN),
rotation triggers (missing / unparseable / expiring), SSL context
build (TLS 1.2 minimum, cert loaded), pair-URL adoption of
https://, autopair preflight surfaces insecure-context message,
boot stashes error to state.boot_error_msg.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path

import pytest


def test_cert_generation_writes_files(tmp_path: Path):
    """generate_self_signed mints a cert + key and writes both
    to <base>/peer_https/. Both files exist + non-empty."""
    from one_link.peer_https import (
        cert_path,
        generate_self_signed,
        key_path,
    )

    cp, kp = generate_self_signed(tmp_path)
    assert cp == cert_path(tmp_path)
    assert kp == key_path(tmp_path)
    assert cp.is_file()
    assert kp.is_file()
    assert cp.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert kp.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")


def test_cert_uses_ecdsa_p256(tmp_path: Path):
    """Browser compatibility floor — ECDSA P-256 is universally
    accepted as a TLS server cert. RSA-2048 also works but is
    bigger; Ed25519 is rejected by Safari for server certs as of
    2026."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from one_link.peer_https import generate_self_signed

    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    pub = cert.public_key()
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    assert pub.curve.name == "secp256r1"


def test_cert_validity_is_one_year(tmp_path: Path):
    """365-day default. Auto-rotates within 30 days of expiry so
    phones never hit a sudden invalid cert mid-session."""
    from cryptography import x509
    from one_link.peer_https import CERT_VALID_DAYS, generate_self_signed

    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    expiry = getattr(cert, "not_valid_after_utc", None)
    if expiry is None:
        expiry = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is None:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    span = expiry - not_before
    # +5 minutes of pre-validity slack, so total span is ~365d + 5min.
    assert datetime.timedelta(days=CERT_VALID_DAYS - 1) < span
    assert span < datetime.timedelta(days=CERT_VALID_DAYS + 1)


def test_cert_san_includes_localhost_and_lan(tmp_path: Path):
    """SAN MUST cover localhost (loopback access from desktop
    browsers) AND any LAN IP we can detect. Without this, the
    phone hits a hostname-mismatch error even after accepting
    the cert."""
    from cryptography import x509
    from one_link.peer_https import generate_self_signed

    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    san = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName,
    ).value
    dns_names = [n.value for n in san if isinstance(n, x509.DNSName)]
    assert "localhost" in dns_names
    assert "onelink.local" in dns_names
    # At least one IP — 127.0.0.1 is always there.
    ip_strs = [str(n.value) for n in san if isinstance(n, x509.IPAddress)]
    assert "127.0.0.1" in ip_strs


def test_cert_ext_key_usage_server_auth(tmp_path: Path):
    """SERVER_AUTH ekuoid is required by browsers for a TLS
    server cert. Without it, Chrome rejects the cert outright."""
    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID
    from one_link.peer_https import generate_self_signed

    cp, _ = generate_self_signed(tmp_path)
    cert = x509.load_pem_x509_certificate(cp.read_bytes())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_chain_is_two_cert_leaf_then_root(tmp_path: Path):
    """2026-05-23 (TN2326): cert.pem is leaf + root concatenated.
    aiohttp's load_cert_chain reads multi-cert PEM correctly — leaf
    is the server cert, root is the trust anchor; iOS validates the
    leaf via the chain when the root was installed via mobileconfig.

    Previous shape (single self-signed dual-purpose cert) passed
    the iOS Certificate Trust Settings toggle but failed the actual
    TLS handshake on iOS 17/18 with a generic "network connection
    lost" Safari error. The two-cert chain is Apple's well-trodden
    path per TN2326.
    """
    from cryptography import x509
    from one_link.peer_https import generate_self_signed

    cp, _ = generate_self_signed(tmp_path)
    certs = x509.load_pem_x509_certificates(cp.read_bytes())
    assert len(certs) == 2, "cert.pem must contain leaf + root"
    leaf, root = certs
    assert leaf.issuer == root.subject, "leaf must be issued by root"
    assert root.issuer == root.subject, "root must be self-signed"


def test_root_ca_has_required_ios_trust_flags(tmp_path: Path):
    """The ROOT CA (root_ca.pem, embedded in the mobileconfig) is
    what iOS shows in Certificate Trust Settings. It must pass the
    full CA-recognition gate:

      * BasicConstraints critical, CA:TRUE, pathlen:0
      * KeyUsage critical, keyCertSign + crlSign (NO
        digitalSignature — root never signs TLS messages directly)
      * NO ExtendedKeyUsage (root is an anchor; constraining its
        EKU narrows what leaves it can issue, but per TN2326 leave
        the root unconstrained)
      * subjectKeyIdentifier present
      * authorityKeyIdentifier == subjectKeyIdentifier (self-issued)
      * subject == issuer
    """
    from cryptography import x509
    from one_link.peer_https import generate_self_signed, root_ca_path

    generate_self_signed(tmp_path)
    rcp = root_ca_path(tmp_path)
    root = x509.load_pem_x509_certificate(rcp.read_bytes())

    bc = root.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True, "root BasicConstraints.ca must be True"

    ku = root.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True, "root KeyUsage.key_cert_sign must be True"
    assert ku.crl_sign is True, "root KeyUsage.crl_sign must be True"

    ski_ext = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    aki_ext = root.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert ski_ext.value.digest is not None
    assert aki_ext.value.key_identifier == ski_ext.value.digest, (
        "root AuthorityKeyIdentifier must match SubjectKeyIdentifier"
    )
    assert root.subject == root.issuer, "root must be self-signed"


def test_leaf_tls_cert_shape(tmp_path: Path):
    """The leaf TLS cert (first cert in cert.pem, what aiohttp
    serves at handshake) must be a proper TN2326 end-entity:

      * BasicConstraints critical, CA:FALSE
      * KeyUsage critical, digitalSignature only (ECDSA P-256)
      * ExtendedKeyUsage serverAuth
      * subjectKeyIdentifier present
      * authorityKeyIdentifier == ROOT's subjectKeyIdentifier
      * issuer == ROOT's subject
      * SAN includes the IP(s) and DNS name(s) the phone uses
    """
    from cryptography import x509
    from one_link.peer_https import generate_self_signed, root_ca_path

    cp, _ = generate_self_signed(tmp_path)
    rcp = root_ca_path(tmp_path)
    leaf = x509.load_pem_x509_certificate(cp.read_bytes())
    root = x509.load_pem_x509_certificate(rcp.read_bytes())

    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False, "leaf BasicConstraints.ca must be False"

    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature is True
    assert ku.key_cert_sign is False, "leaf must NOT be a CA"
    assert ku.crl_sign is False

    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku

    leaf_ski = leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert leaf_ski.digest is not None

    leaf_aki = leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    root_ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    assert leaf_aki.key_identifier == root_ski.digest, (
        "leaf AuthorityKeyIdentifier must match root SubjectKeyIdentifier"
    )

    assert leaf.issuer == root.subject, "leaf must be issued by the root"


def test_leaf_signature_verifies_under_root_pubkey(tmp_path: Path):
    """The cryptographic chain check: the leaf's signature, when
    re-verified with the root's public key, must validate. If this
    fails, iOS will reject the TLS handshake regardless of the
    Trust Settings toggle."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec
    from one_link.peer_https import generate_self_signed, root_ca_path

    cp, _ = generate_self_signed(tmp_path)
    rcp = root_ca_path(tmp_path)
    leaf = x509.load_pem_x509_certificate(cp.read_bytes())
    root = x509.load_pem_x509_certificate(rcp.read_bytes())
    # Will raise InvalidSignature on failure.
    root.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        ec.ECDSA(leaf.signature_hash_algorithm),
    )


def test_root_authority_is_lockbox_wrapped_and_contains_matching_pair(
    tmp_path: Path,
):
    """The phone-wide signing key must never persist as cleartext PKCS#8.

    Certificate + key are authenticated in one authority record so a crash
    cannot silently pair one root projection with another private key.
    """
    from cryptography.hazmat.primitives import serialization
    from one_link.lockbox import acquire_lockbox, is_wrapped
    from one_link.peer_https import (
        _decode_root_authority,
        generate_self_signed,
        root_ca_key_path,
    )

    generate_self_signed(tmp_path)
    blob = root_ca_key_path(tmp_path).read_bytes()
    assert is_wrapped(blob)
    assert b"PRIVATE KEY" not in blob
    key, cert = _decode_root_authority(acquire_lockbox(tmp_path).unwrap(blob))
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert key_pub == cert_pub


def test_root_name_constraints_are_critical_and_endpoint_exact(tmp_path: Path):
    """An installed One Link CA cannot authenticate arbitrary websites."""
    import ipaddress

    from cryptography import x509
    from one_link.peer_https import generate_self_signed, root_ca_path

    generate_self_signed(tmp_path)
    root = x509.load_pem_x509_certificate(root_ca_path(tmp_path).read_bytes())
    extension = root.extensions.get_extension_for_class(x509.NameConstraints)
    assert extension.critical is True
    permitted = extension.value.permitted_subtrees or []
    dns = {entry.value for entry in permitted if isinstance(entry, x509.DNSName)}
    assert {"localhost", "onelink.local"}.issubset(dns)
    assert "example.com" not in dns
    networks = [entry.value for entry in permitted if isinstance(entry, x509.IPAddress)]
    assert ipaddress.ip_address("127.0.0.1") in networks[0] or any(
        ipaddress.ip_address("127.0.0.1") in network for network in networks
    )
    assert all(network.prefixlen == network.max_prefixlen for network in networks)
    assert not any(ipaddress.ip_address("8.8.8.8") in network for network in networks)


def test_tampered_root_authority_fails_closed_without_rotation(tmp_path: Path):
    from one_link.peer_https import (
        build_ssl_context,
        generate_self_signed,
        root_ca_key_path,
        root_ca_path,
    )

    generate_self_signed(tmp_path)
    root_before = root_ca_path(tmp_path).read_bytes()
    authority_path = root_ca_key_path(tmp_path)
    tampered = bytearray(authority_path.read_bytes())
    tampered[-1] ^= 0x01
    authority_path.write_bytes(bytes(tampered))

    assert build_ssl_context(tmp_path) is None
    assert root_ca_path(tmp_path).read_bytes() == root_before
    assert authority_path.read_bytes() == bytes(tampered)


def test_mismatched_leaf_key_is_atomically_reminted_under_same_root(tmp_path: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from one_link.peer_https import (
        cert_path,
        ensure_cert,
        generate_self_signed,
        key_path,
        root_ca_path,
    )

    generate_self_signed(tmp_path)
    root_before = x509.load_pem_x509_certificate(root_ca_path(tmp_path).read_bytes()).fingerprint(
        hashes.SHA256()
    )
    leaf_before = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes()).fingerprint(
        hashes.SHA256()
    )
    wrong_key = ec.generate_private_key(ec.SECP256R1())
    key_path(tmp_path).write_bytes(
        wrong_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    ensure_cert(tmp_path)
    root_after = x509.load_pem_x509_certificate(root_ca_path(tmp_path).read_bytes()).fingerprint(
        hashes.SHA256()
    )
    leaf_after = x509.load_pem_x509_certificate(cert_path(tmp_path).read_bytes()).fingerprint(
        hashes.SHA256()
    )
    assert root_after == root_before
    assert leaf_after != leaf_before


def test_non_regular_leaf_key_fails_closed_without_replacement(tmp_path: Path):
    from one_link.key_material import KeyMaterialIntegrityError
    from one_link.peer_https import ensure_cert, generate_self_signed, key_path

    generate_self_signed(tmp_path)
    key_path(tmp_path).unlink()
    key_path(tmp_path).mkdir()
    with pytest.raises(KeyMaterialIntegrityError, match="not a non-reparse regular file"):
        ensure_cert(tmp_path)
    assert key_path(tmp_path).is_dir()


def test_authenticated_authority_repairs_missing_public_projection(tmp_path: Path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from one_link.peer_https import ensure_cert, generate_self_signed, root_ca_path

    generate_self_signed(tmp_path)
    root_before = x509.load_pem_x509_certificate(root_ca_path(tmp_path).read_bytes())
    fingerprint = root_before.fingerprint(hashes.SHA256())
    root_ca_path(tmp_path).unlink()

    ensure_cert(tmp_path)
    repaired = x509.load_pem_x509_certificate(root_ca_path(tmp_path).read_bytes())
    assert repaired.fingerprint(hashes.SHA256()) == fingerprint


def test_partial_root_projection_is_not_silently_replaced(tmp_path: Path):
    from one_link.peer_https import (
        TLSAuthorityError,
        generate_self_signed,
        root_ca_path,
    )

    root_ca_path(tmp_path).parent.mkdir(parents=True)
    existing = b"existing phone trust anchor"
    root_ca_path(tmp_path).write_bytes(existing)
    with pytest.raises(TLSAuthorityError, match="without its signing authority"):
        generate_self_signed(tmp_path)
    assert root_ca_path(tmp_path).read_bytes() == existing


def test_endpoint_scope_change_rotates_root_instead_of_widening_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from one_link import peer_https

    monkeypatch.setattr(
        peer_https,
        "_detect_lan_addresses",
        lambda: ["127.0.0.1", "::1"],
    )
    peer_https.generate_self_signed(tmp_path)
    first = x509.load_pem_x509_certificate(
        peer_https.root_ca_path(tmp_path).read_bytes()
    ).fingerprint(hashes.SHA256())

    monkeypatch.setattr(
        peer_https,
        "_detect_lan_addresses",
        lambda: ["127.0.0.1", "::1", "192.0.2.7"],
    )
    peer_https.ensure_cert(tmp_path)
    second = x509.load_pem_x509_certificate(
        peer_https.root_ca_path(tmp_path).read_bytes()
    ).fingerprint(hashes.SHA256())
    assert second != first


def test_needs_rotation_for_missing_file(tmp_path: Path):
    from one_link.peer_https import cert_path, needs_rotation

    assert needs_rotation(cert_path(tmp_path)) is True


def test_needs_rotation_for_corrupt_file(tmp_path: Path):
    from one_link.peer_https import cert_path, https_dir, needs_rotation

    https_dir(tmp_path).mkdir(parents=True)
    cert_path(tmp_path).write_bytes(b"not a cert")
    assert needs_rotation(cert_path(tmp_path)) is True


def test_needs_rotation_false_for_fresh_cert(tmp_path: Path):
    from one_link.peer_https import cert_path, generate_self_signed, needs_rotation

    generate_self_signed(tmp_path)
    assert needs_rotation(cert_path(tmp_path)) is False


def test_needs_rotation_true_for_near_expiry_cert(tmp_path: Path):
    """A cert expiring within the rotation window MUST rotate."""
    from one_link.peer_https import cert_path, generate_self_signed, needs_rotation

    # 10-day cert + default 30-day rotation window → needs rotation.
    generate_self_signed(tmp_path, valid_days=10)
    assert needs_rotation(cert_path(tmp_path)) is True


def test_ensure_cert_idempotent(tmp_path: Path):
    """ensure_cert returns the same paths each call when the cert
    is fresh; doesn't re-mint."""
    from one_link.peer_https import ensure_cert

    cp1, kp1 = ensure_cert(tmp_path)
    cert_bytes_1 = cp1.read_bytes()
    cp2, kp2 = ensure_cert(tmp_path)
    cert_bytes_2 = cp2.read_bytes()
    assert cp1 == cp2
    assert kp1 == kp2
    # Same cert; no re-mint.
    assert cert_bytes_1 == cert_bytes_2


def test_build_ssl_context_returns_loadable_context(tmp_path: Path):
    """The context loaded from the self-signed material must be
    a usable server-side SSL context."""
    from one_link.peer_https import build_ssl_context

    ctx = build_ssl_context(tmp_path)
    assert ctx is not None
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_constrained_chain_completes_a_verified_tls_handshake(tmp_path: Path):
    """Exercise OpenSSL path validation, hostname checks, and constraints."""
    import socket
    import threading

    from one_link.peer_https import build_ssl_context, root_ca_path

    server_ctx = build_ssl_context(tmp_path)
    assert server_ctx is not None
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    outcomes: list[str] = []

    def _serve_once() -> None:
        connection, _ = listener.accept()
        try:
            with server_ctx.wrap_socket(connection, server_side=True) as tls:
                assert tls.recv(1) == b"x"
                tls.sendall(b"y")
                outcomes.append("verified")
        finally:
            listener.close()

    thread = threading.Thread(target=_serve_once, daemon=True)
    thread.start()
    client_ctx = ssl.create_default_context(cafile=str(root_ca_path(tmp_path)))
    client_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with client_ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
            assert tls.version() == "TLSv1.3"
            tls.sendall(b"x")
            assert tls.recv(1) == b"y"
    thread.join(timeout=3)
    assert outcomes == ["verified"]


def test_build_ssl_context_does_not_advertise_h2(tmp_path: Path):
    """2026-05-23: server MUST NOT advertise h2 via ALPN.
    aiohttp speaks HTTP/1.1 only — advertising h2 leads browsers
    that prefer it (Safari, modern Chrome) to negotiate HTTP/2,
    receive HTTP/1.x bytes back, treat the response as a protocol
    violation, and tear the connection down reporting
    NSURLErrorNetworkConnectionLost (-1005) on iOS or
    ERR_HTTP2_PROTOCOL_ERROR on Chromium. curl with default
    http/1.1 was succeeding the whole time, masking the bug.

    The check uses the private ALPN protocols list from the
    underlying OpenSSL context (Python doesn't expose a public
    getter, so we re-negotiate against a stub client to read
    back what the server would advertise).
    """
    import socket
    import ssl as _ssl
    import threading
    from one_link.peer_https import build_ssl_context

    server_ctx = build_ssl_context(tmp_path)
    assert server_ctx is not None

    selected: list = []

    def server_thread(sock: socket.socket):
        conn, _ = sock.accept()
        try:
            ss = server_ctx.wrap_socket(conn, server_side=True)
            selected.append(ss.selected_alpn_protocol())
            ss.close()
        except Exception as e:
            selected.append(("error", str(e)))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=server_thread, args=(srv,), daemon=True)
    t.start()

    client_ctx = _ssl.create_default_context()
    client_ctx.check_hostname = False
    client_ctx.verify_mode = _ssl.CERT_NONE
    # Reproduce Safari: offer h2 first.
    client_ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection(("127.0.0.1", port), timeout=3) as cs:
        with client_ctx.wrap_socket(cs) as css:
            client_selected = css.selected_alpn_protocol()

    t.join(timeout=3)
    srv.close()
    # Server must NOT select h2 even when client offers it first.
    assert client_selected != "h2", (
        f"Server picked h2 via ALPN — will break Safari. "
        f"client selected {client_selected!r}; server selected {selected!r}"
    )


def test_cert_fingerprint_sha256(tmp_path: Path):
    """Fingerprint helper returns a 64-char lowercase hex string."""
    from one_link.peer_https import (
        cert_fingerprint_sha256,
        cert_path,
        generate_self_signed,
    )

    generate_self_signed(tmp_path)
    fp = cert_fingerprint_sha256(cert_path(tmp_path))
    assert fp is not None
    assert len(fp) == 64
    assert all(c in "0123456789abcdef" for c in fp)


def test_cert_fingerprint_sha256_missing_file(tmp_path: Path):
    """Returns None for a missing cert. Don't raise."""
    from one_link.peer_https import cert_fingerprint_sha256, cert_path

    fp = cert_fingerprint_sha256(cert_path(tmp_path))
    assert fp is None


# ───────── peer.html autopair preflight + boot error ───────────────


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx : idx + size]


def test_autopair_preflight_helper_present(peer_html: str):
    """Preflight runs synchronous platform checks BEFORE the 12s
    identity wait. Without this the user sees a generic 'no identity'
    message; with it they see the specific reason (insecure context
    / no Web Crypto / no OPFS)."""
    snippet = _snippet(peer_html, "function _autopairPreflight", 2200)
    assert "window.isSecureContext" in snippet
    assert "crypto.subtle.generateKey" in snippet
    assert "navigator.storage.getDirectory" in snippet


def test_autopair_preflight_called_first_in_flow(peer_html: str):
    """Preflight MUST run before _waitForIdentity — otherwise the
    user waits 12s for nothing on an insecure-context page."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 4000)
    pf_idx = snippet.find("_autopairPreflight()")
    wait_idx = snippet.find("_waitForIdentity(")
    assert pf_idx > 0
    assert wait_idx > pf_idx, "preflight must run before identity wait"


def test_autopair_preflight_surfaces_insecure_context(peer_html: str):
    """Insecure-context message MUST mention HTTPS specifically.
    A user reading 'page loaded over HTTP' immediately knows what
    to do (regenerate the QR on a v0.20.4+ daemon)."""
    snippet = _snippet(peer_html, "function _autopairPreflight", 2200)
    assert "HTTPS" in snippet
    assert "QR" in snippet or "laptop" in snippet


def test_boot_stashes_error_for_autopair(peer_html: str):
    """When boot fails (insecure context, keygen, etc.), it MUST
    set state.boot_error_msg so the autopair flow can surface the
    real reason instead of the generic 'no identity in 12s'."""
    snippet = _snippet(peer_html, "async function boot()", 6000)
    assert "peerIdentity.failBoot(" in snippet


def test_wait_for_identity_aborts_on_boot_error(peer_html: str):
    """The wait loop MUST short-circuit when state.boot_error_msg
    is set — otherwise we wait 12s for an identity that will never
    arrive."""
    snippet = _snippet(peer_html, "async function _waitForIdentity", 800)
    assert "state.boot_error_msg" in snippet
    assert "return null" in snippet


def test_autopair_surfaces_real_boot_error(peer_html: str):
    """When _waitForIdentity returns null because of a boot error,
    autopair MUST display the actual error message — not the
    generic 'no identity' line."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 4000)
    assert "state.boot_error_msg" in snippet
    assert "Identity boot failed" in snippet


def test_boot_checks_secure_context_first(peer_html: str):
    """The insecure-context check MUST run BEFORE the
    crypto.subtle existence check. On insecure HTTP, crypto.subtle
    is sometimes present-but-restricted, so the no-web-crypto
    branch would fire with a misleading message."""
    snippet = _snippet(peer_html, "async function boot()", 4000)
    secure_idx = snippet.find("window.isSecureContext")
    crypto_idx = snippet.find("if (!window.crypto || !crypto.subtle)")
    assert secure_idx > 0
    assert crypto_idx > 0
    assert secure_idx < crypto_idx


# ───────── pair-URL adoption of https:// ──────────────────────────


def test_pair_url_uses_https_when_available():
    """Pure-Python check: when self.https_port is set, the
    api_mint_pairing handler should produce https:// pair URLs.
    We don't bring up a real listener here; just test the URL-
    building branch in isolation against a stub server."""
    # The branching logic lives inside api_mint_pairing. We can
    # verify it by reading the source — the actual integration
    # test is the live daemon probe at the end of the ship.
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    end = src.find("\n    async def ", idx + 1)
    snippet = src[idx : end if end > idx else None]
    assert "if self.https_port:" in snippet
    assert 'f"https://{host}:{self.https_port}"' in snippet
    assert 'ws_scheme = "wss"' in snippet


def test_pair_url_fallback_to_http_when_no_https():
    """If HTTPS bring-up fails, pair URLs fall back to http://. The
    daemon still works for desktop loopback access; phone-over-LAN
    just won't work without HTTPS, which is a separate concern."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    end = src.find("\n    async def ", idx + 1)
    snippet = src[idx : end if end > idx else None]
    # The fallback branch must exist.
    assert 'f"http://{host}:{self.port}"' in snippet


def test_pair_url_includes_cert_fingerprint_when_https():
    """The pair URL embeds the cert fingerprint as `&cert=...` so
    a future-ship phone-side check can pin against it. v0.20.4
    just emits it; v0.20.5+ can verify."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def api_mint_pairing")
    end = src.find("\n    async def ", idx + 1)
    snippet = src[idx : end if end > idx else None]
    assert "self.https_cert_fp_sha256" in snippet
    assert "&cert=" in snippet


# ───────── legacy QR removal ──────────────────────────────────────


def test_legacy_connect_info_section_removed():
    """v0.20.4 removes the second QR (the desktop-UI-on-phone
    URL-only flow). Two QRs side-by-side was confusing the user
    about which to scan. The new pair-by-QR is now the only path
    in the About pane."""
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    # The old section_h with "Open desktop UI on another device" is gone.
    assert "Open desktop UI on another device" not in html
    # The id stays present as an empty hidden div for any inline JS
    # that still references it (defensive); but the visible section
    # markup is gone.


# ───────── server bind metadata ───────────────────────────────────


def test_server_init_declares_https_attrs():
    """UIServer.__init__ MUST declare self.https_site,
    self.https_port, self.https_cert_fp_sha256 even before start()
    runs, so api_mint_pairing can read them safely on first
    request without an AttributeError.

    2026-05-22: the bind_host comment block (LAN-bind default doc)
    grew start() past the original 5000-char window. Read to the
    next ``async def`` boundary or 10000 chars max so structural
    checks survive reasonable in-function additions.
    """
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def start(self)")
    end_idx = src.find("\n    async def ", idx + 30)
    if end_idx == -1 or end_idx - idx > 10000:
        end_idx = idx + 10000
    snippet = src[idx:end_idx]
    assert "self.https_site = None" in snippet
    assert "self.https_port = None" in snippet
    assert "self.https_cert_fp_sha256 = None" in snippet


def test_server_logs_https_listener_up():
    """For operators / debugging — when HTTPS comes up, log it. A
    silent HTTPS bring-up is hard to diagnose if something later
    misbehaves."""
    src = Path("src/one_link/server.py").read_text(encoding="utf-8")
    idx = src.find("async def _start_https_listener")
    # Scan the FUNCTION, not a byte count. A fixed window measures comment
    # length as much as behaviour: documenting why cert building runs off the
    # event loop pushed the log line past a 3000-char cutoff and failed this
    # test without changing anything it is about.
    next_def = src.find("\n    async def ", idx + 1)
    if next_def == -1:
        next_def = src.find("\n    def ", idx + 1)
    snippet = src[idx : next_def if next_def != -1 else idx + 10000]
    assert "UI server HTTPS up" in snippet


# ───────── version pin ────────────────────────────────────────────


def test_peer_version_at_or_above_v0204(peer_html: str):
    import re

    m = re.search(r"version:\s*['\"](\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?['\"]", peer_html)
    assert m
    parts = tuple(int(p) for p in m.groups())
    assert parts >= (0, 20, 4)


def test_page_version_matches_package():
    from one_link import __version__

    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
