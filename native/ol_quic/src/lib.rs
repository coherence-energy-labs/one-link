//! `ol_quic` — QUIC transport for One Link's daemon↔daemon hot path
//! per [ADR-0009](../../../docs/decisions/0009-quic-transport.md) and
//! [ADR-0010](../../../docs/decisions/0010-identity-bound-tls.md).
//!
//! Built on [`quinn`] with [`rustls`] for TLS 1.3 and [`rcgen`] for
//! self-signed identity-bound certs. Replaces the WebRTC/DTLS-SRTP
//! transport for daemon↔daemon connections; WebRTC stays as the
//! browser-as-peer transport (browsers don't speak raw QUIC yet).
//!
//! ## What this crate gives you
//!
//! - [`Identity`] — an Ed25519 keypair + derived self-signed cert.
//! - [`Endpoint`] — QUIC listener / dialer combined.
//! - [`Connection`] — wraps `quinn::Connection` with our wire-protocol
//!   helpers.
//! - [`proto::Frame`] — typed frame protocol per ADR-0009.
//! - [`tls::IdentityBoundServerVerifier`] /
//!   [`tls::IdentityBoundClientVerifier`] — the custom rustls verifiers
//!   that bind TLS to peer fingerprint per ADR-0010.
//!
//! ## What this crate does NOT do
//!
//! - It does not coordinate connection lifetime with the daemon's peer
//!   registry — that's a higher-level binding concern.
//! - It does not parse or interpret `ChunkResponse` / `ManifestRecord`
//!   payloads; those are passed through verbatim and the `chunk_store` /
//!   `manifest_log` on the receiving end consume them.
//! - It does not (yet) implement 0-RTT replay protection beyond
//!   "0-RTT only carries idempotent reads." That layer ships in Phase B
//!   alongside the per-chunk ratchet.

#![doc(html_root_url = "https://docs.rs/ol_quic/0.21.0")]

pub mod error;
pub mod identity;
pub mod proto;
pub mod tls;
pub mod transport;

pub use error::QuicError;
pub use identity::{Identity, PeerFingerprint, FINGERPRINT_LEN};
pub use proto::{Frame, FrameKind, MAX_BULK_FRAME_BYTES, MAX_CONTROL_FRAME_BYTES};
pub use tls::{IdentityBoundClientVerifier, IdentityBoundServerVerifier, PeerRegistry, ALPN};
pub use transport::{Connection, Endpoint, EndpointConfig};

/// Crate version embedded for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the rustls crypto provider (ring) once at process
/// start. Safe to call multiple times. Most callers should use
/// [`Endpoint::server_for_identity`] / [`Endpoint::client_for_identity`]
/// which call this internally.
pub fn install_default_crypto_provider() {
    // The rustls 0.23 + ring backend installs lazily; calling
    // `CryptoProvider::install_default` early avoids a runtime warning
    // when the first connection forces installation.
    let _ = rustls::crypto::ring::default_provider().install_default();
}
