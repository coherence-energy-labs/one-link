//! obfs4-style handshake — ECDH + bridge-identity HMAC binding.
//!
//! Threat model:
//!
//! - **Passive DPI** observes wire bytes. Both handshake messages
//!   look uniformly random; `ChaCha20` obfuscation under the
//!   handshake-derived key kicks in for the bulk data.
//! - **Active probe attacker** tries to detect bridges by sending
//!   random / well-known protocol bytes to candidate IPs and seeing
//!   if anything responds in a bridge-shaped way. Defeated by the
//!   bridge-identity HMAC: a valid first message requires
//!   `HMAC(bridge_id || epoch_hour, client_ephem_pk)`. Without
//!   `bridge_id` the attacker can't forge it. The bridge silently
//!   drops invalid handshakes; a probe attacker sees nothing.
//! - **Replay** within the current epoch is possible — the client's
//!   ephemeral pubkey + HMAC are valid for ~1 hour. After the
//!   epoch rolls over, the same handshake is rejected. Combined
//!   with the bulk-cipher's per-conn nonce, replay yields no useful
//!   plaintext-side oracle.
//! - **Time-skew tolerance**: server accepts HMACs computed against
//!   the current OR previous epoch, so clients off by < 1 hour
//!   still succeed.
//!
//! ## Wire format
//!
//! ```text
//!   Client → Server:
//!     client_ephem_pubkey  : [u8; 32]    (X25519 ephemeral)
//!     hmac_tag             : [u8; 16]    (BLAKE3-keyed tag)
//!     pad                  : variable    (random; daemon picks size)
//!
//!   Server → Client:
//!     server_ephem_pubkey  : [u8; 32]
//!     auth_tag             : [u8; 16]    (BLAKE3-keyed over transcript)
//!     pad                  : variable
//! ```
//!
//! The 48 fixed bytes of each handshake message are wrapped in the
//! `primitive` obfuscator using a session-derived key (or a pre-
//! shared bridge "obfs key" for the very first message — for
//! simplicity here we emit the bytes raw + rely on the HMAC for
//! authenticity; the daemon can layer the byte obfuscator on top if
//! it wants extra DPI resistance for the handshake itself).

use blake3::Hasher;
use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::transport_obfs::primitive::OBFS_KEY_LEN;
use crate::transport_obfs::session::Session;

/// Length of the bridge identity handle (a public 32-byte tag the
/// client knows out-of-band). This is bound into the HMAC so probe
/// attackers without it can't forge a valid handshake.
pub const BRIDGE_ID_LEN: usize = 32;

/// Length of the bridge's long-term X25519 public key.
pub const BRIDGE_PUBKEY_LEN: usize = 32;

/// Length of the bridge's long-term X25519 secret key.
pub const BRIDGE_SECRET_LEN: usize = 32;

/// Length of the per-message handshake MAC.
pub const HANDSHAKE_MAC_LEN: usize = 16;

/// Length of the fixed-portion handshake message (`ephem_pk` + mac).
pub const HANDSHAKE_LEN: usize = 32 + HANDSHAKE_MAC_LEN;

/// Epoch window for the HMAC binding (seconds). 1 hour = 3600.
/// Clients with skew < this value still authenticate.
pub const HANDSHAKE_EPOCH_SECS: u64 = 3600;

/// Domain-separation tag for the handshake HMAC.
const HMAC_DOMAIN: &[u8] = b"OL-obfs-handshake-v1";

/// Domain-separation tag for the per-direction session key derivation.
const KDF_DOMAIN: &[u8] = b"OL-obfs-session-kdf-v1";

/// Typed error surface.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Wrong byte length for a key, MAC, or handshake message.
    #[error("wrong length: expected {expected}, got {got}")]
    BadLength {
        /// Required length.
        expected: usize,
        /// Actual length.
        got: usize,
    },
    /// HMAC verification failed. Either the `bridge_id` is wrong, the
    /// epoch is too far skewed, or the message was tampered.
    #[error("handshake MAC did not verify")]
    BadMac,
    /// ECDH yielded a small-order shared secret (all-zero bytes).
    #[error("ECDH produced small-order shared secret")]
    SmallOrderPubkey,
}

/// Result alias.
pub type HandshakeResult<T> = Result<T, HandshakeError>;

/// Bridge keypair = long-term X25519 keys + a 32-byte public id tag.
/// The id tag identifies which bridge a client is targeting + binds
/// the HMAC. Clients learn `(bridge_pk, bridge_id)` out-of-band
/// (e.g., via F2 pair-by-QR or an existing trusted channel).
#[derive(Clone)]
pub struct BridgeKeypair {
    /// Long-term static X25519 secret. Drop zeroizes via x25519-dalek.
    pub secret: StaticSecret,
    /// Long-term static X25519 public.
    pub public: PublicKey,
    /// 32-byte public id tag. Bound into HMAC; not secret itself.
    pub id: [u8; BRIDGE_ID_LEN],
}

impl BridgeKeypair {
    /// Generate a fresh keypair from a CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = StaticSecret::random_from_rng(&mut *rng);
        let public = PublicKey::from(&secret);
        let mut id = [0u8; BRIDGE_ID_LEN];
        rng.fill_bytes(&mut id);
        Self { secret, public, id }
    }

    /// Construct from raw seed + id bytes. The secret is the X25519
    /// seed; clamping happens at use.
    pub fn from_parts(secret_seed: [u8; BRIDGE_SECRET_LEN], id: [u8; BRIDGE_ID_LEN]) -> Self {
        let secret = StaticSecret::from(secret_seed);
        let public = PublicKey::from(&secret);
        Self { secret, public, id }
    }

    /// Serialize the SECRET half to wire bytes. Store encrypted at
    /// rest; loss = bridge identity lost.
    pub fn secret_bytes(&self) -> [u8; BRIDGE_SECRET_LEN] {
        self.secret.to_bytes()
    }

    /// Public X25519 key bytes (shareable; clients pin this).
    pub fn public_bytes(&self) -> [u8; BRIDGE_PUBKEY_LEN] {
        *self.public.as_bytes()
    }

    /// Public id tag bytes (shareable; bound into HMACs).
    pub fn id_bytes(&self) -> [u8; BRIDGE_ID_LEN] {
        self.id
    }
}

impl std::fmt::Debug for BridgeKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeKeypair").finish_non_exhaustive()
    }
}

/// Client handshake state. Created via `start`, completed by feeding
/// the server's reply.
pub struct ClientHandshake {
    /// Ephemeral secret used for ECDH; consumed at `finish`.
    ephem: Option<EphemeralSecret>,
    /// Cached ephemeral public bytes (for the transcript).
    ephem_pk_bytes: [u8; 32],
    /// Bridge's long-term public key (target of the ECDH).
    bridge_pubkey: PublicKey,
    /// Bridge's id (bound into HMACs).
    bridge_id: [u8; BRIDGE_ID_LEN],
    /// The first message the daemon ships to the bridge.
    first_message: [u8; HANDSHAKE_LEN],
    /// The wall-clock epoch the client computed its HMAC against.
    epoch: u64,
}

impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// Start a client handshake. The daemon sends the returned bytes
    /// to the bridge over its transport (TCP/QUIC/UDP).
    pub fn start<R: RngCore + CryptoRng>(
        rng: &mut R,
        bridge_pubkey: &[u8; BRIDGE_PUBKEY_LEN],
        bridge_id: &[u8; BRIDGE_ID_LEN],
        now_unix: u64,
    ) -> Self {
        let ephem = EphemeralSecret::random_from_rng(&mut *rng);
        let ephem_pk = PublicKey::from(&ephem);
        let ephem_pk_bytes = *ephem_pk.as_bytes();
        let bridge_pubkey_pt = PublicKey::from(*bridge_pubkey);
        let epoch = now_unix / HANDSHAKE_EPOCH_SECS;
        let tag = compute_handshake_tag(bridge_id, epoch, &ephem_pk_bytes);
        let mut first_message = [0u8; HANDSHAKE_LEN];
        first_message[..32].copy_from_slice(&ephem_pk_bytes);
        first_message[32..].copy_from_slice(&tag);
        Self {
            ephem: Some(ephem),
            ephem_pk_bytes,
            bridge_pubkey: bridge_pubkey_pt,
            bridge_id: *bridge_id,
            first_message,
            epoch,
        }
    }

    /// The bytes the daemon transmits to the bridge as the first
    /// handshake message.
    pub fn first_message(&self) -> &[u8; HANDSHAKE_LEN] {
        &self.first_message
    }

    /// Complete the handshake using the server's reply bytes. Returns
    /// a [`Session`] with the per-direction obfuscation keys derived.
    pub fn finish(mut self, server_reply: &[u8]) -> HandshakeResult<Session> {
        if server_reply.len() < HANDSHAKE_LEN {
            return Err(HandshakeError::BadLength {
                expected: HANDSHAKE_LEN,
                got: server_reply.len(),
            });
        }
        let mut server_pk_bytes = [0u8; 32];
        server_pk_bytes.copy_from_slice(&server_reply[..32]);
        let mut server_tag = [0u8; HANDSHAKE_MAC_LEN];
        server_tag.copy_from_slice(&server_reply[32..HANDSHAKE_LEN]);
        // Verify server's auth tag binds the transcript so far.
        let expected_tag = compute_server_auth_tag(
            &self.bridge_id,
            self.epoch,
            &self.ephem_pk_bytes,
            &server_pk_bytes,
        );
        if !bool::from(expected_tag.ct_eq(&server_tag)) {
            return Err(HandshakeError::BadMac);
        }
        let server_pk = PublicKey::from(server_pk_bytes);
        // ECDH: shared = client_ephem * bridge_pubkey.
        // (We use bridge_pubkey here, not server_ephem_pk; the
        // server side mirrors via bridge_secret * client_ephem.)
        let ephem = self.ephem.take().ok_or(HandshakeError::SmallOrderPubkey)?;
        let shared = ephem.diffie_hellman(&self.bridge_pubkey);
        // `was_contributory` is x25519-dalek's constant-time all-zero test.
        // ct-audit: declassify (small-order verdict is the public result)
        if !shared.was_contributory() {
            return Err(HandshakeError::SmallOrderPubkey);
        }
        let _ = server_pk;
        let (client_tx_key, server_tx_key) = derive_session_keys(
            shared.as_bytes(),
            &self.bridge_id,
            &self.ephem_pk_bytes,
            &server_pk_bytes,
        );
        Ok(Session::new(client_tx_key, server_tx_key))
    }
}

/// Server-side handshake. The bridge holds [`BridgeKeypair`]; on
/// receiving a client's first message it produces a reply + a session.
#[derive(Debug)]
pub struct ServerHandshake;

impl ServerHandshake {
    /// Accept a client handshake. Verifies the client's HMAC against
    /// both the current epoch AND the previous epoch (tolerates ~1
    /// hour of clock skew). Returns the bytes the bridge ships back
    /// + the resulting Session.
    pub fn accept<R: RngCore + CryptoRng>(
        rng: &mut R,
        bridge: &BridgeKeypair,
        client_first: &[u8],
        now_unix: u64,
    ) -> HandshakeResult<([u8; HANDSHAKE_LEN], Session)> {
        if client_first.len() < HANDSHAKE_LEN {
            return Err(HandshakeError::BadLength {
                expected: HANDSHAKE_LEN,
                got: client_first.len(),
            });
        }
        let mut client_pk_bytes = [0u8; 32];
        client_pk_bytes.copy_from_slice(&client_first[..32]);
        let mut client_tag = [0u8; HANDSHAKE_MAC_LEN];
        client_tag.copy_from_slice(&client_first[32..HANDSHAKE_LEN]);

        // Try the current epoch first, then the previous one.
        let current_epoch = now_unix / HANDSHAKE_EPOCH_SECS;
        let mut matched_epoch = None;
        for candidate in [current_epoch, current_epoch.saturating_sub(1)] {
            let expected = compute_handshake_tag(&bridge.id, candidate, &client_pk_bytes);
            // ct-audit: declassify (MAC verdict per public epoch)
            if bool::from(expected.ct_eq(&client_tag)) {
                matched_epoch = Some(candidate);
                break;
            }
        }
        let epoch = matched_epoch.ok_or(HandshakeError::BadMac)?;

        // Generate the server's ephemeral.
        let server_ephem = EphemeralSecret::random_from_rng(&mut *rng);
        let server_pk = PublicKey::from(&server_ephem);
        let server_pk_bytes = *server_pk.as_bytes();

        // ECDH: shared = bridge_secret * client_ephem_pk.
        let client_pk = PublicKey::from(client_pk_bytes);
        let shared = bridge.secret.diffie_hellman(&client_pk);
        // `was_contributory` is x25519-dalek's constant-time all-zero test.
        // ct-audit: declassify (small-order verdict is the public result)
        if !shared.was_contributory() {
            return Err(HandshakeError::SmallOrderPubkey);
        }
        // Server's auth tag binds the transcript: client_ephem + server_ephem.
        let server_tag =
            compute_server_auth_tag(&bridge.id, epoch, &client_pk_bytes, &server_pk_bytes);

        let mut reply = [0u8; HANDSHAKE_LEN];
        reply[..32].copy_from_slice(&server_pk_bytes);
        reply[32..].copy_from_slice(&server_tag);

        // Derive matching session keys. Server's perspective: the
        // CLIENT sends to us with client_tx_key, we send back with
        // server_tx_key. Mirror the client's derivation order.
        let (client_tx_key, server_tx_key) = derive_session_keys(
            shared.as_bytes(),
            &bridge.id,
            &client_pk_bytes,
            &server_pk_bytes,
        );
        // The server's incoming-direction key is client_tx_key, its
        // outgoing-direction key is server_tx_key. The Session ctor
        // takes (my_outbound, peer_outbound) → mirror via swap.
        // We pass the SAME (client_tx_key, server_tx_key) pair as
        // the client did, but the Session ctor produces a symmetric
        // pair where each side names its own keys properly. To keep
        // both sides aligned, ServerSession::for_server swaps them.
        let session = Session::for_server(client_tx_key, server_tx_key);
        // Drop the server_ephem after deriving — we don't need it
        // again.
        let _ = server_ephem;
        Ok((reply, session))
    }
}

/// Compute the client's handshake HMAC tag:
///   `BLAKE3-keyed(domain || bridge_id || epoch_be, client_ephem_pk)`
/// truncated to [`HANDSHAKE_MAC_LEN`].
fn compute_handshake_tag(
    bridge_id: &[u8; BRIDGE_ID_LEN],
    epoch: u64,
    client_ephem_pk: &[u8; 32],
) -> [u8; HANDSHAKE_MAC_LEN] {
    let mut key = [0u8; 32];
    let mut kh = Hasher::new();
    kh.update(HMAC_DOMAIN);
    kh.update(b"-client-mac");
    kh.update(bridge_id);
    kh.update(&epoch.to_be_bytes());
    let d = kh.finalize();
    key.copy_from_slice(d.as_bytes());
    let mut mh = Hasher::new_keyed(&key);
    mh.update(client_ephem_pk);
    let m = mh.finalize();
    let mut out = [0u8; HANDSHAKE_MAC_LEN];
    out.copy_from_slice(&m.as_bytes()[..HANDSHAKE_MAC_LEN]);
    key.zeroize();
    out
}

/// Compute the server's auth tag binding the full handshake transcript.
fn compute_server_auth_tag(
    bridge_id: &[u8; BRIDGE_ID_LEN],
    epoch: u64,
    client_ephem_pk: &[u8; 32],
    server_ephem_pk: &[u8; 32],
) -> [u8; HANDSHAKE_MAC_LEN] {
    let mut key = [0u8; 32];
    let mut kh = Hasher::new();
    kh.update(HMAC_DOMAIN);
    kh.update(b"-server-mac");
    kh.update(bridge_id);
    kh.update(&epoch.to_be_bytes());
    let d = kh.finalize();
    key.copy_from_slice(d.as_bytes());
    let mut mh = Hasher::new_keyed(&key);
    mh.update(client_ephem_pk);
    mh.update(server_ephem_pk);
    let m = mh.finalize();
    let mut out = [0u8; HANDSHAKE_MAC_LEN];
    out.copy_from_slice(&m.as_bytes()[..HANDSHAKE_MAC_LEN]);
    key.zeroize();
    out
}

/// Derive `(client_tx_key, server_tx_key)` from the ECDH shared +
/// transcript. Each direction gets a distinct OBFS_KEY_LEN-byte key
/// so client→server and server→client streams never collide.
fn derive_session_keys(
    shared: &[u8; 32],
    bridge_id: &[u8; BRIDGE_ID_LEN],
    client_ephem_pk: &[u8; 32],
    server_ephem_pk: &[u8; 32],
) -> ([u8; OBFS_KEY_LEN], [u8; OBFS_KEY_LEN]) {
    let derive = |label: &[u8]| -> [u8; OBFS_KEY_LEN] {
        let mut h = Hasher::new();
        h.update(KDF_DOMAIN);
        h.update(label);
        h.update(shared);
        h.update(bridge_id);
        h.update(client_ephem_pk);
        h.update(server_ephem_pk);
        let d = h.finalize();
        let mut out = [0u8; OBFS_KEY_LEN];
        out.copy_from_slice(d.as_bytes());
        out
    };
    let client_tx = derive(b"-client-tx");
    let server_tx = derive(b"-server-tx");
    (client_tx, server_tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn handshake_round_trip_derives_matching_session_keys() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let now = 1_700_000_000u64;

        let client = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, now);
        let first = *client.first_message();

        let (reply, server_session) =
            ServerHandshake::accept(&mut OsRng, &bridge, &first, now).unwrap();

        let client_session = client.finish(&reply).unwrap();
        // Both sides should hold matching key sets — proof via
        // round-trip of a packet.
        let plaintext = b"hello over the bridge";
        let on_wire = client_session.seal_outbound(plaintext, 1);
        let recovered = server_session.open_inbound(&on_wire, 1).unwrap();
        assert_eq!(recovered, plaintext);
        // And in the reverse direction.
        let plaintext2 = b"reply from the bridge";
        let on_wire2 = server_session.seal_outbound(plaintext2, 1);
        let recovered2 = client_session.open_inbound(&on_wire2, 1).unwrap();
        assert_eq!(recovered2, plaintext2);
    }

    #[test]
    fn server_rejects_handshake_with_wrong_bridge_id() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let wrong_id = [0x99u8; BRIDGE_ID_LEN];
        let now = 1_700_000_000u64;
        let client = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &wrong_id, now);
        let err =
            ServerHandshake::accept(&mut OsRng, &bridge, client.first_message(), now).unwrap_err();
        assert_eq!(err, HandshakeError::BadMac);
    }

    #[test]
    fn server_tolerates_one_epoch_of_skew() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let client_now = 1_700_000_000u64;
        let client = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, client_now);
        // Server is ~1 epoch ahead (3600 sec).
        let server_now = client_now + HANDSHAKE_EPOCH_SECS;
        let (_reply, _session) =
            ServerHandshake::accept(&mut OsRng, &bridge, client.first_message(), server_now)
                .expect("server accepts within 1 epoch skew");
    }

    #[test]
    fn server_rejects_two_epoch_skew() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let client_now = 1_700_000_000u64;
        let client = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, client_now);
        // Server is 2 epochs ahead.
        let server_now = client_now + 2 * HANDSHAKE_EPOCH_SECS;
        let err = ServerHandshake::accept(&mut OsRng, &bridge, client.first_message(), server_now)
            .unwrap_err();
        assert_eq!(err, HandshakeError::BadMac);
    }

    #[test]
    fn client_rejects_tampered_server_reply() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let now = 1_700_000_000u64;
        let client = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, now);
        let (mut reply, _server_session) =
            ServerHandshake::accept(&mut OsRng, &bridge, client.first_message(), now).unwrap();
        reply[40] ^= 0x01; // flip a byte in the auth tag
        let err = client.finish(&reply).unwrap_err();
        assert_eq!(err, HandshakeError::BadMac);
    }

    #[test]
    fn truncated_handshake_rejected() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let too_short = [0u8; HANDSHAKE_LEN - 1];
        let err = ServerHandshake::accept(&mut OsRng, &bridge, &too_short, 0).unwrap_err();
        assert!(matches!(err, HandshakeError::BadLength { .. }));
    }

    #[test]
    fn handshake_message_size_is_constant() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let client =
            ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, 1_700_000_000);
        assert_eq!(client.first_message().len(), HANDSHAKE_LEN);
        assert_eq!(HANDSHAKE_LEN, 48);
    }

    #[test]
    fn different_clients_get_distinct_session_keys() {
        let bridge = BridgeKeypair::generate(&mut OsRng);
        let bridge_pk_bytes: [u8; BRIDGE_PUBKEY_LEN] = *bridge.public.as_bytes();
        let now = 1_700_000_000u64;

        let client_a = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, now);
        let (reply_a, server_a) =
            ServerHandshake::accept(&mut OsRng, &bridge, client_a.first_message(), now).unwrap();
        let session_a = client_a.finish(&reply_a).unwrap();

        let client_b = ClientHandshake::start(&mut OsRng, &bridge_pk_bytes, &bridge.id, now);
        let (reply_b, server_b) =
            ServerHandshake::accept(&mut OsRng, &bridge, client_b.first_message(), now).unwrap();
        let session_b = client_b.finish(&reply_b).unwrap();

        // Encrypting the same plaintext under both sessions produces
        // different bytes (different ephemerals → different keys).
        let p = b"same plaintext";
        let cipher_a = session_a.seal_outbound(p, 1);
        let cipher_b = session_b.seal_outbound(p, 1);
        assert_ne!(cipher_a, cipher_b);
        let _ = (server_a, server_b);
    }
}
