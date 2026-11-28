//! Errors for `ol_pqkem`.

use thiserror::Error;

/// Errors produced by the hybrid KEM.
#[derive(Debug, Error, Clone, Eq, PartialEq)]
pub enum PqKemError {
    /// Decoding a serialized hybrid public/secret/ciphertext failed
    /// because the byte length is wrong.
    #[error("invalid wire length: expected {expected} bytes, got {got}")]
    InvalidWireLength {
        /// Expected length for this object.
        expected: usize,
        /// Actual length received.
        got: usize,
    },

    /// The ML-KEM encapsulation key is not a valid key: one of its
    /// coefficients is not reduced modulo q. FIPS 203 section 7.2 requires
    /// this check before a key received from another party is used.
    #[error("invalid ML-KEM encapsulation key: coefficient not reduced modulo q")]
    InvalidEncapsulationKey,

    /// ML-KEM internal failure during keygen / encapsulate / decapsulate.
    /// The `ml-kem` crate generally surfaces these only on malformed
    /// inputs; we forward as a generic error.
    #[error("ML-KEM operation failed: {reason}")]
    MlKemFailed {
        /// Reason as reported by the underlying crate.
        reason: &'static str,
    },
}
