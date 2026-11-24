//! Error types. Verification errors carry a stable machine-readable [`VerifyError::code`]
//! so services and the demo can explain *why* a proof was rejected without leaking
//! anything about the witness (the verifier never had it).

use thiserror::Error;

/// Why a prover could not produce a proof. These never leave the wallet.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProveError {
    /// `Δ = D* − D < 0`: the holder is younger than the threshold. By §7.6 no
    /// bit-decomposition of a negative Δ exists, so an honest proof is impossible.
    #[error("holder is under the age threshold by {days_short} day(s); no valid range proof exists (§7.6)")]
    Underage {
        /// How many days short of the cutoff date the holder is.
        days_short: u64,
    },
    /// `Δ ≥ 2ⁿ`: the slack does not fit in the configured bit width (≈179 years for n = 16).
    #[error("slack Δ = {delta} does not fit in {n_bits} bits")]
    OutOfRange {
        /// The slack value.
        delta: u64,
        /// The configured bit width.
        n_bits: u8,
    },
    /// The credential's opening `(D, r)` does not open its commitment `C_D`.
    #[error("credential is internally inconsistent: (D, r) does not open C_D")]
    InvalidCredential,
    /// The statement itself is malformed.
    #[error("invalid statement: {0}")]
    InvalidStatement(String),
}

/// Why a verifier rejected a proof. Ordered roughly by the order checks run in.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// Bytes could not be decoded (bad encoding, non-canonical point/scalar, …).
    #[error("malformed proof: {0}")]
    Malformed(String),
    /// Unknown wire-format version.
    #[error("unsupported wire version {0}")]
    UnsupportedVersion(u8),
    /// The proof answers a different nonce than the statement being checked.
    #[error("proof answers a different challenge nonce")]
    NonceMismatch,
    /// The statement is malformed (bad threshold, empty verifier id, …).
    #[error("invalid statement: {0}")]
    InvalidStatement(String),
    /// `issuer_pk` is not on the verifier's trust list (T8).
    #[error("issuer key is not on the trust list")]
    UntrustedIssuer,
    /// The issuer signature over `C_D` does not verify (§7.8 Tier A, T2).
    #[error("issuer signature over C_D is invalid")]
    BadSignature,
    /// The statement's validity window has not opened yet.
    #[error("statement not yet valid")]
    NotYetValid,
    /// The statement's validity window has closed.
    #[error("statement expired")]
    Expired,
    /// Proof has the wrong number of bit proofs.
    #[error("expected {expected} bit proofs, got {got}")]
    WrongBitCount {
        /// Expected `n`.
        expected: usize,
        /// Received.
        got: usize,
    },
    /// `Σ 2ⁱ·Cᵢ ≠ C_Δ` (§7.5 consistency).
    #[error("bit commitments do not recombine to C_Δ (§7.5 consistency check)")]
    ConsistencyFailed,
    /// An OR-proof equation failed under the recomputed Fiat–Shamir challenge
    /// (§7.4 / §7.7). Tampering, a non-bit digit, or a replay against a different
    /// statement all land here.
    #[error("bit {bit}: OR-proof fails under the recomputed Fiat–Shamir challenge (§7.4/§7.7)")]
    FiatShamirCheckFailed {
        /// Index of the first failing bit.
        bit: usize,
    },
    /// A Schnorr proof equation failed (§7.3).
    #[error("Schnorr verification equation failed (§7.3)")]
    SchnorrFailed,
}

impl VerifyError {
    /// Stable snake_case code for APIs and logs.
    pub fn code(&self) -> &'static str {
        match self {
            VerifyError::Malformed(_) => "malformed",
            VerifyError::UnsupportedVersion(_) => "unsupported_version",
            VerifyError::NonceMismatch => "nonce_mismatch",
            VerifyError::InvalidStatement(_) => "invalid_statement",
            VerifyError::UntrustedIssuer => "untrusted_issuer",
            VerifyError::BadSignature => "bad_signature",
            VerifyError::NotYetValid => "not_yet_valid",
            VerifyError::Expired => "expired",
            VerifyError::WrongBitCount { .. } => "wrong_bit_count",
            VerifyError::ConsistencyFailed => "consistency_failed",
            VerifyError::FiatShamirCheckFailed { .. } => "fiat_shamir_check_failed",
            VerifyError::SchnorrFailed => "schnorr_failed",
        }
    }
}

/// Errors from issuing or importing a credential.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// Date could not be parsed or is not a real calendar date.
    #[error("invalid date: {0}")]
    InvalidDate(String),
    /// Birthdate is after the issuance date.
    #[error("date of birth is in the future")]
    FutureBirthdate,
    /// Birthdate precedes the 1900-01-01 epoch.
    #[error("date of birth precedes the 1900-01-01 encoding epoch")]
    BeforeEpoch,
    /// The credential's `(D, r)` does not open `C_D`, or the signature is bad.
    #[error("credential failed self-check: {0}")]
    SelfCheck(String),
    /// Bad encoding.
    #[error("malformed credential: {0}")]
    Malformed(String),
    /// Unknown wire-format version.
    #[error("unsupported credential version {0}")]
    UnsupportedVersion(u8),
}
