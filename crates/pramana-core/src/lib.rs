//! # pramana-core — Gūḍhapramāṇa (गूढप्रमाण), "concealed proof"
//!
//! A from-scratch, auditable implementation of a zero-knowledge age proof:
//! the prover convinces a verifier that a birthdate attested by a trusted issuer
//! satisfies `age ≥ threshold` while revealing nothing else about it.
//!
//! The construction follows PRD §7 exactly, and every security-relevant step in the
//! code carries a `§7.x` cross-reference:
//!
//! | Layer | PRD | Module |
//! |---|---|---|
//! | Group & NUMS generators (Ristretto255) | §7.1 | [`params`] |
//! | Pedersen commitments | §7.2 | [`pedersen`] |
//! | Schnorr proof of knowledge of an opening | §7.3 | [`schnorr`] |
//! | Bit OR-proof (Chaum–Pedersen / CDS) | §7.4 | [`range`] |
//! | Range proof by bit decomposition | §7.5 | [`range`] |
//! | Age predicate → range statement | §7.6 | [`age`] |
//! | Strong Fiat–Shamir (full-statement + nonce binding) | §7.7 | [`transcript`], [`age`] |
//! | Credential binding, Tier A (Ed25519 over `C_D`) | §7.8 | [`credential`] |
//! | HVZK simulator (§7.3) used for the §17 X-ray | §7.3 / §17 | [`simulator`] |
//! | Cheating provers for the §17 demonstration | §17 | [`adversary`] |
//!
//! No curve arithmetic is hand-rolled: all group operations come from
//! `curve25519-dalek` (constant-time scalar multiplication), signatures from
//! `ed25519-dalek`, hashing from `sha2`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod adversary;
pub mod age;
pub mod credential;
pub mod date;
pub mod error;
pub mod params;
pub mod pedersen;
pub mod range;
pub mod rng;
pub mod schnorr;
pub mod simulator;
pub mod transcript;
pub mod wire;

pub use age::{prove_age, prove_age_with_rng, verify_age, AgeProof, Statement, Verified};
pub use credential::{Credential, IssuerKey, IssuerPublicKey};
pub use date::Date;
pub use error::{CredentialError, ProveError, VerifyError};
pub use params::Params;

/// Wire-format version carried by every serialised object (FR-8).
pub const WIRE_VERSION: u8 = 1;

/// Human-readable protocol suite identifier.
pub const SUITE: &str = "gudhapramana/v1/tier-a/ristretto255/sha512";
