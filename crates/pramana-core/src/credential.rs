//! §7.8 Tier A credential binding and §9.1 issuance (FR-6).
//!
//! The issuer verifies a real birthdate out of band (mocked in the demo), encodes
//! `D = days_since_1900(dob)`, samples `r`, forms `C_D = D·G + r·H`, and signs the
//! serialised point with Ed25519. The wallet receives `{C_D, r, D, sig, issuer_pk}`;
//! `r` and `D` never leave the wallet again.
//!
//! **Known Tier A limitation (documented, not hidden):** `C_D` and `sig` are constant
//! across presentations, so colluding verifiers can link a holder (T5). Tier B
//! (BBS+ re-randomisation) removes this; see `docs/SECURITY.md`.

use crate::date::Date;
use crate::error::CredentialError;
use crate::params::{Params, PARAMS_ID};
use crate::pedersen::commit_u64;
use crate::rng::random_scalar;
use crate::wire::{decode_point, decode_scalar, hexbytes};
use crate::WIRE_VERSION;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Domain-separation prefix for the issuer's signature over `C_D`.
pub const SIG_DOMAIN: &[u8] = b"pramana/credential-sig/v1";

/// The exact bytes the issuer signs: `SIG_DOMAIN ‖ C_D`.
pub fn signing_message(c_d: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + 32);
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(c_d);
    m
}

/// Verify an issuer signature over `C_D` (strict Ed25519: rejects small-order keys
/// and malleable signatures).
pub fn verify_signature(issuer_pk: &[u8; 32], c_d: &[u8; 32], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(issuer_pk) else {
        return false;
    };
    let sig = Signature::from_bytes(sig);
    vk.verify_strict(&signing_message(c_d), &sig).is_ok()
}

/// A trusted issuer's public identity, as published on a verifier's trust list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuerPublicKey {
    /// Display name, e.g. "Demo Authority".
    pub name: String,
    /// Ed25519 public key.
    #[serde(with = "hexbytes")]
    pub public_key: [u8; 32],
}

/// An issuer signing key (mock authority, demo only).
pub struct IssuerKey {
    name: String,
    signing: SigningKey,
}

/// On-disk representation of an issuer key.
#[derive(Serialize, Deserialize)]
pub struct IssuerKeyFile {
    /// Format version.
    pub v: u8,
    /// Always `"pramana-issuer-key"`.
    pub kind: String,
    /// Issuer display name.
    pub name: String,
    /// Ed25519 secret seed.
    #[serde(with = "hexbytes")]
    pub secret_key: [u8; 32],
    /// Ed25519 public key (informational; re-derived on load).
    #[serde(with = "hexbytes")]
    pub public_key: [u8; 32],
}

impl Drop for IssuerKeyFile {
    fn drop(&mut self) {
        self.secret_key.zeroize();
    }
}

impl IssuerKey {
    /// Generate a fresh key.
    pub fn generate<R: RngCore + CryptoRng + ?Sized>(name: &str, rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let k = Self::from_secret(name, &seed);
        seed.zeroize();
        k
    }

    /// Load from a 32-byte Ed25519 seed.
    pub fn from_secret(name: &str, seed: &[u8; 32]) -> Self {
        IssuerKey {
            name: name.to_string(),
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Display name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Public key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Public identity for trust lists.
    pub fn public(&self) -> IssuerPublicKey {
        IssuerPublicKey {
            name: self.name.clone(),
            public_key: self.public_key(),
        }
    }

    /// Serialise to the key-file format.
    pub fn to_file(&self) -> IssuerKeyFile {
        IssuerKeyFile {
            v: WIRE_VERSION,
            kind: "pramana-issuer-key".into(),
            name: self.name.clone(),
            secret_key: self.signing.to_bytes(),
            public_key: self.public_key(),
        }
    }

    /// Load from the key-file format.
    pub fn from_file(f: &IssuerKeyFile) -> Result<Self, CredentialError> {
        if f.v != WIRE_VERSION {
            return Err(CredentialError::UnsupportedVersion(f.v));
        }
        if f.kind != "pramana-issuer-key" {
            return Err(CredentialError::Malformed(
                "not a pramana issuer key".into(),
            ));
        }
        let k = Self::from_secret(&f.name, &f.secret_key);
        if k.public_key() != f.public_key {
            return Err(CredentialError::Malformed(
                "public key does not match secret key".into(),
            ));
        }
        Ok(k)
    }

    /// §9.1 issuance: commit to `D`, sign `C_D`, return the credential.
    ///
    /// `today` is the issuer's current date, used only to reject future birthdates.
    pub fn issue<R: RngCore + CryptoRng + ?Sized>(
        &self,
        p: &Params,
        dob: Date,
        today: Date,
        issued_at: u64,
        rng: &mut R,
    ) -> Result<Credential, CredentialError> {
        if dob > today {
            return Err(CredentialError::FutureBirthdate);
        }
        let d = dob.days_since_epoch();
        if d < 0 {
            return Err(CredentialError::BeforeEpoch);
        }
        let d = d as u32;
        // §9.1 step 2: C_D = D·G + r·H with fresh uniform r (§7.2 perfect hiding).
        let r = random_scalar(rng);
        let c_d = commit_u64(p, d as u64, &r).compress().to_bytes();
        // §9.1 step 3 / §7.8 Tier A: Ed25519 over the serialised point.
        let sig = self.signing.sign(&signing_message(&c_d)).to_bytes();
        Ok(Credential {
            v: WIRE_VERSION,
            kind: "pramana-age-credential".into(),
            params: PARAMS_ID.into(),
            issuer_name: self.name.clone(),
            issuer_pk: self.public_key(),
            c_d,
            sig,
            d,
            r: r.to_bytes(),
            issued_at,
        })
    }
}

/// The holder's credential `{C_D, r, D, sig, issuer_pk, params}` (§9.1 step 4).
/// Contains secrets (`r`, `D`) — it lives only in the wallet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Wire version.
    pub v: u8,
    /// Always `"pramana-age-credential"`.
    pub kind: String,
    /// Parameter-set identifier.
    pub params: String,
    /// Issuer display name.
    pub issuer_name: String,
    /// Issuer Ed25519 public key.
    #[serde(with = "hexbytes")]
    pub issuer_pk: [u8; 32],
    /// `C_D = D·G + r·H`.
    #[serde(with = "hexbytes")]
    pub c_d: [u8; 32],
    /// Ed25519 signature over `SIG_DOMAIN ‖ C_D`.
    #[serde(with = "hexbytes")]
    pub sig: [u8; 64],
    /// Witness: days since 1900-01-01. **Secret.**
    pub d: u32,
    /// Witness: commitment randomness. **Secret.**
    #[serde(with = "hexbytes")]
    pub r: [u8; 32],
    /// Unix time of issuance.
    pub issued_at: u64,
}

impl Credential {
    /// Wallet-side import check: version, opening and signature are all valid.
    pub fn self_check(&self, p: &Params) -> Result<(), CredentialError> {
        if self.v != WIRE_VERSION {
            return Err(CredentialError::UnsupportedVersion(self.v));
        }
        if self.kind != "pramana-age-credential" {
            return Err(CredentialError::Malformed(
                "not a pramana age credential".into(),
            ));
        }
        if self.params != PARAMS_ID {
            return Err(CredentialError::Malformed(format!(
                "unknown parameter set {}",
                self.params
            )));
        }
        let c = decode_point(&self.c_d).map_err(|e| CredentialError::Malformed(e.to_string()))?;
        let r = decode_scalar(&self.r).map_err(|e| CredentialError::Malformed(e.to_string()))?;
        if commit_u64(p, self.d as u64, &r) != c {
            return Err(CredentialError::SelfCheck(
                "(D, r) does not open C_D".into(),
            ));
        }
        if !verify_signature(&self.issuer_pk, &self.c_d, &self.sig) {
            return Err(CredentialError::SelfCheck(
                "issuer signature invalid".into(),
            ));
        }
        Ok(())
    }

    /// The attested birthdate (wallet-only view).
    pub fn birthdate(&self) -> Date {
        Date::from_days_since_epoch(self.d as i64).expect("d is a valid day count")
    }

    /// Parse from JSON and self-check.
    pub fn from_json_checked(p: &Params, s: &str) -> Result<Self, CredentialError> {
        let c: Credential = crate::wire::from_json(s).map_err(CredentialError::Malformed)?;
        c.self_check(p)?;
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::HashDrbg;

    #[test]
    fn issue_and_self_check() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"issuer");
        let k = IssuerKey::generate("Demo Authority", &mut rng);
        let cred = k
            .issue(
                &p,
                Date::parse("2001-04-12").unwrap(),
                Date::parse("2026-11-19").unwrap(),
                0,
                &mut rng,
            )
            .unwrap();
        cred.self_check(&p).unwrap();
        assert_eq!(cred.birthdate().to_string(), "2001-04-12");
        let back = Credential::from_json_checked(&p, &crate::wire::to_json(&cred)).unwrap();
        assert_eq!(back, cred);
        let cbor: Credential = crate::wire::from_cbor(&crate::wire::to_cbor(&cred)).unwrap();
        assert_eq!(cbor, cred);
    }

    #[test]
    fn rejects_future_and_pre_epoch() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"issuer2");
        let k = IssuerKey::generate("X", &mut rng);
        let today = Date::parse("2026-11-19").unwrap();
        assert_eq!(
            k.issue(&p, Date::parse("2027-01-01").unwrap(), today, 0, &mut rng),
            Err(CredentialError::FutureBirthdate)
        );
        assert_eq!(
            k.issue(&p, Date::parse("1899-12-31").unwrap(), today, 0, &mut rng),
            Err(CredentialError::BeforeEpoch)
        );
    }

    #[test]
    fn tampered_credential_fails_self_check() {
        let p = Params::new();
        let mut rng = HashDrbg::from_seed_material(b"issuer3");
        let k = IssuerKey::generate("X", &mut rng);
        let mut cred = k
            .issue(
                &p,
                Date::parse("2001-04-12").unwrap(),
                Date::parse("2026-11-19").unwrap(),
                0,
                &mut rng,
            )
            .unwrap();
        cred.d -= 3650; // claim to be 10 years older
        assert!(cred.self_check(&p).is_err());
    }

    #[test]
    fn key_file_roundtrip() {
        let mut rng = HashDrbg::from_seed_material(b"kf");
        let k = IssuerKey::generate("Demo Authority", &mut rng);
        let f = k.to_file();
        let k2 = IssuerKey::from_file(&f).unwrap();
        assert_eq!(k.public_key(), k2.public_key());
    }
}
