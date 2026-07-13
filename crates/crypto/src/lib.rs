use std::fmt::{Display, Formatter};

use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use model::{KeyAlgorithm, PeerId};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("signature bytes are invalid")]
    InvalidSignature,
    #[error("public key bytes are invalid")]
    InvalidPublicKey,
    #[error("key material length is invalid")]
    InvalidKeyMaterial,
    #[error("hkdf expansion failed")]
    KeyDerivationFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentityKey {
    pub algorithm: KeyAlgorithm,
    pub bytes: Vec<u8>,
}

impl PublicIdentityKey {
    pub fn as_verifying_key(&self) -> Result<VerifyingKey, CryptoError> {
        let bytes: [u8; 32] = self
            .bytes
            .clone()
            .try_into()
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidPublicKey)
    }

    pub fn peer_id(&self) -> PeerId {
        PeerId::from_public_key(self.algorithm, &self.bytes)
    }
}

#[derive(Clone)]
pub struct IdentityKeypair {
    signing_key: SigningKey,
}

impl IdentityKeypair {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self {
            signing_key: SigningKey::generate(rng),
        }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn public_key(&self) -> PublicIdentityKey {
        PublicIdentityKey {
            algorithm: KeyAlgorithm::Ed25519,
            bytes: self.signing_key.verifying_key().to_bytes().to_vec(),
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.public_key().peer_id()
    }

    pub fn sign(&self, payload: &[u8]) -> SignatureBytes {
        SignatureBytes(self.signing_key.sign(payload).to_bytes().to_vec())
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl Drop for IdentityKeypair {
    fn drop(&mut self) {
        let mut secret = self.signing_key.to_bytes();
        secret.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

impl SignatureBytes {
    pub fn verify(
        &self,
        public_key: &PublicIdentityKey,
        payload: &[u8],
    ) -> Result<(), CryptoError> {
        let signature_bytes: [u8; 64] = self
            .0
            .clone()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let signature = DalekSignature::from_bytes(&signature_bytes);
        public_key
            .as_verifying_key()?
            .verify(payload, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl Display for SignatureBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct SessionKeypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl SessionKeypair {
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let secret = StaticSecret::random_from_rng(rng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn derive_shared_secret(
        &self,
        remote_public_key: [u8; 32],
        info: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        let remote = X25519PublicKey::from(remote_public_key);
        let shared = self.secret.diffie_hellman(&remote);
        let hkdf = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut output = [0_u8; 32];
        hkdf.expand(info, &mut output)
            .map_err(|_| CryptoError::KeyDerivationFailed)?;
        Ok(output)
    }
}

impl Drop for SessionKeypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

pub fn hash_bytes(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

pub fn hkdf_derive(secret: &[u8], context: &[u8]) -> Result<[u8; 32], CryptoError> {
    let hkdf = Hkdf::<Sha256>::new(None, secret);
    let mut output = [0_u8; 32];
    hkdf.expand(context, &mut output)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::*;

    #[test]
    fn ed25519_signatures_verify() {
        let keypair = IdentityKeypair::generate(&mut OsRng);
        let payload = b"quicnet-signed-payload";
        let signature = keypair.sign(payload);
        signature
            .verify(&keypair.public_key(), payload)
            .expect("signature should verify");
    }

    #[test]
    fn peer_id_tracks_public_key() {
        let keypair = IdentityKeypair::generate(&mut OsRng);
        assert_eq!(keypair.peer_id(), keypair.public_key().peer_id());
    }

    #[test]
    fn session_key_exchange_matches() {
        let alice = SessionKeypair::generate(&mut OsRng);
        let bob = SessionKeypair::generate(&mut OsRng);
        let alice_secret = alice
            .derive_shared_secret(bob.public_key_bytes(), b"handshake")
            .expect("alice secret");
        let bob_secret = bob
            .derive_shared_secret(alice.public_key_bytes(), b"handshake")
            .expect("bob secret");
        assert_eq!(alice_secret, bob_secret);
    }
}
