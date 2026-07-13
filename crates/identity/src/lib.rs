use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use crypto::{hash_bytes, IdentityKeypair, PublicIdentityKey, SignatureBytes};
use model::{NetworkId, PeerId};
use rand::{rngs::OsRng, RngCore};
use scrypt::{scrypt, Params as ScryptParams};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid keystore passphrase or ciphertext")]
    InvalidKeystore,
    #[error("scrypt key derivation failed")]
    KeyDerivation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCredential {
    pub network_id: NetworkId,
    pub peer_id: PeerId,
    pub session_public_key: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub protocol_versions: Vec<String>,
    pub key_epoch: u64,
    pub nonce: [u8; 16],
    pub identity_signature: SignatureBytes,
}

impl SessionCredential {
    pub fn issue(
        network_id: NetworkId,
        identity: &IdentityKeypair,
        session_public_key: [u8; 32],
        protocol_versions: Vec<String>,
        ttl_secs: u64,
        key_epoch: u64,
    ) -> Self {
        let issued_at = now_epoch_secs();
        let expires_at = issued_at + ttl_secs;
        let mut nonce = [0_u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let peer_id = identity.peer_id();

        let unsigned = SessionCredentialUnsigned {
            network_id: network_id.clone(),
            peer_id: peer_id.clone(),
            session_public_key,
            issued_at,
            expires_at,
            protocol_versions: protocol_versions.clone(),
            key_epoch,
            nonce,
        };
        let canonical = serde_json::to_vec(&unsigned).expect("session credential serialization");

        Self {
            network_id,
            peer_id,
            session_public_key,
            issued_at,
            expires_at,
            protocol_versions,
            key_epoch,
            nonce,
            identity_signature: identity.sign(&canonical),
        }
    }

    pub fn verify(&self, public_key: &PublicIdentityKey) -> Result<(), IdentityError> {
        let canonical = serde_json::to_vec(&SessionCredentialUnsigned::from(self.clone()))?;
        self.identity_signature
            .verify(public_key, &canonical)
            .map_err(|_| IdentityError::InvalidKeystore)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionCredentialUnsigned {
    network_id: NetworkId,
    peer_id: PeerId,
    session_public_key: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    protocol_versions: Vec<String>,
    key_epoch: u64,
    nonce: [u8; 16],
}

impl From<SessionCredential> for SessionCredentialUnsigned {
    fn from(value: SessionCredential) -> Self {
        Self {
            network_id: value.network_id,
            peer_id: value.peer_id,
            session_public_key: value.session_public_key,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            protocol_versions: value.protocol_versions,
            key_epoch: value.key_epoch,
            nonce: value.nonce,
        }
    }
}

pub trait IdentityKeystore {
    fn load(&self, passphrase: &str) -> Result<IdentityKeypair, IdentityError>;
    fn store(&self, keypair: &IdentityKeypair, passphrase: &str) -> Result<(), IdentityError>;
}

#[derive(Debug, Clone)]
pub struct FileKeystore {
    routing: PathBuf,
}

impl FileKeystore {
    pub fn new(routing: impl Into<PathBuf>) -> Self {
        Self {
            routing: routing.into(),
        }
    }

    pub fn routing(&self) -> &Path {
        &self.routing
    }
}

impl IdentityKeystore for FileKeystore {
    fn load(&self, passphrase: &str) -> Result<IdentityKeypair, IdentityError> {
        let blob: EncryptedKeyFile = serde_json::from_slice(&fs::read(&self.routing)?)?;
        let mut key = derive_file_key(passphrase.as_bytes(), &blob.salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&blob.nonce),
                BASE64
                    .decode(blob.ciphertext.as_bytes())
                    .map_err(|_| IdentityError::InvalidKeystore)?
                    .as_ref(),
            )
            .map_err(|_| IdentityError::InvalidKeystore)?;
        key.zeroize();
        let secret: [u8; 32] = plaintext
            .try_into()
            .map_err(|_| IdentityError::InvalidKeystore)?;
        Ok(IdentityKeypair::from_secret_bytes(secret))
    }

    fn store(&self, keypair: &IdentityKeypair, passphrase: &str) -> Result<(), IdentityError> {
        let mut salt = [0_u8; 16];
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let mut key = derive_file_key(passphrase.as_bytes(), &salt)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let secret = keypair.secret_bytes();
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), secret.as_ref())
            .map_err(|_| IdentityError::InvalidKeystore)?;
        key.zeroize();

        let blob = EncryptedKeyFile {
            version: 1,
            kdf: "scrypt".to_string(),
            salt,
            nonce,
            ciphertext: BASE64.encode(&ciphertext),
            public_key_hash: hex::encode(hash_bytes(&keypair.public_key().bytes)),
        };
        fs::write(&self.routing, serde_json::to_vec_pretty(&blob)?)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedKeyFile {
    version: u8,
    kdf: String,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: String,
    public_key_hash: String,
}

fn derive_file_key(passphrase: &[u8], salt: &[u8; 16]) -> Result<[u8; 32], IdentityError> {
    let params = ScryptParams::recommended();
    let mut key = [0_u8; 32];
    scrypt(passphrase, salt, &params, &mut key).map_err(|_| IdentityError::KeyDerivation)?;
    Ok(key)
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use std::env;

    use crypto::SessionKeypair;
    use model::NetworkId;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn file_keystore_roundtrips() {
        let keypair = IdentityKeypair::generate(&mut OsRng);
        let routing = env::temp_dir().join(format!("identity-key-{}.json", now_epoch_secs()));
        let store = FileKeystore::new(&routing);
        store
            .store(&keypair, "correct horse battery staple")
            .unwrap();
        let loaded = store.load("correct horse battery staple").unwrap();
        assert_eq!(keypair.peer_id(), loaded.peer_id());
        let _ = fs::remove_file(routing);
    }

    #[test]
    fn session_credentials_are_signed() {
        let identity = IdentityKeypair::generate(&mut OsRng);
        let session = SessionKeypair::generate(&mut OsRng);
        let credential = SessionCredential::issue(
            NetworkId::derive("personalcloud-prod"),
            &identity,
            session.public_key_bytes(),
            vec!["transport/1".to_string()],
            60,
            1,
        );
        credential.verify(&identity.public_key()).unwrap();
    }
}
