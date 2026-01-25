use chacha20poly1305::{aead::Aead, KeyInit};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[allow(dead_code)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("invalid kdf parameters")]
    InvalidParams(argon2::Error),
    #[error("key derivation failed")]
    DerivationFailed(argon2::Error),
}

const MIB: u32 = 1024;
const MEMORY_COST_KIB: u32 = 64 * MIB;

/// Hash data using Argon2id with a salt.
/// Returns hex-encoded 32-byte hash.
///
/// This is a general-purpose Argon2id hash suitable for verification codes,
/// tokens, or any data that needs deterministic hashing with a salt.
pub fn argon2_hash(data: &[u8], salt: &[u8]) -> Result<String, KdfError> {
    let params =
        argon2::Params::new(MEMORY_COST_KIB, 3, 1, Some(32)).map_err(KdfError::InvalidParams)?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(data, salt, hash.as_mut())
        .map_err(KdfError::DerivationFailed)?;

    Ok(hex::encode(hash.as_ref()))
}

/// Hash data using Argon2id, returning raw bytes instead of hex.
/// Returns 32-byte hash wrapped in Zeroizing for security.
///
/// Use this when you need the raw key bytes (e.g., for encryption).
pub fn argon2_hash_raw(data: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    let params =
        argon2::Params::new(MEMORY_COST_KIB, 3, 1, Some(32)).map_err(KdfError::InvalidParams)?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut hash = Zeroizing::new([0u8; 32]);

    argon2
        .hash_password_into(data, salt, hash.as_mut())
        .map_err(KdfError::DerivationFailed)?;

    Ok(hash)
}

/// Derive master key from passphrase
pub fn derive_master_key(pass: &str, salt: &[u8]) -> Result<MasterKey, KdfError> {
    let mut key = Zeroizing::new([0u8; 32]);

    let params =
        argon2::Params::new(MEMORY_COST_KIB, 3, 1, None).map_err(KdfError::InvalidParams)?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    argon2
        .hash_password_into(pass.as_bytes(), salt, key.as_mut())
        .map_err(KdfError::DerivationFailed)?;

    Ok(MasterKey(key))
}

#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Dek(Zeroizing<[u8; 32]>);
impl Dek {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, &'static str> {
        Ok(Dek(Zeroizing::new(*bytes)))
    }
}

/// Generate new DEK for an environment
pub fn generate_dek() -> Dek {
    let mut key = Zeroizing::new([0u8; 32]);
    rand_core::OsRng.fill_bytes(key.as_mut());
    Dek(key)
}

pub struct Nonce(pub [u8; 24]);
pub struct Ciphertext(pub Vec<u8>);

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("AEAD encryption failed")]
    AeadFailed(chacha20poly1305::aead::Error),
}

/// AEAD encrypt
pub fn encrypt(
    plaintext: &[u8],
    dek: &Dek,
    aad: &[u8],
) -> Result<(Nonce, Ciphertext), EncryptError> {
    let key = chacha20poly1305::Key::from(*dek.as_bytes());
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key);

    let mut nonce_bytes = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(EncryptError::AeadFailed)?;

    Ok((Nonce(nonce_bytes), Ciphertext(ct)))
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("AEAD decryption failed")]
    AeadFailed(chacha20poly1305::aead::Error),
}

/// AEAD decrypt
pub fn decrypt(
    ciphertext: &[u8],
    nonce: &Nonce,
    dek: &Dek,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DecryptError> {
    let key = chacha20poly1305::Key::from(*dek.as_bytes());
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key);

    let nonce = chacha20poly1305::XNonce::from(nonce.0);

    let pt = cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(DecryptError::AeadFailed)?;

    Ok(Zeroizing::new(pt))
}

// ──────────────────────────────────────────────────────────────────────────────
// X25519 keypairs for principals (devices)
// ──────────────────────────────────────────────────────────────────────────────

/// Principal keypair (X25519)
pub struct Keypair {
    secret: StaticSecret,
    public: PublicKey,
}

impl Keypair {
    /// Generate a new random X25519 keypair
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Construct keypair from secret key bytes (e.g., from config file)
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the secret key as bytes (for storage)
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Get the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Get the public key as bytes (for storage)
    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }

    /// Derive shared secret with another principal's public key (ECDH)
    pub fn shared_secret(&self, their_public: &PublicKey) -> SharedSecret {
        let secret_bytes = self.secret.diffie_hellman(their_public);
        SharedSecret(Zeroizing::new(*secret_bytes.as_bytes()))
    }
}

impl zeroize::ZeroizeOnDrop for Keypair {}

/// Shared secret derived from ECDH
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SharedSecret(Zeroizing<[u8; 32]>);

impl SharedSecret {
    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Construct a public key from bytes (e.g., from database)
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey, &'static str> {
    if bytes.len() != 32 {
        return Err("public key must be 32 bytes");
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(bytes);
    Ok(PublicKey::from(array))
}

#[derive(Debug, Error)]
pub enum WrapError {
    #[error("AEAD encryption failed")]
    AeadFailed(chacha20poly1305::aead::Error),
}

/// Wrap a key (e.g., KEK or DEK) using a shared secret
pub fn wrap_key(
    key: &[u8],
    shared_secret: &SharedSecret,
    aad: &[u8],
) -> Result<(Nonce, Ciphertext), WrapError> {
    let cipher_key = chacha20poly1305::Key::from(*shared_secret.as_bytes());
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&cipher_key);

    let mut nonce_bytes = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);

    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ct = cipher
        .encrypt(&nonce, chacha20poly1305::aead::Payload { msg: key, aad })
        .map_err(WrapError::AeadFailed)?;

    Ok((Nonce(nonce_bytes), Ciphertext(ct)))
}

#[derive(Debug, Error)]
pub enum UnwrapError {
    #[error("AEAD decryption failed")]
    AeadFailed(chacha20poly1305::aead::Error),
}

/// Unwrap a key using a shared secret
pub fn unwrap_key(
    wrapped: &[u8],
    nonce: &Nonce,
    shared_secret: &SharedSecret,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, UnwrapError> {
    let cipher_key = chacha20poly1305::Key::from(*shared_secret.as_bytes());
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&cipher_key);

    let nonce = chacha20poly1305::XNonce::from(nonce.0);

    let pt = cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload { msg: wrapped, aad },
        )
        .map_err(UnwrapError::AeadFailed)?;

    Ok(Zeroizing::new(pt))
}

// ──────────────────────────────────────────────────────────────────────────────
// Hashing utilities
// ──────────────────────────────────────────────────────────────────────────────

/// Hash data with SHA256 (for invite secret lookup, etc.)
pub fn hash_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_round_trip_basic() {
        let salt = b"not_random_salt_just_for_test";
        let master = derive_master_key("password", salt).unwrap();
        let dek = generate_dek();

        let plaintext = b"super-secret";
        let aad = b"project:foo|env:dev|key:DB_PASSWORD";

        let (nonce, ct) = encrypt(plaintext, &dek, aad).unwrap();
        let decrypted = decrypt(&ct.0, &nonce, &dek, aad).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
        drop(master);
    }

    #[test]
    fn decrypt_fails_on_tamper() {
        let dek = generate_dek();
        let (nonce, mut ct) = encrypt(b"hello", &dek, b"aad").unwrap();

        // flip a bit
        ct.0[0] ^= 0x01;
        assert!(decrypt(&ct.0, &nonce, &dek, b"aad").is_err());

        // wrong AAD
        let (nonce2, ct2) = encrypt(b"hello", &dek, b"aad").unwrap();
        assert!(decrypt(&ct2.0, &nonce2, &dek, b"other").is_err());
    }

    #[test]
    fn tampering_ciphertext_fails() {
        let dek = generate_dek();
        let (nonce, mut ct) = encrypt(b"hello", &dek, b"aad").unwrap();

        // Flip a bit in ciphertext
        ct.0[0] ^= 0x01;

        assert!(decrypt(&ct.0, &nonce, &dek, b"aad").is_err());
    }

    #[test]
    fn tampering_nonce_fails() {
        let dek = generate_dek();
        let (nonce, ct) = encrypt(b"hello", &dek, b"aad").unwrap();

        let mut bad_nonce = nonce;
        bad_nonce.0[0] ^= 0x01;

        assert!(decrypt(&ct.0, &bad_nonce, &dek, b"aad").is_err());
    }

    #[test]
    fn tampering_aad_fails() {
        let dek = generate_dek();
        let (nonce, ct) = encrypt(b"hello", &dek, b"good-aad").unwrap();

        assert!(decrypt(&ct.0, &nonce, &dek, b"bad-aad").is_err());
    }

    #[test]
    fn empty_plaintext_ok() {
        let dek = generate_dek();
        let (nonce, ct) = encrypt(b"", &dek, b"aad").unwrap();
        let dec = decrypt(&ct.0, &nonce, &dek, b"aad").unwrap();
        assert_eq!(dec.len(), 0);
    }

    #[test]
    fn kdf_fails_on_short_salt() {
        assert!(derive_master_key("pwd", b"short").is_err());
    }

    #[test]
    fn sensitive_types_impl_zeroize() {
        fn assert_zeroize<T: zeroize::Zeroize>() {}
        assert_zeroize::<Dek>();
        assert_zeroize::<MasterKey>();
        assert_zeroize::<SharedSecret>();
    }

    // ───────────────────────────── X25519 Tests ─────────────────────────────

    #[test]
    fn keypair_generation() {
        let kp = Keypair::generate();
        let pk_bytes = kp.public_key_bytes();
        assert_eq!(pk_bytes.len(), 32);
    }

    #[test]
    fn public_key_roundtrip() {
        let kp = Keypair::generate();
        let bytes = kp.public_key_bytes();
        let pk = public_key_from_bytes(&bytes).unwrap();
        assert_eq!(pk.as_bytes(), &bytes);
    }

    #[test]
    fn public_key_from_bytes_validates_length() {
        assert!(public_key_from_bytes(&[0u8; 31]).is_err());
        assert!(public_key_from_bytes(&[0u8; 33]).is_err());
        assert!(public_key_from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn ecdh_shared_secret_is_symmetric() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let alice_shared = alice.shared_secret(bob.public_key());
        let bob_shared = bob.shared_secret(alice.public_key());

        // Both parties should derive the same shared secret
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn key_wrap_unwrap_roundtrip() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        // Alice wraps a key for Bob
        let kek = b"workspace-key-encryption-key-32b";
        let shared = alice.shared_secret(bob.public_key());
        let aad = b"workspace:uuid-here";
        let (nonce, wrapped) = wrap_key(kek, &shared, aad).unwrap();

        // Bob unwraps the key
        let bob_shared = bob.shared_secret(alice.public_key());
        let unwrapped = unwrap_key(&wrapped.0, &nonce, &bob_shared, aad).unwrap();

        assert_eq!(&unwrapped[..], kek);
    }

    #[test]
    fn key_unwrap_fails_with_wrong_key() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();
        let eve = Keypair::generate();

        let kek = b"secret-key";
        let shared = alice.shared_secret(bob.public_key());
        let (nonce, wrapped) = wrap_key(kek, &shared, b"aad").unwrap();

        // Eve shouldn't be able to unwrap
        let eve_shared = eve.shared_secret(alice.public_key());
        assert!(unwrap_key(&wrapped.0, &nonce, &eve_shared, b"aad").is_err());
    }

    #[test]
    fn key_unwrap_fails_with_tampered_ciphertext() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let kek = b"secret-key";
        let shared = alice.shared_secret(bob.public_key());
        let (nonce, mut wrapped) = wrap_key(kek, &shared, b"aad").unwrap();

        // Tamper with ciphertext
        wrapped.0[0] ^= 0x01;

        let bob_shared = bob.shared_secret(alice.public_key());
        assert!(unwrap_key(&wrapped.0, &nonce, &bob_shared, b"aad").is_err());
    }

    #[test]
    fn key_unwrap_fails_with_wrong_aad() {
        let alice = Keypair::generate();
        let bob = Keypair::generate();

        let kek = b"secret-key";
        let shared = alice.shared_secret(bob.public_key());
        let (nonce, wrapped) = wrap_key(kek, &shared, b"good-aad").unwrap();

        let bob_shared = bob.shared_secret(alice.public_key());
        assert!(unwrap_key(&wrapped.0, &nonce, &bob_shared, b"bad-aad").is_err());
    }

    // ───────────────────────────── Argon2 Hash Tests ─────────────────────────────

    #[test]
    fn argon2_hash_is_deterministic() {
        let data = b"123456";
        let salt = b"test@example.com";

        let hash1 = argon2_hash(data, salt).unwrap();
        let hash2 = argon2_hash(data, salt).unwrap();

        assert_eq!(hash1, hash2, "Same input should produce same hash");
    }

    #[test]
    fn argon2_hash_different_inputs() {
        let salt = b"test@example.com";

        let hash1 = argon2_hash(b"123456", salt).unwrap();
        let hash2 = argon2_hash(b"654321", salt).unwrap();

        assert_ne!(
            hash1, hash2,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn argon2_hash_different_salts() {
        let data = b"123456";

        let hash1 = argon2_hash(data, b"test@example.com").unwrap();
        let hash2 = argon2_hash(data, b"other@example.com").unwrap();

        assert_ne!(
            hash1, hash2,
            "Different salts should produce different hashes"
        );
    }

    #[test]
    fn argon2_hash_raw_is_deterministic() {
        let data = b"123456";
        let salt = b"test@example.com";

        let hash1 = argon2_hash_raw(data, salt).unwrap();
        let hash2 = argon2_hash_raw(data, salt).unwrap();

        assert_eq!(*hash1, *hash2, "Same input should produce same hash");
    }
}
