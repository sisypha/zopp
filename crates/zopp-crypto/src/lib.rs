use chacha20poly1305::{KeyInit, aead::Aead};
use thiserror::Error;
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
}

/// Generate new DEK for an environment
pub fn generate_dek() -> Dek {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::fill(key.as_mut());
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
    rand::fill(&mut nonce_bytes);

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
    }
}
