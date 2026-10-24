use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use std::path::Path;
use std::{fmt, fs};
use zeroize::Zeroize;

const MAGIC_HEADER: &[u8; 4] = b"KRY1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
pub const VERSION: &[u8] = b"1.0.0\0";

#[derive(Debug, PartialEq, Eq)]
pub enum KryError {
    AlreadyEncrypted,
    NotDlkFile,
    InvalidHeaderOrCorrupt,
    InvalidPasswordOrCorrupt,
    Argon2Error(String),
    AesError(String),
    IoError(String),
}

impl std::error::Error for KryError {}

impl fmt::Display for KryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KryError::AlreadyEncrypted => write!(f, "Already encrypted"),
            KryError::NotDlkFile => write!(f, "Not a .dlk file"),
            KryError::InvalidHeaderOrCorrupt => write!(f, "Invalid header or corrupt"),
            KryError::InvalidPasswordOrCorrupt => write!(f, "Wrong password or corrupt"),
            KryError::Argon2Error(msg) => write!(f, "Argon2 error: {}", msg),
            KryError::AesError(msg) => write!(f, "AES error: {}", msg),
            KryError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], KryError> {
    let mut key = [0u8; 32];
    let params =
        Params::new(131072, 3, 1, Some(32)).map_err(|e| KryError::Argon2Error(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| KryError::Argon2Error(e.to_string()))?;

    Ok(key)
}

pub fn encrypt_file(file_path: &Path, password: &str) -> Result<std::path::PathBuf, KryError> {
    if file_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("dlk"))
    {
        return Err(KryError::AlreadyEncrypted);
    }

    let plaintext = fs::read(file_path).map_err(|e| KryError::IoError(e.to_string()))?;

    let ext_str = file_path
        .extension()
        .map(|e| e.to_string_lossy())
        .unwrap_or_default();

    let ext_bytes = ext_str.as_bytes();

    let mut payload = Vec::with_capacity(1 + ext_bytes.len() + plaintext.len());
    payload.push(ext_bytes.len() as u8);
    payload.extend_from_slice(ext_bytes);
    payload.extend_from_slice(&plaintext);

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];

    rand::fill(&mut salt);
    rand::fill(&mut nonce_bytes);

    let mut key_bytes = derive_key(password, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| KryError::AesError(e.to_string()))?;
    key_bytes.zeroize();

    let nonce = Nonce::try_from(&nonce_bytes[..]).unwrap();

    let mut ciphertext = cipher
        .encrypt(&nonce, payload.as_ref())
        .map_err(|e| KryError::AesError(e.to_string()))?;

    payload.zeroize();

    let mut output_data = Vec::with_capacity(4 + SALT_LEN + NONCE_LEN + ciphertext.len());
    output_data.extend_from_slice(MAGIC_HEADER);
    output_data.extend_from_slice(&salt);
    output_data.extend_from_slice(&nonce_bytes);
    output_data.extend_from_slice(&ciphertext);

    let mut new_path = file_path.to_path_buf();
    new_path.set_extension("dlk");

    fs::write(&new_path, &output_data).map_err(|e| KryError::IoError(e.to_string()))?;
    output_data.zeroize();
    salt.zeroize();
    nonce_bytes.zeroize();
    ciphertext.zeroize();

    if let Err(e) = fs::remove_file(file_path) {
        return Err(KryError::IoError(e.to_string()));
    }

    Ok(new_path)
}

pub fn decrypt_file(file_path: &Path, password: &str) -> Result<std::path::PathBuf, KryError> {
    if !file_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("dlk"))
    {
        return Err(KryError::NotDlkFile);
    }

    let mut data = fs::read(file_path).map_err(|e| KryError::IoError(e.to_string()))?;

    if data.len() < SALT_LEN + NONCE_LEN + 4 || &data[0..4] != MAGIC_HEADER {
        data.zeroize();
        return Err(KryError::InvalidHeaderOrCorrupt);
    }

    let salt = &data[4..4 + SALT_LEN];
    let nonce_bytes = &data[4 + SALT_LEN..4 + SALT_LEN + NONCE_LEN];
    let ciphertext = &data[4 + SALT_LEN + NONCE_LEN..];

    let mut key_bytes = derive_key(password, salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| KryError::AesError(e.to_string()))?;
    key_bytes.zeroize();

    let nonce = Nonce::try_from(nonce_bytes).map_err(|_| KryError::InvalidHeaderOrCorrupt)?;

    let mut decrypted_payload = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| KryError::InvalidPasswordOrCorrupt)?;

    data.zeroize();

    let ext_len = decrypted_payload[0] as usize;
    let ext_bytes = &decrypted_payload[1..1 + ext_len];
    let original_extension = String::from_utf8_lossy(ext_bytes);
    let plaintext = &decrypted_payload[1 + ext_len..];

    let mut new_path = file_path.to_path_buf();
    if original_extension.is_empty() {
        new_path.set_extension("");
    } else {
        new_path.set_extension(original_extension.as_ref());
    }

    fs::write(&new_path, plaintext).map_err(|e| KryError::IoError(e.to_string()))?;
    decrypted_payload.zeroize();

    if let Err(e) = fs::remove_file(file_path) {
        return Err(KryError::IoError(e.to_string()));
    }

    Ok(new_path)
}
