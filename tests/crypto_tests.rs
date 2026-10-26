use std::fs;
use tempfile::tempdir;

use kry_core::{KryError, decrypt_file, encrypt_file};

#[test]
fn encrypt_then_decrypt_should_restore_content() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("teste.txt");
    let original = b"Kry Core Test";
    fs::write(&file_path, original).unwrap();

    let encrypted = encrypt_file(&file_path, "senha123").unwrap();
    assert!(encrypted.exists());

    let restored_path = decrypt_file(&encrypted, "senha123").unwrap();
    let restored = fs::read(&restored_path).unwrap();
    assert_eq!(restored, original);
}

#[test]
fn decrypt_should_fail_with_wrong_password() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("segredo.txt");
    fs::write(&file_path, b"segredo").unwrap();
    let encrypted = encrypt_file(&file_path, "senha-correta").unwrap();

    let result = decrypt_file(&encrypted, "senha-errada");
    assert_eq!(result, Err(KryError::InvalidPasswordOrCorrupt));
}

#[test]
fn decrypt_should_fail_for_invalid_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("fake.dlk");
    fs::write(&file_path, b"arquivo invalido").unwrap();

    let result = decrypt_file(&file_path, "senha");
    assert_eq!(result, Err(KryError::InvalidHeaderOrCorrupt));
}

#[test]
fn encrypt_should_fail_if_already_dlk() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("arquivo.txt.dlk");
    fs::write(&file_path, b"conteudo falso").unwrap();

    let result = encrypt_file(&file_path, "senha123");
    assert_eq!(result, Err(KryError::AlreadyEncrypted));
}

#[test]
fn decrypt_should_fail_if_not_dlk() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("documento.txt");
    fs::write(&file_path, b"conteudo em texto plano").unwrap();

    let result = decrypt_file(&file_path, "senha123");
    assert_eq!(result, Err(KryError::NotDlkFile));
}

#[test]
fn encrypt_file_without_extension() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("arquivo_sem_extensao");
    fs::write(&file_path, b"conteudo").unwrap();

    let encrypted = encrypt_file(&file_path, "senha123").unwrap();
    assert!(encrypted.exists());

    let restored_path = decrypt_file(&encrypted, "senha123").unwrap();
    assert!(restored_path.exists());
}

#[test]
fn decrypt_should_fail_for_corrupted_metadata() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("corrompido.dlk");
    let mut bad_data = Vec::new();
    bad_data.extend_from_slice(b"KRY1");
    bad_data.extend_from_slice(&[0u8; 16]);
    bad_data.extend_from_slice(&[0u8; 12]);
    bad_data.extend_from_slice(b"dados_falsos_nao_cifrados_corretamente");
    fs::write(&file_path, bad_data).unwrap();

    let result = decrypt_file(&file_path, "senha123");
    assert!(result.is_err());
}

#[test]
fn encrypt_empty_file_without_extension() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("vazio");
    fs::write(&file_path, b"").unwrap();

    let encrypted = encrypt_file(&file_path, "senha123").unwrap();
    assert!(encrypted.exists());

    let restored_path = decrypt_file(&encrypted, "senha123").unwrap();
    assert!(restored_path.exists());
    let content = fs::read(&restored_path).unwrap();
    assert!(content.is_empty());
}

#[test]
fn test_kry_error_display() {
    assert_eq!(KryError::AlreadyEncrypted.to_string(), "Already encrypted");
    assert_eq!(KryError::NotDlkFile.to_string(), "Not a .dlk file");
    assert_eq!(
        KryError::InvalidHeaderOrCorrupt.to_string(),
        "Invalid header or corrupt"
    );
    assert_eq!(
        KryError::InvalidPasswordOrCorrupt.to_string(),
        "Wrong password or corrupt"
    );
    assert_eq!(
        KryError::Argon2Error("test".into()).to_string(),
        "Argon2 error: test"
    );
    assert_eq!(
        KryError::AesError("test".into()).to_string(),
        "AES error: test"
    );
    assert_eq!(
        KryError::IoError("test".into()).to_string(),
        "IO error: test"
    );
}
