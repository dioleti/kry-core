use std::ffi::{CStr, CString};
use std::fs;
use tempfile::tempdir;

use kry_core::{
    ERR_ALREADY_ENCRYPTED, ERR_INVALID_PASSWORD_UTF8, ERR_INVALID_PATH_UTF8, ERR_NOT_DLK,
    ERR_NULL_PASSWORD, ERR_NULL_PATH, ERR_OPERATION_FAILED, ERR_SUCCESS, ERR_WRONG_PASSWORD,
    decrypt, encrypt, version,
};

#[test]
fn version_must_be_valid() {
    let ptr = version();
    assert!(!ptr.is_null());

    let version_str = unsafe { CStr::from_ptr(ptr) };
    assert_eq!(version_str.to_str().unwrap(), "1.0.0"); // Removido o \0 daqui
}

#[test]
fn test_version_returns_valid_cstr() {
    let ptr = version();
    assert!(!ptr.is_null());

    let c_str = unsafe { CStr::from_ptr(ptr) };
    let str_slice = c_str.to_str().expect("version deve ser um UTF-8 válido");
    assert!(!str_is_empty_or_something(str_slice));
}

fn str_is_empty_or_something(s: &str) -> bool {
    s.is_empty()
}

#[test]
fn test_encrypt_null_pointers() {
    let valid_str = CString::new("test.txt").unwrap();
    let valid_ptr = valid_str.as_ptr();

    unsafe {
        assert_eq!(encrypt(std::ptr::null(), valid_ptr), ERR_NULL_PATH);
        assert_eq!(encrypt(valid_ptr, std::ptr::null()), ERR_NULL_PASSWORD);
        assert_eq!(encrypt(std::ptr::null(), std::ptr::null()), ERR_NULL_PATH);
    }
}

#[test]
fn test_decrypt_null_pointers() {
    let valid_str = CString::new("test.txt").unwrap();
    let valid_ptr = valid_str.as_ptr();

    unsafe {
        assert_eq!(decrypt(std::ptr::null(), valid_ptr), ERR_NULL_PATH);
        assert_eq!(decrypt(valid_ptr, std::ptr::null()), ERR_NULL_PASSWORD);
    }
}

#[test]
fn test_encrypt_invalid_utf8() {
    let invalid_bytes: Vec<u8> = vec![0xff, 0xfe, 0x00];
    let invalid_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(&invalid_bytes) };
    let invalid_ptr = invalid_cstr.as_ptr();

    let valid_str = CString::new("senha123").unwrap();
    let valid_ptr = valid_str.as_ptr();

    unsafe {
        assert_eq!(encrypt(invalid_ptr, valid_ptr), ERR_INVALID_PATH_UTF8);
        assert_eq!(encrypt(valid_ptr, invalid_ptr), ERR_INVALID_PASSWORD_UTF8);
    }
}

#[test]
fn test_decrypt_invalid_utf8() {
    let invalid_bytes: Vec<u8> = vec![0xff, 0xfe, 0x00];
    let invalid_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(&invalid_bytes) };
    let invalid_ptr = invalid_cstr.as_ptr();

    let valid_str = CString::new("senha123").unwrap();
    let valid_ptr = valid_str.as_ptr();

    unsafe {
        assert_eq!(decrypt(invalid_ptr, valid_ptr), ERR_INVALID_PATH_UTF8);
        assert_eq!(decrypt(valid_ptr, invalid_ptr), ERR_INVALID_PASSWORD_UTF8);
    }
}

#[test]
fn test_encrypt_decrypt_operation_failure() {
    let path_txt = CString::new("arquivo_que_nao_existe_12345.txt").unwrap();
    let path_dlk = CString::new("arquivo_que_nao_existe_12345.dlk").unwrap();
    let password = CString::new("minhasenha").unwrap();

    unsafe {
        let enc_res = encrypt(path_txt.as_ptr(), password.as_ptr());
        assert_eq!(enc_res, ERR_OPERATION_FAILED);

        let dec_res = decrypt(path_dlk.as_ptr(), password.as_ptr());
        assert_eq!(dec_res, ERR_OPERATION_FAILED);
    }
}
#[test]
fn test_ffi_encrypt_already_dlk() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("arquivo.txt.dlk");
    fs::write(&file_path, b"conteudo").unwrap();

    let c_path = CString::new(file_path.to_str().unwrap()).unwrap();
    let c_pass = CString::new("senha123").unwrap();

    unsafe {
        let res = encrypt(c_path.as_ptr(), c_pass.as_ptr());
        assert_eq!(res, ERR_ALREADY_ENCRYPTED);
    }
}

#[test]
fn test_ffi_decrypt_not_dlk() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("documento.txt");
    fs::write(&file_path, b"conteudo plano").unwrap();

    let c_path = CString::new(file_path.to_str().unwrap()).unwrap();
    let c_pass = CString::new("senha123").unwrap();

    unsafe {
        let res = decrypt(c_path.as_ptr(), c_pass.as_ptr());
        assert_eq!(res, ERR_NOT_DLK);
    }
}

#[test]
fn test_ffi_decrypt_wrong_password() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("segredo.txt");
    fs::write(&file_path, b"conteudo").unwrap();

    let c_path_str = file_path.to_str().unwrap().to_string();
    let c_pass_correct = CString::new("correta").unwrap();
    let c_pass_wrong = CString::new("errada").unwrap();

    let c_path = CString::new(c_path_str.clone()).unwrap();

    unsafe {
        assert_eq!(
            encrypt(c_path.as_ptr(), c_pass_correct.as_ptr()),
            ERR_SUCCESS
        );
    }

    let dlk_path_buf = dir.path().join("segredo.dlk");
    let c_dlk_path = CString::new(dlk_path_buf.to_str().unwrap()).unwrap();

    unsafe {
        let res = decrypt(c_dlk_path.as_ptr(), c_pass_wrong.as_ptr());
        assert_eq!(res, ERR_WRONG_PASSWORD);
    }
}
