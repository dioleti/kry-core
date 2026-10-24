mod suite;

pub use crate::suite::{KryError, VERSION};
use std::ffi::CStr;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

pub const ERR_SUCCESS: i32 = 0;
pub const ERR_NULL_PATH: i32 = -1;
pub const ERR_NULL_PASSWORD: i32 = -2;
pub const ERR_INVALID_PATH_UTF8: i32 = -3;
pub const ERR_INVALID_PASSWORD_UTF8: i32 = -4;
pub const ERR_OPERATION_FAILED: i32 = -5;
pub const ERR_ALREADY_ENCRYPTED: i32 = -6;
pub const ERR_NOT_DLK: i32 = -7;
pub const ERR_INVALID_HEADER: i32 = -8;
pub const ERR_WRONG_PASSWORD: i32 = -9;

pub fn encrypt_file(path: &Path, password: &str) -> Result<PathBuf, KryError> {
    suite::encrypt_file(path, password)
}

pub fn decrypt_file(path: &Path, password: &str) -> Result<PathBuf, KryError> {
    suite::decrypt_file(path, password)
}

/// Retorna a versão atual do Kry Core.
///
/// A string retornada é uma string C terminada em '\0'
/// e permanece válida durante toda a vida da DLL.
#[unsafe(no_mangle)]
pub extern "C" fn version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

// 0  = Sucesso
// -1 = Path nulo
// -2 = Senha nula
// -3 = Path UTF-8 inválido
// -4 = Senha UTF-8 inválida
// -5 = Falha genérica na operação
// -6 = Arquivo já criptografado (.dlk)
/// Criptografa um arquivo utilizando AES-256-GCM.
///
/// # Safety
///
/// - `path` deve apontar para uma string C válida terminada em '\0'.
/// - `path` não pode ser um ponteiro nulo.
/// - `password` deve apontar para uma string C válida terminada em '\0'.
/// - `password` não pode ser um ponteiro nulo.
/// - Ambos os ponteiros devem permanecer válidos durante toda a execução da função.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn encrypt(path: *const c_char, password: *const c_char) -> i32 {
    if path.is_null() {
        return ERR_NULL_PATH;
    }

    if password.is_null() {
        return ERR_NULL_PASSWORD;
    }

    let path = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(v) => v,
            Err(_) => return ERR_INVALID_PATH_UTF8,
        }
    };

    let password = unsafe {
        match CStr::from_ptr(password).to_str() {
            Ok(v) => v,
            Err(_) => return ERR_INVALID_PASSWORD_UTF8,
        }
    };

    match encrypt_file(Path::new(path), password) {
        Ok(_) => ERR_SUCCESS,
        Err(err) => match err {
            KryError::AlreadyEncrypted => ERR_ALREADY_ENCRYPTED,
            _ => ERR_OPERATION_FAILED,
        },
    }
}

// 0  = Sucesso
// -1 = Path nulo
// -2 = Senha nula
// -3 = Path UTF-8 inválido
// -4 = Senha UTF-8 inválida
// -5 = Falha genérica na operação
// -7 = Não é um arquivo .dlk
// -8 = Cabeçalho inválido ou arquivo corrompido
// -9 = Senha incorreta ou arquivo corrompido
/// Descriptografa um arquivo utilizando AES-256-GCM.
///
/// # Safety
///
/// - `path` deve apontar para uma string C válida terminada em '\0'.
/// - `path` não pode ser um ponteiro nulo.
/// - `password` deve apontar para uma string C válida terminada em '\0'.
/// - `password` não pode ser um ponteiro nulo.
/// - Ambos os ponteiros devem permanecer válidos durante toda a execução da função.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn decrypt(path: *const c_char, password: *const c_char) -> i32 {
    if path.is_null() {
        return ERR_NULL_PATH;
    }

    if password.is_null() {
        return ERR_NULL_PASSWORD;
    }

    let path = unsafe {
        match CStr::from_ptr(path).to_str() {
            Ok(v) => v,
            Err(_) => return ERR_INVALID_PATH_UTF8,
        }
    };

    let password = unsafe {
        match CStr::from_ptr(password).to_str() {
            Ok(v) => v,
            Err(_) => return ERR_INVALID_PASSWORD_UTF8,
        }
    };

    match decrypt_file(Path::new(path), password) {
        Ok(_) => ERR_SUCCESS,
        Err(err) => match err {
            KryError::NotDlkFile => ERR_NOT_DLK,
            KryError::InvalidHeaderOrCorrupt => ERR_INVALID_HEADER,
            KryError::InvalidPasswordOrCorrupt => ERR_WRONG_PASSWORD,
            _ => ERR_OPERATION_FAILED,
        },
    }
}
