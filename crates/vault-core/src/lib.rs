//! vault-core — container format, crypto, and lockout logic for FolderVault.
//!
//! Deliberately free of any UI or Win32 dependency so every security-relevant
//! path is unit-testable cross-platform. See docs/SPEC.md for the wire format.

pub mod crypto;
pub mod format;
pub mod journal;
pub mod lockout;
pub mod recovery;
pub mod secrets;
pub mod trash;
pub mod walk;

use std::path::PathBuf;
use thiserror::Error;

/// Plaintext chunk size for streaming encryption (see SPEC.md).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Container magic: "FVLT" + format version 1.
pub const MAGIC: [u8; 4] = *b"FVLT";
pub const VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("wrong password ({attempts_left} attempts remaining)")]
    WrongPassword { attempts_left: u32 },
    #[error("locked out until unix time {until_unix}")]
    LockedOut { until_unix: u64 },
    #[error("container is corrupt or has been tampered with")]
    Tampered,
    #[error("not a FolderVault container")]
    BadMagic,
    #[error("unsupported container version {0}")]
    BadVersion(u32),
    #[error("destination already exists: {0}")]
    Exists(PathBuf),
    #[error("unsupported item: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
