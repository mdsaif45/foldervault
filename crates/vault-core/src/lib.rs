//! vault-core — container format, crypto, and lockout logic for FolderVault.
//!
//! Deliberately free of any UI or Win32 dependency so every security-relevant
//! path is unit-testable cross-platform. See docs/SPEC.md for the wire format.

pub mod crypto;
pub mod format;
pub mod lockout;
pub mod recovery;
pub mod walk;

use thiserror::Error;

/// Plaintext chunk size for streaming encryption (see SPEC.md).
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// Container magic: "FVLT" + version 1.
pub const MAGIC: [u8; 8] = *b"FVLT\x00\x01\x00\x00";

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("wrong password ({attempts_left} attempts remaining)")]
    WrongPassword { attempts_left: u32 },
    #[error("locked out until {until_unix} (unix time)")]
    LockedOut { until_unix: u64 },
    #[error("container is corrupt or has been tampered with")]
    Tampered,
    #[error("not a FolderVault container")]
    BadMagic,
    #[error("unsupported container version")]
    BadVersion,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
