//! Key derivation, key wrapping, and streaming chunk encryption.
//!
//! Phase 1 implementation targets (see docs/PLAN.md):
//! - `derive_kek(password, salt, params) -> Kek`         (Argon2id)
//! - `wrap_dk(kek, dk) -> [u8; 60]` / `unwrap_dk(...)`   (AES-256-GCM)
//! - `encrypt_chunk(dk, uuid, seq, plain) -> Vec<u8>`    (nonce|len|ct|tag,
//!    AAD = uuid ‖ seq so chunks can't be reordered or cross-spliced)
//! - `decrypt_chunk(...)` mirror
//!
//! All key material must be held in `zeroize`-on-drop wrappers.

// TODO(phase-1): implement per SPEC.md §Keys.
