//! Master recovery key: generation, display encoding, and DK wrapping.
//!
//! First run: generate 256-bit key, present as 8×4 Crockford-base32 groups
//! (e.g. `K7Q2-9FWX-...`), offer recovery-file export. Derive KEK_mk via HKDF
//! and wrap every container's DK with it so master unlock bypasses lockout.

// TODO(phase-2): implement per SPEC.md §Keys.
