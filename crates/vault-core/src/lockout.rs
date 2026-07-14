//! 3-attempts / 24-hour lockout state machine (SPEC.md §Lockout).
//!
//! State lives in the container header (HMAC'd) and is mirrored by the caller
//! (vault-app) into HKCU; this module is pure logic + header mutation:
//! - `check(header, now) -> Ok | LockedOut { until }`
//! - `record_failure(header, now)` → increments, arms 24 h lock on 3rd fail
//! - `reset(header)` on successful unlock (password or master)
//! - tamper rule: HMAC mismatch or mirror disagreement ⇒ treat as locked out.

pub const MAX_ATTEMPTS: u32 = 3;
pub const LOCKOUT_SECS: u64 = 24 * 60 * 60;

// TODO(phase-1): implement + unit-test clock-rollback behavior.
