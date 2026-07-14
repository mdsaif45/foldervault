//! Win32 UI layer (phase 3).
//!
//! - window.rs      borderless host: DWM round corners, Mica w/ solid fallback,
//!                  per-monitor DPI v2, drag region, close glyph
//! - lock_dialog    password + confirm + strength meter + options → progress
//! - unlock_dialog  password box, attempt dots, shake-on-fail animation,
//!                  lockout countdown timer, "use master password" flow
//! - progress       determinate bar, MB/s + ETA, cancel-safe

// TODO(phase-3): implement per PLAN.md §UI spec.
