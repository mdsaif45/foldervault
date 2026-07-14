//! Container header + manifest read/write (SPEC.md layout).
//!
//! Phase 1 targets:
//! - `Header { uuid, salt, kdf_params, wrapped_dk_pw, wrapped_dk_mk, lockout, .. }`
//!   with `read_from`/`write_to` that verify/emit the trailing HMAC-SHA256.
//! - Encrypted bincode manifest of `Entry { rel_path, size, mtime, attrs, .. }`.
//! - `lock_folder(src_dir, dest_file, password, master_pub, progress_cb)`
//! - `unlock_container(file, credentials, dest_dir, progress_cb)`
//!   Both follow the atomic tmp-write → fsync → rename → verify → delete dance
//!   from PLAN.md §Crash safety (journal lands in phase 2).

// TODO(phase-1): implement per SPEC.md.
