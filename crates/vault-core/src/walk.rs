//! Parallel folder traversal + streaming pipeline.
//!
//! Reader threads feed 1 MiB chunks into a rayon-encrypted bounded channel so
//! working set stays < 50 MB regardless of folder size. Must handle:
//! `\\?\` long paths, unicode names, empty dirs, reparse points / OneDrive
//! placeholders (warn, don't recurse), files locked by other processes
//! (abort whole operation — a folder locks fully or not at all).

// TODO(phase-1): implement.
