//! Folder traversal: produce the manifest entry list for a lock operation.
//!
//! Policy: a folder locks fully or not at all — symlinks/reparse points and
//! unreadable files abort the scan rather than being silently skipped.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::{Result, VaultError};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Relative path with `/` separators, e.g. `sub/inner/file.txt`.
    pub rel_path: String,
    pub size: u64,
    /// Modification time, unix seconds (0 if unavailable).
    pub mtime: u64,
    pub is_dir: bool,
    pub readonly: bool,
}

pub struct FolderScan {
    /// Directories first (creation order), then files.
    pub entries: Vec<Entry>,
    pub total_bytes: u64,
}

pub fn scan(root: &Path) -> Result<FolderScan> {
    let meta = fs::symlink_metadata(root)?;
    if !meta.is_dir() {
        return Err(VaultError::Unsupported(format!("{} is not a directory", root.display())));
    }
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    let mut total = 0u64;
    walk_into(root, root, &mut dirs, &mut files, &mut total)?;
    dirs.extend(files);
    Ok(FolderScan { entries: dirs, total_bytes: total })
}

fn walk_into(
    root: &Path,
    dir: &Path,
    dirs: &mut Vec<Entry>,
    files: &mut Vec<Entry>,
    total: &mut u64,
) -> Result<()> {
    for item in fs::read_dir(dir)? {
        let item = item?;
        let path = item.path();
        let meta = fs::symlink_metadata(&path)?;
        let rel = rel_path(root, &path)?;
        if meta.file_type().is_symlink() {
            return Err(VaultError::Unsupported(format!(
                "symlink or reparse point not supported: {rel}"
            )));
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if meta.is_dir() {
            dirs.push(Entry {
                rel_path: rel,
                size: 0,
                mtime,
                is_dir: true,
                readonly: false,
            });
            walk_into(root, &path, dirs, files, total)?;
        } else {
            *total += meta.len();
            files.push(Entry {
                rel_path: rel,
                size: meta.len(),
                mtime,
                is_dir: false,
                readonly: meta.permissions().readonly(),
            });
        }
    }
    Ok(())
}

fn rel_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|_| VaultError::Other(format!("path escapes root: {}", path.display())))?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    Ok(parts.join("/"))
}
