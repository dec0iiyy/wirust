//! Files that hold secrets (the UI link with its token, session files): owner-only modes,
//! no following of a symlink someone planted at the path, and warnings when others could
//! read the file or replace it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// Fails when `path` itself is a symbolic link. A missing path is fine.
///
/// # Errors
///
/// Fails on a symbolic link, or when `path` cannot be examined.
pub fn refuse_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is a symbolic link; refusing to write a secret through it",
                path.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Replaces `path` with `contents` atomically: a new file in the same directory, created
/// exclusively with mode 0600 (Unix) before anything is written, then renamed over `path`.
/// A symbolic link at `path` is refused, so a link planted in a shared directory cannot
/// redirect the write.
///
/// # Errors
///
/// Fails on a symbolic link at `path`, or when creating, writing or renaming fails.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    refuse_symlink(path)?;
    let temp = temp_path(path);
    let written = create_owner_only(&temp).and_then(|mut file| {
        file.write_all(contents)?;
        file.sync_all()
    });
    let renamed = written.and_then(|()| fs::rename(&temp, path));
    if renamed.is_err() {
        let _ = fs::remove_file(&temp);
    }
    renamed
}

/// A fresh name next to `path`: `.NAME.PID.NANOS.tmp`.
fn temp_path(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    path.with_file_name(format!(".{name}.{}.{nanos}.tmp", std::process::id()))
}

/// Creates `path`, which must not exist (a symlink there counts as existing), mode 0600.
fn create_owner_only(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// A warning when the directory of `path` lets other users replace files in it: group or
/// world writable without the sticky bit (Unix only; `None` elsewhere).
#[must_use]
pub fn shared_directory_warning(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let mode = fs::metadata(parent).ok()?.permissions().mode();
        (mode & 0o022 != 0 && mode & 0o1000 == 0).then(|| {
            format!(
                "{} is writable by other users (mode {:o}); they could replace {}",
                parent.display(),
                mode & 0o7777,
                path.display()
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// A warning when `path` is readable by its group or by everyone (Unix only).
#[must_use]
pub fn readable_by_others_warning(path: &Path) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(path).ok()?.permissions().mode();
        (mode & 0o044 != 0).then(|| {
            format!(
                "{} is readable by other users (mode {:o}); chmod 600 it",
                path.display(),
                mode & 0o777
            )
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Narrows an open file to mode 0600 when it is wider; `true` when it changed (Unix only).
///
/// # Errors
///
/// Fails when the mode cannot be read or set.
pub fn narrow_to_owner(file: &File) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        /// Permission bits of the group and of everyone.
        const OTHERS: u32 = 0o077;
        let wider = file.metadata()?.permissions().mode() & OTHERS != 0;
        if wider {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        Ok(wider)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(false)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{}-private-{name}-{}",
            crate::NAME,
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn warns_about_shared_directories_and_readable_files() -> io::Result<()> {
        let dir = temp_dir("modes");
        let file = dir.join("f");
        fs::write(&file, "x")?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600))?;
        assert_eq!(shared_directory_warning(&file), None);
        assert_eq!(readable_by_others_warning(&file), None);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))?;
        assert!(shared_directory_warning(&file).is_some());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1777))?;
        assert_eq!(shared_directory_warning(&file), None, "sticky: like /tmp");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644))?;
        assert!(readable_by_others_warning(&file).is_some());
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        fs::remove_dir_all(dir)
    }
}
