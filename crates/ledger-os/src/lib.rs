//! Everything in the ledger that differs by operating system, behind one portable
//! API. Each item picks the system's behaviour at compile time with `#[cfg]`;
//! nothing here asks which system it is on while running.

use std::fs::{self, File};
use std::io::{self, Write as _};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A whole file, mapped read-only into memory.
#[derive(Debug)]
pub struct Mapped(memmap2::Mmap);

impl Deref for Mapped {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Maps the file at `path`. An empty file maps to an empty slice.
///
/// # Safety
/// Nothing may shorten or rewrite the file while the mapping is alive. On Unix a
/// read past a new end of file kills the process; on every system the bytes could
/// change under a `&[u8]`.
///
/// # Errors
/// The file cannot be opened or mapped.
pub unsafe fn map(path: &Path) -> io::Result<Mapped> {
    let file = File::open(path)?;
    // SAFETY: the caller keeps the file unchanged for as long as the mapping lives.
    Ok(Mapped(unsafe { memmap2::Mmap::map(&file)? }))
}

/// Creates the file `to` holding `bytes`, for a file that is named after its
/// content and never changed. When this returns, the file is on the disk under
/// its name and will be there after a power cut. At no moment, and after no
/// crash, does the name hold part of the content. If the file is already there
/// it is left as it is.
///
/// # Errors
/// The file cannot be written, renamed into place or flushed.
pub fn write_once(to: &Path, bytes: &[u8]) -> io::Result<()> {
    static TEMP: AtomicU64 = AtomicU64::new(0);
    if !to.exists() {
        // A name of its own, so two writers of the same file cannot tear each other.
        let n = TEMP.fetch_add(1, Ordering::Relaxed);
        let tmp = to.with_extension(format!("{}-{n}.tmp", std::process::id()));
        let written = private().open(&tmp).and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, to)) {
            let _ = fs::remove_file(&tmp);
            // Another writer of the same content got there first. Some systems refuse
            // to replace a file that is open, and there is nothing to replace it with.
            if !to.exists() {
                return Err(e);
            }
        }
    }
    // Also when the file was there already: whoever put it there may not have got this far.
    sync_dir(parent(to))
}

/// Creates the directory `dir`, and any missing ones above it, for files only this
/// user should read. When this returns, the directory will be there after a power cut.
///
/// # Errors
/// The directory cannot be created or flushed.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    if !dir.is_dir() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        owner_only(&mut builder);
        builder.create(dir)?;
    }
    sync_dir(parent(dir))
}

/// Locks the file `path`, created if it is not there, for as long as the returned
/// file stays open. `None` if it is locked already, by this process or another.
///
/// # Errors
/// The file cannot be created or opened, or the system cannot lock it.
pub fn lock(path: &Path) -> io::Result<Option<File>> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

/// The directory a path's last name lives in. A bare name lives in the current one.
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// How a new file is opened: it must not exist yet, and where the system has file
/// modes only its owner may read it. Evidence can be a signing key.
#[cfg(unix)]
fn private() -> fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options
}

/// Windows has no file modes; a new file takes the access list of its directory.
#[cfg(not(unix))]
fn private() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    options
}

#[cfg(unix)]
fn owner_only(builder: &mut fs::DirBuilder) {
    use std::os::unix::fs::DirBuilderExt as _;
    builder.mode(0o700);
}

#[cfg(not(unix))]
const fn owner_only(_builder: &mut fs::DirBuilder) {}

/// Makes a new name in `dir` survive a power cut. A rename only changes the
/// directory, and on Unix a directory is flushed like a file.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Windows cannot flush a directory and journals the rename itself. `SQLite` and
/// `RocksDB` do nothing here on Windows either.
#[cfg(not(unix))]
#[allow(
    clippy::unnecessary_wraps,
    reason = "same signature as the Unix version"
)]
const fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// The absolute path of an existing file, with links resolved, in the form other
/// programs accept on their command line.
///
/// # Errors
/// The file does not exist or a directory on the way cannot be read.
pub fn absolute(path: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(path).map(plain)
}

#[cfg(not(windows))]
const fn plain(path: PathBuf) -> PathBuf {
    path
}

/// Windows resolves a path to its `\\?\C:\...` form, which many programs do not
/// take. The prefix is dropped where the plain form means the same.
#[cfg(windows)]
fn plain(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        Some(rest) if !rest.starts_with(r"UNC\") => PathBuf::from(rest),
        _ => path,
    }
}

/// `SQLite` settings that make `synchronous = FULL` mean "on the disk". Apple's
/// `fsync` leaves data in the drive's cache, and `SQLite` only asks for a real
/// flush there when told to. Empty on systems where `fsync` already does.
#[cfg(target_vendor = "apple")]
pub const SQLITE_DURABLE: &str = "PRAGMA fullfsync = ON; PRAGMA checkpoint_fullfsync = ON;";
#[cfg(not(target_vendor = "apple"))]
pub const SQLITE_DURABLE: &str = "";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_written_once_and_maps_back() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("abc123");
        write_once(&file, b"evidence")?;
        // A second writer of the same name changes nothing and is not an error.
        write_once(&file, b"other bytes")?;
        // SAFETY: nothing else knows this file.
        assert_eq!(&unsafe { map(&file) }?[..], b"evidence");
        let names: Vec<_> = fs::read_dir(dir.path())?.collect::<Result<_, _>>()?;
        assert_eq!(names.len(), 1, "a temporary file was left behind");
        write_once(&dir.path().join("empty"), b"")?;
        // SAFETY: as above.
        assert!(unsafe { map(&dir.path().join("empty")) }?.is_empty());
        // A directory that is not there is an error, not a silent success.
        assert!(write_once(&dir.path().join("missing").join("x"), b"x").is_err());
        // A bare file name lives in the current directory, which can be flushed.
        assert_eq!(parent(Path::new("ledger.db.evidence")), Path::new("."));
        assert_eq!(parent(Path::new("a/b")), Path::new("a"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn new_files_and_directories_are_for_their_owner_only() -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let evidence = dir.path().join("l.db.evidence");
        create_private_dir(&evidence)?;
        create_private_dir(&evidence)?;
        write_once(&evidence.join("key"), b"secret")?;
        let mode = |path: &Path| fs::metadata(path).map(|m| m.permissions().mode() & 0o777);
        assert_eq!(mode(&evidence)?, 0o700);
        assert_eq!(mode(&evidence.join("key"))?, 0o600);
        Ok(())
    }

    #[test]
    fn absolute_paths_are_absolute_and_need_the_file() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::write(dir.path().join("f"), b"")?;
        let found = absolute(&dir.path().join(".").join("f"))?;
        assert!(found.is_absolute());
        assert!(found.ends_with("f"));
        assert!(absolute(&dir.path().join("nope")).is_err());
        Ok(())
    }
}
