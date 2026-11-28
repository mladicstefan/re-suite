//! Everything in the ledger that differs by operating system, behind one portable
//! API. Each item picks the system's behaviour at compile time with `#[cfg]`;
//! nothing here asks which system it is on while running.

use std::fmt;
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
    if !to.exists() {
        let tmp = temp(parent(to));
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

/// Copies the regular file `from` into `dir`, under the name `name` gives for the
/// bytes of the copy. Everything [`write_once`] promises holds for the copy, and the
/// name fits the bytes stored even if `from` changes meanwhile. `from` is read a
/// buffer at a time, so memory use does not grow with the file.
///
/// # Errors
/// `from` is not a regular file or cannot be read, or the copy cannot be written,
/// renamed into place or flushed.
pub fn copy_once<N: fmt::Display>(
    from: &Path,
    dir: &Path,
    name: impl FnOnce(&[u8]) -> N,
) -> io::Result<N> {
    // A device can feed bytes forever, a pipe can block the open, a directory has no bytes.
    let regular = |meta: fs::Metadata| {
        if meta.is_file() {
            Ok(())
        } else {
            let why = format!("{} is not a regular file", from.display());
            Err(io::Error::new(io::ErrorKind::InvalidInput, why))
        }
    };
    regular(fs::metadata(from)?)?;
    let mut source = File::open(from)?;
    regular(source.metadata()?)?;
    let tmp = temp(dir);
    let named = private()
        .open(&tmp)
        .and_then(|mut file| {
            io::copy(&mut source, &mut file)?;
            file.sync_all()
        })
        .and_then(|()| {
            // SAFETY: the copy is this call's own file, and it is written no more.
            let named = name(&unsafe { map(&tmp) }?);
            let to = dir.join(named.to_string());
            // Another writer of the same content may be there first; see `write_once`.
            if !to.exists()
                && let Err(e) = fs::rename(&tmp, &to)
                && !to.exists()
            {
                return Err(e);
            }
            Ok(named)
        });
    // Gone in every case: renamed into place, not needed, or never finished.
    let _ = fs::remove_file(&tmp);
    let named = named?;
    sync_dir(dir)?;
    Ok(named)
}

/// A name in `dir` for a file being written, which no other writer in any process
/// uses, so two writers of the same file cannot tear each other.
fn temp(dir: &Path) -> PathBuf {
    static TEMP: AtomicU64 = AtomicU64::new(0);
    let n = TEMP.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{}-{n}.tmp", std::process::id()))
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

pub use tempfile::TempDir;

/// A new, empty directory in the system's temporary directory that only this user
/// can open, for the files a child process reads. Dropping it removes it and
/// everything in it.
///
/// # Errors
/// The directory cannot be created.
pub fn private_temp_dir() -> io::Result<TempDir> {
    let mut builder = tempfile::Builder::new();
    owner_only_temp(builder.prefix("ledger-"));
    builder.tempdir()
}

#[cfg(unix)]
fn owner_only_temp(builder: &mut tempfile::Builder<'_, '_>) {
    use std::os::unix::fs::PermissionsExt as _;
    builder.permissions(fs::Permissions::from_mode(0o700));
}

/// Windows has no file modes; the directory takes the access list of the user's own
/// temporary directory.
#[cfg(not(unix))]
const fn owner_only_temp(_builder: &mut tempfile::Builder<'_, '_>) {}

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
/// The name the system gives the running process `pid`.
///
/// # Errors
/// There is no such process, or it cannot be looked at.
#[cfg(target_os = "linux")]
pub fn process_name(pid: u32) -> io::Result<String> {
    Ok(std::fs::read_to_string(format!("/proc/{pid}/comm"))?
        .trim_end()
        .to_owned())
}

/// Reads `len` bytes at `address` from the memory of the running process `pid`,
/// without stopping it. The process is only read.
///
/// # Errors
/// The system does not let this user read that process, or the range is not all mapped.
#[cfg(target_os = "linux")]
pub fn read_memory(pid: u32, address: u64, len: usize) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::FileExt as _;
    let memory = File::open(format!("/proc/{pid}/mem"))?;
    let mut bytes = vec![0; len];
    memory.read_exact_at(&mut bytes, address)?;
    Ok(bytes)
}

/// The variable that holds bubblewrap's absolute path. The flake's shell sets it.
#[cfg(target_os = "linux")]
const BWRAP: &str = "LEDGER_TOOL_BWRAP";

/// Where Nix keeps programs and the libraries they load: all of the host a confined
/// program sees.
#[cfg(target_os = "linux")]
const STORE: &str = "/nix/store";

/// Most bytes a confined program may keep in its `/tmp`, which is held in memory.
#[cfg(target_os = "linux")]
const SCRATCH: u64 = 64 << 20;

/// A command that starts `program` confined; the caller adds its arguments. It sees
/// the Nix store read-only, `work` as its working directory and the one place it can
/// write that outlives it, an empty `/tmp` of at most 64 MiB, its own
/// `/proc` and a minimal read-only `/dev` (`null`, `zero`, `urandom` and the like).
/// Nothing else of the host: no network, no home directory, no other file, no
/// environment, no other process. Started without `work`, it runs in `/tmp`.
///
/// It is killed when the thread that started it ends, so start it from one that
/// lives as long as the server, and not from a pool that stops idle threads.
///
/// # Errors
/// `program` is not there or not in the store, or bubblewrap's variable does not
/// hold an absolute path. On a system with no confinement written, always
/// ([`io::ErrorKind::Unsupported`]).
#[cfg(target_os = "linux")]
pub fn confined(program: &Path, work: Option<&Path>) -> io::Result<std::process::Command> {
    // A missing program reads as missing, not as a run that failed inside.
    fs::metadata(program)?;
    if !program.starts_with(STORE) {
        let why = format!("{} is not in {STORE}", program.display());
        return Err(io::Error::new(io::ErrorKind::InvalidInput, why));
    }
    let bwrap = std::env::var_os(BWRAP).map(PathBuf::from);
    let bwrap = bwrap.filter(|path| path.is_absolute()).ok_or_else(|| {
        let why = format!("`{BWRAP}` does not hold bubblewrap's absolute path");
        io::Error::new(io::ErrorKind::NotFound, why)
    })?;
    let scratch = SCRATCH.to_string();
    let mut command = std::process::Command::new(bwrap);
    command.args([
        // Every namespace of its own, the network's and the processes' among them.
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        // A terminal it inherited cannot be made to type into the server's.
        "--new-session",
        "--clearenv",
        "--ro-bind",
        STORE,
        STORE,
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--remount-ro",
        "/dev",
        "--size",
        &scratch,
        "--tmpfs",
        "/tmp",
    ]);
    match work {
        Some(dir) => command
            .arg("--bind")
            .args([dir, dir])
            .arg("--chdir")
            .arg(dir),
        None => command.args(["--chdir", "/tmp"]),
    };
    // The root holds only the mount points; nothing can be written next to them.
    command.args(["--remount-ro", "/", "--"]).arg(program);
    Ok(command)
}

/// Bytes of memory that the process `pid` and every process under it hold in RAM,
/// added up, so a page two of them share counts twice.
///
/// # Errors
/// There is no process `pid`, or the system does not say what it holds.
#[cfg(target_os = "linux")]
pub fn resident(pid: u32) -> io::Result<u64> {
    let mut under = Vec::new();
    let mut held = resident_one(pid, &mut under)?;
    while let Some(child) = under.pop() {
        // A process under it can end while it is read, and then it holds nothing.
        held += resident_one(child, &mut under).unwrap_or(0);
    }
    Ok(held)
}

/// What `pid` alone holds in RAM. Its children are added to `under`.
#[cfg(target_os = "linux")]
fn resident_one(pid: u32, under: &mut Vec<u32>) -> io::Result<u64> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    // Each thread lists the children it started.
    for task in fs::read_dir(proc.join("task"))? {
        let task = task?.path();
        match fs::read_to_string(task.join("children")) {
            Ok(children) => {
                let children = children.split_whitespace().map(str::parse::<u32>);
                under.extend(children.filter_map(Result::ok));
            }
            // A thread can end while it is read; the first one lasts as long as the process.
            Err(_) if !task.ends_with(pid.to_string()) => {}
            Err(e) => return Err(e),
        }
    }
    let status = fs::read_to_string(proc.join("status"))?;
    // A process that has ended and is not yet waited for has no such line.
    let Some(kib) = status.lines().find_map(|line| line.strip_prefix("VmRSS:")) else {
        return Ok(0);
    };
    let kib = kib.trim().trim_end_matches("kB").trim_end().parse::<u64>();
    kib.map(|kib| kib * 1024).map_err(io::Error::other)
}

#[cfg(not(target_os = "linux"))]
const NO_CONFINEMENT: &str = "confining an outside tool is only written for Linux";

/// A command that starts `program` confined.
///
/// # Errors
/// Always, on this system ([`io::ErrorKind::Unsupported`]): no confinement is written for it yet.
#[cfg(not(target_os = "linux"))]
pub fn confined(_program: &Path, _work: Option<&Path>) -> io::Result<std::process::Command> {
    Err(io::Error::new(io::ErrorKind::Unsupported, NO_CONFINEMENT))
}

/// Bytes of memory that the process `pid` and every process under it hold in RAM.
///
/// # Errors
/// Always, on this system: see [`confined`].
#[cfg(not(target_os = "linux"))]
pub fn resident(_pid: u32) -> io::Result<u64> {
    Err(io::Error::new(io::ErrorKind::Unsupported, NO_CONFINEMENT))
}

#[cfg(not(target_os = "linux"))]
const LINUX_ONLY: &str = "reading a running process is only written for Linux";

/// The name the system gives the running process `pid`.
///
/// # Errors
/// Always, on this system: see [`read_memory`].
#[cfg(not(target_os = "linux"))]
pub fn process_name(_pid: u32) -> io::Result<String> {
    Err(io::Error::new(io::ErrorKind::Unsupported, LINUX_ONLY))
}

/// Reads `len` bytes at `address` from the memory of the running process `pid`.
///
/// # Errors
/// Always, on this system: it is written for Linux only so far.
#[cfg(not(target_os = "linux"))]
pub fn read_memory(_pid: u32, _address: u64, _len: usize) -> io::Result<Vec<u8>> {
    Err(io::Error::new(io::ErrorKind::Unsupported, LINUX_ONLY))
}

#[cfg(target_vendor = "apple")]
pub const SQLITE_DURABLE: &str = "PRAGMA fullfsync = ON; PRAGMA checkpoint_fullfsync = ON;";
#[cfg(not(target_vendor = "apple"))]
pub const SQLITE_DURABLE: &str = "";

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn a_process_reads_memory_it_may_read_and_nothing_else() -> io::Result<()> {
        let known = std::hint::black_box(*b"what the process holds");
        let address = u64::try_from(known.as_ptr().addr()).map_err(io::Error::other)?;
        let me = std::process::id();
        assert_eq!(read_memory(me, address, known.len())?, known);
        assert_ne!(process_name(me)?, "");
        assert!(resident(me)? > 0);
        // Nothing is mapped at address 0, and process 0 is not a process.
        assert!(read_memory(me, 0, 16).is_err());
        assert!(read_memory(0, address, 16).is_err());
        assert!(process_name(0).is_err());
        assert!(resident(0).is_err());
        Ok(())
    }

    /// A program the flake's shell names, by its variable.
    #[cfg(target_os = "linux")]
    fn from_flake(var: &str) -> io::Result<PathBuf> {
        std::env::var_os(var).map(PathBuf::from).ok_or_else(|| {
            let why = format!("`{var}` is not set: run the tests inside `nix develop`");
            io::Error::new(io::ErrorKind::NotFound, why)
        })
    }

    /// What a shell from the store prints for `script`, confined to `work`.
    #[cfg(target_os = "linux")]
    fn confined_sh(work: &Path, script: &str) -> io::Result<std::process::Output> {
        let mut sh = confined(&from_flake("LEDGER_TEST_SH")?, Some(work))?;
        let sh = sh.args(["-c", script]).stdin(std::process::Stdio::null());
        sh.output()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_confined_program_cannot_reach_a_server_on_loopback() -> io::Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let work = private_temp_dir()?;
        // Bash connects when it writes to /dev/tcp.
        let script = format!("echo hello > /dev/tcp/127.0.0.1/{port}");
        let ran = confined_sh(&absolute(work.path())?, &script)?;
        assert!(!ran.status.success(), "it connected: {ran:?}");
        let seen = listener.accept().map_err(|e| e.kind());
        assert_eq!(
            seen.err(),
            Some(io::ErrorKind::WouldBlock),
            "the server saw it"
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_confined_program_reads_and_writes_its_directory_and_nothing_else() -> io::Result<()> {
        let work = private_temp_dir()?;
        fs::write(work.path().join("input"), "its input")?;
        // Stand-ins for the ledger, next to the work directory, and for a file in the home directory.
        let ledger = tempfile::tempdir()?;
        fs::write(ledger.path().join("l.db"), "the ledger")?;
        let home = std::env::home_dir().ok_or_else(|| io::Error::other("no home directory"))?;
        let home = tempfile::Builder::new()
            .prefix(".ledger-test-")
            .tempdir_in(home)?;
        fs::write(home.path().join("key"), "a key")?;
        let (ledger_dir, home_dir) = (ledger.path().display(), home.path().display());
        let script = format!(
            r#"for f in input {ledger_dir}/l.db {home_dir}/key; do line=; read -r line < "$f"; echo "$f: $line"; done
            for d in . {ledger_dir} {home_dir} /nix/store /; do echo written > "$d/new"; done"#
        );
        let ran = confined_sh(&absolute(work.path())?, &script)?;
        let read = format!("input: its input\n{ledger_dir}/l.db: \n{home_dir}/key: \n");
        assert_eq!(String::from_utf8_lossy(&ran.stdout), read);
        assert!(
            work.path().join("new").is_file(),
            "it could not write its own directory"
        );
        assert!(
            !ledger.path().join("new").exists(),
            "it wrote next to the ledger"
        );
        assert!(
            !home.path().join("new").exists(),
            "it wrote in the home directory"
        );
        Ok(())
    }

    /// Every program the flake's shell names for the runner, and what makes it print its version.
    #[cfg(target_os = "linux")]
    const TOOLS: [(&str, &str); 6] = [
        ("LEDGER_TOOL_RIZIN", "-v"),
        ("LEDGER_TOOL_WAKARU", "--version"),
        ("LEDGER_TOOL_WEBCRACK", "--version"),
        ("LEDGER_TOOL_RETIRE", "--version"),
        ("LEDGER_TOOL_AST_GREP", "--version"),
        ("LEDGER_TOOL_FINGERPRINT", "--version"),
    ];

    #[cfg(target_os = "linux")]
    #[test]
    fn every_tool_in_the_flake_starts_confined_and_says_its_version() -> io::Result<()> {
        for (var, flag) in TOOLS {
            let mut tool = confined(&from_flake(var)?, None)?;
            let ran = tool.arg(flag).stdin(std::process::Stdio::null()).output()?;
            let printed = String::from_utf8_lossy(&ran.stdout);
            let first = printed.lines().next().unwrap_or_default();
            let version = first.chars().any(|c| c.is_ascii_digit());
            assert!(ran.status.success() && version, "{var}: {ran:?}");
        }
        Ok(())
    }

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

    #[test]
    fn a_regular_file_is_copied_once_under_the_name_of_its_bytes() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let (from, to) = (dir.path().join("capture"), dir.path().join("store"));
        fs::create_dir(&to)?;
        fs::write(&from, b"evidence")?;
        assert_eq!(copy_once(&from, &to, <[u8]>::len)?, 8);
        // SAFETY: nothing else knows this file.
        assert_eq!(&unsafe { map(&to.join("8")) }?[..], b"evidence");
        // A name that is taken keeps its file.
        fs::write(&from, b"other")?;
        copy_once(&from, &to, |_| 8)?;
        // SAFETY: as above.
        assert_eq!(&unsafe { map(&to.join("8")) }?[..], b"evidence");
        // Only a regular file is copied, and a copy that cannot be placed leaves nothing.
        assert!(copy_once(dir.path(), &to, |_| "x").is_err());
        assert!(copy_once(&from, &to, |_| "missing/x").is_err());
        assert_eq!(fs::read_dir(&to)?.count(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn devices_and_pipes_are_not_copied() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let fifo = dir.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()?
                .success()
        );
        // One never ends, and the other would block the open until someone writes it.
        for from in [Path::new("/dev/zero"), &fifo] {
            let refused = copy_once(from, dir.path(), |_| "x").map_err(|e| e.kind());
            assert_eq!(refused.err(), Some(io::ErrorKind::InvalidInput));
        }
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
        let work = private_temp_dir()?;
        let path = work.path().to_path_buf();
        fs::write(path.join("input"), b"program")?;
        assert_eq!(mode(&path)?, 0o700);
        drop(work);
        assert!(!path.exists(), "a temporary directory was left behind");
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
