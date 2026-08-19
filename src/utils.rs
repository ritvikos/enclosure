use crate::{Parent, ProcessContext, config::OctalPermissions};
use anyhow::{Context, Result, anyhow, bail};
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl, openat},
    libc::{PR_SET_NO_NEW_PRIVS, prctl},
    sched::CloneFlags,
    sys::{stat::Mode, utsname::uname},
    unistd::{Uid, setfsuid},
};
use std::{
    fs::{DirBuilder, File, Permissions, create_dir_all},
    io::{self, ErrorKind},
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::fs::{DirBuilderExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub(crate) fn apply_no_new_privs() -> Result<()> {
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!("PR_SET_NO_NEW_PRIVS: Failed to set this flag");
        Err(std::io::Error::last_os_error()).context("Failed to restrict privileges")
    } else {
        Ok(())
    }
}

pub(crate) fn setuid_restrict_fs_privileges() -> Result<()> {
    // SAFETY: parent context is initialized in main()
    let context = unsafe { ProcessContext::<Parent>::get() };
    let target = context.ruid();

    // 1. Request FSUID change
    setfsuid(target);

    // 2. Read current FSUID with setfsuid(-1)
    let current = setfsuid(Uid::from_raw(!0u32));

    // 3. Compare actual FSUID with target
    if current != target {
        bail!(
            "FSUID: Failed to set FSUID to {} (current FSUID is {})",
            target,
            current
        );
    }

    Ok(())
}

pub(crate) fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    let stripped = path.strip_prefix("/").unwrap_or(path);
    root.join(stripped)
}

/// Executes a closure with a borrowed FD while ensuring that the provided FD is valid.
pub fn with_raw_fd<T: AsRawFd, F>(raw_fd: T, f: F) -> Result<()>
where
    F: FnOnce(BorrowedFd<'_>) -> Result<()>,
{
    let fd = raw_fd.as_raw_fd();
    let validated_fd = is_fd_valid(fd)?;

    // SAFETY:
    // - We already validated the file descriptor.
    // - Lifetime is scoped to this function.
    unsafe { with_valid_fd(validated_fd, f) }
}

/// Executes a closure with borrowed FD.
pub unsafe fn with_valid_fd<F>(fd: i32, f: F) -> Result<()>
where
    F: FnOnce(BorrowedFd<'_>) -> Result<()>,
{
    // SAFETY: Caller ensures the validity of FD
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
    f(borrowed_fd)
}

/// Checks whether a given FD is valid.
pub fn is_fd_valid(raw_fd: i32) -> Result<i32> {
    // SAFETY: This call doesn't dereference or take ownership, just validates via `fcntl`.
    let fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };

    fcntl(fd, FcntlArg::F_GETFD)
        .map_err(|error| anyhow!(format!("\nInvalid file descriptor \n{error} ({raw_fd})")))?;
    Ok(raw_fd)
}

pub fn retry_on_interrupt<T, F>(mut operation: F) -> Result<T, std::io::Error>
where
    F: FnMut() -> Result<T, std::io::Error>,
{
    loop {
        match operation() {
            Ok(result) => return Ok(result),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

pub fn getcwd() -> Result<std::path::PathBuf> {
    Ok(nix::unistd::getcwd()?)
}

pub fn create_file<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    let file = File::create_new(path)?;
    file.set_permissions(Permissions::from_mode(mode))?;

    Ok(())
}

pub fn create_file_recursive<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    create_file(path, mode)?;

    Ok(())
}

pub fn ensure_file<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    if path.exists() {
        if !path.is_file() {
            bail!("Path \"{}\" is not a file", path.to_string_lossy());
        }
        return Ok(());
    }

    create_file_recursive(path, mode)?;

    Ok(())
}

pub fn create_directory<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();
    DirBuilder::new().mode(mode).recursive(true).create(path)?;
    Ok(())
}

pub fn ensure_dir_with_mode<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    match DirBuilder::new().mode(mode).recursive(true).create(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            if !path.is_dir() {
                bail!("Path \"{}\" is not a directory", path.display());
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

pub fn ensure_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    ensure_dir_with_mode(path, 0o755)
}

pub fn is_namespace_supported(flag: CloneFlags) -> bool {
    fn exists(ns: &str) -> bool {
        Path::new(&format!("/proc/self/ns/{}", ns)).exists()
    }

    // FIXME: hacky minimum version
    fn min_version(version: &str) -> bool {
        let release = uname().unwrap().release().to_string_lossy().to_string();
        !release.starts_with(version)
    }

    match flag {
        CloneFlags::CLONE_FILES => min_version("2.0"),
        CloneFlags::CLONE_FS => min_version("2.0"),

        CloneFlags::CLONE_SYSVSEM => min_version("2.6.19"),
        CloneFlags::CLONE_NEWCGROUP => exists("cgroup"),
        CloneFlags::CLONE_NEWIPC => exists("ipc"),
        CloneFlags::CLONE_NEWNET => exists("net"),
        CloneFlags::CLONE_NEWNS => exists("mnt"),
        CloneFlags::CLONE_NEWPID => exists("pid"),
        CloneFlags::CLONE_NEWUSER => exists("user"),
        CloneFlags::CLONE_NEWUTS => exists("uts"),
        _ => todo!(),
    }
}

pub(crate) fn is_cgroups_supported() -> bool {
    Path::new("/proc/self/ns/cgroup").exists()
}

pub struct Dir<'a> {
    fd: BorrowedFd<'a>,
}

impl Dir<'_> {
    pub fn open_with<P: AsRef<Path> + ?Sized>(
        &self,
        path: &P,
        flags: OFlag,
    ) -> std::io::Result<File> {
        let path = path.as_ref();

        let fd = retry_on_interrupt(|| Ok(openat(self.fd, path, flags, Mode::empty())?))?;
        let file = File::from(fd);

        Ok(file)
    }
}

impl<'a> From<BorrowedFd<'a>> for Dir<'a> {
    fn from(fd: BorrowedFd<'a>) -> Self {
        Self { fd }
    }
}

pub(crate) fn ls(path: &str) {
    println!("{path}:");
    match std::fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let meta = entry.metadata().ok();
                println!(
                    "{:>10}  {}",
                    meta.map(|m| m.len()).unwrap_or(0),
                    entry.file_name().to_string_lossy()
                );
            }
        }
        Err(e) => eprintln!("failed to read {}: {}", path, e),
    }
}

pub(crate) fn cat(path: &str) {
    println!("{path}:");
    match std::fs::read_to_string(path) {
        Ok(contents) => println!("{}", contents),
        Err(e) => eprintln!("failed to read {}: {}", path, e),
    }
}

// basically; `mkdir -p` w/ permissions w/o returning error if directory already exists
pub(crate) fn create_dir_recursive(path: &Path, mode: OctalPermissions) -> io::Result<()> {
    let mut to_create = vec![];
    let mut current = path;

    loop {
        match std::fs::metadata(current) {
            Ok(meta) if meta.is_dir() => break,
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a directory", current.display()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                to_create.push(current);
                match current.parent() {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
            Err(e) => return Err(e),
        }
    }

    for dir in to_create.into_iter().rev() {
        match DirBuilder::new().mode(*mode).create(dir) {
            Ok(()) => {}
            Err(_) if dir.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_privileges() {
        let result = apply_no_new_privs();
        assert!(
            result.is_ok(),
            "Failed to drop privileges: {:?}",
            result.err()
        );
    }
}
