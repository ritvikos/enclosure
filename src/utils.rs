use crate::context::OverFlowIds;
use anyhow::{Result, anyhow, bail};
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl, openat},
    sys::stat::Mode,
    unistd::{Gid, Pid, SysconfVar, Uid, sysconf},
};
use std::{
    fs::{DirBuilder, File, Permissions, create_dir_all},
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
        unix::fs::{DirBuilderExt, PermissionsExt},
    },
    path::Path,
};

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

/// Returns the system page size.
pub fn page_size() -> Result<usize> {
    match sysconf(SysconfVar::PAGE_SIZE)? {
        Some(size) if size > 0 => Ok(size as usize),
        Some(_) => Err(anyhow!("PAGE_SIZE returned non-positive value")),
        None => Err(anyhow!("PAGE_SIZE is not defined on this system")),
    }
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

pub fn ensure_directory<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    if path.exists() {
        if !path.is_dir() {
            bail!("Path \"{}\" is not a directory", path.to_string_lossy());
        }
        return Ok(());
    }

    DirBuilder::new().mode(mode).recursive(true).create(path)?;

    Ok(())
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

#[derive(Clone, Copy, Debug)]
pub struct IdentityMap {
    sandbox_uid: Uid,
    sandbox_gid: Gid,
    host_uid: Uid,
    host_gid: Gid,
    overflow: OverFlowIds,
}

impl IdentityMap {
    pub fn new(
        sandbox_uid: Uid,
        sandbox_gid: Gid,
        host_uid: Uid,
        host_gid: Gid,
        overflow: OverFlowIds,
    ) -> Self {
        Self {
            sandbox_uid,
            sandbox_gid,
            host_uid,
            host_gid,
            overflow,
        }
    }

    pub fn uid_map(&self) -> String {
        format!("{} {} 1\n", self.sandbox_uid, self.host_uid)
    }

    pub fn gid_map(&self) -> String {
        format!("{} {} 1\n", self.sandbox_gid, self.host_gid)
    }
}

fn write_proc_map_file(parent: &File, name: &str, content: &str) -> Result<()> {
    let dir = Dir::from(parent.as_fd());
    let mut file = dir.open_with(name, OFlag::O_WRONLY | OFlag::O_CLOEXEC)?;

    retry_on_interrupt(|| file.write_all(content.as_bytes()))?;

    Ok(())
}

pub struct ExternalWriter {
    pid: Pid,
    map: IdentityMap,
}

impl ExternalWriter {
    pub fn new(pid: Pid, map: IdentityMap) -> Self {
        Self { pid, map }
    }

    pub fn write(&self, proc_fd: BorrowedFd<'_>) -> Result<()> {
        let dir = Dir::from(proc_fd);
        let pid_str = i32::from(self.pid).to_string();
        let parent = dir.open_with(&pid_str, OFlag::O_PATH)?;

        write_proc_map_file(&parent, "setgroups", "deny\n")?;
        write_proc_map_file(&parent, "uid_map", &self.map.uid_map())?;
        write_proc_map_file(&parent, "gid_map", &self.map.gid_map())?;

        Ok(())
    }
}

pub struct SelfWriter {
    map: IdentityMap,
}

impl SelfWriter {
    pub fn new(map: IdentityMap) -> Self {
        Self { map }
    }

    pub fn write(&self, proc_fd: BorrowedFd<'_>) -> Result<()> {
        let dir = Dir::from(proc_fd);
        let parent = dir.open_with("self", OFlag::O_PATH)?;

        write_proc_map_file(&parent, "setgroups", "deny\n")?;
        write_proc_map_file(&parent, "uid_map", &self.map.uid_map())?;
        write_proc_map_file(&parent, "gid_map", &self.map.gid_map())?;

        Ok(())
    }
}
