use crate::{Parent, ProcessContext, context::OverFlowIds};
use anyhow::{Context, Result, anyhow, bail};
use memmap2::{MmapMut, MmapOptions};
use nix::{
    fcntl::{FcntlArg, OFlag, fcntl, openat},
    libc::{PR_SET_NO_NEW_PRIVS, PROT_NONE, mprotect, prctl},
    sched::CloneFlags,
    sys::{stat::Mode, utsname::uname},
    unistd::{Gid, Pid, SysconfVar, Uid, setfsuid, sysconf},
};
use std::{
    fs::{DirBuilder, File, Permissions, create_dir_all},
    io::Write,
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd},
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

/// A (mmap'ed) stack allocation with a guard page.
pub struct GuardedStack {
    _mmap: MmapMut,
    stack: *mut u8,
    size: usize,
}

impl GuardedStack {
    /// Create a new instance of `GuardedStack`
    pub fn new(stack_size: usize) -> Result<Self> {
        let page_size = page_size()?;

        if stack_size == 0 || stack_size % page_size != 0 {
            return Err(anyhow!(
                "stack_size must be a non-zero multiple of the system page size ({} bytes)",
                page_size
            ));
        }

        let total_size = stack_size
            .checked_add(page_size)
            .ok_or_else(|| anyhow!("stack_size + guard page overflows usize"))?;

        let mut mmap = MmapOptions::new().len(total_size).map_anon()?;
        let base_ptr = mmap.as_mut_ptr();

        let guard_addr = unsafe { base_ptr.add(stack_size) };

        // SAFETY:
        // - guard_addr is page-aligned and within bounds.
        // - `page_size` is guaranteed to be a page multiple.
        // - `mmap` owns the memory.
        let ret = unsafe { mprotect(guard_addr.cast(), page_size, PROT_NONE) };
        if ret != 0 {
            return Err(anyhow!(
                "Failed to set guard page protection: {}",
                std::io::Error::last_os_error()
            ));
        }

        Ok(Self {
            _mmap: mmap,
            stack: base_ptr,
            size: stack_size,
        })
    }

    /// Returns a mutable slice to the stack memory.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY:
        // - `stack` is offset beyond the guard page and points to `size` valid bytes.
        // - A single mutable reference is created, single-threaded runtime.
        unsafe { std::slice::from_raw_parts_mut(self.stack, self.size) }
    }
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
