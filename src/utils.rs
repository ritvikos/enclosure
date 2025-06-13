use anyhow::{Result, anyhow};
use nix::{
    fcntl::{FcntlArg, fcntl},
    unistd::{SysconfVar, sysconf},
};
use std::os::fd::{AsRawFd, BorrowedFd};

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
