use crate::context::{BASE_PATH, GlobalContext};
use anyhow::{Context, Result, bail};
use nix::{
    libc::{PR_SET_NO_NEW_PRIVS, prctl},
    mount::{MsFlags, mount},
    unistd::{Uid, pivot_root, setfsuid},
};

/// The process and its children are prevented from gaining new privileges via `execve()`
pub(crate) fn apply_no_new_privs() -> Result<()> {
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        eprintln!("PR_SET_NO_NEW_PRIVS: Failed to set this flag");
        Err(std::io::Error::last_os_error()).context("Failed to restrict privileges")
    } else {
        Ok(())
    }
}

/// Restricts filesystem privileges by setting the FSUID.
///
/// # NOTES:
/// Error handling based on https://www.man7.org/linux/man-pages/man2/setfsuid.2.html
pub(crate) fn setuid_restrict_fs_privileges() -> Result<()> {
    let context = GlobalContext::current();
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

/// Recursively marks the root mount (`/`) as a *slave* to prevent mount
/// propagation from the current mount namespace back to the host.
pub fn set_mounts_slave_recursive() -> Result<()> {
    let flags = MsFlags::MS_REC | MsFlags::MS_SLAVE | MsFlags::MS_SILENT;
    mount::<str, str, str, str>(None, BASE_PATH, None, flags, None)?;
    Ok(())
}

pub fn set_tmpfs() -> Result<()> {
    let flags = MsFlags::MS_NODEV | MsFlags::MS_NOSUID;
    mount::<str, str, str, str>(Some("tmpfs"), BASE_PATH, Some("tmpfs"), flags, None)?;
    Ok(())
}

pub fn bind_mount_self(src: &str) -> Result<()> {
    let flags = MsFlags::MS_MGC_VAL | MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_SILENT;
    mount::<str, str, str, str>(Some(src), src, None, flags, None)?;
    Ok(())
}

pub fn change_root(new: &str, put_old: &str) -> Result<()> {
    Ok(pivot_root(new, put_old)?)
}

pub fn chdir(path: &str) -> Result<()> {
    nix::unistd::chdir(path)?;
    Ok(())
}

pub struct MountHardener<'a> {
    base_path: &'a str,
    new_root: &'a str,
    old_root: &'a str,
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
