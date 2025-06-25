use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, BorrowedFd},
    path::Path,
};

use crate::{
    context::{BASE_PATH, GlobalContext, OverFlowIds},
    utils,
};
use anyhow::{Context, Result, bail};
use nix::{
    fcntl::OFlag,
    libc::{PR_SET_NO_NEW_PRIVS, prctl},
    mount::{MntFlags, mount, umount2},
    unistd::{Gid, Pid, Uid, fchdir, pivot_root, setfsuid},
};

pub use nix::mount::MsFlags;

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

pub fn remount_with_flags(src: &str, flags: MsFlags) -> Result<()> {
    mount::<str, str, str, str>(Some(src), src, None, flags, None)?;
    Ok(())
}

pub fn unmount_fs(target: &str) -> Result<()> {
    umount2(target, MntFlags::MNT_DETACH)?;
    Ok(())
}

pub fn change_working_dir<'a>(fd: BorrowedFd<'a>) -> Result<()> {
    fchdir(fd)?;
    Ok(())
}

pub fn get_env(path: &str) -> Result<String> {
    Ok(std::env::var("HOME")?)
}

pub struct MountHardener<'a> {
    base_path: &'a str,
    new_root: &'a str,
    old_root: &'a str,
}

pub struct IdMapWriter {
    /// Sandbox's UID
    uid: Uid,

    /// Sandbox's GID
    gid: Gid,

    /// Real UID
    ruid: Uid,

    /// Real GUID
    guid: Gid,

    /// Pid
    pid: Option<Pid>,

    deny_groups: bool,

    map_root: bool,

    overflow: OverFlowIds,
}

impl IdMapWriter {
    pub fn new(
        uid: Uid,
        gid: Gid,
        ruid: Uid, // Real UID
        guid: Gid, // Real GID
        overflow: OverFlowIds,
        deny_groups: bool,
        map_root: bool,
        pid: Option<Pid>,
    ) -> Self {
        Self {
            uid,
            gid,
            ruid,
            guid,
            pid,
            overflow,
            map_root,
            deny_groups,
        }
    }

    pub fn write<'a>(&self, fd: BorrowedFd<'a>) -> Result<()> {
        let directory = match self.pid {
            Some(pid) => i32::from(pid).to_string(),
            None => String::from("self"),
        };

        let dir = utils::Dir::from(fd);
        let mut file = dir.open_with(&directory, OFlag::O_PATH)?;

        let context = GlobalContext::current();
        println!("{context:?}");

        let uid_map = if self.map_root && !self.ruid.is_root() && !self.uid.is_root() {
            let overflow_uid = self.overflow.uid.as_raw();
            format!("0 {} 1\n{} {} 1\n", overflow_uid, self.uid, self.ruid)
        } else {
            format!("{} {} 1\n", self.uid, self.ruid)
        };

        let gid_map = if self.map_root && self.guid.as_raw() != 0 && self.gid.as_raw() != 0 {
            let overflow_gid = self.overflow.gid.as_raw();
            format!("0 {} 1\n{} {} 1\n", overflow_gid, self.gid, self.guid)
        } else {
            format!("{} {} 1\n", self.gid, self.guid)
        };

        if self.deny_groups {
            self.write_inner(&mut file, "setgroups", "deny\n")?;
        }

        println!("uid_map: {uid_map}");
        println!("gid_map: {gid_map}");

        self.write_inner(&mut file, "uid_map", &uid_map)?;
        self.write_inner(&mut file, "gid_map", &gid_map)?;

        Ok(())
    }

    fn write_inner<'a, P: AsRef<Path>>(
        &self,
        file: &mut File,
        path: P,
        buffer: &str,
    ) -> Result<()> {
        let directory = utils::Dir::from(file.as_fd());

        let mut file = directory.open_with(&path, OFlag::O_RDWR | OFlag::O_CLOEXEC)?;

        utils::retry_on_interrupt(|| file.write(buffer.as_bytes()))?;

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
