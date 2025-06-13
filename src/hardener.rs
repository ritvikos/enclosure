use crate::context::GlobalContext;
use anyhow::{Context, Result, bail};
use nix::{
    libc::{PR_SET_NO_NEW_PRIVS, prctl},
    unistd::{Uid, setfsuid},
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
