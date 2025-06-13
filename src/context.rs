use crate::capabilities::has_any_permitted_capabilities;
use anyhow::{Context, Result, bail};
use nix::unistd::{Uid, geteuid, getuid};
use std::cell::RefCell;

thread_local! {
    static GLOBAL_CONTEXT: RefCell<Option<GlobalContext>> = RefCell::new(None);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrivilegeLevel {
    Root,
    Rootless,
    Setuid,
    RootlessWithCapabilities,
}

#[derive(Debug, Clone, Copy)]
pub struct GlobalContext {
    ruid: Uid,
    euid: Uid,
    level: PrivilegeLevel,
}

impl GlobalContext {
    /// Creates a new instance of `GlobalContext`
    #[deny(unused)]
    pub fn init() -> Result<()> {
        let context = GlobalContext::new().context("Failed to create global context")?;

        GLOBAL_CONTEXT.with(|cell| {
            *cell.borrow_mut() = Some(context);
        });

        Ok(())
    }

    /// Get the current context
    pub fn current() -> Self {
        // SAFETY: The global context is guaranteed to be initialized
        GLOBAL_CONTEXT.with(|cell| unsafe { cell.borrow().unwrap_unchecked() })
    }

    #[inline]
    pub fn ruid(&self) -> Uid {
        self.ruid
    }

    #[inline]
    pub fn euid(&self) -> Uid {
        self.euid
    }

    #[inline]
    pub fn root(&self) -> bool {
        self.euid().is_root()
    }

    #[inline]
    pub fn real_root(&self) -> bool {
        self.ruid().is_root()
    }

    #[inline]
    pub fn setuid(&self) -> bool {
        self.privilege_level() == PrivilegeLevel::Setuid
    }

    #[inline]
    pub fn privilege_level(&self) -> PrivilegeLevel {
        self.level
    }

    fn new() -> Result<Self> {
        let ruid = getuid();
        let euid = geteuid();

        let level = if ruid != euid {
            if euid.as_raw() != 0 {
                bail!(
                    "FATAL: setuid binary must elevate to root (euid=0), but got euid={}",
                    euid
                );
            }
            PrivilegeLevel::Setuid
        } else if euid.as_raw() == 0 {
            PrivilegeLevel::Root
        } else if has_any_permitted_capabilities()? {
            PrivilegeLevel::RootlessWithCapabilities
        } else {
            PrivilegeLevel::Rootless
        };

        Ok(Self { ruid, euid, level })
    }
}

pub(crate) const ROOTLESS_WITH_CAPABILITY_ERROR_MESSAGE: &str = "Unsupported configuration: Detected unexpected capabilities without setuid or root privileges. \
This may indicate that the binary is using file capabilities (setcap), which is no longer supported. \
Please ensure the binary is setuid or root privileges and not setcap, and retry.";
