use crate::capabilities::has_any_permitted_capabilities;
use anyhow::{Context, Result, bail};
use nix::unistd::{Gid, Uid, geteuid, getgid, getuid};
use std::{cell::RefCell, fs};

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
    guid: Gid,
    level: PrivilegeLevel,
    overflow: OverFlowIds,
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
    pub fn guid(&self) -> Gid {
        self.guid
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

    #[inline]
    pub fn overflow_ids(&self) -> OverFlowIds {
        self.overflow
    }

    #[inline]
    pub fn overflow_uid(&self) -> Uid {
        self.overflow.uid
    }

    #[inline]
    pub fn overflow_gid(&self) -> Gid {
        self.overflow.gid
    }

    fn new() -> Result<Self> {
        let ruid = getuid();
        let euid = geteuid();
        let guid = getgid();
        let overflow = OverFlowIds::read()?;

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

        Ok(Self {
            ruid,
            euid,
            guid,
            level,
            overflow,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OverFlowIds {
    pub uid: Uid,
    pub gid: Gid,
}

impl OverFlowIds {
    const OVERFLOW_UID_PATH: &str = "/proc/sys/kernel/overflowuid";
    const OVERFLOW_GID_PATH: &str = "/proc/sys/kernel/overflowgid";

    pub fn read() -> Result<Self> {
        let uid = fs::read_to_string(Self::OVERFLOW_UID_PATH)?;
        let gid = fs::read_to_string(Self::OVERFLOW_GID_PATH)?;

        let uid = uid.trim().parse::<u32>()?;
        let gid = gid.trim().parse::<u32>()?;

        Ok(Self::new(uid, gid))
    }

    fn new<T: Into<Uid>, U: Into<Gid>>(uid: T, gid: U) -> Self {
        Self {
            uid: uid.into(),
            gid: gid.into(),
        }
    }
}

pub(crate) const ROOTLESS_WITH_CAPABILITY_ERROR_MESSAGE: &str = "Unsupported configuration: Detected unexpected capabilities without setuid or root privileges. \
This may indicate that the binary is using file capabilities (setcap), which is no longer supported. \
Please ensure the binary is setuid or root privileges and not setcap, and retry.";
