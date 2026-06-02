use crate::capabilities::has_any_permitted_capabilities;
use anyhow::{Context, Result, bail};
use nix::unistd::{Gid, Uid, geteuid, getgid, getuid};
use std::{cell::RefCell, marker::PhantomData};

thread_local! {
    static PARENT_CONTEXT: RefCell<Option<ProcessContext<Parent>>> = RefCell::new(None);
    static CHILD_CONTEXT: RefCell<Option<ProcessContext<Child>>> = RefCell::new(None);
}

#[derive(Clone, Copy)]
pub struct Parent;

#[derive(Clone, Copy)]
pub struct Child;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PrivilegeLevel {
    Root,
    Rootless,
    Setuid,
    RootlessWithCapabilities,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessContext<Role> {
    ruid: Uid,
    euid: Uid,
    guid: Gid,
    level: PrivilegeLevel,
    overflow: OverFlowIds,
    _role: PhantomData<Role>,
}

impl ProcessContext<Parent> {
    pub fn init() -> Result<()> {
        let context = ProcessContext::<Parent>::new().context("Failed to create parent context")?;

        PARENT_CONTEXT.with(|cell| {
            *cell.borrow_mut() = Some(context);
        });

        Ok(())
    }

    /// # Safety
    /// Must be called only after `ProcessContext::<Parent>::init()`.
    pub unsafe fn get() -> Self {
        PARENT_CONTEXT.with(|cell| unsafe {
            let opt: &Option<Self> = &*cell.borrow();
            *opt.as_ref().unwrap_unchecked()
        })
    }

    /// # Safety
    /// Child context must have been initialized via `ProcessContext::<Child>::init_child()`.
    pub unsafe fn child(&self) -> ProcessContext<Child> {
        CHILD_CONTEXT.with(|cell| unsafe {
            let opt: &Option<ProcessContext<Child>> = &*cell.borrow();
            *opt.as_ref().unwrap_unchecked()
        })
    }
}

impl ProcessContext<Child> {
    pub fn init_child() -> Result<()> {
        let context = ProcessContext::<Child>::new().context("Failed to create child context")?;

        CHILD_CONTEXT.with(|cell| {
            *cell.borrow_mut() = Some(context);
        });

        Ok(())
    }

    /// # Safety
    /// Must be called only after `ProcessContext::<Child>::init_child()`.
    pub unsafe fn get() -> Self {
        CHILD_CONTEXT.with(|cell| unsafe {
            let opt: &Option<Self> = &*cell.borrow();
            *opt.as_ref().unwrap_unchecked()
        })
    }

    /// # Safety
    /// Parent context must have been initialized via `ProcessContext::<Parent>::init()`.
    pub unsafe fn parent(&self) -> ProcessContext<Parent> {
        PARENT_CONTEXT.with(|cell| unsafe {
            let opt: &Option<ProcessContext<Parent>> = &*cell.borrow();
            *opt.as_ref().unwrap_unchecked()
        })
    }
}

#[allow(unused)]
impl<R> ProcessContext<R> {
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
            _role: PhantomData,
        })
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
        let uid = std::fs::read_to_string(Self::OVERFLOW_UID_PATH)?;
        let gid = std::fs::read_to_string(Self::OVERFLOW_GID_PATH)?;

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
