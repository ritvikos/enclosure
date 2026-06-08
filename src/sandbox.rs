use crate::{
    capabilities::{
        CapabilityBuilder, CapabilityManager, SETUID_CAPABILITIES, apply_setuid_capabilities,
    },
    config::Config,
    context::{Parent, PrivilegeLevel, ProcessContext, ROOTLESS_WITH_CAPABILITY_ERROR_MESSAGE},
    jail::Jail,
    jailer::{ExitHandler, HostResource, JailHandle, Jailer},
    utils,
};
use anyhow::{Result, bail};
use nix::{
    fcntl::OFlag,
    sched::{CloneFlags, setns},
    sys::stat::Mode,
    unistd::{Gid, Uid},
};
use std::os::fd::AsFd;

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for Configured {}
impl sealed::Sealed for Spawned {}
impl sealed::Sealed for Launched {}

pub struct Configured;
pub struct Spawned {
    handle: JailHandle,
}
pub struct Launched {
    handle: JailHandle,
}

#[derive(Debug)]
pub struct Sandbox<S: sealed::Sealed = Configured> {
    config: Config,
    manager: CapabilityManager,
    state: S,
}

impl Sandbox<Configured> {
    const STACK_SIZE: usize = 1024 * 1024;

    /// Create a new instance of `Sandbox`
    pub fn new(config: Config) -> Result<Self> {
        // SAFETY: parent context is initialized in main()
        let context = unsafe { ProcessContext::<Parent>::get() };
        let builder = CapabilityBuilder::new();

        print!("[PRIVILEGE LEVEL]: ");
        let manager = match context.privilege_level() {
            PrivilegeLevel::Root => {
                println!("ROOT");
                builder.build()
            }
            PrivilegeLevel::Rootless => {
                println!("ROOTLESS");
                builder.build()
            }
            PrivilegeLevel::Setuid => {
                println!("SETUID");
                utils::setuid_restrict_fs_privileges()?;
                let manager = builder.with_capabilities(SETUID_CAPABILITIES).build();
                manager.configure_with(apply_setuid_capabilities)?;
                manager
            }
            PrivilegeLevel::RootlessWithCapabilities => {
                println!("ROOTLESS (WITH CAPABILITIES)");
                bail!(ROOTLESS_WITH_CAPABILITY_ERROR_MESSAGE);
            }
        };

        Ok(Self {
            config,
            manager,
            state: Configured,
        })
    }

    pub fn spawn_jail(self) -> Result<Sandbox<Spawned>> {
        utils::apply_no_new_privs()?;

        let flags = self.config.parse_clone_flags()?;
        if let Some(fd) = self.config.user.userns {
            utils::with_raw_fd(fd, |borrowed_fd| {
                setns(borrowed_fd, flags)?;
                return Ok(());
            })?;
        };

        let proc_fd = nix::fcntl::open("/proc", OFlag::O_PATH, Mode::empty())?;
        let jail = Jail::new(self.config.clone(), HostResource::new(proc_fd.as_fd()));

        let handle = Jailer::new(jail)
            .with_clone_flags(flags)
            .spawn()?
            .finalize()?;

        Ok(Sandbox {
            config: self.config,
            manager: self.manager,
            state: Spawned { handle },
        })
    }
}

impl Sandbox<Spawned> {
    pub fn prepare_child(self) -> Result<Sandbox<Launched>> {
        let child_pid = self.state.handle.pid();
        // SAFETY: parent context is initialized in main()
        let context = unsafe { ProcessContext::<Parent>::get() };

        if context.setuid() && self.config.namespace.unshare_user {
            let namespace_uid = self
                .config
                .user
                .uid
                .map(Uid::from)
                .unwrap_or_else(|| context.ruid());

            let namespace_gid = self
                .config
                .user
                .gid
                .map(Gid::from)
                .unwrap_or_else(|| context.guid());

            let map = utils::IdentityMap::new(
                namespace_uid,
                namespace_gid,
                context.ruid(),
                context.guid(),
                context.overflow_ids(),
            );

            let writer = utils::ExternalWriter::new(child_pid, map);

            let proc_fd = nix::fcntl::open("/proc", OFlag::O_PATH, Mode::empty())?;
            writer.write(proc_fd.as_fd())?;
            println!("[PARENT]: Wrote uid/gid mappings for child {child_pid}");
        }

        if let Some(raw_fd) = self.config.user.switch_userns {
            utils::with_raw_fd(raw_fd, |fd| {
                setns(fd, CloneFlags::CLONE_NEWUSER)?;
                Ok(())
            })?;
        }

        self.manager.clear_unprivileged_capabilities()?;

        Ok(Sandbox {
            config: self.config,
            manager: self.manager,
            state: Launched {
                handle: self.state.handle,
            },
        })
    }
}

impl Sandbox<Launched> {
    pub fn resume(self) -> Result<ExitHandler> {
        let handler = self.state.handle.resume()?;
        Ok(handler)
    }
}
