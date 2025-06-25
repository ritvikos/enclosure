use crate::{
    capabilities::{
        CapabilityBuilder, CapabilityManager, SETUID_CAPABILITIES, apply_setuid_capabilities,
    },
    config::Config,
    context::{GlobalContext, OverFlowIds, PrivilegeLevel, ROOTLESS_WITH_CAPABILITY_ERROR_MESSAGE},
    hardener,
    jail::Jail,
    jailer::{Jailable, JailerBuilder},
    print_capability_snapshot, utils,
};
use anyhow::{Result, bail};
use nix::{
    fcntl::OFlag,
    sched::{CloneFlags, setns},
    sys::stat::Mode,
    unistd::{Gid, Pid, Uid},
};
use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, BorrowedFd},
    path::Path,
};

#[derive(Debug)]
pub struct Enclosure {
    config: Config,
    manager: CapabilityManager,
}

impl Enclosure {
    const STACK_SIZE: usize = 1024 * 1024;

    /// Create a new instance of `Enclosure`
    pub fn new(config: Config) -> Result<Self> {
        let manager = Self::configure_capabilities_by_privilege()?;
        hardener::apply_no_new_privs()?;
        Ok(Self { config, manager })
    }

    pub fn spawn(&self) -> Result<()> {
        let flags = self.config.parse_clone_flags()?;
        let proc_fd = nix::fcntl::open("/proc", OFlag::O_PATH, Mode::empty())?;

        if let Some(fd) = self.config.user.userns {
            utils::with_raw_fd(fd, |borrowed_fd| {
                setns(borrowed_fd, flags)?;
                return Ok(());
            })?;
        };

        self.spawn_inner(flags, proc_fd.as_fd())?;

        Ok(())
    }

    fn configure_capabilities_by_privilege() -> Result<CapabilityManager> {
        let context = GlobalContext::current();
        let builder = CapabilityBuilder::new();

        print!("[PRIVILEGE LEVEL]: ");
        let manager = match context.privilege_level() {
            // Preserve privileges
            PrivilegeLevel::Root => {
                println!("ROOT");
                builder.build()
            }

            // Unprivileged
            PrivilegeLevel::Rootless => {
                println!("ROOTLESS");
                builder.build()
            }

            // Restrict/Limit privileges
            PrivilegeLevel::Setuid => {
                println!("SETUID");

                hardener::setuid_restrict_fs_privileges()?;

                let manager = builder.with_capabilities(SETUID_CAPABILITIES).build();
                manager.configure_with(apply_setuid_capabilities)?;
                manager
            }

            // Unsupported
            PrivilegeLevel::RootlessWithCapabilities => {
                println!("ROOTLESS (WITH CAPABILITIES)");
                bail!(ROOTLESS_WITH_CAPABILITY_ERROR_MESSAGE);
            }
        };

        Ok(manager)
    }

    fn spawn_inner<'a>(&self, flags: CloneFlags, proc_fd: BorrowedFd<'a>) -> Result<()> {
        let jail = Jail::new(&self.config, proc_fd);

        let jailer = JailerBuilder::new(jail)?
            .with_stack_size(Self::STACK_SIZE)
            .build();

        let handle = jailer.spawn_blocking(flags)?;

        handle.execute(|| {
            println!("[PARENT]: After spawning child process");
            self.configure_parent()?;
            return Ok(());
        })?;

        Ok(())
    }

    fn configure_parent(&self) -> Result<()> {
        let context = GlobalContext::current();
        print_capability_snapshot!("[PARENT]: CAPABILITIES AFTER SPAWNING CHILD");

        if context.setuid() && self.config.namespace.unshare_user {
            // TODO: write uid / gid mapping
        }

        if let Some(raw_fd) = self.config.user.switch_userns {
            utils::with_raw_fd(raw_fd, |fd| {
                setns(fd, CloneFlags::CLONE_NEWUSER)?;
                Ok(())
            })?;
        }

        self.manager.clear_unprivileged_capabilities()?;

        Ok(())
    }
}
