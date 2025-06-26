use crate::{
    capabilities::CapabilityManager,
    config::Config,
    context::GlobalContext,
    hardener::{self, IdMapWriter},
    jailer::Jailable,
    utils,
};
use anyhow::Result;
use nix::unistd::{Gid, Uid, execvp};
use std::{ffi::CString, os::fd::BorrowedFd};

const BASE_PATH: &str = "/tmp";
const NEW_ROOT: &str = "newroot";
const OLD_ROOT: &str = "oldroot";

pub struct Jail<'jail> {
    pub config: &'jail Config,
    pub proc_fd: BorrowedFd<'jail>,
}

impl Jail<'_> {
    fn setup_privileges(&self, setuid: bool) -> Result<()> {
        if self.config.namespace.unshare_user {
            CapabilityManager::drop_all_bounding_capabilities()?;
        }

        if !setuid {
            return Ok(());
        }

        Ok(())
    }
}

impl<'a> Jailable<'a> for Jail<'a> {
    fn new(config: &'a Config, proc_fd: BorrowedFd<'a>) -> Self {
        Self { config, proc_fd }
    }

    fn config(&self) -> &Config {
        self.config
    }

    fn proc_fd(&self) -> BorrowedFd<'a> {
        self.proc_fd
    }

    fn prepare(&self, parent_context: &GlobalContext) -> Result<()> {
        let namespace_uid = match self.config.user.uid {
            Some(uid) => Uid::from(uid),
            None => parent_context.ruid(),
        };

        let namespace_gid = match self.config.user.gid {
            Some(gid) => Gid::from(gid),
            None => parent_context.guid(),
        };

        let ruid = parent_context.ruid();
        let guid = parent_context.guid();

        let overflow_ids = parent_context.overflow_ids();
        let parent_setuid = parent_context.setuid();

        if !parent_context.setuid() && self.config.namespace.unshare_user {
            let writer = IdMapWriter::new(
                namespace_uid,
                namespace_gid,
                ruid,
                guid,
                overflow_ids,
                true,
                false,
                None,
            );

            writer.write(self.proc_fd())?;
            println!("[CHILD]: Wrote Mappings");
        }

        GlobalContext::init()?;

        self.setup_privileges(parent_setuid)?;

        // TODO: Resolve symlinks

        // Handle mount propagation
        hardener::set_mounts_slave_recursive()?;

        // Mount tmpfs at '/tmp'
        hardener::set_tmpfs(BASE_PATH)?;

        // We are in '/tmp'
        hardener::chdir(BASE_PATH)?;

        // We have '/tmp/newroot'
        utils::create_directory(NEW_ROOT, 0o755)?;

        hardener::bind_mount_self(NEW_ROOT)?;

        // We have '/tmp/oldroot'
        utils::create_directory(OLD_ROOT, 0o755)?;

        hardener::pivot_root(BASE_PATH, OLD_ROOT)?;

        // Change the working directory to the new root ('/'),
        // which should now be 'BASE_PATH'.
        hardener::chdir("/")?;

        Ok(())
    }

    fn execute(&self) -> Result<isize> {
        let file = CString::new(self.config.executable.to_string_lossy().as_bytes())?;

        let args: Vec<_> = std::iter::once(&self.config.executable)
            .map(|path| CString::new(path.to_string_lossy().as_bytes()))
            .chain(
                self.config
                    .args
                    .iter()
                    .map(|arg| CString::new(arg.as_bytes())),
            )
            .collect::<Result<Vec<CString>, _>>()?;

        execvp(&file, &args)?;

        Ok(0)
    }

    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}
