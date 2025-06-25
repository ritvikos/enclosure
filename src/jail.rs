use crate::{
    config::Config,
    context::{BASE_PATH, GlobalContext},
    hardener::{self, IdMapWriter, MsFlags},
    jailer::Jailable,
    print_capability_snapshot, utils,
};
use anyhow::Result;
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
    unistd::{Gid, Uid, execvp},
};
use std::{
    ffi::CString,
    os::fd::{AsFd, BorrowedFd},
};

const NEW_ROOT: &str = "newroot";
const OLD_ROOT: &str = "oldroot";

pub struct Jail<'jail> {
    pub config: &'jail Config,
    pub proc_fd: BorrowedFd<'jail>,
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
        let context = GlobalContext::current();
        println!("[CHILD]: {:?}", context);

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

        print_capability_snapshot!("[CHILD]: CAPABILITIES ON INITIALIZATION");

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

        // TODO: Resolve symlinks

        // Handle mount propagation
        hardener::set_mounts_slave_recursive()?;

        // Mount tmpfs
        hardener::set_tmpfs()?;

        // let oldcwd = utils::getcwd()?;

        hardener::chdir(BASE_PATH)?;

        utils::create_directory_recursive(NEW_ROOT, 0755)?;

        hardener::bind_mount_self(NEW_ROOT)?;

        utils::create_directory_recursive(OLD_ROOT, 0755)?;

        hardener::change_root(NEW_ROOT, OLD_ROOT)?;

        // Change the working directory to the new root ('/'),
        // which should now be the base path.
        hardener::chdir("/")?;

        self.handle_mounts()?;

        // Prevent mount event propagation completely
        hardener::remount_with_flags(
            OLD_ROOT,
            MsFlags::MS_SILENT | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        )?;

        // Detach the old rootfs
        hardener::unmount_fs(OLD_ROOT)?;

        let fd = open("/", OFlag::O_DIRECTORY | OFlag::O_RDONLY, Mode::empty())?;
        let borrowed_fd = fd.as_fd();

        hardener::chdir(&format!("/{}", NEW_ROOT))?;
        hardener::change_root(".", ".")?;
        hardener::change_working_dir(borrowed_fd)?;
        hardener::unmount_fs(".")?;
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
