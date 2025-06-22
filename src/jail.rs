use crate::{
    config::Config,
    context::{BASE_PATH, GlobalContext},
    hardener,
    jailer::Jailable,
    print_capability_snapshot,
    utils::create_directory_recursive,
};
use anyhow::Result;

const NEW_ROOT: &str = "newroot";
const OLD_ROOT: &str = "oldroot";

pub struct Jail<'jail> {
    pub config: &'jail Config,
}

impl<'a> Jailable<'a> for Jail<'a> {
    fn new(config: &'a Config) -> Self {
        Self { config }
    }

    fn config(&self) -> &Config {
        self.config
    }

    fn prepare(&self) -> Result<()> {
        let context = GlobalContext::current();
        println!("[CHILD]: {:?}", context);

        print_capability_snapshot!("[CHILD]: CAPABILITIES ON INITIALIZATION");

        if !context.setuid() && self.config.namespace.unshare_user {
            // TODO: write uid / gid mapping
        }

        // TODO: Resolve symlinks

        // Handle mount propagation
        hardener::set_mounts_slave_recursive()?;

        // Mount tmpfs
        hardener::set_tmpfs()?;

        // let oldcwd = get_cwd()?;

        hardener::chdir(BASE_PATH)?;

        create_directory_recursive(NEW_ROOT, 0755)?;

        hardener::bind_mount_self(NEW_ROOT)?;

        create_directory_recursive(OLD_ROOT, 0755)?;

        hardener::change_root(NEW_ROOT, OLD_ROOT)?;

        // Change the working directory to the new root ('/'),
        // which should now be the base path.
        hardener::chdir("/")?;

        if context.setuid() {
            self.handle_mounts()?;
        }

        Ok(())
    }

    fn execute(&self) -> Result<isize> {
        println!("[CHILD]: EXECUTED");
        Ok(0)
    }

    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}
