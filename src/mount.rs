pub mod bind;
pub mod pivot;

use crate::{
    config::{MountEntry, NamespaceOptions},
    utils,
};
use anyhow::{Context, Result, anyhow};
use nix::mount::{MsFlags, mount};
use std::{
    io,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct MountContext<'ctx> {
    mount: &'ctx [MountEntry],
    namespace: &'ctx NamespaceOptions,
    oldroot: &'ctx Path,
    newroot: &'ctx Path,
}

impl<'ctx> MountContext<'ctx> {
    pub fn new<P1, P2>(
        mount: &'ctx [MountEntry],
        namespace: &'ctx NamespaceOptions,
        oldroot: &'ctx P1,
        newroot: &'ctx P2,
    ) -> Self
    where
        P1: AsRef<Path> + ?Sized,
        P2: AsRef<Path> + ?Sized,
    {
        MountContext {
            mount,
            namespace,
            oldroot: oldroot.as_ref(),
            newroot: newroot.as_ref(),
        }
    }
}

impl<'ctx> MountContext<'ctx> {
    pub fn apply(&self) -> Result<()> {
        for mnt in self.mount {
            self.apply_one(mnt)
                .with_context(|| format!("Failed to apply mount entry: {mnt:?}"))?;
        }
        Ok(())
    }

    fn apply_one(&self, mnt: &MountEntry) -> Result<()> {
        match mnt {
            MountEntry::Dir { path, mode } => match mode {
                Some(mode) => utils::ensure_dir_with_mode(path, **mode),
                None => utils::ensure_dir(path),
            },
            MountEntry::Mqueue { dest } => {
                utils::ensure_dir(dest)?;
                mount::<str, Path, str, str>(
                    Some("mqueue"),
                    &dest,
                    Some("mqueue"),
                    MsFlags::empty(),
                    None,
                )
                .with_context(|| format!("Failed to mount mqueue at {}", dest.display()))?;
                Ok(())
            }
            MountEntry::Proc { dest } => self.apply_proc(dest),
            MountEntry::Symlink { target, link } => self.apply_symlink(target, link),
            _ => todo!("Mount entry type not implemented: {mnt:?}"),
        }
    }

    fn apply_proc(&self, dest: &Path) -> Result<()> {
        // We've '/<new-root>/<dest>'
        let target = self.rebase(dest);
        utils::ensure_dir(&target)?;

        match &self.namespace.unshare_pid {
            true => {
                mount::<str, std::path::Path, str, str>(
                    Some("proc"),
                    &target,
                    Some("proc"),
                    MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                    None,
                )
                .with_context(|| format!("Failed to mount procfs at {}", target.display()))?;
            }
            false => {
                todo!(
                    "WIP: `BindMount` abstraction in mount/bind.rs to use system's proc-fs (w/ shared PID-NS)"
                )
            }
        }

        // TODO: cleanup '/proc' special dirs that could be exploited: sys, sysrq, irq, bus
        Ok(())
    }

    // Too noisy, probably, it can be cleaned up later
    fn apply_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        match symlink(target, link) {
            Ok(()) => Ok(()),

            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => match link.read_link() {
                Ok(existing) if existing == target => Ok(()),
                Ok(existing) => Err(anyhow!(
                    "can't make symlink at {}: existing destination is {}",
                    link.display(),
                    existing.display()
                )),
                Err(e) if e.kind() == io::ErrorKind::InvalidInput => Err(anyhow!(
                    "can't make symlink at {}: destination is not a symlink",
                    link.display()
                )),
                Err(e) => Err(e).with_context(|| {
                    format!(
                        "can't make symlink at {}: can't read existing symlink target",
                        link.display()
                    )
                }),
            },

            Err(e) => Err(e).with_context(|| format!("can't make symlink at {}", link.display())),
        }
    }

    fn rebase(&self, dst: &Path) -> PathBuf {
        self.newroot.join(dst.strip_prefix("/").unwrap_or(dst))
    }
}
