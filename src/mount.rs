pub mod bind;
mod info;
pub mod pivot;

use crate::{
    config::{
        BindSource, BindSourceKind, MountEntry, NamespaceOptions, OctalPermissions,
        OctalPermissionsError,
    },
    jailer::HostResource,
    mount::bind::{AccessMode, BindMount, RemountOptions, RemountPolicy},
    utils::{self},
};
use anyhow::{Context, Result, anyhow};
use std::{
    io::ErrorKind as IoErrorKind,
    os::{fd::BorrowedFd, unix::fs::symlink},
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub(crate) struct MountContext<'ctx> {
    newroot: &'ctx Path,
    oldroot: &'ctx Path,
    host: &'ctx HostResource<'ctx>,
    namespace: &'ctx NamespaceOptions,
}

impl<'ctx> MountContext<'ctx> {
    pub fn new(
        oldroot: &'ctx Path,
        newroot: &'ctx Path,
        host: &'ctx HostResource<'ctx>,
        namespace: &'ctx NamespaceOptions,
    ) -> Self {
        Self {
            oldroot,
            newroot,
            host,
            namespace,
        }
    }

    #[inline]
    fn rebase<P: AsRef<Path>>(&self, root: &Path, dest: P) -> PathBuf {
        let dest = dest.as_ref();
        root.join(dest.strip_prefix("/").unwrap_or(dest))
    }

    #[inline]
    fn rebase_new<P: AsRef<Path>>(&self, dest: P) -> PathBuf {
        self.rebase(self.newroot, dest)
    }

    #[inline]
    fn rebase_old<P: AsRef<Path>>(&self, dest: P) -> PathBuf {
        self.rebase(self.oldroot, dest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceKind {
    Directory,
    Other,
    Missing,
}

impl From<u32> for SourceKind {
    fn from(st_mode: u32) -> Self {
        const S_IFMT: u32 = nix::libc::S_IFMT;
        const S_IFDIR: u32 = nix::libc::S_IFDIR;
        if st_mode & S_IFMT == S_IFDIR {
            SourceKind::Directory
        } else {
            SourceKind::Other
        }
    }
}

impl SourceKind {
    pub fn ensure_dest(&self, dest: &Path) -> Result<()> {
        match self {
            SourceKind::Directory => utils::ensure_dir_with_mode(dest, 0o755)
                .with_context(|| format!("can't mkdir {}", dest.display())),
            SourceKind::Other => utils::ensure_file(dest, 0o444)
                .with_context(|| format!("can't create file at {}", dest.display())),
            SourceKind::Missing => Ok(()),
        }
    }
}

pub fn stat_source(src: &Path) -> Result<SourceKind> {
    try_stat_source(src)?.ok_or_else(|| anyhow::anyhow!("source does not exist: {}", src.display()))
}

pub fn try_stat_source(src: &Path) -> Result<Option<SourceKind>> {
    fn stat(src: &Path) -> Result<Option<SourceKind>, nix::Error> {
        match nix::sys::stat::stat(src) {
            Ok(st) => Ok(Some(SourceKind::from(st.st_mode))),
            Err(nix::errno::Errno::ENOENT) => Ok(None),
            Err(e) => Err(e),
        }
    }
    stat(src).with_context(|| format!("can't determine source-type for {}", src.display()))
}

fn resolve_dest_with_perms(dest: &Path, perms: OctalPermissions) -> Result<()> {
    #[inline]
    pub(crate) fn parent_mode_for(
        perms: OctalPermissions,
    ) -> Result<OctalPermissions, OctalPermissionsError> {
        const GROUP: u32 = 0o070;
        const OTHER: u32 = 0o007;

        let mut mode = *OctalPermissions::OWNER_RWX_GROUP_RX_OTHER_RX;
        if !(*perms & GROUP != 0) {
            mode &= !0o050;
        }
        if !(*perms & OTHER != 0) {
            mode &= !0o005;
        }
        OctalPermissions::try_from(mode)
    }

    let parent = dest.parent().unwrap_or(dest);
    let mode = parent_mode_for(perms)?;
    utils::create_dir_recursive(parent, mode)
        .with_context(|| format!("unable to create parent dirs for {}", dest.display()))
}

fn resolve_dest(dest: &Path) -> Result<()> {
    let parent = dest.parent().unwrap_or(dest);
    let mode = OctalPermissions::OWNER_RWX_GROUP_RX_OTHER_RX;
    utils::create_dir_recursive(parent, mode)
        .with_context(|| format!("unable to create parent dirs for {}", dest.display()))
}

impl MountEntry {
    pub(crate) fn apply(&self, ctx: &MountContext) -> Result<()> {
        match self {
            MountEntry::Bind {
                src,
                dest,
                mode,
                mount_dev,
            } => apply_bind(ctx, src, dest, mode, *mount_dev),
            MountEntry::Symlink { target, link } => apply_symlink(ctx, &target, &link),
            _ => {
                todo!("mount-type not implemented yet: {:?}", self);
            }
        }
    }
}

fn apply_bind(
    ctx: &MountContext,
    src: &BindSource,
    dest: &Path,
    mode: &AccessMode,
    mount_dev: bool,
) -> Result<()> {
    unsafe fn do_bind_mount<'a>(
        src_path: &'a Path,
        src_kind: &'a BindSourceKind,
        dest: &'a Path,
        oldroot: &'a Path,
        proc_fd: BorrowedFd<'a>,
        mode: &'a AccessMode,
        mount_dev: bool,
    ) -> Result<()> {
        // fix: remount-policy should be configurable based on caller's args, the security-boundary
        let remount_policy = RemountPolicy::Restrictive;

        let remount_opts = RemountOptions::builder()
            .access(*mode)
            .remount_policy(remount_policy)
            .devices(mount_dev)
            .recursive(true)
            .build();

        BindMount::bind(&dest, proc_fd, src_path, true)?
            .resolve_tree(oldroot)?
            .remount(remount_opts)?;

        match src_kind {
            BindSourceKind::Path { .. } => {}
            BindSourceKind::Fd { .. } => {
                todo!("resolve-symlinks before mount(ing)");
            }
        }

        Ok(())
    }

    // src
    let src_path = ctx.rebase_old(src.path());
    println!("src_path: {}", &src_path.display());
    let source_kind = match src.kind() {
        BindSourceKind::Path { allow_missing } if *allow_missing => {
            match try_stat_source(&src_path)? {
                Some(kind) => kind,
                None => return Ok(()),
            }
        }
        BindSourceKind::Path { .. } => stat_source(&src_path)?,
        BindSourceKind::Fd { .. } => SourceKind::Other,
    };

    // dst
    let dst_path = ctx.rebase_new(dest);
    println!("dst_path: {}", &dst_path.display());
    resolve_dest(&dst_path)?;
    source_kind.ensure_dest(&dst_path)?;

    let proc_fd = ctx.host.proc_fd();

    unsafe {
        do_bind_mount(
            &src_path,
            &src.kind(),
            &dst_path,
            &ctx.oldroot,
            proc_fd,
            mode,
            mount_dev,
        )
    }
}

fn apply_symlink(ctx: &MountContext, target: &Path, link: &Path) -> Result<()> {
    let dest = ctx.rebase_new(link);
    resolve_dest(&dest)?;
    println!("target: {}", target.display());
    println!("link: {}", dest.display());

    match symlink(target, &dest) {
        Ok(()) => Ok(()),

        Err(e) if e.kind() == IoErrorKind::AlreadyExists => match dest.read_link() {
            Ok(existing) if existing == target => Ok(()),
            Ok(existing) => Err(anyhow!(
                "can't make symlink at {}: existing destination is {}",
                link.display(),
                existing.display()
            )),
            Err(e) if e.kind() == IoErrorKind::InvalidInput => Err(anyhow!(
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

// fn apply_proc

/*
struct ResolvedProc<'ctx> {
    dest_abs: PathBuf,
    dest_raw: &'ctx Path,
}

impl ResolvedProc<'_> {
    fn apply(self, ctx: &ApplyContext<'_>) -> Result<()> {
        let Self { dest_abs, dest_raw } = self;

        utils::ensure_dir(&dest_abs)?;

        match ctx.unshare_pid {
            true => {
                mount::<str, Path, str, str>(
                    Some("proc"),
                    &dest_abs,
                    Some("proc"),
                    MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
                    None,
                )
                .with_context(|| format!("Failed to mount procfs at {}", dest_abs.display()))?;
            }
            false => {
                BindMount::bind(&dest_abs, ctx.proc_fd, dest_raw, true)?
                    .resolve_tree(ctx.oldroot)?
                    .remount(RemountOptions::default())?;
            }
        }

        // TODO cleanup '/proc' special dirs that could be exploited: sys, sysrq, irq, bus.
        Ok(())
    }
}

struct ResolvedDir<'ctx> {
    path: &'ctx Path,
    mode: &'ctx Option<OctalPermissions>,
}

impl ResolvedDir<'_> {
    fn apply(self) -> Result<()> {
        let Self { path, mode } = self;
        match mode {
            Some(mode) => utils::ensure_dir_with_mode(path, **mode),
            None => utils::ensure_dir(path),
        }
    }
}

struct ResolvedMqueue<'ctx> {
    dest: &'ctx Path,
}

impl ResolvedMqueue<'_> {
    fn apply(self) -> Result<()> {
        let Self { dest } = self;
        utils::ensure_dir(dest)?;
        mount::<str, Path, str, str>(Some("mqueue"), dest, Some("mqueue"), MsFlags::empty(), None)
            .with_context(|| format!("Failed to mount mqueue at {}", dest.display()))?;
        Ok(())
    }
}

struct ResolvedSymlink<'ctx> {
    target: &'ctx Path,
    link: &'ctx Path,
}

impl ResolvedSymlink<'_> {
    fn apply(self) -> Result<()> {
        let Self { target, link } = self;

        match symlink(target, link) {
            Ok(()) => Ok(()),

            Err(e) if e.kind() == IoErrorKind::AlreadyExists => match link.read_link() {
                Ok(existing) if existing == target => Ok(()),
                Ok(existing) => Err(anyhow!(
                    "can't make symlink at {}: existing destination is {}",
                    link.display(),
                    existing.display()
                )),
                Err(e) if e.kind() == IoErrorKind::InvalidInput => Err(anyhow!(
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
}
*/
