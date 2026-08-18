use crate::{
    mount::info::{MountInfo, MountInfoError, MountInfoLines, MountTree, MountTreeError},
    utils::ls,
};
use nix::{
    fcntl::OFlag,
    mount::{MsFlags, mount},
    sys::stat::Mode,
};
use std::{
    io::Error as IoError,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("bind-mount failed: {stage}")]
    Mount {
        stage: &'static str,
        #[source]
        source: IoError,
    },

    #[error("file-system operation failed: {stage}")]
    Fs {
        stage: &'static str,
        #[source]
        source: IoError,
    },

    #[error("failed to read mount-info")]
    MountInfo(#[source] MountInfoError),

    #[error("failed to build mount-tree")]
    MountTree(#[source] MountTreeError),
}

mod sealed {
    pub trait Sealed {}
}

pub struct Bound;
pub struct TreeResolved {
    tree: MountTree,
}
pub struct Remounted;

impl sealed::Sealed for Bound {}
impl sealed::Sealed for TreeResolved {}
impl sealed::Sealed for Remounted {}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum AccessMode {
    ReadOnly,
    #[default]
    ReadWrite,
}

#[derive(Clone, Copy, Default, PartialEq)]
pub enum RemountPolicy {
    // Sub-mount re-mount failures are fatal.
    #[default]
    Restrictive,

    // Sub-mounts re-mount failures are warned and skipped.
    Permissive,
}

#[derive(Clone, Copy)]
pub struct RemountOptions {
    access: AccessMode,
    recursive: bool,
    devices: bool,
    remount_policy: RemountPolicy,
}

impl Default for RemountOptions {
    fn default() -> Self {
        Self {
            access: AccessMode::ReadWrite,
            recursive: true,
            devices: false,
            remount_policy: RemountPolicy::Restrictive,
        }
    }
}

impl RemountOptions {
    #[inline]
    pub fn builder() -> RemountOptionsBuilder {
        RemountOptionsBuilder::default()
    }

    #[inline]
    pub(crate) fn access(&self) -> AccessMode {
        self.access
    }

    #[inline]
    pub(crate) fn recursive(&self) -> bool {
        self.recursive
    }

    #[inline]
    pub(crate) fn devices(&self) -> bool {
        self.devices
    }

    #[inline]
    pub(crate) fn remount_policy(&self) -> RemountPolicy {
        self.remount_policy
    }
}

#[derive(Clone, Copy, Default)]
pub struct RemountOptionsBuilder {
    inner: RemountOptions,
}

impl RemountOptionsBuilder {
    #[inline]
    pub fn access(mut self, access: AccessMode) -> Self {
        self.inner.access = access;
        self
    }

    #[inline]
    pub fn recursive(mut self, recursive: bool) -> Self {
        self.inner.recursive = recursive;
        self
    }

    #[inline]
    pub fn devices(mut self, devices: bool) -> Self {
        self.inner.devices = devices;
        self
    }

    #[inline]
    pub fn remount_policy(mut self, policy: RemountPolicy) -> Self {
        self.inner.remount_policy = policy;
        self
    }

    #[inline]
    pub fn build(self) -> RemountOptions {
        self.inner
    }
}

pub struct BindMount<'a, State: sealed::Sealed> {
    destination: PathBuf,
    proc_fd: BorrowedFd<'a>,
    state: State,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> BindMount<'a, Bound> {
    pub fn bind(
        destination: impl AsRef<Path>,
        proc_fd: BorrowedFd<'a>,
        src: impl AsRef<Path>,
        recursive: bool,
    ) -> Result<Self, BindError> {
        let destination = destination.as_ref().to_owned();
        let flags = MsFlags::MS_SILENT
            | MsFlags::MS_BIND
            | match recursive {
                true => MsFlags::MS_REC,
                false => MsFlags::empty(),
            };

        mount::<Path, Path, str, str>(Some(src.as_ref()), &destination, None, flags, None)
            .map_err(|e| BindError::Mount {
                stage: "initial bind-mount",
                source: IoError::from(e),
            })?;

        Ok(Self {
            destination,
            proc_fd,
            state: Bound,
            _phantom: PhantomData,
        })
    }

    // basically: source exists, trust me bro
    pub(crate) unsafe fn from_existing(
        destination: impl AsRef<Path>,
        proc_fd: BorrowedFd<'a>,
    ) -> Self {
        Self {
            destination: destination.as_ref().to_owned(),
            proc_fd,
            state: Bound,
            _phantom: PhantomData,
        }
    }

    pub fn resolve_tree(self, oldroot: &Path) -> Result<BindMount<'a, TreeResolved>, BindError> {
        println!("destination: {}", self.destination.display());

        let kernel_resolved_dest = {
            let resolved_destination =
                self.destination
                    .canonicalize()
                    .map_err(|source| BindError::Fs {
                        source,
                        stage: "canonicalizing <destination> path",
                    })?;
            println!("resolved_destination: {}", resolved_destination.display());

            let resolved_destination_fd = {
                nix::fcntl::open(
                    &resolved_destination,
                    OFlag::O_PATH | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(IoError::from)
            }
            .map_err(|source| BindError::Fs {
                source,
                stage: "opening <destination> for flag-inspection",
            })?;

            println!("fd: {}", resolved_destination_fd.as_raw_fd());
            ls(&format!(
                "/oldroot/proc/self/fd/{}",
                resolved_destination_fd.as_raw_fd()
            ));

            // '/<old-root>/proc/self/fd/<fd>'
            let oldroot_dest_proc = PathBuf::from(oldroot).join(format!(
                "proc/self/fd/{}",
                resolved_destination_fd.as_raw_fd()
            ));

            oldroot_dest_proc
                .canonicalize()
                .map_err(|source| BindError::Fs {
                    source,
                    stage: "canonicalizing <old-root> destination proc path",
                })?
        };

        println!(
            "<old-root> proc path (kernel_resolved_dest): {}",
            kernel_resolved_dest.display()
        );

        Ok(BindMount {
            destination: self.destination,
            proc_fd: self.proc_fd,
            state: TreeResolved {
                tree: MountInfo::try_from(self.proc_fd.as_fd())
                    .and_then(|info| MountInfoLines::try_from(info.into_iter()))
                    .map_err(BindError::MountInfo)?
                    .into_tree(&kernel_resolved_dest)
                    .map_err(BindError::MountTree)?
                    .build(),
            },
            _phantom: PhantomData,
        })
    }
}

impl<'a> BindMount<'a, TreeResolved> {
    pub(crate) fn remount(
        self,
        remount_opts: RemountOptions,
    ) -> Result<BindMount<'a, Remounted>, BindError> {
        self.state
            .tree
            .flatten()
            .map_err(BindError::MountTree)?
            .remount(&self.destination, &remount_opts)?;

        Ok(BindMount {
            destination: self.destination,
            proc_fd: self.proc_fd,
            state: Remounted,
            _phantom: PhantomData,
        })
    }
}
