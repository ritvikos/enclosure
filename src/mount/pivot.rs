use nix::{
    mount::{MntFlags, MsFlags, mount, umount2},
    unistd::{chdir, fchdir, pivot_root},
};
use std::{
    ffi::OsStr,
    fs::DirBuilder,
    marker::PhantomData,
    os::{fd::OwnedFd, unix::fs::DirBuilderExt},
    path::{Component, Path, PathBuf},
};

mod sealed {
    pub trait Sealed {}
}

#[derive(Debug, thiserror::Error)]
pub enum PivotError {
    #[error("base path is not a directory")]
    NotADirectory,

    #[error("child path escapes base: path traversal rejected")]
    PathTraversal,

    #[error("mount operation failed: {stage}")]
    Mount {
        stage: &'static str,
        #[source]
        source: nix::Error,
    },

    #[error("filesystem operation failed: {stage}")]
    Fs {
        stage: &'static str,
        #[source]
        source: std::io::Error,
    },
}

pub struct Uninitialized;
pub struct StagingMounted;
pub struct RootMounted;
pub struct PivotedToStaging;
pub struct Staging;
pub struct OldRootDetached;
pub struct PivotedToNewRoot;
pub struct Isolated;

impl sealed::Sealed for Uninitialized {}
impl sealed::Sealed for StagingMounted {}
impl sealed::Sealed for RootMounted {}
impl sealed::Sealed for PivotedToStaging {}
impl sealed::Sealed for Staging {}
impl sealed::Sealed for OldRootDetached {}
impl sealed::Sealed for PivotedToNewRoot {}
impl sealed::Sealed for Isolated {}

pub struct PivotContext<State: sealed::Sealed> {
    base_path: PathBuf,
    old_root: PathBuf,
    new_root: PathBuf,
    _state: PhantomData<State>,
}

impl PivotContext<Uninitialized> {
    // TODO: Check for path existance and nesting (w/ naming).
    pub fn new(
        base_path: impl AsRef<Path>,
        new_root_name: impl AsRef<OsStr>,
        old_root_name: impl AsRef<OsStr>,
    ) -> Result<Self, PivotError> {
        let base_path = base_path.as_ref();

        if !base_path.is_dir() {
            return Err(PivotError::NotADirectory);
        }

        for name in [new_root_name.as_ref(), old_root_name.as_ref()] {
            for component in Path::new(name).components() {
                if component == Component::ParentDir {
                    return Err(PivotError::PathTraversal);
                }
            }
        }

        return Ok(Self {
            base_path: base_path.to_path_buf(),
            old_root: base_path.join(old_root_name.as_ref()),
            new_root: base_path.join(new_root_name.as_ref()),
            _state: PhantomData,
        });
    }
}

impl PivotContext<Uninitialized> {
    pub fn enslave_and_mount(self) -> Result<PivotContext<StagingMounted>, PivotError> {
        // Handle mount propagation
        mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_SLAVE, None)
            .map_err(|e| PivotError::Mount {
                stage: "remount / as slave",
                source: e,
            })?;

        // Mount tmpfs at '/tmp'
        mount::<str, Path, str, str>(
            Some("tmpfs"),
            &self.base_path,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            None,
        )
        .map_err(|e| PivotError::Mount {
            stage: "mount tmpfs at base",
            source: e,
        })?;

        Ok(PivotContext {
            base_path: self.base_path,
            old_root: self.old_root,
            new_root: self.new_root,
            _state: PhantomData,
        })
    }
}

impl PivotContext<StagingMounted> {
    pub fn bind_new_root(self) -> Result<PivotContext<RootMounted>, PivotError> {
        // We're in '/tmp'
        chdir(&self.base_path).map_err(|e| PivotError::Fs {
            stage: "chdir (into base-path>)",
            source: e.into(),
        })?;

        // We've '/tmp/<new-root>'
        DirBuilder::new()
            .mode(0o755)
            .create(&self.new_root)
            .map_err(|e| PivotError::Fs {
                stage: "mkdir <new-root>",
                source: e,
            })?;

        // Bind mount root to itself to make it a mount point.
        mount(
            Some(&self.new_root),
            &self.new_root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_MGC_VAL | MsFlags::MS_SILENT,
            None::<&str>,
        )
        .map_err(|e| PivotError::Mount {
            stage: "bind <new-root>",
            source: e,
        })?;

        // We have '/tmp/<old-root>'
        DirBuilder::new()
            .mode(0o755)
            .create(&self.old_root)
            .map_err(|e| PivotError::Fs {
                stage: "mkdir <old-root>",
                source: e,
            })?;

        Ok(PivotContext {
            base_path: self.base_path,
            old_root: self.old_root,
            new_root: self.new_root,
            _state: PhantomData,
        })
    }
}

impl PivotContext<RootMounted> {
    pub fn first_pivot(self) -> Result<PivotContext<Staging>, PivotError> {
        // Perform pivot root to switch FS
        pivot_root(&self.base_path, &self.old_root).map_err(|e| PivotError::Mount {
            stage: "pivot_root",
            source: e,
        })?;

        // Change the working directory to the new root ('/'),
        // which should now be 'BASE_PATH'.
        chdir("/").map_err(|e| PivotError::Fs {
            stage: "chdir (into /<base-path>)",
            source: e.into(),
        })?;

        Ok(PivotContext {
            base_path: PathBuf::from("/"),
            old_root: PathBuf::from("/").join(&self.old_root),
            new_root: PathBuf::from("/").join(&self.new_root),
            _state: PhantomData,
        })
    }
}

impl PivotContext<Staging> {
    pub fn stage<F>(self, f: F) -> anyhow::Result<PivotContext<PivotedToStaging>>
    where
        F: FnOnce(&Path, &Path) -> anyhow::Result<()>,
    {
        f(&self.old_root, &self.new_root)?;
        Ok(PivotContext {
            base_path: self.base_path,
            old_root: self.old_root,
            new_root: self.new_root,
            _state: PhantomData,
        })
    }
}

impl PivotContext<PivotedToStaging> {
    pub fn detach_old_root(self) -> Result<PivotContext<OldRootDetached>, PivotError> {
        // Change the mount propagation of old root to private.
        mount(
            Some(&self.old_root),
            &self.old_root,
            None::<&str>,
            MsFlags::MS_SILENT | MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .map_err(|e| PivotError::Mount {
            stage: "rprivate <old-root>",
            source: e,
        })?;

        // Unmount old root
        umount2(&self.old_root, MntFlags::MNT_DETACH).map_err(|e| PivotError::Mount {
            stage: "umount <old-root>",
            source: e,
        })?;

        Ok(PivotContext {
            base_path: self.base_path,
            old_root: self.old_root,
            new_root: self.new_root,
            _state: PhantomData,
        })
    }
}

impl PivotContext<OldRootDetached> {
    pub fn second_pivot(self) -> Result<PivotContext<PivotedToNewRoot>, PivotError> {
        let old_root_fd =
            Into::<OwnedFd>::into(std::fs::File::open("/").map_err(|e| PivotError::Fs {
                stage: "open / for old root fd",
                source: e,
            })?);

        chdir(&self.new_root).map_err(|e| PivotError::Mount {
            stage: "chdir (into /<new-root>)",
            source: e,
        })?;

        pivot_root(".", ".").map_err(|e| PivotError::Mount {
            stage: "second pivot_root (/<new-root>)",
            source: e,
        })?;

        // Jump back to staging tmpfs via fd we saved before pivoting.
        fchdir(old_root_fd).map_err(|e| PivotError::Mount {
            stage: "fchdir old root fd",
            source: e,
        })?;

        Ok(PivotContext {
            base_path: PathBuf::from("/"),
            new_root: PathBuf::from("/"),
            old_root: self.old_root,
            _state: std::marker::PhantomData,
        })
    }
}

impl PivotContext<PivotedToNewRoot> {
    pub fn detach_staging(self) -> Result<PivotContext<Isolated>, PivotError> {
        // Unmount the staging tmpfs
        umount2(".", MntFlags::MNT_DETACH).map_err(|e| PivotError::Mount {
            stage: "umount staging tmpfs",
            source: e,
        })?;

        // Change working directory to the new root ('<new-root>')
        chdir("/").map_err(|e| PivotError::Mount {
            stage: "chdir / (into <new-root>)",
            source: e,
        })?;

        Ok(PivotContext {
            base_path: self.base_path,
            new_root: self.new_root,
            old_root: self.old_root,
            _state: std::marker::PhantomData,
        })
    }
}
