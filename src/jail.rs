use crate::{
    capabilities::CapabilityManager,
    config::{Config, MountEntry},
    context::{Child, ProcessContext},
    jailer::HostResource,
    mount::{
        MountContext,
        pivot::{PivotContext, Uninitialized},
    },
    utils::{self, IdentityMap, SelfWriter},
};
use anyhow::{Context, Result};
use nix::{
    mount::{MsFlags, mount},
    unistd::{Gid, Uid, execvp},
};
use std::{ffi::CString, marker::PhantomData, os::unix::fs::symlink};

mod sealed {
    pub trait Sealed {}
}

const BASE_PATH: &str = "/tmp";
const NEW_ROOT: &str = "newroot";
const OLD_ROOT: &str = "oldroot";

impl sealed::Sealed for AwaitingPrivileges {}
impl sealed::Sealed for Privileged {}
impl sealed::Sealed for Isolated {}
impl sealed::Sealed for Restricted {}
impl sealed::Sealed for Executed {}

pub struct AwaitingPrivileges;
pub struct Privileged;
pub struct Isolated;
pub struct Restricted;
pub struct Executed;

pub struct Jail<'resource, State: sealed::Sealed> {
    config: Config,
    resource: HostResource<'resource>,
    _state: PhantomData<State>,
}

impl<'resource> Jail<'resource, AwaitingPrivileges> {
    pub fn new(config: Config, resource: HostResource<'resource>) -> Self {
        Self {
            config,
            resource,
            _state: PhantomData,
        }
    }

    pub fn setup_privileges(self) -> Result<Jail<'resource, Privileged>> {
        self.write_mappings()?;

        Ok(Jail {
            config: self.config,
            resource: self.resource,
            _state: PhantomData,
        })
    }

    fn write_mappings(&self) -> Result<()> {
        let child = unsafe { ProcessContext::<Child>::get() };
        // SAFETY: parent context is initialized at startup before clone()
        let parent = unsafe { child.parent() };

        if !parent.setuid() && self.config.namespace.unshare_user {
            let namespace_uid = match self.config.user.uid {
                Some(uid) => Uid::from(uid),
                None => Uid::from_raw(0),
            };

            let namespace_gid = match self.config.user.gid {
                Some(gid) => Gid::from(gid),
                None => Gid::from_raw(0),
            };

            let map = IdentityMap::new(
                namespace_uid,
                namespace_gid,
                parent.ruid(),
                parent.guid(),
                parent.overflow_ids(),
            );

            let writer = SelfWriter::new(map);
            writer.write(self.resource.proc_fd())?;
            println!("[CHILD]: Wrote Mappings");
        }

        Ok(())
    }
}

impl<'resource> Jail<'resource, Privileged> {
    pub fn isolate(self) -> Result<Jail<'resource, Isolated>> {
        PivotContext::<Uninitialized>::new(BASE_PATH, NEW_ROOT, OLD_ROOT)?
            .enslave_and_mount()?
            .bind_new_root()?
            .first_pivot()?
            .stage(
                |oldroot_abs /* '/oldroot' */, newroot_abs /* '/newroot' */| {
                    todo!("WIP: `MountContext` abstraction in src/mount.rs")
                },
            )?
            .detach_old_root()?
            .second_pivot()?
            .detach_staging()?;

        Ok(Jail {
            config: self.config,
            resource: self.resource,
            _state: PhantomData,
        })
    }
}

impl<'resource> Jail<'resource, Isolated> {
    pub fn restrict(self) -> Result<Jail<'resource, Restricted>> {
        if self.config.namespace.unshare_user {
            CapabilityManager::drop_all_bounding_capabilities()?;
        }

        Ok(Jail {
            config: self.config,
            resource: self.resource.clone(),
            _state: PhantomData,
        })
    }
}

impl<'resource> Jail<'resource, Restricted> {
    pub fn execute(self) -> Result<isize> {
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
}
