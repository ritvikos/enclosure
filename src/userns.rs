use crate::{
    context::OverFlowIds,
    utils::{Dir, retry_on_interrupt},
};
use anyhow::Result;
use nix::{
    fcntl::OFlag,
    unistd::{Gid, Pid, Uid},
};
use std::{
    fs::File,
    io::Write,
    os::fd::{AsFd, BorrowedFd},
};

#[derive(Clone, Copy, Debug)]
pub struct IdentityMap {
    sandbox_uid: Uid,
    sandbox_gid: Gid,
    host_uid: Uid,
    host_gid: Gid,
    overflow: OverFlowIds,
}

impl IdentityMap {
    pub fn new(
        sandbox_uid: Uid,
        sandbox_gid: Gid,
        host_uid: Uid,
        host_gid: Gid,
        overflow: OverFlowIds,
    ) -> Self {
        Self {
            sandbox_uid,
            sandbox_gid,
            host_uid,
            host_gid,
            overflow,
        }
    }

    pub fn uid_map(&self) -> String {
        format!("{} {} 1\n", self.sandbox_uid, self.host_uid)
    }

    pub fn gid_map(&self) -> String {
        format!("{} {} 1\n", self.sandbox_gid, self.host_gid)
    }
}

fn write_proc_map_file(parent: &File, name: &str, content: &str) -> Result<()> {
    let dir = Dir::from(parent.as_fd());
    let mut file = dir.open_with(name, OFlag::O_WRONLY | OFlag::O_CLOEXEC)?;

    retry_on_interrupt(|| file.write_all(content.as_bytes()))?;

    Ok(())
}

pub struct ExternalWriter {
    pid: Pid,
    map: IdentityMap,
}

impl ExternalWriter {
    pub fn new(pid: Pid, map: IdentityMap) -> Self {
        Self { pid, map }
    }

    pub fn write(&self, proc_fd: BorrowedFd<'_>) -> Result<()> {
        let dir = Dir::from(proc_fd);
        let pid_str = i32::from(self.pid).to_string();
        let parent = dir.open_with(&pid_str, OFlag::O_PATH)?;

        write_proc_map_file(&parent, "setgroups", "deny\n")?;
        write_proc_map_file(&parent, "uid_map", &self.map.uid_map())?;
        write_proc_map_file(&parent, "gid_map", &self.map.gid_map())?;

        Ok(())
    }
}

pub struct SelfWriter {
    map: IdentityMap,
}

impl SelfWriter {
    pub fn new(map: IdentityMap) -> Self {
        Self { map }
    }

    pub fn write(&self, proc_fd: BorrowedFd<'_>) -> Result<()> {
        let dir = Dir::from(proc_fd);
        let parent = dir.open_with("self", OFlag::O_PATH)?;

        write_proc_map_file(&parent, "setgroups", "deny\n")?;
        write_proc_map_file(&parent, "uid_map", &self.map.uid_map())?;
        write_proc_map_file(&parent, "gid_map", &self.map.gid_map())?;

        Ok(())
    }
}
