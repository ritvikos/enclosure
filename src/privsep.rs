// TODO: zero-copy?

use anyhow::{Context, Result};
use bincode::{Decode, Encode};
use nix::{
    sys::{
        socket::{AddressFamily, SockFlag, SockType, socketpair},
        wait::{WaitStatus, waitpid},
    },
    unistd::{ForkResult, fork, read, write},
};
use std::{
    marker::PhantomData,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

pub struct Supervisor<T>(OwnedFd, PhantomData<T>);

impl<T: Decode<()>> Supervisor<T> {
    pub fn listen<C, F>(&self, config: &C, mut handler: F) -> Result<()>
    where
        F: FnMut(&C, T) -> Result<()>,
    {
        let fd = self.as_fd();
        let mut buf = vec![0u8; std::mem::size_of::<T>()];

        loop {
            let n = read(fd, &mut buf)?;

            if n == 0 {
                println!("[PARENT SUPERVISOR LISTENER]: Closed");
                break;
            }

            let (cmd, _) = bincode::decode_from_slice(&buf[..n], bincode::config::standard())?;

            handler(&config, cmd)?;
        }

        Ok(())
    }
}

impl<T: Decode<()>> From<OwnedFd> for Supervisor<T> {
    fn from(fd: OwnedFd) -> Self {
        Self(fd, PhantomData)
    }
}

impl<T: Decode<()>> AsFd for Supervisor<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

pub struct Worker<T: Encode>(OwnedFd, PhantomData<T>);

impl<T: Encode> Worker<T> {
    pub fn send(&self, command: T) -> Result<()> {
        let buf = bincode::encode_to_vec(command, bincode::config::standard())?;
        write(self.as_fd(), buf.as_slice())?;
        Ok(())
    }
}

impl<T: Encode> From<OwnedFd> for Worker<T> {
    fn from(fd: OwnedFd) -> Self {
        Self(fd, PhantomData)
    }
}

impl<T: Encode> AsFd for Worker<T> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Forks the current process into a privileged parent (supervisor) and an isolated child (worker),
/// and manages communication between them.
pub fn privsep<T: Decode<()> + Encode, ChildFn, ParentFn>(
    child_fn: ChildFn,
    parent_fn: ParentFn,
) -> Result<()>
where
    ChildFn: FnOnce(Worker<T>) -> Result<()>,
    ParentFn: FnOnce(Supervisor<T>) -> Result<()>,
{
    let (parent_fd, child_fd) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .context("failed to create socketpair")?;

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            drop(child_fd);
            let supervisor = Supervisor::from(parent_fd);
            let result = parent_fn(supervisor);

            match waitpid(child, None)? {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, status) => {
                    eprintln!("Child exited with status: {}", status);
                }
                other => {
                    eprintln!("Child exit: {:?}", other);
                }
            }

            result
        }
        ForkResult::Child => {
            drop(parent_fd);
            let worker = Worker::from(child_fd);
            std::process::exit(match child_fn(worker) {
                Ok(_) => 0,
                Err(e) => {
                    eprintln!("Child error: {:?}", e);
                    1
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::privsep;
    use crate::{
        config::{BindOptions, MountCommand, MountOp},
        privsep::{Supervisor, Worker},
    };
    use anyhow::Result;

    #[test]
    fn test_privsep() -> Result<()> {
        fn child_fn(worker: Worker<MountCommand>) -> Result<()> {
            worker.send(&MountCommand::Mount(MountOp::Bind {
                source: PathBuf::from("/tmp"),
                target: PathBuf::from("/mnt/tmp"),
                options: BindOptions {
                    readonly: true,
                    mount_dev: false,
                },
            }))?;

            Ok(())
        }

        fn parent_fn(supervisor: Supervisor<MountCommand>) -> Result<()> {
            let config = 1;

            supervisor.listen(&config, |_, cmd| match cmd {
                MountCommand::Mount(op) => {
                    println!("mount op: {op:?}");
                    Ok(())
                }
                MountCommand::File(_) => todo!(),
                MountCommand::System(_) => todo!(),
            })?;

            Ok(())
        }

        privsep(child_fn, parent_fn)?;

        Ok(())
    }
}
