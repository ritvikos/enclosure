use crate::{
    context::{Child, ProcessContext},
    ipc::{
        notifier::{NotifierReceiver, NotifierSender, notifier_pair},
        reporter::ErrorReporter,
    },
    jail::{self, Jail},
    utils::GuardedStack,
};
use anyhow::{Context, Result, anyhow};
use nix::{
    sched::{CloneFlags, clone},
    sys::{
        signal::{
            Signal::{self, SIGKILL},
            kill,
        },
        wait::{WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::os::fd::BorrowedFd;

mod sealed {
    pub trait Sealed {}
}

pub struct Configured;
pub struct Prepared {
    pub(super) flags: CloneFlags,
}
pub struct Forked {
    pub(super) pid: Pid,
    pub(super) sender: NotifierSender,
}

pub struct Running;
pub struct Terminated {
    pub(super) code: i32,
}

impl sealed::Sealed for Configured {}
impl sealed::Sealed for Prepared {}
impl sealed::Sealed for Running {}
impl sealed::Sealed for Terminated {}
impl sealed::Sealed for Forked {}

struct ChildContext<'resource> {
    target: Jail<'resource, jail::AwaitingPrivileges>,
    report: ErrorReporter,
    notifier: NotifierReceiver,
}

impl ChildContext<'_> {
    fn run(self) -> Result<isize> {
        self.notifier.wait_for_signal()?;
        ProcessContext::<Child>::init_child()?;

        let response = self
            .target
            .setup_privileges()
            .context("Privilege setup phase failed")?
            .isolate()
            .context("Isolation phase failed")?
            .restrict()
            .context("Restriction phase failed")?
            .execute()
            .context("Execution phase failed")?;

        self.report.check_for_reported_errors()?;

        Ok(response)
    }
}

pub struct Jailer<'resource, S: sealed::Sealed = Configured> {
    target: Jail<'resource, jail::AwaitingPrivileges>,
    report: ErrorReporter,
    stack_bytes: usize,
    state: S,
}

impl<'resource> Jailer<'resource, Configured> {
    pub fn new(target: Jail<'resource, jail::AwaitingPrivileges>) -> Self {
        Self {
            target,
            report: ErrorReporter::new().expect("Failed to create error reporter"),
            stack_bytes: 1024 * 1024,
            state: Configured,
        }
    }

    pub fn with_clone_flags(self, flags: CloneFlags) -> Jailer<'resource, Prepared> {
        Jailer {
            target: self.target,
            report: self.report,
            stack_bytes: self.stack_bytes,
            state: Prepared { flags },
        }
    }

    pub fn with_stack_bytes(mut self, bytes: usize) -> Self {
        self.stack_bytes = bytes;
        self
    }
}

impl<'resource> Jailer<'resource, Prepared> {
    pub fn spawn(self) -> Result<StagedJail> {
        let Jailer {
            target,
            report,
            stack_bytes,
            ..
        } = self;

        let (sender, receiver) = notifier_pair()?;

        let child_ctx = ChildContext {
            target,
            report,
            notifier: receiver,
        };

        let mut stack = GuardedStack::new(stack_bytes)?;
        let mut child_ctx = Some(child_ctx);
        let callback = {
            Box::new(move || {
                let ctx = child_ctx
                    .take()
                    .expect("Child context should only be used once");

                match ctx.run() {
                    Ok(code) => code,
                    Err(e) => {
                        eprintln!("Child process error: {:#}", e);
                        1
                    }
                }
            })
        };

        println!("[PARENT]: Spawning child process with clone");

        let pid = unsafe {
            clone(
                Box::new(callback),
                stack.as_mut_slice(),
                self.state.flags,
                Some(Signal::SIGCHLD as i32),
            )
        }?;

        Ok(StagedJail { pid, sender })
    }
}

pub struct StagedJail {
    pid: Pid,
    sender: NotifierSender,
}

impl StagedJail {
    pub fn finalize(self) -> Result<JailHandle<Running>> {
        /*
        let map = IdentityMap::new(sandbox_uid, sandbox_gid, host_uid, host_gid, overflow);

        ExternalWriter::new(self.pid, map)
            .write(host.proc_fd())
            .with_context(|| format!("Failed to write userns maps for pid {}", self.pid))?;

        todo!()
        */

        Ok(JailHandle {
            pid: self.pid,
            notifier: self.sender,
            state: Running,
        })
    }
}

pub struct JailHandle<S: sealed::Sealed = Running> {
    pid: Pid,
    notifier: NotifierSender,
    state: S,
}

impl JailHandle<Running> {
    #[inline]
    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn resume(self) -> Result<ExitHandler> {
        self.notifier
            .signal()
            .context("Failed to unblock child process")?;

        Ok(ExitHandler { pid: self.pid })
    }
}

pub struct ExitHandler {
    pid: Pid,
}

impl ExitHandler {
    pub fn wait(self) -> Result<i32> {
        match waitpid(self.pid, None)
            .with_context(|| format!("Failed to wait for process {}", self.pid))?
        {
            WaitStatus::Exited(_, code) => Ok(code),
            WaitStatus::Signaled(_, signal, _) => {
                Err(anyhow!("Child process killed by signal: {:?}", signal))
            }
            status => Err(anyhow!("Unexpected wait status: {:?}", status)),
        }
    }

    pub fn kill(self) -> Result<i32> {
        kill(self.pid, SIGKILL)
            .with_context(|| format!("Failed to kill process {} with SIGKILL", self.pid))?;

        return {
            match waitpid(self.pid, None)
                .with_context(|| format!("Failed to wait for process {}", self.pid))?
            {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, signal, _) => {
                    Err(anyhow!("Child process killed by signal: {:?}", signal))
                }
                status => Err(anyhow!("Unexpected wait status: {:?}", status)),
            }
        };
    }
}

pub struct HostResource<'resource> {
    proc_fd: BorrowedFd<'resource>,
}

impl<'resource> HostResource<'resource> {
    pub fn new(proc_fd: BorrowedFd<'resource>) -> Self {
        Self { proc_fd }
    }

    #[inline]
    pub fn proc_fd(&self) -> BorrowedFd<'resource> {
        self.proc_fd
    }
}

impl Clone for HostResource<'_> {
    fn clone(&self) -> Self {
        Self::new(self.proc_fd)
    }
}
