use crate::{
    config::Config, context::GlobalContext, notifier::Notifier, report::ErrorReporter,
    stack::GuardedStack,
};
use anyhow::{Context, Result, anyhow};
use nix::{
    sched::{CloneCb, CloneFlags, clone},
    sys::{
        signal::{
            Signal::{self, SIGKILL},
            kill,
        },
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use std::{cell::Cell, marker::PhantomData, os::fd::BorrowedFd};

pub struct JailerBuilder<'builder, C: Jailable<'builder>> {
    target: C,
    notifier: Notifier,
    report: ErrorReporter,
    stack_bytes: usize,
    _marker: PhantomData<&'builder ()>,
}

impl<'builder, C: Jailable<'builder>> JailerBuilder<'builder, C> {
    pub fn new(target: C) -> Result<Self> {
        let notifier = Notifier::new()?;
        let report = ErrorReporter::new()?;

        Ok(Self {
            notifier,
            stack_bytes: 1024 * 1024,
            target,
            report,
            _marker: PhantomData,
        })
    }

    pub fn with_stack_size(mut self, stack_size: usize) -> Self {
        self.stack_bytes = stack_size;
        self
    }

    pub fn build(self) -> Jailer<'builder, C> {
        assert!(self.stack_bytes >= 64 * 1024, "stack size too small");

        Jailer {
            context: GlobalContext::current(),
            notifier: self.notifier,
            target: self.target,
            report: self.report,
            stack_bytes: self.stack_bytes,
            _marker: PhantomData,
        }
    }
}

pub struct Jailer<'jailer, C: Jailable<'jailer>> {
    target: C,
    notifier: Notifier,
    report: ErrorReporter,
    stack_bytes: usize,
    context: GlobalContext,
    _marker: PhantomData<&'jailer ()>,
}

impl<'jailer, C: Jailable<'jailer>> Jailer<'jailer, C> {
    pub fn spawn_blocking(&self, flags: CloneFlags) -> Result<JailHandle> {
        let callback = self.create_child_callback();
        let guard = self.spawn_child(callback, flags)?;
        Ok(guard)
    }

    fn create_child_callback(&self) -> Box<impl FnMut() -> isize> {
        Box::new(|| match self.child_main() {
            Ok(code) => return code,
            Err(error) => {
                eprintln!("Child process error: {:?}", error);
                return 1;
            }
        })
    }

    fn spawn_child(&self, callback: CloneCb, flags: CloneFlags) -> Result<JailHandle> {
        let mut stack = GuardedStack::new(self.stack_bytes)?;

        println!("[PARENT]: Spawning child process with clone");

        let pid = unsafe {
            clone(
                Box::new(callback),
                stack.as_mut_slice(),
                flags,
                Some(Signal::SIGCHLD as i32),
            )
        }?;

        Ok(JailHandle::new(pid, &self.notifier))
    }

    fn child_main(&self) -> Result<isize> {
        // Wait for the parent's signal to continue execution
        self.notifier.wait_for_signal()?;

        // Initialize global context for the child
        GlobalContext::init()?;

        // Prepare the child's execution environment
        self.target.prepare(&self.context)?;

        // Execute the process
        self.target.execute()?;

        // Cleanup
        self.target.cleanup()?;

        // Check for reported errors from the child (if any)
        self.report.check_for_reported_errors()?;

        // TODO: Return the exit code from the child process
        Ok(0)
    }
}

pub struct JailHandle<'handle> {
    /// PID of the child process
    pid: Pid,

    /// Signals the child process to execute
    notifier: &'handle Notifier,

    // Track if the process has been waited on
    waited: Cell<bool>,
}

impl<'handle> JailHandle<'handle> {
    #[inline]
    fn new(pid: Pid, notifier: &'handle Notifier) -> Self {
        Self {
            pid,
            notifier,
            waited: Cell::new(false),
        }
    }

    #[inline]
    pub fn pid(&self) -> Pid {
        self.pid
    }

    // Setup the parent once child process is spawned
    pub fn execute<P>(&self, parent: P) -> Result<i32>
    where
        P: FnOnce() -> Result<()>,
    {
        parent().context("Parent setup failed")?;

        self.notifier
            .signal()
            .context("Failed to unblock child process")?;

        self.wait()
    }

    pub fn wait(&self) -> Result<i32> {
        let status = waitpid(self.pid, None)
            .with_context(|| format!("Failed to wait for process {}", self.pid))?;

        self.waited.set(true);

        match status {
            WaitStatus::Exited(_, code) => Ok(code),
            WaitStatus::Signaled(_, signal, _) => {
                Err(anyhow!("Child process killed by signal: {:?}", signal))
            }
            _ => Err(anyhow!("Unexpected wait status: {:?}", status)),
        }
    }

    pub fn terminate(&self) -> Result<()> {
        if self.has_waited() {
            return Ok(());
        }

        if self.try_wait()?.is_some() {
            return Ok(());
        }

        let signal = SIGKILL;

        kill(self.pid, signal).with_context(|| {
            format!(
                "Failed to terminate process {} with signal {}",
                self.pid, signal
            )
        })?;

        Ok(())
    }

    fn try_wait(&self) -> Result<Option<i32>> {
        if self.has_waited() {
            return Ok(None);
        }

        match waitpid(self.pid, Some(WaitPidFlag::WNOHANG))
            .with_context(|| format!("Failed to check status of process {}", self.pid))?
        {
            WaitStatus::Exited(_, code) => {
                self.waited.set(true);
                Ok(Some(code))
            }
            WaitStatus::Signaled(_, signal, _) => {
                self.waited.set(true);
                Err(anyhow!(
                    "Child process {} killed by signal: {:?}",
                    self.pid,
                    signal
                ))
            }
            WaitStatus::StillAlive => Ok(None),
            _ => Ok(None),
        }
    }

    #[inline]
    fn has_waited(&self) -> bool {
        self.waited.get()
    }
}

impl Drop for JailHandle<'_> {
    fn drop(&mut self) {
        if !self.waited.get() {
            match self.try_wait() {
                Ok(None) => {
                    eprintln!(
                        "Warning: JailHandle dropped while child process {} is still running. \
                         Consider calling wait_for_completion() or terminate_child() explicitly.",
                        self.pid
                    );
                }
                Ok(Some(exit_code)) => {
                    eprintln!(
                        "Info: Child process {} exited with code {} during JailHandle drop",
                        self.pid, exit_code
                    );
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to check status of child process {} during drop: {}",
                        self.pid, e
                    );
                }
            }
        }
    }
}

pub trait Jailable<'a> {
    fn config(&self) -> &Config;
    fn proc_fd(&self) -> BorrowedFd<'a>;

    fn new(config: &'a Config, proc_fd: BorrowedFd<'a>) -> Self;
    fn prepare(&self, parent_context: &GlobalContext) -> Result<()>;
    fn execute(&self) -> Result<isize>; // TODO: Path as well
    fn cleanup(&self) -> Result<()>;
}
