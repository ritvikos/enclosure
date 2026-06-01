use anyhow::{Context, Result};
use std::os::fd::{AsFd, OwnedFd};

// Blocks waiting for the parent's signal
pub struct NotifierReceiver {
    read_fd: OwnedFd,
}

impl NotifierReceiver {
    pub fn wait_for_signal(self) -> Result<()> {
        let mut buffer = 0u64.to_ne_bytes();
        nix::unistd::read(&self.read_fd.as_fd(), &mut buffer)
            .context("failed to read signal value")?;
        Ok(())
    }
}

// Sends the signal to unblock the child
pub struct NotifierSender {
    write_fd: OwnedFd,
}

impl NotifierSender {
    pub fn signal(&self) -> Result<()> {
        let buffer = 1u64.to_ne_bytes();
        nix::unistd::write(&self.write_fd.as_fd(), &buffer)
            .context("failed to write signal value")?;
        Ok(())
    }
}

pub fn notifier_pair() -> Result<(NotifierSender, NotifierReceiver)> {
    let (read_fd, write_fd) = nix::unistd::pipe().context("Failed to create notifier pipe")?;
    Ok((NotifierSender { write_fd }, NotifierReceiver { read_fd }))
}
