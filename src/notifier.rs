use core::fmt;

use anyhow::{Context, Result};
use nix::{
    sys::eventfd::{EfdFlags, EventFd},
    unistd::{read, write},
};

pub struct Notifier {
    inner: EventFd,
}

impl Notifier {
    pub fn new() -> Result<Self> {
        let inner = EventFd::from_value_and_flags(0, EfdFlags::EFD_CLOEXEC)
            .context("Failed to create EventFd")?;

        Ok(Self { inner })
    }

    pub fn wait_for_signal(&self) -> Result<usize> {
        let mut buffer = 0u64.to_ne_bytes();
        let read = read(&self.inner, &mut buffer).context("Failed to read signal value")?;
        Ok(read)
    }

    pub fn signal(&self) -> Result<()> {
        let buffer = 1u64.to_ne_bytes();
        write(&self.inner, &buffer).context("Failed to write signal value")?;
        Ok(())
    }
}

impl fmt::Debug for Notifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Notifier").field("fd", &self.inner).finish()
    }
}
