use anyhow::{Context, Error, Result, bail};
use nix::{
    fcntl::OFlag,
    unistd::{pipe2, read, write},
};
use std::os::fd::OwnedFd;

#[derive(Debug)]
pub struct ErrorReporter {
    /// Read end of the pipe
    reader: OwnedFd,

    /// Write end of the pipe
    writer: OwnedFd,
}

impl ErrorReporter {
    /// Create new instance of `ErrorReporter`
    pub fn new() -> Result<Self> {
        let (reader, writer) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .context("Failed to create pipe for process error reporting")?;

        Ok(Self { reader, writer })
    }

    /// Consumes the reporter and returns the writer along with a new reporter
    /// that only contains the reader.
    pub fn split(self) -> (ParentErrorReader, ChildErrorWriter) {
        (
            ParentErrorReader::new(self.reader),
            ChildErrorWriter::new(self.writer),
        )
    }

    /// Helper method to convert any error implementing `std::error::Error`
    /// to a string before reporting.
    pub fn report_child_error<E>(&self, error: &E) -> Result<()>
    where
        E: std::error::Error,
    {
        self.report_error(&error.to_string())
    }

    /// Reports an error from the child process
    fn report_error(&self, error_message: &str) -> Result<()> {
        let error_bytes = error_message.as_bytes();
        let bytes_to_write = error_bytes.len();

        write(&self.writer, &error_bytes[..bytes_to_write])
            .context("Failed to write error message to pipe")?;

        Ok(())
    }

    /// Checks for reported errors without waiting for child process
    ///
    /// Check for error messages from the child process.
    /// Returns `Ok(())` if no errors are available to read.
    pub fn check_for_reported_errors(&self) -> Result<()> {
        match self.read_error_message() {
            Ok(message) if !message.is_empty() => {
                bail!("Child process reported error: {}", message);
            }
            Ok(_) => Ok(()),
            Err(e) => {
                if let Some(error) = e.downcast_ref::<nix::Error>() {
                    if *error == nix::Error::EAGAIN {
                        return Ok(());
                    }
                }
                Err(e).context("Failed to check for reported errors")
            }
        }
    }

    /// Reads an error message from the pipe
    fn read_error_message(&self) -> Result<String> {
        read_error_message_inner(&self.reader)
    }
}

/// Helper to manage FD in child processes
#[derive(Debug)]
pub struct ChildErrorWriter {
    writer: OwnedFd,
}

impl ChildErrorWriter {
    /// Creates a new instance of `ChildErrorWriter`
    pub fn new(writer: OwnedFd) -> Self {
        Self { writer }
    }

    /// Reports an error message to the parent process
    fn report_error(&self, error_message: &str) -> Result<()> {
        let bytes = error_message.as_bytes();
        let n = bytes.len();

        write(&self.writer, &bytes[..n])
            .context("Failed to write error message to parent process")?;

        Ok(())
    }
}

/// Helper to manage FD in parent processes
#[derive(Debug)]
pub struct ParentErrorReader {
    reader: OwnedFd,
}

impl ParentErrorReader {
    /// Creates a new `ParentErrorReader` from an owned FD
    pub fn new(reader: OwnedFd) -> Self {
        Self { reader }
    }

    /// Reads any available error message
    pub fn read_error_message(&self) -> Result<String> {
        read_error_message_inner(&self.reader)
    }
}

pub fn read_error_message_inner(reader: &OwnedFd) -> Result<String> {
    let mut buffer = Vec::new();

    match read(reader, &mut buffer) {
        Ok(0) => Ok(String::new()),
        Ok(n) => {
            let error_bytes = &buffer[..n];
            String::from_utf8(error_bytes.to_vec()).context("Error message contains invalid UTF-8")
        }
        Err(nix_error) => Err(Error::from(nix_error)),
    }
}
