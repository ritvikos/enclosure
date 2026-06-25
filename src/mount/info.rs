use nix::{
    fcntl::OFlag,
    libc::{MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_RDONLY, MS_RELATIME},
    sys::stat::Mode,
    sys::statfs::{PROC_SUPER_MAGIC, fstatfs},
};
use std::{
    fs::File,
    io::{BufRead, BufReader, Lines},
    os::fd::BorrowedFd,
    path::PathBuf,
    str::FromStr,
};
use thiserror::Error;

#[derive(Debug)]
pub(crate) struct MountInfo {
    reader: BufReader<File>,
}

#[derive(Debug, Error)]
pub(crate) enum MountInfoError {
    #[error("file descriptor is not a procfs mount")]
    InvalidProcFd,

    #[error("failed to validate proc file descriptor")]
    ValidateProcFd(#[source] std::io::Error),

    #[error("failed to open /proc/self/mountinfo")]
    Open(#[source] std::io::Error),

    #[error("failed to read /proc/self/mountinfo")]
    Read(#[source] std::io::Error),

    #[error("failed to parse mountinfo line")]
    Parse(#[source] MountLineError),
}

impl TryFrom<BorrowedFd<'_>> for MountInfo {
    type Error = MountInfoError;

    fn try_from(procfd: BorrowedFd) -> Result<Self, Self::Error> {
        let stat =
            fstatfs(procfd).map_err(|e| MountInfoError::ValidateProcFd(std::io::Error::from(e)))?;

        if stat.filesystem_type() != PROC_SUPER_MAGIC {
            return Err(MountInfoError::InvalidProcFd);
        }

        let fd = nix::fcntl::openat(
            procfd,
            "self/mountinfo",
            OFlag::O_CLOEXEC | OFlag::O_RDONLY,
            Mode::empty(),
        )
        .map_err(|e| MountInfoError::Open(std::io::Error::from(e)))?;

        Ok(MountInfo {
            reader: BufReader::new(File::from(fd)),
        })
    }
}

pub(crate) struct MountInfoIter {
    lines: Lines<BufReader<File>>,
}

impl Iterator for MountInfoIter {
    type Item = Result<MountLine, MountInfoError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.lines.next().map(|line| {
            line.map_err(MountInfoError::Read)?
                .parse::<MountLine>()
                .map_err(MountInfoError::Parse)
        })
    }
}

impl IntoIterator for MountInfo {
    type Item = Result<MountLine, MountInfoError>;
    type IntoIter = MountInfoIter;

    fn into_iter(self) -> Self::IntoIter {
        MountInfoIter {
            lines: self.reader.lines(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct MountLine {
    id: u32,
    parent_id: u32,
    mountpoint: PathBuf,
    options: MountFlags,
}

#[derive(Debug, Error)]
pub(crate) enum MountLineError {
    #[error("missing or malformed field `{field}`")]
    Malformed { field: &'static str },

    #[error("invalid mount flags")]
    InvalidFlags(#[source] ParseFlagsError),
}

#[derive(Debug, Error)]
#[error("unrecognized flag `{0}`")]
pub(crate) struct ParseFlagsError(String);

// Valid format: <https://manpages.ubuntu.com/manpages/noble/man5/proc_pid_mountinfo.5.html>
impl FromStr for MountLine {
    type Err = MountLineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let mut next =
            |field: &'static str| parts.next().ok_or(MountLineError::Malformed { field });

        let id = next("mount ID")?
            .parse::<u32>()
            .map_err(|_| MountLineError::Malformed { field: "mount ID" })?;
        let parent_id = next("parent ID")?
            .parse::<u32>()
            .map_err(|_| MountLineError::Malformed { field: "parent ID" })?;

        // skip 'major:minor' and 'root' fields
        {
            let _major_minor = next("major:minor")?;
            let _root = next("root")?;
        }

        let mountpoint = PathBuf::from(next("mountpoint")?);
        let options =
            MountFlags::from_str(next("mount options")?).map_err(MountLineError::InvalidFlags)?;

        Ok(MountLine {
            id,
            parent_id,
            mountpoint,
            options,
        })
    }
}

bitflags::bitflags! {
   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct MountFlags: u32 {
        const RDONLY     = MS_RDONLY as u32;
        const NOSUID     = MS_NOSUID as u32;
        const NODEV      = MS_NODEV as u32;
        const NOEXEC     = MS_NOEXEC as u32;
        const NOATIME    = MS_NOATIME as u32;
        const NODIRATIME = MS_NODIRATIME as u32;
        const RELATIME   = MS_RELATIME as u32;
    }
}

impl FromStr for MountFlags {
    type Err = ParseFlagsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let flags = s
            .trim()
            .split(',')
            .filter_map(|flag| match flag {
                "ro" => Some(MountFlags::RDONLY),
                "nosuid" => Some(MountFlags::NOSUID),
                "nodev" => Some(MountFlags::NODEV),
                "noexec" => Some(MountFlags::NOEXEC),
                "noatime" => Some(MountFlags::NOATIME),
                "nodiratime" => Some(MountFlags::NODIRATIME),
                "relatime" => Some(MountFlags::RELATIME),
                _ => None,
            })
            .fold(MountFlags::empty(), |acc, flag| acc | flag);
        Ok(flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn create_mountinfo(path: impl AsRef<std::path::Path>) -> Result<MountInfo, MountInfoError> {
        let proc_fd = nix::fcntl::open(path.as_ref(), OFlag::O_PATH, Mode::empty())
            .map_err(|e| MountInfoError::ValidateProcFd(std::io::Error::from(e)))?;
        MountInfo::try_from(proc_fd.as_fd())
    }

    #[test]
    fn test_mountinfo_invalid_procfd() {
        assert!(matches!(
            create_mountinfo("/"),
            Err(MountInfoError::InvalidProcFd)
        ));
    }

    #[test]
    fn test_mountinfo_iter() {
        let mnt_info = create_mountinfo("/proc").unwrap();
        for mnt_line in mnt_info {
            match mnt_line {
                Ok(line) => println!("{:?}", line),
                Err(e) => eprintln!("Error parsing mount line: {}", e),
            }
        }
    }
}
