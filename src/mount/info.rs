use crate::mount::bind::{AccessMode, BindError, RemountOptions, RemountPolicy};
use indextree::{Arena, NodeId};
use nix::{
    errno::Errno,
    fcntl::OFlag,
    libc::{MS_NOATIME, MS_NODEV, MS_NODIRATIME, MS_NOEXEC, MS_NOSUID, MS_RDONLY, MS_RELATIME},
    mount::{MsFlags, mount},
    sys::{
        stat::Mode,
        statfs::{PROC_SUPER_MAGIC, fstatfs},
    },
};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Error as IoError, Lines},
    os::fd::BorrowedFd,
    path::{Path, PathBuf},
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
    ValidateProcFd(#[source] IoError),

    #[error("failed to open /proc/self/mountinfo")]
    Open(#[source] IoError),

    #[error("failed to read /proc/self/mountinfo")]
    Read(#[source] IoError),

    #[error("failed to parse mountinfo line")]
    Parse(#[source] MountLineError),
}

impl TryFrom<BorrowedFd<'_>> for MountInfo {
    type Error = MountInfoError;

    fn try_from(procfd: BorrowedFd) -> Result<Self, Self::Error> {
        let stat = fstatfs(procfd).map_err(|e| MountInfoError::ValidateProcFd(IoError::from(e)))?;

        if stat.filesystem_type() != PROC_SUPER_MAGIC {
            return Err(MountInfoError::InvalidProcFd);
        }

        let fd = nix::fcntl::openat(
            procfd,
            "self/mountinfo",
            OFlag::O_CLOEXEC | OFlag::O_RDONLY,
            Mode::empty(),
        )
        .map_err(|e| MountInfoError::Open(IoError::from(e)))?;

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

#[derive(Debug, Error)]
pub(crate) enum MountTreeError {
    #[error("missing root")]
    MissingRoot,
}

mod sealed {
    pub trait Sealed {}
}

pub(crate) struct Parsed;
pub(crate) struct Linked;

impl sealed::Sealed for Parsed {}
impl sealed::Sealed for Linked {}

#[derive(Debug)]
pub(crate) struct MountTree {
    arena: Arena<MountLine>,

    // auxiliary data structures
    id_lookup: HashMap<u32, NodeId>,
    ids_ordered: Vec<NodeId>, // ordered-list

    root_mnt: PathBuf,
}

impl MountTree {
    pub(crate) fn build(self) -> MountTree {
        let Self {
            mut arena,
            id_lookup,
            ids_ordered,
            root_mnt,
            ..
        } = self;

        let root_mnt: &Path = root_mnt.as_ref();
        println!("root_mnt: {root_mnt:?}");

        for current_id in ids_ordered.iter() {
            let (current_mountpoint, parent_id) = {
                let current = arena[*current_id].get();
                (current.mountpoint.clone(), current.parent_id)
            };

            // skip mount-points not under root mount-point sub-tree '/<root-mnt>/'
            if !current_mountpoint.starts_with(root_mnt) {
                continue;
            }

            let Some(&parent_id) = id_lookup.get(&parent_id) else {
                continue;
            };

            {
                let parent = arena[parent_id].get_mut();
                if parent.mountpoint == current_mountpoint {
                    parent.covered = true;
                }
            }

            let siblings: Vec<NodeId> = parent_id.children(&arena).collect();
            let mut covered = false;

            for sibling_node in siblings {
                let sibling_mountpoint = &arena[sibling_node].get().mountpoint;

                // when current mount-point is sub-path of sibling mount-point
                if current_mountpoint.starts_with(&sibling_mountpoint) {
                    covered = true;
                    break;
                }

                // when sibling mount-point is sub-path of current mount-point
                if sibling_mountpoint.starts_with(&current_mountpoint) {
                    sibling_node.detach(&mut arena);
                }
            }

            if !covered {
                parent_id.append(*current_id, &mut arena);
            }
        }

        println!("parsed mountpoints");
        for node_id in ids_ordered.iter() {
            let mntline = arena[*node_id].get();
            println!("\t{}", mntline.mountpoint.display(),);
        }

        MountTree {
            arena,
            id_lookup,
            ids_ordered,
            root_mnt: root_mnt.to_path_buf(),
        }
    }

    pub(crate) fn flatten(&self) -> Result<Mounts<'_>, MountTreeError> {
        // TODO: init vec w/ capacity
        let mut mounts = Vec::new();

        // `self.ids_ordered` is guaranteed to have atleast the root mount-point.
        let root_id = self
            .ids_ordered
            .iter()
            .find(|id| self.arena[**id].get().mountpoint == self.root_mnt)
            .copied()
            .ok_or(MountTreeError::MissingRoot)?;

        self.flatten_inner(root_id, &mut mounts);
        if mounts.is_empty() {
            return Err(MountTreeError::MissingRoot);
        }

        println!("flattened mountpoints");
        for mount in mounts.iter() {
            let mntline = self.arena[*mount].get();
            println!("\t{}", mntline.mountpoint.display(),);
        }

        return Ok(Mounts {
            arena: &self.arena,
            mounts,
        });
    }

    // recursively traverse tree & collect uncovered mount-points.
    fn flatten_inner(&self, node_id: NodeId, mounts: &mut Vec<NodeId>) {
        if !self.arena[node_id].get().covered {
            mounts.push(node_id);
        }
        for child_id in node_id.children(&self.arena) {
            self.flatten_inner(child_id, mounts);
        }
    }
}

pub(crate) struct Mounts<'a> {
    arena: &'a Arena<MountLine>,
    mounts: Vec<NodeId>,
}

impl<'a> Mounts<'a> {
    pub(crate) fn remount(self, target: &Path, options: &RemountOptions) -> Result<(), BindError> {
        self.remount_root(target, options)?;

        if options.recursive() {
            self.remount_submounts(options)?;
        }

        Ok(())
    }

    fn remount_root(&self, target: &Path, options: &RemountOptions) -> Result<(), BindError> {
        // `self.mounts` is guaranteed to have atleast the root mount-point.
        let current_flags = self.arena[self.mounts[0]].get().options();
        let restricted_flags = self.restrict_flags(current_flags, options);
        println!("current_flags: {:?}", current_flags);
        println!("restricted_flags: {:?}", restricted_flags);
        if current_flags == restricted_flags {
            return Ok(());
        }
        Self::_remount(target, restricted_flags).map_err(|e| BindError::Mount {
            stage: Cow::Borrowed("re-mounting root-mount-point w/ restricted-flags"),
            source: IoError::from(e),
        })
    }

    fn remount_submounts(&self, options: &RemountOptions) -> Result<(), BindError> {
        for mount in self.mounts.iter().skip(1) {
            let mntline = self.arena[*mount].get();
            let current_flags = mntline.options();
            let restricted_flags = self.restrict_flags(current_flags, options);

            if current_flags == restricted_flags {
                continue;
            }

            if let Err(errno) = Self::_remount(&mntline.mountpoint(), restricted_flags) {
                if errno == Errno::EACCES {
                    match options.remount_policy() {
                        RemountPolicy::Restrictive => {
                            return Err(BindError::Mount {
                                stage: Cow::Borrowed(
                                    "re-mounting sub-mount-point w/ restricted-flags",
                                ),
                                source: IoError::from(errno),
                            });
                        }
                        RemountPolicy::Permissive => {
                            eprintln!(
                                "Warning: failed to re-mount submount-point {} w/ restricted-flags: {}",
                                mntline.mountpoint().display(),
                                errno
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn restrict_flags(&self, current_flags: MountFlags, options: &RemountOptions) -> MountFlags {
        println!("options: {:?}", options);
        let mut restricted = current_flags;
        if !options.devices() {
            restricted.insert(MountFlags::NODEV);
        }
        if options.access() == AccessMode::ReadOnly {
            restricted.insert(MountFlags::RDONLY);
        }
        restricted.insert(MountFlags::NOSUID);
        restricted
    }

    /// flags-only bind re-mount of an already-mounted path.
    fn _remount(target: &Path, flags: MountFlags) -> nix::Result<()> {
        mount(
            Some("none"),
            target,
            None::<&str>,
            MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_SILENT | flags.into(),
            None::<&str>,
        )
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct MountInfoLines(Vec<MountLine>);

impl MountInfoLines {
    pub(crate) fn into_tree(self, root_mnt: impl AsRef<Path>) -> Result<MountTree, MountTreeError> {
        if !self
            .0
            .iter()
            .any(|line| line.mountpoint == root_mnt.as_ref())
        {
            return Err(MountTreeError::MissingRoot);
        }

        let mut arena = Arena::with_capacity(self.0.len());
        let mut id_lookup = HashMap::with_capacity(self.0.len());
        let mut ids_ordered = Vec::with_capacity(self.0.len());

        for line in self.0 {
            let id = line.id;
            let node = arena.new_node(line);
            id_lookup.insert(id, node);
            ids_ordered.push(node);
        }

        Ok(MountTree {
            arena,
            id_lookup,
            ids_ordered,
            root_mnt: root_mnt.as_ref().to_path_buf(),
        })
    }
}

impl From<Vec<MountLine>> for MountInfoLines {
    fn from(lines: Vec<MountLine>) -> Self {
        Self(lines)
    }
}

impl TryFrom<MountInfoIter> for MountInfoLines {
    type Error = MountInfoError;

    fn try_from(iter: MountInfoIter) -> Result<Self, Self::Error> {
        iter.collect::<Result<Vec<MountLine>, MountInfoError>>()
            .map(Self::from)
    }
}

#[derive(Debug)]
pub(crate) struct MountLine {
    id: u32,
    parent_id: u32,
    mountpoint: PathBuf,
    options: MountFlags,

    // this is used during tree-building phase to
    // mark whether the mount-point is already covered
    covered: bool,
}

impl MountLine {
    #[inline]
    pub(crate) fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    #[inline]
    pub(crate) fn options(&self) -> MountFlags {
        self.options
    }
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
            covered: false,
        })
    }
}

bitflags::bitflags! {
   #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct MountFlags: u32 {
        const RDONLY     = MS_RDONLY as u32;
        const NOSUID     = MS_NOSUID as u32;
        const NODEV      = MS_NODEV as u32;
        const NOEXEC     = MS_NOEXEC as u32;
        const NOATIME    = MS_NOATIME as u32;
        const NODIRATIME = MS_NODIRATIME as u32;
        const RELATIME   = MS_RELATIME as u32;
    }
}

impl MountFlags {}

impl From<MountFlags> for MsFlags {
    fn from(flags: MountFlags) -> Self {
        MsFlags::from_bits_truncate(flags.bits() as _)
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
    use crate::mount::bind::BindError;
    use std::os::fd::{AsFd, OwnedFd};

    fn create_mountinfo(path: impl AsRef<std::path::Path>) -> Result<MountInfo, MountInfoError> {
        let proc_fd = nix::fcntl::open(path.as_ref(), OFlag::O_PATH, Mode::empty())
            .map_err(|e| MountInfoError::ValidateProcFd(IoError::from(e)))?;
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

    #[test]
    fn test_mountinfo_tree() -> anyhow::Result<()> {
        let mntinfo_iter = {
            let proc_fd = create_mountinfo("/proc").unwrap();
            MountInfo::try_from(proc_fd)?.into_iter()
        };

        let mnt_lines = MountInfoLines::try_from(mntinfo_iter).map_err(BindError::MountInfo)?;

        let mnt_tree = mnt_lines
            .into_tree("/")
            .map_err(BindError::MountTree)?
            .build();

        Ok(())
    }
}
