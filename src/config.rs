use crate::{checks::is_namespace_supported, utils::is_fd_valid};
use anyhow::{Error, Result, anyhow};
use bincode::{Decode, Encode};
use clap::{ArgGroup, Args, Parser};
use nix::sched::CloneFlags;
use std::{path::PathBuf, str::FromStr};

// TODO: Following sections:
// const HEADING_SECURITY: &str = "Security";
// const HEADING_SESSION: &str = "Session";
// const HEADING_ADVANCED: &str = "Advanced";

const HEADING_GENERAL: &str = "General";
const HEADING_NAMESPACES: &str = "Namespaces";
const HEADING_USER: &str = "User";
const HEADING_MOUNT: &str = "Mount";
const HEADING_ENVIRONMENT: &str = "Environment";
const HEADING_DEBUG: &str = "Debug";

#[derive(Parser, Debug)]
#[command(name = "Enclosure", about = "Unprivileged Sandboxing Tool")]
pub struct Config {
    #[command(flatten)]
    pub general: GeneralOptions,

    #[command(flatten)]
    pub namespace: NamespaceOptions,

    #[command(flatten)]
    pub user: UserOptions,

    #[command(flatten)]
    pub mount: MountOptions,

    #[command(flatten)]
    pub env: EnvOptions,

    #[command(flatten)]
    pub debug: DebugOptions,

    #[arg(value_name = "EXECUTABLE")]
    pub executable: PathBuf,

    #[arg(value_name = "ARGS", trailing_var_arg = true)]
    pub args: Vec<String>,
}

impl Config {
    pub fn parse_clone_flags(&self) -> Result<CloneFlags, Error> {
        self.namespace.parse()
    }
}

#[derive(Args, Debug)]
pub struct GeneralOptions {
    #[arg(long, help = "Print version", help_heading = HEADING_GENERAL)]
    pub version: bool,
}

#[derive(Args, Debug)]
pub struct NamespaceOptions {
    #[arg(
        long,
        help = "Unshare all supported namespaces",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_all: bool,

    #[arg(
        long,
        help = "Create new IPC namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_ipc: bool,

    #[arg(
        long,
        help = "Create new PID namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_pid: bool,

    #[arg(
        long,
        help = "Create new network namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_net: bool,

    #[arg(
        long,
        help = "Create new UTS namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_uts: bool,

    #[arg(
        long,
        help = "Create new cgroup namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_cgroup: bool,

    #[arg(
        long,
        help = "Create new user namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_user: bool,

    #[arg(
        long,
        help = "Create new file descriptor namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_files: bool,

    #[arg(
        long,
        help = "Create new filesystem namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_fs: bool,

    #[arg(
        long,
        help = "Create new mount namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_ns: bool,

    #[arg(
        long,
        help = "Create new time namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_time: bool,

    #[arg(
        long,
        help = "Create new system v semaphore namespace",
        help_heading = HEADING_NAMESPACES
    )]
    pub unshare_sysvsem: bool,
}

impl NamespaceOptions {
    fn mappings(&self) -> [(bool, CloneFlags); 10] {
        [
            (self.unshare_files, CloneFlags::CLONE_FILES),
            (self.unshare_fs, CloneFlags::CLONE_FS),
            (self.unshare_cgroup, CloneFlags::CLONE_NEWCGROUP),
            (self.unshare_user, CloneFlags::CLONE_NEWUSER),
            (self.unshare_ipc, CloneFlags::CLONE_NEWIPC),
            (self.unshare_net, CloneFlags::CLONE_NEWNET),
            (self.unshare_ns, CloneFlags::CLONE_NEWNS),
            (self.unshare_pid, CloneFlags::CLONE_NEWPID),
            (self.unshare_uts, CloneFlags::CLONE_NEWUTS),
            (self.unshare_sysvsem, CloneFlags::CLONE_SYSVSEM),
        ]
    }

    fn parse(&self) -> Result<CloneFlags, Error> {
        match self.unshare_all {
            true => Ok(CloneFlags::all()),
            false => {
                let mut flags = CloneFlags::CLONE_NEWNS;

                for (enabled, flag) in self.mappings() {
                    if enabled {
                        if !is_namespace_supported(flag) {
                            return Err(anyhow!("Kernel doesn't support: {:?}", flag));
                        }

                        flags.insert(flag);
                    }
                }

                if flags.is_empty() {
                    return Ok(CloneFlags::all());
                }

                return Ok(flags);
            }
        }
    }
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("userns_mode").args(&["userns", "unshare_user"]).multiple(false).required(false)))]
pub struct UserOptions {
    #[arg(
        long,
        help = "Use this user namespace (cannot be used with --unshare-user)",
        value_parser = validate_fd_arg,
        help_heading = HEADING_USER
    )]
    pub userns: Option<i32>,

    #[arg(
        long,
        help = "Switch to this user namespace",
        requires = "unshare_user",
        help_heading = HEADING_USER
    )]
    pub switch_userns: Option<i32>,

    #[arg(
        long,
        help = "Disable nested user namespace (requires --unshare-user)",
        requires = "unshare_user",
        help_heading = HEADING_USER
    )]
    pub disable_nested_userns: bool,

    #[arg(
        long,
        help = "Use this pid namespace (requires --unshare-pid)",
        requires = "unshare_pid",
        help_heading = HEADING_USER,
    )]
    pub pidns: Option<i32>,

    #[arg(
        long,
        help = "Custom uid",
        requires = "unshare_user",
        requires = "userns",
        help_heading = HEADING_USER
    )]
    pub uid: Option<u32>,

    #[arg(
        long,
        help = "Custom gid",
        requires = "unshare_user",
        requires = "userns",
        help_heading = HEADING_USER
    )]
    pub gid: Option<u32>,

    #[arg(
        long,
        help = "Customm hostname",
        requires = "unshare_uts",
        help_heading = HEADING_USER,
    )]
    pub hostname: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct MountOptions {
    /// Base directory for mount operations
    #[arg(
        long,
        default_value = "/tmp",
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub base: PathBuf,

    #[arg(
        long,
        value_parser = PathPair::from_str,
        help_heading = HEADING_MOUNT
    )]
    pub bind: Option<PathPair>,

    /// Bind mount with device access
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub dev_bind: Option<PathPair>,

    /// Read-only bind mount
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub ro_bind: Option<PathPair>,

    /// Bind mount from file descriptor (FD DEST pairs)
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub bind_fd: Option<FdPathPair>,

    /// Read-only bind mount from file descriptor (FD DEST pairs)
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub ro_bind_fd: Option<FdPathPair>,

    /// Remount paths as read-only
    #[arg(
        long,
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub remount_ro: Option<PathBuf>,

    /// Mount procfs at specified path
    #[arg(
        long,
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub proc: Option<PathBuf>,

    /// Mount devfs at specified path
    #[arg(
        long,
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub dev: Option<PathBuf>,

    /// Mount tmpfs at specified path
    #[arg(
        long,
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub tmpfs: Option<PathBuf>,

    /// Mount message queue filesystem at specified path
    #[arg(
        long,
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub mqueue: Option<PathBuf>,

    /// Create directories
    #[arg(
        long,
        help_heading = HEADING_MOUNT,
        value_hint = clap::ValueHint::DirPath
    )]
    pub dir: Option<PathBuf>,

    /// Create files from file descriptor (FD DEST pairs)
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub file: Vec<FdPathPair>,

    /// Create symbolic links
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub symlink: Option<PathPair>,

    /// Set default permissions (octal format, e.g., 755)
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub perms: Option<OctalPermissions>,

    /// Set tmpfs size (e.g., 100M, 1G)
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub size: Option<Size>,

    /// Change file permissions (OCTAL PATH pairs)
    #[arg(
        long,
        help_heading = HEADING_MOUNT
    )]
    pub chmod: Vec<ChmodPair>,
}

/// Represents a source-destination path pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPair {
    pub source: PathBuf,
    pub destination: PathBuf,
}

impl FromStr for PathPair {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();
        let src = parts.next().ok_or("Missing source")?;
        let dst = parts.next().ok_or("Missing destination")?;

        if parts.next().is_some() {
            return Err("Too many arguments for --bind".into());
        }

        Ok(PathPair {
            source: PathBuf::from(src),
            destination: PathBuf::from(dst),
        })
    }
}

/// Represents a file descriptor and destination path pair
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdPathPair {
    pub fd: i32,
    pub destination: PathBuf,
}

/// Represents a chmod operation with permissions and target path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChmodPair {
    pub permissions: u32,
    pub path: PathBuf,
}

impl std::str::FromStr for FdPathPair {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split_whitespace();

        let fd = parts
            .next()
            .ok_or("Missing file descriptor")?
            .parse::<i32>()
            .map_err(|error| format!("Invalid file descriptor: {s} \n{error}"))?;

        let destination = parts
            .next()
            .ok_or("Missing destination argument")
            .map(PathBuf::from)?;

        destination
            .is_absolute()
            .then_some(())
            .ok_or("The path must be absolute")?;

        Ok(FdPathPair { fd, destination })
    }
}

impl std::str::FromStr for ChmodPair {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        match parts.as_slice() {
            [octal_str, path] => {
                let permissions = u32::from_str_radix(octal_str, 8)
                    .map_err(|_| format!("Invalid octal permissions: '{}'", octal_str))?;

                Ok(ChmodPair {
                    permissions,
                    path: PathBuf::from(path),
                })
            }
            _ => Err(format!("Expected 'OCTAL PATH', got: '{}'", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OctalPermissions(pub u32);

impl std::str::FromStr for OctalPermissions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        u32::from_str_radix(s, 8)
            .map(OctalPermissions)
            .map_err(|_| format!("Invalid octal permissions: '{}'", s))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size(pub u64);

impl std::str::FromStr for Size {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_uppercase();
        if let Some(stripped) = s.strip_suffix('K') {
            let num: u64 = stripped
                .parse()
                .map_err(|_| format!("Invalid size format: '{}'", s))?;
            Ok(Size(num * 1024))
        } else if let Some(stripped) = s.strip_suffix('M') {
            let num: u64 = stripped
                .parse()
                .map_err(|_| format!("Invalid size format: '{}'", s))?;
            Ok(Size(num * 1024 * 1024))
        } else if let Some(stripped) = s.strip_suffix('G') {
            let num: u64 = stripped
                .parse()
                .map_err(|_| format!("Invalid size format: '{}'", s))?;
            Ok(Size(num * 1024 * 1024 * 1024))
        } else {
            s.parse::<u64>()
                .map(Size)
                .map_err(|_| format!("Invalid size format: '{}'", s))
        }
    }
}

impl From<MountOptions> for MountCommands {
    fn from(opts: MountOptions) -> Self {
        let mut ops = Vec::new();

        if let Some(bind) = opts.bind {
            ops.push(MountCommand::Mount(MountOp::Bind {
                source: bind.source,
                target: bind.destination,
                options: BindOptions {
                    readonly: false,
                    mount_dev: false,
                },
            }));
        }

        if let Some(dev_bind) = opts.dev_bind {
            ops.push(MountCommand::Mount(MountOp::Bind {
                source: dev_bind.source,
                target: dev_bind.destination,
                options: BindOptions {
                    readonly: false,
                    mount_dev: true,
                },
            }));
        }

        if let Some(ro_bind) = opts.ro_bind {
            ops.push(MountCommand::Mount(MountOp::Bind {
                source: ro_bind.source,
                target: ro_bind.destination,
                options: BindOptions {
                    readonly: true,
                    mount_dev: false,
                },
            }));
        }

        if let Some(proc_path) = opts.proc {
            ops.push(MountCommand::Mount(MountOp::Special(SpecialMount::Proc(
                proc_path,
            ))));
        }

        if let Some(dev_path) = opts.dev {
            ops.push(MountCommand::Mount(MountOp::Special(SpecialMount::Dev(
                dev_path,
            ))));
        }

        if let Some(tmpfs_path) = opts.tmpfs {
            ops.push(MountCommand::Mount(MountOp::Special(SpecialMount::Tmpfs {
                target: tmpfs_path,
                size_kb: opts.size.map(|s| (s.0 / 1024) as usize),
                mode: opts.perms.map(|p| p.0),
            })));
        }

        if let Some(mqueue_path) = opts.mqueue {
            ops.push(MountCommand::Mount(MountOp::Special(SpecialMount::Mqueue(
                mqueue_path,
            ))));
        }

        // Handle file operations
        if let Some(dir) = opts.dir {
            ops.push(MountCommand::File(FileOp::CreateDir(dir)));
        }

        for pair in opts.file {
            ops.push(MountCommand::File(FileOp::CreateFile {
                fd: pair.fd,
                dest: pair.destination,
            }));
        }

        if let Some(symlink) = opts.symlink {
            ops.push(MountCommand::File(FileOp::CreateSymlink {
                link_path: symlink.destination,
                target: symlink.source,
            }));
        }

        if let Some(remount_path) = opts.remount_ro {
            ops.push(MountCommand::File(FileOp::RemountReadOnly(remount_path)));
        }

        // Handle system operations
        for chmod_pair in opts.chmod {
            ops.push(MountCommand::System(SystemOp::Chmod {
                path: chmod_pair.path,
                mode: chmod_pair.permissions,
            }));
        }

        ops
    }
}

pub type MountCommands = Vec<MountCommand>;

#[derive(Debug, Decode, Encode)]
pub enum MountCommand {
    Mount(MountOp),
    File(FileOp),
    System(SystemOp),
}

/// Types of mount operations.
#[derive(Debug, Decode, Encode)]
pub enum MountOp {
    Bind {
        source: PathBuf,
        target: PathBuf,
        options: BindOptions,
    },
    Overlay {
        lowerdir: PathBuf,
        upperdir: Option<PathBuf>,
        workdir: Option<PathBuf>,
        target: PathBuf,
        mode: OverlayMode,
    },
    Special(SpecialMount),
}

/// Special filesystem mounts like proc, tmpfs, etc.
#[derive(Debug, Decode, Encode)]
pub enum SpecialMount {
    Proc(PathBuf),
    Dev(PathBuf),
    Tmpfs {
        target: PathBuf,
        size_kb: Option<usize>,
        mode: Option<u32>,
    },
    Mqueue(PathBuf),
    OverlaySource {
        lowerdir: PathBuf,
        upperdir: PathBuf,
        workdir: PathBuf,
    },
}

/// Mount options for bind mounts.
#[derive(Debug, Default, Decode, Encode)]
pub struct BindOptions {
    pub readonly: bool,
    pub mount_dev: bool,
}

/// Overlay mount mode: readonly or read-write.
#[derive(Debug, Decode, Encode)]
pub enum OverlayMode {
    ReadOnly,
    ReadWrite,
}

/// Filesystem operations.
#[derive(Debug, Decode, Encode)]
pub enum FileOp {
    CreateDir(PathBuf),
    CreateFile {
        fd: i32,
        dest: PathBuf,
    },
    CreateBindFile {
        source: PathBuf,
        dest: PathBuf,
        readonly: bool,
    },
    CreateSymlink {
        link_path: PathBuf,
        target: PathBuf,
    },
    RemountReadOnly(PathBuf),
}

/// System-level configuration operations.
#[derive(Debug, Decode, Encode)]
pub enum SystemOp {
    SetHostname(String),
    Chmod { path: PathBuf, mode: u32 },
}

#[derive(Args, Debug)]
pub struct EnvOptions {
    #[arg(
        long,
        help = "Change directory to <DIR>",
        help_heading = HEADING_ENVIRONMENT
    )]
    pub chdir: Option<String>,

    #[arg(
        long,
        help = "Unset all environment variables",
        help_heading = HEADING_ENVIRONMENT
    )]
    pub clearenv: bool,

    #[arg(
        long,
        help = "Set environment variable",
        value_names = ["VAR", "VALUE"],
        help_heading = HEADING_ENVIRONMENT
    )]
    pub setenv: Vec<String>,

    #[arg(
        long,
        help = "Unset an environment variable",
        help_heading = HEADING_ENVIRONMENT
    )]
    pub unsetenv: Vec<String>,
}

#[derive(Args, Debug)]
pub struct DebugOptions {
    #[arg(long, help="For debugging CLI arguments", help_heading = HEADING_DEBUG)]
    pub cli_args: bool,
}

fn validate_fd_arg(input: &str) -> Result<()> {
    let raw_fd = input.parse::<i32>()?;
    is_fd_valid(raw_fd).map(|_| {})
}
