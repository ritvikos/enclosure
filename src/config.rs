pub use crate::utils::{is_fd_valid, is_namespace_supported};
use anyhow::{Error, Result, anyhow};
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

const FD_PREFIX: &str = "fd=";

#[derive(Parser, Debug, Clone)]
#[command(name = "Enclosure", about = "Unprivileged Sandboxing Tool")]
pub struct Config {
    #[command(flatten)]
    pub general: GeneralOptions,

    #[command(flatten)]
    pub namespace: NamespaceOptions,

    #[command(flatten)]
    pub user: UserOptions,

    #[arg(long, value_parser = MountEntry::from_str)]
    pub mount: Vec<MountEntry>,

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

#[derive(Args, Debug, Clone)]
pub struct GeneralOptions {
    #[arg(long, help = "Print version", help_heading = HEADING_GENERAL)]
    pub version: bool,
}

#[derive(Args, Debug, Clone)]
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
    fn mappings(&self) -> [(bool, CloneFlags); 9] {
        [
            (self.unshare_files, CloneFlags::CLONE_FILES),
            (self.unshare_fs, CloneFlags::CLONE_FS),
            (self.unshare_cgroup, CloneFlags::CLONE_NEWCGROUP),
            (self.unshare_user, CloneFlags::CLONE_NEWUSER),
            (self.unshare_ipc, CloneFlags::CLONE_NEWIPC),
            (self.unshare_net, CloneFlags::CLONE_NEWNET),
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

#[derive(Args, Debug, Clone)]
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
        help = "Set custom hostname (requires --unshare-uts)",
        requires = "unshare_uts",
        help_heading = HEADING_USER,
    )]
    pub hostname: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParseMountError {
    #[error(
        "unknown mount kind '{kind}' (valid: bind, dev, dir, file, mqueue, overlay, proc, symlink, tmpfs)"
    )]
    UnknownKind { kind: String },

    #[error("invalid {kind} mount: {reason}\n  expected syntax: {syntax}")]
    InvalidSyntax {
        kind: &'static str,
        syntax: &'static str,
        reason: String,
    },

    #[error("invalid {kind} mount option: {reason}")]
    InvalidOption { kind: &'static str, reason: String },
}

impl ParseMountError {
    fn syntax(kind: &'static str, syntax: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidSyntax {
            kind,
            syntax,
            reason: reason.into(),
        }
    }

    fn option(kind: &'static str, reason: impl Into<String>) -> Self {
        Self::InvalidOption {
            kind,
            reason: reason.into(),
        }
    }
}

trait MountParser: Sized {
    const KIND: &'static str;
    const SYNTAX: &'static str;

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError>;

    fn err_syntax(reason: impl Into<String>) -> ParseMountError {
        ParseMountError::syntax(Self::KIND, Self::SYNTAX, reason)
    }

    fn err_option(reason: impl Into<String>) -> ParseMountError {
        ParseMountError::option(Self::KIND, reason)
    }
}

#[derive(Clone, Debug)]
pub enum MountSource {
    Path { target: PathBuf, mount_dev: bool },
    Fd(i32),
}

#[derive(Clone, Debug)]
pub enum Mode {
    ReadOnly,
    ReadWrite,
}

// CONSIDERATION: should we create data structure to parse src/dest/link/target?
// they tend to be quite repetitive across mount kinds.
#[derive(Debug, Clone)]
pub enum MountEntry {
    // Bind mounts
    Bind {
        src: MountSource,
        dest: PathBuf,
        mode: Mode,
    },

    // File tree ops
    Dir {
        path: PathBuf,
        mode: Option<OctalPermissions>,
    },
    File {
        fd: i32,
        dest: PathBuf,
        mode: Option<OctalPermissions>,
    },
    Symlink {
        target: PathBuf,
        link: PathBuf,
    },

    // Overlay
    Overlay {
        dest: PathBuf,
        lowerdir: PathBuf,
        upperdir: Option<PathBuf>,
        workdir: Option<PathBuf>,
    },

    // Special mounts
    Proc {
        dest: PathBuf,
    },
    Dev {
        dest: PathBuf,
    },
    Tmpfs {
        dest: PathBuf,
        size_kb: Option<usize>,
        permission: Option<OctalPermissions>,
    },
    Mqueue {
        dest: PathBuf,
    },
}

impl FromStr for MountEntry {
    type Err = ParseMountError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // NOTE: do not validate/manipulate params here, pass to `parse()` to preserve error context
        let (kind, rest) = s.split_once(':').ok_or_else(|| {
            ParseMountError::syntax("mount", "<kind>:<args>", "missing kind prefix")
        })?;

        match kind {
            BindMount::KIND => BindMount::parse(rest),
            DevMount::KIND => DevMount::parse(rest),
            DirMount::KIND => DirMount::parse(rest),
            FileMount::KIND => FileMount::parse(rest),
            MQueueMount::KIND => MQueueMount::parse(rest),
            OverlayMount::KIND => todo!(),
            ProcMount::KIND => ProcMount::parse(rest),
            SymlinkMount::KIND => SymlinkMount::parse(rest),
            TmpfsMount::KIND => todo!(),
            _ => Err(ParseMountError::UnknownKind {
                kind: kind.to_owned(),
            }),
        }
    }
}

#[derive(Default)]
struct BindOpts {
    mode: Option<Mode>,
    mount_dev: bool,
}
struct BindMount;

impl BindOpts {
    fn parse(opts: &str, is_fd: bool) -> Result<Self, ParseMountError> {
        let mut parsed = Self::default();

        for opt in opts.split(',').filter(|s| !s.is_empty()) {
            match opt.trim() {
                "ro" | "rw" if parsed.mode.is_some() => {
                    return Err(ParseMountError::option(
                        BindMount::KIND,
                        "duplicate 'mode' passed (either 'ro' or 'rw' is allowed)",
                    ));
                }
                "ro" => parsed.mode = Some(Mode::ReadOnly),
                "rw" => parsed.mode = Some(Mode::ReadWrite),
                "dev" if is_fd => {
                    return Err(ParseMountError::option(
                        BindMount::KIND,
                        "'dev' cannot combine with {FD_PREFIX} sources",
                    ));
                }
                "dev" => parsed.mount_dev = true,
                opt => {
                    return Err(ParseMountError::option(
                        BindMount::KIND,
                        format!("unknown option '{opt}' (valid: ro, rw, dev)"),
                    ));
                }
            }
        }

        Ok(parsed)
    }
}

impl MountParser for BindMount {
    const KIND: &'static str = "bind";
    const SYNTAX: &'static str = "bind:<src>:<dest>[,ro|rw][,dev]  or  bind:fd=<N>:<dest>[,ro|rw]";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let (src, rest) = rest
            .split_once(':')
            .ok_or_else(|| Self::err_syntax("missing source / destination"))
            .map(|(s, r)| (s.trim(), r.trim()))
            .and_then(|(s, r)| match (s, r) {
                ("", _) => return Err(Self::err_syntax("source path cannot be empty")),
                (_, "") => return Err(Self::err_syntax("destination path cannot be empty")),
                (s, r) => Ok((s, r)),
            })?;

        let (dest, opts) = match rest.split_once(',') {
            Some(("", _)) => return Err(Self::err_syntax("destination path cannot be empty")),
            Some((d, o)) => (d.trim(), o.trim()),
            None => (rest.trim(), ""),
        };

        let is_fd = src.starts_with(FD_PREFIX);
        let BindOpts { mode, mount_dev } = BindOpts::parse(opts, is_fd)?;

        let src = if let Some(fd) = src.strip_prefix(FD_PREFIX) {
            MountSource::Fd(
                fd.parse::<i32>()
                    .map_err(|_| Self::err_syntax("invalid file descriptor"))?,
            )
        } else {
            MountSource::Path {
                mount_dev,
                target: (!src.is_empty())
                    .then(|| PathBuf::from(src))
                    .ok_or_else(|| Self::err_syntax("source path cannot be empty"))?,
            }
        };

        Ok(MountEntry::Bind {
            src,
            dest: PathBuf::from(dest),
            mode: mode.unwrap_or_else(|| {
                println!("no mode specified for bind-mount, defaulting to 'rw'");
                Mode::ReadWrite
            }),
        })
    }
}

struct DevMount;

impl MountParser for DevMount {
    const KIND: &'static str = "dev";
    const SYNTAX: &'static str = "dev:<dest>";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let rest = rest.trim();

        Ok(MountEntry::Dev {
            dest: (!rest.is_empty())
                .then(|| PathBuf::from(rest))
                .ok_or_else(|| Self::err_syntax("destination path cannot be empty"))?,
        })
    }
}

struct DirMount;

impl MountParser for DirMount {
    const KIND: &'static str = "dir";
    const SYNTAX: &'static str = "dir:<dest>[,mode=<octal>]";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let (path, opts) = {
            let (p, o) = rest.split_once(',').unwrap_or((rest, ""));
            let p = p.trim();
            if p.is_empty() {
                return Err(Self::err_syntax("destination cannot be empty"));
            }
            (PathBuf::from(p), o.trim())
        };

        let mode = match opts.trim() {
            "" => None,
            opt if let Some(mode) = opt.strip_prefix("mode=") => {
                Some(mode.trim().parse::<OctalPermissions>().map_err(|_| {
                    Self::err_option(format!("invalid mode value '{mode}', expected octal"))
                })?)
            }
            _ => {
                return Err(Self::err_option(format!(
                    "unknown option '{opts}' (expected: mode=<octal>)"
                )));
            }
        };

        Ok(MountEntry::Dir { path, mode })
    }
}

struct FileMount;

impl MountParser for FileMount {
    const KIND: &'static str = "file";
    const SYNTAX: &'static str = "file:fd=<N>:<dest>,mode=<octal>";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let (fd, rest) = rest
            .split_once(':')
            .ok_or_else(|| Self::err_syntax("missing fd / destination"))
            .and_then(|(fd, rest)| match (fd.trim(), rest.trim()) {
                ("", _) => return Err(Self::err_syntax("fd cannot be empty")),
                (_, "") => return Err(Self::err_syntax("destination cannot be empty")),
                (fd, _) if !fd.starts_with(FD_PREFIX) => {
                    return Err(Self::err_syntax("fd must start with 'fd='"));
                }
                (fd, rest) => Ok((
                    fd.trim_start_matches(FD_PREFIX)
                        .parse::<i32>()
                        .map_err(|_| Self::err_syntax(format!("invalid fd '{}'", fd)))?,
                    rest,
                )),
            })?;

        let (dest, mode) = match rest.split_once(',') {
            None => (rest.trim(), None),
            Some(("", _)) => return Err(Self::err_syntax("destination cannot be empty")),
            Some((d, m)) => {
                let mode = m
                    .trim()
                    .strip_prefix("mode=")
                    .ok_or_else(|| Self::err_syntax("expected 'mode=<octal>'"))?
                    .parse::<OctalPermissions>()
                    .map_err(|_| {
                        Self::err_syntax(format!(
                            "invalid mode value '{}', expected octal",
                            m.trim()
                        ))
                    })?;
                (d.trim(), Some(mode))
            }
        };

        Ok(MountEntry::File {
            dest: PathBuf::from(dest),
            fd,
            mode,
        })
    }
}

struct MQueueMount;

impl MountParser for MQueueMount {
    const KIND: &'static str = "mqueue";
    const SYNTAX: &'static str = "mqueue:<dest>";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let rest = rest.trim();
        Ok(MountEntry::Mqueue {
            dest: (!rest.is_empty())
                .then(|| PathBuf::from(rest))
                .ok_or_else(|| Self::err_syntax("destination path cannot be empty"))?,
        })
    }
}

struct OverlayMount;

impl MountParser for OverlayMount {
    const KIND: &'static str = "overlay";
    const SYNTAX: &'static str = "overlay:<dest>,lowerdir=<path>[,upperdir=<path>,workdir=<path>]";

    fn parse(_rest: &str) -> Result<MountEntry, ParseMountError> {
        todo!()
    }
}

struct ProcMount;

impl MountParser for ProcMount {
    const KIND: &'static str = "proc";
    const SYNTAX: &'static str = "proc:<dest>";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let rest = rest.trim();

        Ok(MountEntry::Proc {
            dest: (!rest.is_empty())
                .then(|| PathBuf::from(rest))
                .ok_or_else(|| Self::err_syntax("destination path cannot be empty"))?,
        })
    }
}

struct SymlinkMount;

impl MountParser for SymlinkMount {
    const KIND: &'static str = "symlink";
    const SYNTAX: &'static str = "symlink:<target>:<link>";

    fn parse(rest: &str) -> Result<MountEntry, ParseMountError> {
        let (target, link) = rest
            .split_once(':')
            .ok_or_else(|| Self::err_syntax("missing target or link path"))
            .map(|(t, l)| (t.trim(), l.trim()))
            .and_then(|(t, l)| match (t, l) {
                ("", _) => return Err(Self::err_syntax("target path cannot be empty")),
                (_, "") => return Err(Self::err_syntax("link path cannot be empty")),
                (t, l) => Ok((
                    PathBuf::from(t),
                    Self::normalize_link(l).map_err(Self::err_syntax)?,
                )),
            })?;

        Ok(MountEntry::Symlink { target, link })
    }
}

impl SymlinkMount {
    fn normalize_link(path: &str) -> Result<PathBuf, String> {
        let components =
            path.split('/')
                .filter(|c| !c.is_empty())
                .fold(Vec::new(), |mut acc, c| {
                    match c {
                        "." => {}
                        ".." => {
                            acc.pop();
                        }
                        c => acc.push(c),
                    }
                    acc
                });

        Ok(PathBuf::from("/").join(components.join("/")))
    }
}

struct TmpfsMount;

impl MountParser for TmpfsMount {
    const KIND: &'static str = "tmpfs";
    const SYNTAX: &'static str = "tmpfs:<dest>[,size=<N>][,mode=<octal>]";

    fn parse(_rest: &str) -> Result<MountEntry, ParseMountError> {
        todo!()
    }
}

/// Represents a source-destination path pair
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FdPathPair {
    pub fd: i32,
    pub destination: PathBuf,
}

/// Represents a chmod operation with permissions and target path
#[derive(Debug, Clone, PartialEq, Eq, Default)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OctalPermissions(u32);

impl std::str::FromStr for OctalPermissions {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value =
            u32::from_str_radix(s, 8).map_err(|_| format!("invalid octal permissions: '{}'", s))?;

        if value < 0 || value > 0o7777 {
            return Err(format!("octal permissions out-of-range (0-0777): '{}'", s));
        }

        Ok(OctalPermissions(value))
    }
}

impl std::ops::Deref for OctalPermissions {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
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

#[derive(Args, Debug, Clone)]
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

#[derive(Args, Debug, Clone)]
pub struct DebugOptions {
    #[arg(long, help="For debugging CLI arguments", help_heading = HEADING_DEBUG)]
    pub cli_args: bool,
}

fn validate_fd_arg(input: &str) -> Result<()> {
    let raw_fd = input.parse::<i32>()?;
    is_fd_valid(raw_fd).map(|_| {})
}
