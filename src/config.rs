use crate::{checks::is_namespace_supported, utils::is_fd_valid};
use anyhow::{Error, Result, anyhow};
use clap::{ArgGroup, Args, Parser};
use nix::sched::CloneFlags;

// TODO: Following sections:
// const HEADING_MOUNT: &str = "Mount";
// const HEADING_SECURITY: &str = "Security";
// const HEADING_SESSION: &str = "Session";
// const HEADING_ADVANCED: &str = "Advanced";

const HEADING_GENERAL: &str = "General";
const HEADING_NAMESPACES: &str = "Namespaces";
const HEADING_USER: &str = "User";
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
    pub env: EnvOptions,

    #[command(flatten)]
    pub debug: DebugOptions,
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
    unshare_files: bool,

    #[arg(
        long,
        help = "Create new filesystem namespace",
        help_heading = HEADING_NAMESPACES
    )]
    unshare_fs: bool,

    #[arg(
        long,
        help = "Create new mount namespace",
        help_heading = HEADING_NAMESPACES
    )]
    unshare_ns: bool,

    #[arg(
        long,
        help = "Create new time namespace",
        help_heading = HEADING_NAMESPACES
    )]
    unshare_time: bool,

    #[arg(
        long,
        help = "Create new system v semaphore namespace",
        help_heading = HEADING_NAMESPACES
    )]
    unshare_sysvsem: bool,
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
#[command(group(
    ArgGroup::new("userns_mode")
        .args(&["userns", "unshare_user"])
        .multiple(false)
        .required(false)
))]
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
        help_heading = HEADING_USER,
        requires = "unshare_user"
    )]
    pub switch_userns: Option<i32>,

    #[arg(
        long,
        help = "Disable nested user namespace (requires --unshare-user)",
        help_heading = HEADING_USER,
        requires = "unshare_user"
    )]
    pub disable_nested_userns: bool,

    // #[arg(long, help_heading = HEADING_USER)]
    // pub assert_userns_disabled: bool,
    #[arg(
        long,
        help = "Use this pid namespace (requires --unshare-pid)",
        help_heading = HEADING_USER,
        requires = "unshare_pid"
    )]
    pub pidns: Option<i32>,

    #[arg(
        long,
        help = "Custom uid",
        help_heading = HEADING_USER,
        requires = "unshare_user",
        requires = "userns"
    )]
    pub uid: Option<u32>,

    #[arg(
        long,
        help = "Custom gid",
        help_heading = HEADING_USER,
        requires = "unshare_user",
        requires = "userns"
    )]
    pub gid: Option<u32>,

    #[arg(
        long,
        help = "Customm hostname",
        help_heading = HEADING_USER,
        requires = "unshare_uts"
    )]
    pub hostname: Option<String>,
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
