use nix::{sched::CloneFlags, sys::utsname::uname};
use std::path::Path;

pub fn is_namespace_supported(flag: CloneFlags) -> bool {
    fn exists(ns: &str) -> bool {
        Path::new(&format!("/proc/self/ns/{}", ns)).exists()
    }

    // FIXME: hacky minimum version
    fn min_version(version: &str) -> bool {
        let release = uname().unwrap().release().to_string_lossy().to_string();
        !release.starts_with(version)
    }

    match flag {
        CloneFlags::CLONE_FILES => min_version("2.0"),
        CloneFlags::CLONE_FS => min_version("2.0"),

        CloneFlags::CLONE_SYSVSEM => min_version("2.6.19"),
        CloneFlags::CLONE_NEWCGROUP => exists("cgroup"),
        CloneFlags::CLONE_NEWIPC => exists("ipc"),
        CloneFlags::CLONE_NEWNET => exists("net"),
        CloneFlags::CLONE_NEWNS => exists("mnt"),
        CloneFlags::CLONE_NEWPID => exists("pid"),
        CloneFlags::CLONE_NEWUSER => exists("user"),
        CloneFlags::CLONE_NEWUTS => exists("uts"),
        _ => todo!(),
    }
}

pub(crate) fn is_cgroups_supported() -> bool {
    Path::new("/proc/self/ns/cgroup").exists()
}
