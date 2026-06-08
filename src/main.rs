// TODO:
// 1. Check for 'max_user_namespaces'
// 2. Verify kernel support for namespaces and cgroups

// FIXME: More robust design pattern
// - Ensure that the global context is init(ed) exactly once

mod capabilities;
mod config;
mod context;
mod ipc;
mod jail;
mod jailer;
mod mount;
mod sandbox;
mod utils;

use clap::Parser;
use config::Config;
use context::{Parent, ProcessContext};
use sandbox::Sandbox;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    ProcessContext::<Parent>::init()?;

    // SAFETY: parent context is initialized
    // let context = unsafe { ProcessContext::<Parent>::get() };

    let mut config = Config::parse();
    config.prepare();

    // if !context.setuid() && !context.real_root() && config.user.userns.is_none() {
    //     config.namespace.unshare_user = true;
    // }

    let _ = Sandbox::new(config)?
        .spawn_jail()?
        .prepare_child()?
        .resume()?
        .wait()?;

    Ok(())
}
