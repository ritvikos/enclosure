// TODO:
// 1. Check for 'max_user_namespaces'
// 2. standardize visibility qualifiers
// 3. Verify kernel support for namespaces and cgroups

// FIXME: More robust design pattern
// - Ensure that the global context is init(ed) exactly once

mod capabilities;
mod checks;
mod config;
mod context;
mod hardener;
mod jail;
mod jailer;
mod mount;
mod notifier;
mod privsep;
mod report;
mod sandbox;
mod stack;
mod utils;

use clap::Parser;
use config::Config;
use context::GlobalContext;
use sandbox::Enclosure;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    GlobalContext::init()?;

    let mut config = Config::parse();
    let context = GlobalContext::current();

    if !context.setuid() && !context.real_root() && config.user.userns.is_none() {
        config.namespace.unshare_user = true;
    }

    let sandbox = Enclosure::new(config)?;
    print_capability_snapshot!();
    sandbox.spawn()?;

    Ok(())
}
