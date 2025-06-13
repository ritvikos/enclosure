use crate::{config::Config, context::GlobalContext, jailer::Jailable, print_capability_snapshot};
use anyhow::Result;

pub struct Jail<'jail> {
    config: &'jail Config,
}

impl Jail<'_> {}

impl<'a> Jailable<'a> for Jail<'a> {
    fn new(config: &'a Config) -> Self {
        Self { config }
    }

    fn config(&self) -> &Config {
        self.config
    }

    fn prepare(&self) -> Result<()> {
        let context = GlobalContext::current();
        println!("[CHILD]: {:?}", context);

        // let permitted = caps::read(None, caps::CapSet::Permitted)?;
        // println!("permitted: {permitted:?}");

        print_capability_snapshot!("[CHILD]: CAPABILITIES ON INITIALIZATION");

        println!("[CHILD]: CONFIGURED");
        Ok(())
    }

    fn execute(&self) -> Result<isize> {
        println!("[CHILD]: EXECUTED");
        Ok(0)
    }

    fn cleanup(&self) -> Result<()> {
        Ok(())
    }
}
