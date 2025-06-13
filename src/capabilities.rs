use anyhow::{Context, Result, bail};
use caps::CapsHashSet;
use std::collections::HashSet;

pub(crate) use caps::{CapSet, Capability};

pub const SETUID_CAPABILITIES: [Capability; 6] = [
    Capability::CAP_SYS_ADMIN,
    Capability::CAP_SYS_CHROOT,
    Capability::CAP_NET_ADMIN,
    Capability::CAP_SETUID,
    Capability::CAP_SETGID,
    Capability::CAP_SYS_PTRACE,
];

#[derive(Debug)]
pub(crate) struct CapabilityManager {
    config: CapabilityConfig,
}

impl CapabilityManager {
    const UNPRIVILEGED_SETS: [CapSet; 3] =
        [CapSet::Permitted, CapSet::Inheritable, CapSet::Effective];

    /// Create a capability manager with custom configuration
    pub fn with_config(config: CapabilityConfig) -> Self {
        Self { config }
    }

    /// Get the current snapshot of all capability sets
    pub fn current() -> Result<CapabilitySnapshot> {
        Ok(CapabilitySnapshot {
            effective: Self::read_capability_set(CapSet::Effective)
                .context("Failed to read effective capabilities")?,
            permitted: Self::read_capability_set(CapSet::Permitted)
                .context("Failed to read permitted capabilities")?,
            inheritable: Self::read_capability_set(CapSet::Inheritable)
                .context("Failed to read inheritable capabilities")?,
            bounding: Self::read_capability_set(CapSet::Bounding)
                .context("Failed to read bounding capabilities")?,
            ambient: Self::read_capability_set(CapSet::Ambient)
                .context("Failed to read ambient capabilities")?,
        })
    }

    pub fn clear_unprivileged_capabilities(&self) -> Result<()> {
        for cap_set in Self::UNPRIVILEGED_SETS {
            self.clear_capability_set(cap_set)?;
        }

        Ok(())
    }

    /// Retain requested capabilities and drop the remaining ones
    pub fn retain_requested_capabilities(&self, requested: &CapsHashSet) -> Result<()> {
        let available_capabilities = self.get_all_available_capabilities()?;

        for capability in available_capabilities {
            if !requested.contains(&capability) {
                if let Err(err) = self.drop_bounding_capability(capability) {
                    if self.config.permissive_mode && self.is_expected_error(&err) {
                        eprintln!("Ignoring expected error dropping {capability:?}: {err}");
                        continue;
                    }
                    return Err(err);
                }
            }
        }

        Ok(())
    }

    /// Drop all capabilities from the bounding set
    pub fn drop_all_bounding_capabilities(&self) -> Result<()> {
        let bounding_caps = Self::read_capability_set(CapSet::Bounding)?;

        for capability in bounding_caps {
            self.drop_bounding_capability(capability)?;
        }

        Ok(())
    }

    /// Configure the `CapabilityManager`
    /// - Acquire or drop capabilities based on custom logic
    pub fn configure_with<F>(&self, f: F) -> Result<CapabilitySnapshot>
    where
        F: FnOnce(&Self) -> Result<()>,
    {
        f(self)?;

        if self.config.validate_operations {
            self.validate_required_capabilities(&self.user_defined_capabilities())?;
        }

        Self::current()
    }

    /// Get the set of capabilities to retain
    pub(crate) fn user_defined_capabilities(&self) -> CapsHashSet {
        self.config
            .custom_required_caps
            .clone()
            .unwrap_or_else(|| CapsHashSet::new())
    }

    fn set_capability_set(&self, cap_set: CapSet, capabilities: &CapsHashSet) -> Result<()> {
        caps::set(None, cap_set, capabilities)
            .context(format!("Failed to set {:?} capability set", cap_set))?;
        Ok(())
    }

    fn read_capability_set(cap_set: CapSet) -> Result<CapsHashSet> {
        caps::read(None, cap_set).context(format!("Failed to read {:?} capability set", cap_set))
    }

    fn clear_capability_set(&self, cap_set: CapSet) -> Result<()> {
        caps::clear(None, cap_set)
            .context(format!("Failed to clear {:?} capability set", cap_set))?;
        Ok(())
    }

    pub(crate) fn validate_required_capabilities(&self, required: &CapsHashSet) -> Result<()> {
        let current = Self::read_capability_set(CapSet::Effective)?;
        let missing: HashSet<_> = required.difference(&current).collect();

        if !missing.is_empty() {
            bail!(format!("required: {:?}, current: {:?}", required, current));
        }

        Ok(())
    }

    fn get_all_available_capabilities(&self) -> Result<CapsHashSet> {
        Ok(caps::runtime::thread_all_supported())
    }

    fn drop_bounding_capability(&self, capability: Capability) -> Result<()> {
        caps::drop(None, CapSet::Bounding, capability).context(format!(
            "Failed to drop bounding capability: {}",
            capability
        ))?;
        Ok(())
    }

    fn is_expected_error(&self, error: &anyhow::Error) -> bool {
        let message = error.to_string().to_lowercase();
        message.contains("invalid")
            || message.contains("not permitted")
            || message.contains("permission denied")
            || message.contains("operation not supported")
    }
}

#[derive(Debug, Clone)]
pub struct CapabilityConfig {
    /// Whether to ignore non-critical errors
    pub permissive_mode: bool,

    /// Whether to validate operations after performing them
    pub validate_operations: bool,

    /// Custom set of capabilities to retain
    pub custom_required_caps: Option<CapsHashSet>,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            permissive_mode: false,
            validate_operations: true,
            custom_required_caps: None,
        }
    }
}

/// Represents the current state of process capabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilitySnapshot {
    pub effective: CapsHashSet,
    pub permitted: CapsHashSet,
    pub inheritable: CapsHashSet,
    pub bounding: CapsHashSet,
    pub ambient: CapsHashSet,
}

impl std::fmt::Display for CapabilitySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Capabilities - ")?;
        write!(f, "Effective: {}, ", self.effective.len())?;
        write!(f, "Permitted: {}, ", self.permitted.len())?;
        write!(f, "Inheritable: {}, ", self.inheritable.len())?;
        write!(f, "Bounding: {}, ", self.bounding.len())?;
        write!(f, "Ambient: {}", self.ambient.len())
    }
}

#[derive(Debug)]
pub struct CapabilityBuilder {
    config: CapabilityConfig,
    target_capabilities: Option<CapsHashSet>,
}

impl CapabilityBuilder {
    pub fn new() -> Self {
        Self {
            config: CapabilityConfig::default(),
            target_capabilities: None,
        }
    }

    pub fn with_capabilities<I>(mut self, caps: I) -> Self
    where
        I: IntoIterator<Item = Capability>,
    {
        self.target_capabilities = Some(caps.into_iter().collect());
        self
    }

    pub fn build(self) -> CapabilityManager {
        let mut config = self.config;
        if let Some(caps) = self.target_capabilities {
            config.custom_required_caps = Some(caps);
        }
        CapabilityManager::with_config(config)
    }
}

#[macro_export]
macro_rules! print_capability_snapshot {
    ($label:expr) => {{
        use crate::capabilities::CapabilityManager;
        println!($label);
        println!("[CAPABILITY SNAP]: {:#?}", CapabilityManager::current()?);
    }};
    () => {{
        use crate::capabilities::CapabilityManager;
        println!("[CAPABILITY SNAP]: {:#?}", CapabilityManager::current()?);
    }};
}

pub(crate) fn has_any_permitted_capabilities() -> Result<bool> {
    let capabilities = CapabilityManager::read_capability_set(CapSet::Permitted)?;
    Ok(!capabilities.is_empty())
}

pub(crate) fn apply_setuid_capabilities(manager: &CapabilityManager) -> Result<()> {
    let caps = manager.user_defined_capabilities();

    manager.drop_all_bounding_capabilities()?;
    manager.retain_requested_capabilities(&caps)?;

    manager.set_capability_set(CapSet::Effective, &caps)?;
    manager.set_capability_set(CapSet::Permitted, &caps)?;

    manager.clear_capability_set(CapSet::Inheritable)?;
    Ok(())
}
