// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2025 zenofile <zenofile-sf6@unsha.re>

use anyhow::{Context, Result};
use landlock::{
    ABI, Access, AccessFs, AccessNet, Compatible, NetPort, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetError, RulesetStatus, Scope, path_beneath_rules,
};
use std::path::Path;
use tracing::{info, warn};

/// Applies Landlock sandboxing restrictions.
///
/// # Arguments
///
/// * `user_read_paths` - An iterator of file paths to allow read-only access to.
pub fn harden<I, P>(user_read_paths: I) -> Result<()>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let abi = ABI::V6;

    let sys_paths = ["/usr", "/bin", "/sbin", "/lib", "/lib64"];
    let config_paths = [
        "/etc",
        "/proc/net/route",
        "/proc/self",
        "/dev/urandom",
        "/dev/zero",
    ];
    let write_paths = ["/dev/null"];
    let allowed_ports = [80, 443, 53];

    // Define
    let read_exec = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
    let read_only = AccessFs::ReadFile | AccessFs::ReadDir;
    let read_write = AccessFs::ReadFile | AccessFs::WriteFile;

    // Initialize
    let ruleset = Ruleset::default()
        .set_compatibility(landlock::CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(abi))?
        .handle_access(AccessNet::from_all(abi))?
        .scope(Scope::AbstractUnixSocket)?
        .scope(Scope::Signal)?
        .create()
        .context("Failed to create Landlock ruleset")?;

    // Apply
    let status = ruleset
        // System Binaries
        .add_rules(path_beneath_rules(
            sys_paths.iter().copied().filter(|p| Path::new(p).exists()),
            read_exec,
        ))?
        // System Configs
        .add_rules(path_beneath_rules(
            config_paths
                .iter()
                .copied()
                .filter(|p| Path::new(p).exists()),
            read_only,
        ))?
        // Writeable Devices
        .add_rules(path_beneath_rules(
            write_paths
                .iter()
                .copied()
                .filter(|p| Path::new(p).exists()),
            read_write,
        ))?
        // User Provided Paths
        .add_rules(path_beneath_rules(
            user_read_paths.into_iter().filter(|p| p.as_ref().exists()),
            read_only,
        ))?
        // Network Ports
        .add_rules(
            allowed_ports
                .iter()
                .map(|&port| -> Result<NetPort, RulesetError> {
                    Ok(NetPort::new(port, AccessNet::ConnectTcp))
                }),
        )?
        .restrict_self()
        .context("Failed to enforce Landlock restrictions")?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => info!("Landlock sandbox fully active."),
        RulesetStatus::PartiallyEnforced => warn!("Landlock sandbox partially enforced."),
        RulesetStatus::NotEnforced => warn!("Landlock sandbox NOT enforced."),
    }

    Ok(())
}
