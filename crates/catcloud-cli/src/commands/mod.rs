//! Headless CatCloud CLI command definitions, dispatcher, and domain handlers.
//!
//! Architecture overview:
//! - [`args`]: Clap command/subcommand definitions, argument structs, and `AlreadyEmittedJsonError`.
//! - [`redact_helpers`]: Output formatting, storage opening, parsing helpers, and default read-only redaction.
//! - [`node_sub`]: `node` and `sub` subcommand handlers plus subscription refresh workflows.
//! - [`probe_group`]: `probe` and `group` subcommand handlers, dry-run payloads, and strategy evaluation.
//! - [`preaccel`]: `preaccel` relay pool/binding/testing, throughput measurement, and transport snapshots.
//! - [`net_logs`]: Read-only `net doctor`/`connections`/`match`, managed process verification, and `logs tail`.
//! - [`config_reload`]: `config` subcommands, live port/baseline inspection, gateway export, diagnostics, and desktop hot-reload handoff.
//! - [`share_sync`]: `share export`/`inspect`/`import` (`.zip`) and E2EE LAN/relay `send`/`receive` (`.ccsync`).
//! - [`status_docs_update`]: `status`, `docs`, and `update` top-level handlers plus GeoData/TUN helpers.
//! - `tests`: Domain-partitioned unit tests covering all CLI commands and redaction invariants.

mod args;
mod config_reload;
mod net_logs;
mod node_sub;
mod preaccel;
mod probe_group;
mod redact_helpers;
mod share_sync;
mod status_docs_update;
#[cfg(test)]
mod tests;

use anyhow::Result;
use catcloud_core::AppPaths;

pub use args::*;
#[cfg(test)]
pub(crate) use redact_helpers::redact_subscription_for_readonly;

pub async fn dispatch(paths: &AppPaths, as_json: bool, cmd: Commands) -> Result<()> {
    match cmd {
        Commands::Status => status_docs_update::handle_status(paths, as_json).await,
        Commands::Reload(args) => config_reload::execute_config_reload(paths, as_json, args).await,
        Commands::Node { action } => node_sub::handle_node(paths, as_json, action).await,
        Commands::Sub { action } => node_sub::handle_sub(paths, as_json, action).await,
        Commands::Probe { action } => probe_group::handle_probe(paths, as_json, action).await,
        Commands::Group { action } => probe_group::handle_group(paths, as_json, action),
        Commands::Preaccel { action } => preaccel::handle_preaccel(paths, as_json, action).await,
        Commands::Net { action } => net_logs::handle_net(paths, as_json, action).await,
        Commands::Logs { action } => net_logs::handle_logs(paths, as_json, action),
        Commands::Config { action } => config_reload::handle_config(paths, as_json, action).await,
        Commands::Docs { action } => status_docs_update::handle_docs(as_json, action),
        Commands::Share { action } => share_sync::handle_share(paths, as_json, action).await,
        Commands::Update { action } => {
            status_docs_update::handle_update(paths, as_json, action).await
        }
    }
}
