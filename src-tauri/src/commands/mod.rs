//! Desktop Tauri IPC commands organized as a strict acyclic DAG.
//!
//! Architecture Layers (bottom -> top, zero cycles):
//! - Layer 0 (`state`): `AppState`, event constants, shared guards, UI/runtime DTOs, pure helpers.
//! - Layer 1 (`strategy_rank`, `tray_runtime`): pure multi-group candidate ranking & tray/runtime projections.
//! - Layer 2 (`system_proxy`): OS system proxy ownership/cleanup, exit cleanup, standalone pre-accel engine.
//! - Layer 3 (`core_lifecycle`, `updater`): core start/stop/reload, power/TUN/system-proxy takeover, updates.
//! - Layer 4 (`groups_strategy`, `net_conns_rules`, `preaccel/{ctrl,bench}`): domain command handlers.
//! - Layer 5 (`hotkeys`, `nodes_subs_capture`, `probes`): shortcuts & disk hot-reload orchestration, subs, probes.
//! - Layer 6 (`geo_backup`, `settings_ui`, `share_sync`): configuration save, backup/geo, share & LAN sync.
//! - Layer 7 (`diagnostics/{report,issue_docs}`): sanitized diagnostics, AI guides, Agent manuals, GitHub issues.
//!
//! Note: Tauri v2 `#[tauri::command]` emits hidden `__cmd__*` and `__tauri_command_name_*` macros
//! alongside each command function, so every submodule MUST be re-exported via `pub use <mod>::*;`.

mod core_lifecycle;
mod diagnostics;
mod geo_backup;
mod groups_strategy;
mod hotkeys;
mod net_conns_rules;
mod nodes_subs_capture;
mod preaccel;
mod probes;
mod settings_ui;
mod share_sync;
mod state;
mod strategy_rank;
mod system_proxy;
mod tray_runtime;
mod updater;

#[cfg(test)]
mod tests;

pub use core_lifecycle::*;
pub use diagnostics::*;
pub use geo_backup::*;
pub use groups_strategy::*;
pub use hotkeys::*;
pub use net_conns_rules::*;
pub use nodes_subs_capture::*;
pub use preaccel::*;
pub use probes::*;
pub use settings_ui::*;
pub use share_sync::*;
pub use state::*;
pub use strategy_rank::*;
pub use system_proxy::*;
pub use tray_runtime::*;
pub use updater::*;
