use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tauri::plugin::TauriPlugin;
use tauri::{AppHandle, Manager, Runtime};
use tauri_plugin_global_shortcut::{GlobalShortcut, Shortcut, ShortcutState};

/// Default global accelerator for one-click switch to the next best node.
pub const DEFAULT_SWITCH_NEXT_BEST_SHORTCUT: &str = "CommandOrControl+Alt+N";
/// Default global accelerator for toggling the floating capsule window.
pub const DEFAULT_TOGGLE_CAPSULE_SHORTCUT: &str = "CommandOrControl+Alt+C";

/// Actions that can be bound to system-wide hotkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShortcutAction {
    SwitchNextBestNode,
    ToggleCapsule,
    ToggleMainWindow,
    ToggleSystemProxy,
    ToggleTun,
}

/// Configurable global shortcut accelerators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutBindings {
    pub switch_next_best: Option<String>,
    pub toggle_capsule: Option<String>,
    pub toggle_main_window: Option<String>,
    pub toggle_system_proxy: Option<String>,
    #[serde(default)]
    pub toggle_tun: Option<String>,
}

impl Default for ShortcutBindings {
    fn default() -> Self {
        Self {
            switch_next_best: Some(DEFAULT_SWITCH_NEXT_BEST_SHORTCUT.to_string()),
            toggle_capsule: Some(DEFAULT_TOGGLE_CAPSULE_SHORTCUT.to_string()),
            toggle_main_window: None,
            toggle_system_proxy: None,
            toggle_tun: None,
        }
    }
}

impl ShortcutBindings {
    /// Enumerate all configured non-empty `(ShortcutAction, trimmed_accelerator)` pairs.
    pub fn active_pairs(&self) -> Vec<(ShortcutAction, String)> {
        let raw = [
            (
                ShortcutAction::SwitchNextBestNode,
                self.switch_next_best.as_deref(),
            ),
            (ShortcutAction::ToggleCapsule, self.toggle_capsule.as_deref()),
            (
                ShortcutAction::ToggleMainWindow,
                self.toggle_main_window.as_deref(),
            ),
            (
                ShortcutAction::ToggleSystemProxy,
                self.toggle_system_proxy.as_deref(),
            ),
            (ShortcutAction::ToggleTun, self.toggle_tun.as_deref()),
        ];
        raw.into_iter()
            .filter_map(|(action, accel)| {
                let trimmed = accel?.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some((action, trimmed.to_string()))
                }
            })
            .collect()
    }
}

/// Per-action registration status returned for UI conflict feedback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutRegistrationEntry {
    pub action: ShortcutAction,
    pub accelerator: String,
    pub registered: bool,
    pub error: Option<String>,
}

/// Aggregate result of applying a `ShortcutBindings` set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShortcutRegistrationReport {
    pub entries: Vec<ShortcutRegistrationEntry>,
}

impl ShortcutRegistrationReport {
    pub fn succeeded_count(&self) -> usize {
        self.entries.iter().filter(|e| e.registered).count()
    }

    pub fn failed_count(&self) -> usize {
        self.entries.iter().filter(|e| !e.registered).count()
    }

    pub fn all_succeeded(&self) -> bool {
        self.entries.iter().all(|e| e.registered)
    }
}

/// Build the `tauri-plugin-global-shortcut` plugin without pre-registering hotkeys inside
/// plugin setup, ensuring hotkey conflicts can never abort application startup.
pub fn build_plugin<R: Runtime>() -> TauriPlugin<R> {
    tauri_plugin_global_shortcut::Builder::new().build()
}

/// Validate a shortcut accelerator string (e.g. `"CommandOrControl+Alt+N"`).
pub fn validate_shortcut_str(accelerator: &str) -> Result<(), String> {
    let trimmed = accelerator.trim();
    if trimmed.is_empty() {
        return Err("shortcut string is empty".to_string());
    }
    Shortcut::from_str(trimmed)
        .map(|_| ())
        .map_err(|err| format!("invalid shortcut `{trimmed}`: {err}"))
}

/// Register all active bindings safely.
///
/// Clears previous registrations first for clean live-rebind support, skips invalid or
/// duplicate accelerators, and degrades gracefully if the OS reports a hotkey conflict.
pub fn register_shortcuts<R, F>(
    app: &AppHandle<R>,
    bindings: &ShortcutBindings,
    on_action: F,
) -> ShortcutRegistrationReport
where
    R: Runtime,
    F: Fn(&AppHandle<R>, ShortcutAction) + Send + Sync + 'static,
{
    let mut report = ShortcutRegistrationReport::default();
    let pairs = bindings.active_pairs();
    if pairs.is_empty() {
        unregister_all_shortcuts(app);
        return report;
    }

    let Some(global_shortcut) = app.try_state::<GlobalShortcut<R>>() else {
        tracing::warn!(
            "global-shortcut plugin is not initialized; degrading gracefully without hotkeys"
        );
        for (action, accelerator) in pairs {
            report.entries.push(ShortcutRegistrationEntry {
                action,
                accelerator,
                registered: false,
                error: Some("global-shortcut plugin not initialized".to_string()),
            });
        }
        return report;
    };

    if let Err(err) = global_shortcut.unregister_all() {
        tracing::debug!("unregister_all before re-binding shortcuts returned: {err}");
    }

    let callback = Arc::new(on_action);
    let mut seen_ids = HashSet::new();

    for (action, accelerator) in pairs {
        let parsed = match Shortcut::from_str(&accelerator) {
            Ok(s) => s,
            Err(err) => {
                let msg = format!("invalid shortcut `{accelerator}`: {err}");
                tracing::warn!(?action, "{msg}");
                report.entries.push(ShortcutRegistrationEntry {
                    action,
                    accelerator,
                    registered: false,
                    error: Some(msg),
                });
                continue;
            }
        };

        if !seen_ids.insert(parsed.id()) {
            let msg = format!("duplicate shortcut `{accelerator}` already assigned to another action");
            tracing::warn!(?action, "{msg}");
            report.entries.push(ShortcutRegistrationEntry {
                action,
                accelerator,
                registered: false,
                error: Some(msg),
            });
            continue;
        }

        let cb = Arc::clone(&callback);
        match global_shortcut.on_shortcut(parsed, move |app_handle, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                cb(app_handle, action);
            }
        }) {
            Ok(()) => {
                tracing::info!(?action, %accelerator, "registered global shortcut");
                report.entries.push(ShortcutRegistrationEntry {
                    action,
                    accelerator,
                    registered: true,
                    error: None,
                });
            }
            Err(err) => {
                let msg = format!("hotkey conflict or registration failed for `{accelerator}`: {err}");
                tracing::warn!(?action, "{msg}");
                report.entries.push(ShortcutRegistrationEntry {
                    action,
                    accelerator,
                    registered: false,
                    error: Some(msg),
                });
            }
        }
    }

    report
}

/// Register the default global shortcuts (switch next best node + toggle floating capsule)
/// with graceful degradation on conflict.
pub fn register_default_shortcuts<R, F>(
    app: &AppHandle<R>,
    on_action: F,
) -> ShortcutRegistrationReport
where
    R: Runtime,
    F: Fn(&AppHandle<R>, ShortcutAction) + Send + Sync + 'static,
{
    register_shortcuts(app, &ShortcutBindings::default(), on_action)
}

/// Safely unregister a single shortcut by accelerator string. Returns `true` if unregistered.
pub fn unregister_shortcut<R: Runtime>(app: &AppHandle<R>, accelerator: &str) -> bool {
    let Some(global_shortcut) = app.try_state::<GlobalShortcut<R>>() else {
        return false;
    };
    let Ok(parsed) = Shortcut::from_str(accelerator.trim()) else {
        return false;
    };
    match global_shortcut.unregister(parsed) {
        Ok(()) => true,
        Err(err) => {
            tracing::debug!(%accelerator, "unregister shortcut ignored: {err}");
            false
        }
    }
}

/// Safely unregister all global shortcuts owned by this process (used on shutdown or rebind).
pub fn unregister_all_shortcuts<R: Runtime>(app: &AppHandle<R>) {
    if let Some(global_shortcut) = app.try_state::<GlobalShortcut<R>>() {
        if let Err(err) = global_shortcut.unregister_all() {
            tracing::debug!("unregister_all_shortcuts returned: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bindings_parse_cleanly_and_do_not_collide() {
        let bindings = ShortcutBindings::default();
        let pairs = bindings.active_pairs();
        assert_eq!(pairs.len(), 2);

        let mut ids = HashSet::new();
        for (action, accel) in pairs {
            validate_shortcut_str(&accel).unwrap_or_else(|e| panic!("{action:?}: {e}"));
            let parsed = Shortcut::from_str(&accel).expect("parse default shortcut");
            assert!(ids.insert(parsed.id()), "default shortcuts must be distinct");
        }
    }

    #[test]
    fn invalid_and_empty_shortcuts_fail_validation_safely() {
        assert!(validate_shortcut_str("").is_err());
        assert!(validate_shortcut_str("   ").is_err());
        assert!(validate_shortcut_str("NotAModifier+FooBarKey").is_err());
        assert!(validate_shortcut_str("Ctrl+Shift+K").is_ok());
    }

    #[test]
    fn active_pairs_skips_blank_entries() {
        let bindings = ShortcutBindings {
            switch_next_best: Some("  ".into()),
            toggle_capsule: Some(" CommandOrControl+Alt+C ".into()),
            toggle_main_window: None,
            toggle_system_proxy: Some(String::new()),
            toggle_tun: Some("CommandOrControl+Alt+T".into()),
        };
        let pairs = bindings.active_pairs();
        assert_eq!(
            pairs,
            vec![
                (
                    ShortcutAction::ToggleCapsule,
                    "CommandOrControl+Alt+C".to_string()
                ),
                (
                    ShortcutAction::ToggleTun,
                    "CommandOrControl+Alt+T".to_string()
                ),
            ]
        );
    }
}
