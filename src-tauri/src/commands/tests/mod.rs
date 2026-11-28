//! Unit tests split by domain from the legacy monolithic `commands.rs`.
//! Every original test (101 tests total) is preserved intact with zero assertions weakened.

#[allow(unused_imports)]
mod prelude {
    pub(super) use std::collections::{HashMap, HashSet};
    pub(super) use std::path::PathBuf;
    pub(super) use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    pub(super) use std::sync::{Arc, Mutex, RwLock};
    pub(super) use std::time::{Duration, Instant};

    pub(super) use base64::Engine;
    pub(super) use catcloud_core::config;
    pub(super) use catcloud_core::core_adapter::binary_resolver::{
        compute_file_sha256, mihomo_binary_name, resolve_mihomo_binary,
    };
    pub(super) use catcloud_core::core_adapter::config_compiler::{
        BulkRulesParseResult, CompileInput, CompileStats, GatewayExportOptions, GatewayExportOutput,
        GatewayExportProfile, PreAccelTransportDiagnostics, StaticValidationReport,
        build_preaccel_transport_diagnostics, compile_mihomo_config_with_runtime_dir,
        export_gateway_yaml as core_export_gateway_yaml, parse_bulk_rules_text,
        redact_compiled_yaml_for_preview,
    };
    pub(super) use catcloud_core::core_adapter::hot_reload::{
        DiskReloadOptions, HotReloadCoordinator, has_core_config_changes,
    };
    pub(super) use catcloud_core::core_adapter::mihomo::{
        MihomoAdapter, generate_controller_secret, verify_config_with_binary,
    };
    pub(super) use catcloud_core::core_adapter::port_guard::{AllocatedPorts, allocate_safe_ports};
    pub(super) use catcloud_core::core_adapter::stream_client::{
        CoreTelemetryStore, MihomoStreamClient, StreamSessionHandle,
    };
    pub(super) use catcloud_core::core_adapter::{
        ConnectionsSnapshot, CoreAdapter, CoreLogLine, CoreRuntimeStatus, CoreStartRequest,
        DNS_TLS_STATUS_HEALTHY, DnsTlsDiagnostics, ReloadLevel, ReloadOutcome, SINGLE_NODE_GROUP_NAME,
        TrafficTick, analyze_dns_tls_diagnostics, analyze_dns_tls_diagnostics_from_log_file,
    };
    pub(super) use catcloud_core::models::{
        AppConfig, CoreLogLevel, GlobalPreAccelScope, MemoryLimitTier, MultiGroup, MultiGroupMode,
        MultiGroupState, OverrideMode, PersonalizationConfig, PreAccelConfig,
        PreAccelDispatchStrategy, PreAccelLbStrategy, PreAccelRelay, ProbeDefinition, ProbeSnapshot,
        ProxyMode, ProxyNode, RouteTargetMode, SubscriptionKind, SubscriptionRecord, SwitchMode,
        ThemeDaySchedule, ThemeMode, TrayClickAction as CoreTrayClickAction, TrayIconMode,
        TunStackMode, UpdateApplyMode, UpdateConfig, is_info_proxy_node, is_ipv6_only_node,
        normalize_ui_language, pick_smart_default_node_id,
    };
    pub(super) use catcloud_core::platform::{SystemProxySpec, default_platform};
    pub(super) use catcloud_core::preaccel::campus::{
        CampusBypassTracker, CampusPortalState, probe_campus_portal_with_fallback,
    };
    pub(super) use catcloud_core::preaccel::global_tunnel::{GlobalPreAccelManager, GlobalPreAccelStatus};
    #[cfg(all(target_os = "windows", not(target_arch = "aarch64")))]
    pub(super) use catcloud_core::preaccel::global_tunnel::{
        build_default_windivert_proxy_candidates, download_and_install_windivert_with_fallbacks,
        locate_windivert_files,
    };
    pub(super) use catcloud_core::probe::{
        DEFAULT_READY_TIMEOUT, FunnelOptions, FunnelTier, IsolatedProbeCore, ProbeRegistry,
        ThroughputProbeConfig, build_isolated_http_client, probe_live_google_cleanliness,
        run_download_probe_with_config, run_funnel_for_node, run_latency_probe,
        run_upload_probe_with_config,
    };
    pub(super) use catcloud_core::process_guard::{
        ConfigReloadAck, JobGuard, clear_config_reload_request_if_matching,
        read_config_reload_request, write_config_reload_ack,
    };
    #[cfg(target_os = "windows")]
    pub(super) use catcloud_core::process_guard::relaunch_self_as_admin;
    pub(super) use catcloud_core::share_bundle::{
        ShareBundleExportRequest, ShareBundleManifest, ShareBundlePreview, ShareGroupsBundle,
        build_share_groups_bundle, export_share_bundle_zip_bytes_with_groups,
        export_share_bundle_zip_file, merge_imported_groups_into_storage,
        preview_share_bundle_zip_bytes, preview_share_bundle_zip_file,
    };
    pub(super) use catcloud_core::storage::{
        BackupDbSnapshot, MergeSubscriptionsResult, Storage, SubscriptionNodesUpdateResult,
        SubscriptionUpdateMode,
    };
    pub(super) use catcloud_core::strategy::evaluator::evaluate_group_candidates_with_runtime;
    pub(super) use catcloud_core::strategy::health_pool::{NodeHealthHintDto, NodeHealthPool, RuntimeDualHealth};
    pub(super) use catcloud_core::subscription::live_capture::{
        DesktopAppCandidate, LiveCaptureManager, LiveCaptureOutcomeDto, LiveCaptureStartDto,
        LiveCaptureStatusDto, list_desktop_app_candidates as core_list_desktop_app_candidates,
    };
    pub(super) use catcloud_core::subscription::{
        ADAPTER_REASON_MANUAL, AdapterConfig, AdapterCooldownGuard, AdapterRequest, FetchOptions,
        ParsedSubscription, SubscriptionPayloadFormat, apply_parsed_subscription,
        inspect_process_source as core_inspect_process_source, invoke_external_adapter,
        parse_controller_proxies_json, parse_subscription_payload,
        preview_from_text as core_preview_from_text,
    };
    pub(super) use catcloud_core::updater::Updater;
    pub(super) use catcloud_core::AppPaths;
    pub(super) use chrono::Utc;
    pub(super) use serde::{Deserialize, Serialize};
    pub(super) use tauri::{AppHandle, Emitter, Manager, State};
    pub(super) use tokio::io::{AsyncReadExt, AsyncWriteExt};
    pub(super) use tokio::net::TcpStream;

    pub(super) use crate::app_log::{self, APP_EVENT_PREFIX, RotatingAppLogger};
    pub(super) use crate::lan_sync::{LanSyncManager, SyncReceiveSessionDto, SyncSendSessionDto};
    pub(super) use crate::lifecycle;
    pub(super) use crate::shortcuts::{self, ShortcutAction, ShortcutBindings};
    pub(super) use crate::tray::{
        self, TrayClickAction, TrayGroupSummary, TrayHealthState, TrayMenuState, TrayNodeCandidate,
        TrayPreAccelRelayItem, TrayPreAccelSummary, TrayProxyMode, TraySubscriptionItem,
        TraySubscriptionSummary, TrayVisualState,
    };

    pub(super) use catcloud_core::models::NodeSummary;

    pub(super) use crate::commands::core_lifecycle::*;
    pub(super) use crate::commands::diagnostics::issue_docs::*;
    pub(super) use crate::commands::diagnostics::report::*;
    pub(super) use crate::commands::geo_backup::*;
    pub(super) use crate::commands::groups_strategy::*;
    pub(super) use crate::commands::hotkeys::*;
    pub(super) use crate::commands::net_conns_rules::*;
    pub(super) use crate::commands::nodes_subs_capture::*;
    pub(super) use crate::commands::preaccel::bench::*;
    pub(super) use crate::commands::preaccel::ctrl::*;
    pub(super) use crate::commands::probes::*;
    pub(super) use crate::commands::settings_ui::*;
    pub(super) use crate::commands::share_sync::*;
    pub(super) use crate::commands::state::*;
    pub(super) use crate::commands::strategy_rank::*;
    pub(super) use crate::commands::system_proxy::*;
    pub(super) use crate::commands::tray_runtime::*;
    pub(super) use crate::commands::updater::*;
}

mod core_tray_tests;
mod diag_gateway_tests;
mod groups_probes_tests;
mod preaccel_sync_tests;
mod update_backup_tests;
