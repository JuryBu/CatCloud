use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use catcloud_core::config;
use catcloud_core::core_adapter::config_compiler::BulkRulesParseResult;
use catcloud_core::core_adapter::config_compiler::CompileInput;
use catcloud_core::core_adapter::config_compiler::CompileStats;
use catcloud_core::core_adapter::config_compiler::GatewayExportOptions;
use catcloud_core::core_adapter::config_compiler::GatewayExportOutput;
use catcloud_core::core_adapter::config_compiler::GatewayExportProfile;
use catcloud_core::core_adapter::config_compiler::StaticValidationReport;
use catcloud_core::core_adapter::config_compiler::compile_mihomo_config_with_runtime_dir;
use catcloud_core::core_adapter::config_compiler::export_gateway_yaml as core_export_gateway_yaml;
use catcloud_core::core_adapter::config_compiler::parse_bulk_rules_text;
use catcloud_core::core_adapter::config_compiler::redact_compiled_yaml_for_preview;
use catcloud_core::core_adapter::port_guard::AllocatedPorts;
use catcloud_core::core_adapter::ConnectionsSnapshot;
use catcloud_core::core_adapter::CoreAdapter;
use catcloud_core::core_adapter::CoreLogLine;
use catcloud_core::models::AppConfig;
use catcloud_core::models::MultiGroup;
use catcloud_core::models::PreAccelRelay;
use catcloud_core::models::ProxyMode;
use catcloud_core::models::ProxyNode;
use catcloud_core::platform::default_platform;
use catcloud_core::probe::probe_live_google_cleanliness;
use catcloud_core::AppPaths;
use serde::Deserialize;
use serde::Serialize;
use tauri::AppHandle;
use tauri::State;
use crate::app_log;

use crate::commands::core_lifecycle::start_core_internal;
use crate::commands::core_lifecycle::trigger_reload_if_running;
use crate::commands::state::AppState;
use crate::commands::state::ExitIpInfoDto;
use crate::commands::state::SiteCheckItemDto;
use crate::commands::state::TrafficEventPayload;
use crate::commands::state::mask_ip_address;
use crate::commands::state::summarize_connections;
use crate::commands::tray_runtime::emit_config_updated;
use crate::commands::tray_runtime::format_mihomo_error_for_user;
use crate::commands::tray_runtime::has_enabled_nodes;
use crate::commands::tray_runtime::sync_tray_and_window_side_effects;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct GeoIpLookupResult {
    pub(in crate::commands) ip: String,
    pub(in crate::commands) isp: String,
    pub(in crate::commands) location: String,
    pub(in crate::commands) timezone: String,
}


fn join_location_parts(city: Option<&str>, country: Option<&str>) -> String {
    let c = city.map(str::trim).filter(|s| !s.is_empty());
    let co = country.map(str::trim).filter(|s| !s.is_empty());
    match (c, co) {
        (Some(city_s), Some(country_s)) if !city_s.eq_ignore_ascii_case(country_s) => {
            format!("{city_s}, {country_s}")
        }
        (Some(city_s), _) => city_s.to_string(),
        (None, Some(country_s)) => country_s.to_string(),
        (None, None) => "未知地区".to_string(),
    }
}


pub(in crate::commands) fn parse_ipsb_geoip_json(val: &serde_json::Value) -> Option<GeoIpLookupResult> {
    let ip = val.get("ip").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())?;
    let isp = val
        .get("isp")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            val.get("organization")
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("未知运营商")
        .to_string();
    let city = val.get("city").and_then(|v| v.as_str());
    let country = val.get("country").and_then(|v| v.as_str());
    let location = join_location_parts(city, country);
    let timezone = val
        .get("timezone")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("未知时区")
        .to_string();
    Some(GeoIpLookupResult {
        ip: ip.to_string(),
        isp,
        location,
        timezone,
    })
}


pub(in crate::commands) fn parse_ipwhois_json(val: &serde_json::Value) -> Option<GeoIpLookupResult> {
    if val.get("success").and_then(|v| v.as_bool()) == Some(false) {
        return None;
    }
    let ip = val.get("ip").and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty())?;
    let conn = val.get("connection");
    let isp = conn
        .and_then(|c| c.get("isp"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            conn.and_then(|c| c.get("org"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("未知运营商")
        .to_string();
    let city = val.get("city").and_then(|v| v.as_str());
    let country = val.get("country").and_then(|v| v.as_str());
    let location = join_location_parts(city, country);
    let tz = val.get("timezone");
    let timezone = tz
        .and_then(|t| t.get("id"))
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            tz.and_then(|t| t.get("utc"))
                .and_then(|v| v.as_str())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        })
        .unwrap_or("未知时区")
        .to_string();
    Some(GeoIpLookupResult {
        ip: ip.to_string(),
        isp,
        location,
        timezone,
    })
}


pub(in crate::commands) fn parse_cloudflare_trace(body: &str) -> Option<GeoIpLookupResult> {
    let mut ip = String::new();
    let mut loc = String::new();
    let mut colo = String::new();
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            ip = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("loc=") {
            loc = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("colo=") {
            colo = v.trim().to_string();
        }
    }
    if ip.is_empty() {
        return None;
    }
    Some(GeoIpLookupResult {
        ip,
        isp: if colo.is_empty() {
            "Cloudflare 出口已连通".to_string()
        } else {
            format!("Cloudflare 接入节点 {colo}")
        },
        location: if loc.is_empty() {
            "未知地区".to_string()
        } else {
            loc
        },
        timezone: "未知时区".to_string(),
    })
}


const MAX_GEOIP_RESPONSE_BYTES: usize = 64 * 1024;


async fn read_bounded_response_bytes(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(format!(
                "出口检测响应体过大（{len} 字节，超出 {max_bytes} 字节上限）"
            ));
        }
    }
    let initial_cap = resp
        .content_length()
        .map(|n| (n as usize).min(max_bytes))
        .unwrap_or(4096);
    let mut buf = Vec::with_capacity(initial_cap);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("读取出口检测响应失败：{e}"))?
    {
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(format!("出口检测响应体超出 {max_bytes} 字节安全上限"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}


async fn query_exit_geoip(client: &reqwest::Client) -> Result<GeoIpLookupResult, String> {
    let mut last_err = String::new();

    // 1. Primary: api.ip.sb/geoip
    match client.get("https://api.ip.sb/geoip").send().await {
        Ok(resp) if resp.status().is_success() => {
            match read_bounded_response_bytes(resp, MAX_GEOIP_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(parsed) = parse_ipsb_geoip_json(&val) {
                            return Ok(parsed);
                        }
                    }
                }
                Err(err) => {
                    last_err = err;
                }
            }
        }
        Ok(resp) => {
            last_err = format!("出口检测响应异常（HTTP {}）", resp.status().as_u16());
        }
        Err(err) => {
            last_err = if err.is_timeout() {
                "出口检测超时，请检查当前路线是否可用".to_string()
            } else {
                "无法连接出口检测服务，请切换路线后重试".to_string()
            };
        }
    }

    // 2. Fallback: ipwho.is
    match client.get("https://ipwho.is/").send().await {
        Ok(resp) if resp.status().is_success() => {
            match read_bounded_response_bytes(resp, MAX_GEOIP_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if let Some(parsed) = parse_ipwhois_json(&val) {
                            return Ok(parsed);
                        }
                    }
                }
                Err(err) => {
                    if last_err.is_empty() {
                        last_err = err;
                    }
                }
            }
        }
        Ok(resp) => {
            if last_err.is_empty() {
                last_err = format!("出口检测响应异常（HTTP {}）", resp.status().as_u16());
            }
        }
        Err(err) => {
            if last_err.is_empty() {
                last_err = if err.is_timeout() {
                    "出口检测超时，请检查当前路线是否可用".to_string()
                } else {
                    "无法连接出口检测服务，请切换路线后重试".to_string()
                };
            }
        }
    }

    // 3. Final fallback: Cloudflare trace
    match client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            match read_bounded_response_bytes(resp, MAX_GEOIP_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    let body = String::from_utf8_lossy(&bytes);
                    if let Some(parsed) = parse_cloudflare_trace(&body) {
                        return Ok(parsed);
                    }
                }
                Err(err) => {
                    if last_err.is_empty() {
                        last_err = err;
                    }
                }
            }
        }
        Ok(resp) => {
            if last_err.is_empty() {
                last_err = format!("出口检测响应异常（HTTP {}）", resp.status().as_u16());
            }
        }
        Err(err) => {
            if last_err.is_empty() {
                last_err = if err.is_timeout() {
                    "出口检测超时，请检查当前路线是否可用".to_string()
                } else {
                    "无法连接出口检测服务，请切换路线后重试".to_string()
                };
            }
        }
    }

    if last_err.is_empty() {
        Err("未能解析出口 IP 信息，请稍后重试".to_string())
    } else {
        Err(last_err)
    }
}


#[tauri::command]
pub async fn get_exit_ip_info(state: State<'_, AppState>) -> Result<ExitIpInfoDto, String> {
    let cfg = state.snapshot_config();
    let rt = state.adapter.status().await;
    state.update_cached_runtime(rt.clone());
    if !rt.running {
        return Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: "核心未启动".to_string(),
            location: "未连接".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean: None,
            core_running: false,
            ip_clean: None,
            ip_risk_level: None,
            ip_asn: None,
            ip_risk_flags: None,
        });
    }

    if rt.proxy_mode == ProxyMode::Direct || cfg.proxy_mode == ProxyMode::Direct {
        return Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: "当前处于直连模式（不经代理节点）".to_string(),
            location: "本地直连".to_string(),
            timezone: "UTC+8".to_string(),
            google_clean: None,
            core_running: true,
            ip_clean: None,
            ip_risk_level: None,
            ip_asn: None,
            ip_risk_flags: None,
        });
    }

    let proxy_url = format!("socks5h://127.0.0.1:{}", rt.mixed_port);
    let geo_proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("初始化出口检测代理通道失败：{e}"))?;
    let geo_client = reqwest::Client::builder()
        .no_proxy()
        .proxy(geo_proxy)
        .user_agent("CatCloud/1.0")
        .timeout(Duration::from_secs(6))
        .build()
        .map_err(|e| format!("初始化出口检测客户端失败：{e}"))?;

    let google_proxy = reqwest::Proxy::all(&proxy_url)
        .map_err(|e| format!("初始化谷歌送中检测代理通道失败：{e}"))?;
    let google_client = reqwest::Client::builder()
        .no_proxy()
        .proxy(google_proxy)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| format!("初始化谷歌送中检测客户端失败：{e}"))?;

    let (geo_res, google_assessment, purity_signals) = tokio::join!(
        query_exit_geoip(&geo_client),
        probe_live_google_cleanliness(&google_client, Duration::from_secs(5)),
        catcloud_core::probe::builtins::query_ip_purity_signals(&geo_client),
    );

    let live_google_clean = if google_assessment
        .reasons
        .iter()
        .any(|r| r == "no_google_ground_truth")
    {
        None
    } else {
        Some(google_assessment.google_clean)
    };

    let ip_risk_level = {
        let trimmed = purity_signals.ip_risk_level.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("unknown") {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    let ip_clean = purity_signals.ip_clean;
    let ip_asn = purity_signals.ip_asn;
    let ip_risk_flags = purity_signals.ip_risk_flags;

    match geo_res {
        Ok(info) => Ok(ExitIpInfoDto {
            ip_masked: mask_ip_address(&info.ip),
            ip_raw: Some(info.ip),
            isp: info.isp,
            location: info.location,
            timezone: info.timezone,
            google_clean: live_google_clean,
            core_running: true,
            ip_clean,
            ip_risk_level,
            ip_asn,
            ip_risk_flags,
        }),
        Err(reason) => Ok(ExitIpInfoDto {
            ip_masked: "--.--.--.***".to_string(),
            ip_raw: None,
            isp: reason,
            location: "暂未获取到位置".to_string(),
            timezone: "未知时区".to_string(),
            google_clean: live_google_clean,
            core_running: true,
            ip_clean,
            ip_risk_level,
            ip_asn,
            ip_risk_flags,
        }),
    }
}


pub(in crate::commands) fn normalize_quick_site_probe_url(raw: &str) -> String {
    let trimmed = raw.trim();
    let stripped = trimmed.trim_end_matches('/');
    if stripped.eq_ignore_ascii_case("https://chatgpt.com")
        || stripped.eq_ignore_ascii_case("http://chatgpt.com")
        || stripped.eq_ignore_ascii_case("https://www.chatgpt.com")
        || stripped.eq_ignore_ascii_case("http://www.chatgpt.com")
    {
        return "https://chatgpt.com/cdn-cgi/trace".to_string();
    }
    trimmed.to_string()
}


#[tauri::command]
pub async fn check_quick_sites(state: State<'_, AppState>) -> Result<Vec<SiteCheckItemDto>, String> {
    let cfg = state.snapshot_config();
    let rt = state.adapter.status().await;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(7))
        .pool_max_idle_per_host(8)
        .redirect(reqwest::redirect::Policy::none());
    if rt.running {
        let proxy_url = format!("socks5h://127.0.0.1:{}", rt.mixed_port);
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            builder = builder.proxy(proxy);
        }
    }
    let client = builder
        .build()
        .map_err(|e| format!("初始化网站测活客户端失败：{e}"))?;

    let mut handles = Vec::new();
    for site in cfg.core_runtime.quick_check_sites.clone() {
        let cli = client.clone();
        handles.push(tokio::spawn(async move {
            let probe_url = normalize_quick_site_probe_url(&site.url);
            let expected_status = site.expected_status;
            let check_status = |status: u16| {
                expected_status
                    .map(|exp| status == exp)
                    .unwrap_or((200..300).contains(&status))
            };

            // 1. Warmup connection (establish SOCKS5 + TLS tunnel and drain small body for Keep-Alive reuse).
            let t0 = Instant::now();
            let first = match cli.get(&probe_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let _ = read_bounded_response_bytes(resp, 16 * 1024).await;
                    let ms = t0.elapsed().as_millis() as u64;
                    (ms, check_status(status))
                }
                Err(_) => {
                    return SiteCheckItemDto {
                        id: site.id,
                        name: site.name,
                        url: site.url,
                        latency_ms: None,
                        ok: Some(false),
                    };
                }
            };

            // 2. Measure true warm RTT over the reused connection (still strictly checking expected_status).
            let t1 = Instant::now();
            let (final_ms, final_ok) = match cli.get(&probe_url).send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let _ = read_bounded_response_bytes(resp, 16 * 1024).await;
                    let ms = t1.elapsed().as_millis() as u64;
                    (ms, check_status(status))
                }
                Err(_) => first,
            };

            SiteCheckItemDto {
                id: site.id,
                name: site.name,
                url: site.url,
                latency_ms: Some(final_ms),
                ok: Some(final_ok),
            }
        }));
    }

    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(item) = h.await {
            out.push(item);
        }
    }
    Ok(out)
}


#[tauri::command]
pub async fn get_active_connections(
    state: State<'_, AppState>,
) -> Result<ConnectionsSnapshot, String> {
    if !state.adapter.has_live_controller().await {
        return Ok(ConnectionsSnapshot::default());
    }
    state
        .adapter
        .list_connections()
        .await
        .map_err(|e| e.to_string())
}


#[tauri::command]
pub async fn close_connection(state: State<'_, AppState>, id: String) -> Result<bool, String> {
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，无法操作连接".to_string());
    }
    state
        .adapter
        .close_connection(&id)
        .await
        .map_err(|e| format!("断开指定连接失败：{e}"))?;
    Ok(true)
}


#[tauri::command]
pub async fn close_group_connections(
    state: State<'_, AppState>,
    group_name: String,
) -> Result<usize, String> {
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，无法操作连接".to_string());
    }
    state
        .adapter
        .close_connections_for_group_or_node(Some(&group_name), None)
        .await
        .map_err(|e| format!("断开分组连接失败：{e}"))
}


#[tauri::command]
pub async fn close_all_connections(state: State<'_, AppState>) -> Result<usize, String> {
    if !state.adapter.has_live_controller().await {
        return Err("代理核心尚未运行，无法操作连接".to_string());
    }
    let count = state
        .adapter
        .list_connections()
        .await
        .map(|s| summarize_connections(&s.connections).app_connections)
        .unwrap_or(0);
    state
        .adapter
        .close_all_connections()
        .await
        .map_err(|e| format!("断开全部连接失败：{e}"))?;
    Ok(count)
}


pub(crate) fn sanitize_core_log_line(mut line: CoreLogLine) -> CoreLogLine {
    line.payload = app_log::sanitize_log_line(&line.payload);
    line
}


pub(in crate::commands) fn collect_sanitized_recent_log_lines(
    state: &AppState,
    limit: Option<usize>,
) -> Vec<CoreLogLine> {
    let mut logs = state.telemetry.logs_snapshot();
    if let Some(lim) = limit {
        if logs.len() > lim {
            logs = logs.split_off(logs.len() - lim);
        }
    }
    logs.into_iter().map(sanitize_core_log_line).collect()
}


#[tauri::command]
pub fn get_recent_logs(
    state: State<'_, AppState>,
    limit: Option<usize>,
) -> Result<Vec<CoreLogLine>, String> {
    Ok(collect_sanitized_recent_log_lines(&state, limit))
}


pub(in crate::commands) fn build_traffic_history(state: &AppState) -> Vec<TrafficEventPayload> {
    let ticks = state.telemetry.traffic_snapshot();
    if ticks.is_empty() {
        return Vec::new();
    }
    let metrics = state
        .cached_metrics
        .read()
        .map(|m| *m)
        .unwrap_or_default();
    let core_memory_mb = (metrics.core_mem_bytes as f64) / (1024.0 * 1024.0);
    let mut points: Vec<TrafficEventPayload> = ticks
        .into_iter()
        .map(|t| TrafficEventPayload {
            up_bps: t.up,
            down_bps: t.down,
            up_total_bytes: 0,
            down_total_bytes: 0,
            active_connections: 0,
            tunnel_connections: 0,
            core_memory_mb,
            timestamp_ms: t.timestamp_ms,
        })
        .collect();
    if let Some(last) = points.last_mut() {
        last.up_total_bytes = metrics.up_total_bytes;
        last.down_total_bytes = metrics.down_total_bytes;
        last.active_connections = metrics.app_connections;
        last.tunnel_connections = metrics.tunnel_connections;
    }
    points
}


#[tauri::command]
pub fn get_traffic_history(state: State<'_, AppState>) -> Vec<TrafficEventPayload> {
    if !state.snapshot_runtime().running {
        return Vec::new();
    }
    build_traffic_history(&state)
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledYamlPreviewDto {
    pub yaml: String,
    pub sha256: String,
    pub stats: CompileStats,
    pub validation: StaticValidationReport,
}


#[tauri::command]
pub fn compile_preview_yaml(state: State<'_, AppState>) -> Result<CompiledYamlPreviewDto, String> {
    let cfg = state.snapshot_config();
    let (nodes, groups, relays) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        (
            db.list_nodes().map_err(|e| e.to_string())?,
            db.list_multi_groups().map_err(|e| e.to_string())?,
            db.list_preaccel_relays(false).map_err(|e| e.to_string())?,
        )
    };
    let allocated = AllocatedPorts {
        bind_host: cfg.bind_address.clone(),
        mixed_port: cfg.mixed_port,
        controller_port: cfg.controller_port,
        dns_port: cfg.dns_listen_port,
        shifted: Vec::new(),
    };
    let empty_filter = HashMap::new();
    let input = CompileInput {
        config: &cfg,
        nodes: &nodes,
        groups: &groups,
        relays: &relays,
        controller_secret: "preview-redacted-secret",
        allocated_ports: &allocated,
        extra_prepend_rules: &[],
        extra_fake_ip_filters: &[],
        group_filtered_members: &empty_filter,
    };
    let compiled = compile_mihomo_config_with_runtime_dir(&input, Some(&state.paths.runtime_dir))
        .map_err(|e| e.to_string())?;
    let redacted_yaml =
        redact_compiled_yaml_for_preview(&compiled, &relays).map_err(|e| e.to_string())?;
    Ok(CompiledYamlPreviewDto {
        yaml: redacted_yaml,
        sha256: compiled.sha256,
        stats: compiled.stats,
        validation: compiled.validation,
    })
}


const MAX_BULK_RULES_TEXT_BYTES: usize = 2 * 1024 * 1024;


pub(in crate::commands) fn default_gateway_yaml_filename(profile: GatewayExportProfile) -> &'static str {
    match profile {
        GatewayExportProfile::RelayFragment => "catcloud-relay-fragment.yaml",
        GatewayExportProfile::TransparentGateway => "catcloud-transparent-gateway.yaml",
        GatewayExportProfile::PreferredNodes => "catcloud-preferred-nodes.yaml",
    }
}


fn load_gateway_export_snapshot(
    state: &AppState,
) -> Result<
    (
        Arc<AppConfig>,
        Vec<ProxyNode>,
        Vec<MultiGroup>,
        Vec<PreAccelRelay>,
        PathBuf,
    ),
    String,
> {
    let cfg = state.snapshot_config();
    let (nodes, groups, relays) = {
        let db = state
            .storage
            .lock()
            .map_err(|e| format!("读取本地配置数据库失败：{e}"))?;
        (
            db.list_nodes()
                .map_err(|e| format!("读取代理节点列表失败：{e}"))?,
            db.list_multi_groups()
                .map_err(|e| format!("读取智能多选组列表失败：{e}"))?,
            db.list_preaccel_relays(false)
                .map_err(|e| format!("读取国内中转线路失败：{e}"))?,
        )
    };
    Ok((cfg, nodes, groups, relays, state.paths.runtime_dir.clone()))
}


fn format_gateway_export_error(raw: &str) -> String {
    let detail = format_mihomo_error_for_user(raw);
    if detail.contains("导出软路由") || detail.contains("透明网关") {
        detail
    } else {
        format!("导出软路由 / 透明网关配置失败：{detail}")
    }
}


pub(in crate::commands) async fn export_gateway_yaml_async(
    state: &AppState,
    options: GatewayExportOptions,
) -> Result<GatewayExportOutput, String> {
    let (cfg, nodes, groups, relays, runtime_dir) = load_gateway_export_snapshot(state)?;
    tokio::task::spawn_blocking(move || {
        core_export_gateway_yaml(
            &cfg,
            &nodes,
            &groups,
            &relays,
            Some(&runtime_dir),
            &options,
        )
    })
    .await
    .map_err(|e| format!("导出软路由 / 透明网关配置任务异常中止：{e}"))?
    .map_err(|e| format_gateway_export_error(&e.to_string()))
}


#[tauri::command]
pub async fn export_gateway_yaml(
    state: State<'_, AppState>,
    options: GatewayExportOptions,
) -> Result<GatewayExportOutput, String> {
    export_gateway_yaml_async(&state, options).await
}


#[tauri::command]
pub async fn save_gateway_yaml_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
    options: GatewayExportOptions,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let output = export_gateway_yaml_async(&state, options).await?;
    let default_filename = default_gateway_yaml_filename(output.profile);
    let dialog_title = match output.profile {
        GatewayExportProfile::RelayFragment => "导出国内中转与防环片段 (.yaml)",
        GatewayExportProfile::TransparentGateway => "导出透明网关 / 软路由完整配置 (.yaml)",
        GatewayExportProfile::PreferredNodes => "导出优选节点与中转片段 (.yaml)",
    };

    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog()
        .file()
        .set_title(dialog_title)
        .set_file_name(default_filename)
        .add_filter("Mihomo YAML 配置", &["yaml", "yml"])
        .save_file(move |file_path| {
            let _ = tx.send(file_path);
        });

    let picked = match rx.await {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let Some(file_path) = picked else {
        return Ok(None);
    };

    let mut target_path = file_path
        .into_path()
        .map_err(|e| format!("无法解析所选保存路径：{e}"))?;
    if target_path
        .extension()
        .and_then(|e| e.to_str())
        .is_none_or(|ext| {
            !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml")
        })
    {
        target_path.set_extension("yaml");
    }

    let yaml_bytes = output.yaml.into_bytes();
    let write_path = target_path.clone();
    tokio::task::spawn_blocking(move || AppPaths::atomic_write(&write_path, &yaml_bytes))
        .await
        .map_err(|e| format!("后台写入网关 YAML 文件任务异常中止：{e}"))?
        .map_err(|e| format!("写入网关 YAML 文件失败：{e}"))?;

    let saved_path = catcloud_core::paths::normalize_os_path(&target_path)
        .display()
        .to_string();
    state.log_app_event(
        "info",
        "网关导出",
        &format!(
            "已导出软路由 / 透明网关配置（模式：{:?}，脱敏：{}，中转 {} 条，节点 {} 个）",
            output.profile,
            if output.redacted { "是" } else { "否" },
            output.relay_count,
            output.node_count
        ),
    );
    Ok(Some(saved_path))
}


#[tauri::command]
pub async fn parse_bulk_rules_preview(raw_text: String) -> Result<BulkRulesParseResult, String> {
    if raw_text.len() > MAX_BULK_RULES_TEXT_BYTES {
        return Err(format!(
            "批量规则文本超过 2 MiB 上限（当前 {} 字节），请分批导入或改用 rule-providers",
            raw_text.len()
        ));
    }
    Ok(parse_bulk_rules_text(&raw_text))
}


#[tauri::command]
pub fn audit_dangling_rules(
    state: State<'_, AppState>,
) -> Result<catcloud_core::core_adapter::DanglingRulesAudit, String> {
    let cfg = state.snapshot_config();
    let (groups, nodes) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let g = db.list_multi_groups().map_err(|e| e.to_string())?;
        let n = db.list_nodes().map_err(|e| e.to_string())?;
        (g, n)
    };
    Ok(catcloud_core::core_adapter::audit_dangling_global_rules(
        &cfg, &groups, &nodes,
    ))
}


#[tauri::command]
pub async fn repair_dangling_rules(
    app: AppHandle,
    state: State<'_, AppState>,
    mode: String,
    target_group: Option<String>,
    restart_core_if_needed: Option<bool>,
) -> Result<catcloud_core::core_adapter::DanglingRuleRepairReport, String> {
    let _cfg_guard = state.config_transition_lock.lock().await;
    let (groups, nodes) = {
        let db = state.storage.lock().map_err(|e| e.to_string())?;
        let g = db.list_multi_groups().map_err(|e| e.to_string())?;
        let n = db.list_nodes().map_err(|e| e.to_string())?;
        (g, n)
    };
    let mut cfg = state.clone_config();
    let action = match mode.trim().to_ascii_lowercase().as_str() {
        "remove" | "delete" | "clean" => catcloud_core::core_adapter::DanglingRuleRepairAction::Remove,
        "rewrite" | "remap" => {
            let valid_targets =
                catcloud_core::core_adapter::collect_valid_rule_target_names(&groups, &nodes);
            let dest = target_group
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty() && valid_targets.contains(*s))
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| {
                    catcloud_core::core_adapter::resolve_default_fallback_group_name(&cfg, &groups)
                });
            catcloud_core::core_adapter::DanglingRuleRepairAction::RewriteToGroup {
                target_group: dest,
            }
        }
        other => {
            return Err(format!(
                "不支持的规则修复方式 `{other}`（仅支持 remove 或 rewrite）"
            ));
        }
    };

    let report = catcloud_core::core_adapter::repair_dangling_global_rules(
        &mut cfg, &groups, &nodes, action, None,
    );
    let changed = report.removed_count > 0 || report.rewritten_count > 0;
    if changed {
        config::save(&state.paths, &cfg).map_err(|e| e.to_string())?;
        if let Ok(mut guard) = state.config.write() {
            *guard = Arc::new(cfg.clone());
        }
        state.clear_app_error();
        state.log_app_event(
            "info",
            "分流规则",
            &format!(
                "已修复悬空分流规则：清理 {} 条、改写 {} 条{}",
                report.removed_count,
                report.rewritten_count,
                report
                    .target_group
                    .as_deref()
                    .map(|g| format!("（目标分组「{g}」）"))
                    .unwrap_or_default()
            ),
        );
    }

    let core_running =
        state.snapshot_runtime().running || state.adapter.has_live_controller().await;
    if changed {
        if core_running {
            let _ = trigger_reload_if_running(&app, &state, false).await;
        } else if restart_core_if_needed.unwrap_or(false)
            && (cfg.system_proxy.enabled || cfg.tun.enabled)
            && has_enabled_nodes(&state).unwrap_or(false)
        {
            if let Err(err) = start_core_internal(&app, &state).await {
                state.log_app_event(
                    "warning",
                    "分流规则",
                    &format!("悬空规则已修复，但重新拉起核心仍未通过：{err}"),
                );
            }
        }
    }

    let latest_cfg = state.snapshot_config();
    emit_config_updated(&app, &latest_cfg);
    sync_tray_and_window_side_effects(&app, &state, &latest_cfg);
    Ok(report)
}


#[tauri::command]
pub fn export_shell_env(state: State<'_, AppState>, shell: String) -> String {
    let cfg = state.snapshot_config();
    let rt = state.snapshot_runtime();
    let port = if rt.running { rt.mixed_port } else { cfg.mixed_port };
    let plat = default_platform();
    plat.export_shell_env_snippet(&shell, "127.0.0.1", port, port)
}

