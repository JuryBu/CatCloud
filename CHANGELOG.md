# Changelog

All notable changes to **CatCloud** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Global Domestic Pre-Acceleration & Four-Way Sync
- Added standalone system-level **Global Domestic Pre-Acceleration** (usable without enabling CatCloud's own system proxy or TUN): launches an independent lightweight `:443` active-standby relay tunnel (~18 MB, zero TUN/DNS conflict) paired on Windows with dynamically loaded officially signed WinDivert transparent TCP redirection (`IfIdx` physical NIC pinning, per-process filtering for third-party proxy cores / SSH / SCP or global non-443 TCP fallback, RAII instant driver teardown on exit) and cross-platform standalone `socks5h://` entry.
- Unified four-way real-time toggle sync across Overview, Floating Capsule, Domestic Pre-Acceleration page, and System Tray (icon state + tooltip + context menu).

### Smart Watchdog, Routing & Performance
- Hardened smart multi-group background watchdog against false failovers under heavy uploads: reads 10s rolling throughput window unaffected by window minimization, enforces 5-minute anti-flapping cooldown on failed nodes, and live-probes top-3 replacement candidates before switching.
- Expanded conservative domestic direct routing (including Windows/Apple push notification endpoints and domestic CDNs) while keeping overseas & hybrid services strictly proxied.
- Applied active-node YAML pruning (`>90%` config size reduction in rule mode), `geodata-loader: memconservative`, rolling sanitized file logging, AI diagnostic quick-copy entry, custom frameless titlebar + Portal dropdowns/modals, resizable day/night-synced floating capsule, and ~48% steady-state Mihomo memory reduction.

### Cross-Platform Support, Readonly Migration & Auto-Update
- macOS: fixed TUN auto-interface naming (`utun*`), added native App Menu restoring `Cmd+C/V/A`, frameless titlebar traffic-light safe inset, resilient `networksetup` SOCKS & `Empty` bypass handling, LaunchAgent `Aqua` session, single-context `_EMBED_INFO_PLIST` guard, and PID-file orphan core cleanup.
- Linux: added dual KDE (`kwriteconfig5`/`kwriteconfig6`) + GNOME system proxy support, `$APPIMAGE` path resolution, least-privilege `pkexec setcap` for TUN (never elevating GUI as root), Wayland/X11 clipboard fallback (`wl-copy` -> `xclip` -> `xsel`), and automatic `+x` execution bits.
- Windows: fixed UTF-16LE clipboard Chinese encoding; expanded CI test matrix to Ubuntu + macOS (`macos-latest`) + Windows and hardened 5-architecture multi-platform Release workflow; added floating capsule four-edge magnetic dock/expand with multi-DPI physical coordinates.
- Readonly Config Migration: sorted candidate configs by file size descending (capped at 64 files with `16 MiB` bounded reads) so large real subscriptions in busy `profiles/` folders are never truncated by tiny templates; parsed `profiles.yaml` / `profile.yaml` for human-readable `display_name`; expanded open-source client path discovery (`mihomo-party`, `clash-party`, `clash-nyanpasu`, `FlClash`) and added custom directory/file readonly picker with collision-free node ID rebinding.
- Background Auto-Update Loop: wired end-to-end GitHub Releases `latest.json` + `SHA256SUMS.txt` auto-check and portable ZIP background staging (`next_launch` default) with startup cold-boot delay, mutex serialization, downgrade & corrupt-staging auto-recovery, strict portable-install detection decoupled from `--data-dir`, and secret-free external HTTPS URL launcher.

## [0.1.0] - 2026-11-23

### Architecture & Runtime
- Established a three-layer decoupled Rust + Tauri v2 + React 19 workspace (`crates/catcloud-core`, `crates/catcloud-cli`, `src-tauri`, `ui`).
- Implemented portable and standard runtime directory resolution (`--data-dir` > `CATCLOUD_DATA_DIR` > `portable.flag` / `data/` > OS AppData) with Tauri `AppDirectoryOverrides` and `WEBVIEW2_USER_DATA_FOLDER` isolation.
- Implemented per-`data_dir` isolated single-instance locking (Windows Named Mutex + Wakeup Event, Unix `flock`) supporting parallel sandbox instances and `--restarting` graceful handoff.
- Added OS-native zero-zombie process supervision (`JobGuard` with Windows `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, three-path detached self-restart breakaway, Linux `PR_SET_PDEATHSIG(SIGKILL)`, and Unix process-group / PID cleanup).
- Implemented destroyable windowless tray lifecycle (`<= 70 MB` RAM budget with WebView2 completely destroyed on close) and lightweight floating capsule window mode (`<= 165 MB` budget).
- Added SQLite WAL persistence (`subscriptions`, `nodes`, `probe_definitions`, `probe_results`, `multi_groups`, `preaccel_relays`) and atomic `config.json` storage with SHA-256 backup/restore.

### Smart Routing, Probes & Hot Reload
- Built a zero-`eval` safe recursive-descent AST formula engine with built-in cost-effective and max-performance templates plus per-probe addressing functions (`probe_up`, `probe_down`, `probe_ping`, `probe_ok`, `site_unlocked`).
- Added four per-site orchestration modes (`sticky_best`, `conditional_pool`, `load_balance_consistent_hash`, `load_balance_round_robin`), hysteresis anti-flapping, three-way below-threshold fallback policies (`degrade_best_warn`, `cross_pool_escalate` with auto primary-pool recovery, `strict_circuit_break` to `REJECT`), and per-group connection teardown (`force_close_old` / `graceful_new_only`).
- Built an isolated temporary Mihomo probe runner (`127.0.0.1`-only listeners, `redir-host` direct physical DNS, `socks5h://`, `GOMEMLIMIT=32MiB`) with a 3-stage funnel covering latency/jitter, Google-side region cleanliness ground truth, custom regex unlock probes, `512 KB` fast-cut upload/download benchmarks, silent Keep-Alive verification, and external script probes.
- Added multi-format subscription ingestion (Clash/Mihomo YAML with merge anchor expansion and `16 MiB` size cap, Base64/plain URI lists, atomic 0-node/error protection), read-only local config migration, read-only running process inspection, and open `catcloud-adapter/v1` external refresh slots.
- Implemented L1/L2/L3 hot reload with `300 ms` debounce, SHA-256 deduplication, static anti-loop preflight, `mihomo -t` validation, YAML Merge Patch overrides, TCP+UDP dual-protocol port collision guard, authenticated REST control (`Authorization: Bearer`), and active group selection replay.

### Domestic Pre-Acceleration & Campus Network Protection
- Implemented `mmrelay/v1` JSON and `mmrelay://v1/<base64url>` relay bundle import/export with per-protocol empty-SNI enforcement (`sni` for Trojan/AnyTLS, `servername` for VLESS) and expiry countdown warnings.
- Added active-standby `dialer-proxy` chain compilation (`select` -> `fallback` with `lazy: false`), smart native-443 skip with per-node override, domestic-only 204 health probe enforcement (blocking overseas probe domains), and automatic anti-loop `DIRECT,no-resolve` + `fake-ip-filter` injection.
- Added campus network Captive Portal detection (`redirect::Policy::none()` + `.no_proxy()`) with temporary portal exemption rules automatically revoked once HTTP 204 connectivity recovers.

### Headless CLI, Agent Tooling & Desktop UI
- Created standalone headless `catcloud` CLI binary verified with zero GTK/WebKit shared-library dependencies on Linux.
- Embedded four-section dual-read (Human + AI Agent) documentation registry across all six core modules, exportable in Markdown and JSON.
- Built lightweight React 19 + Vite 7 + Tailwind CSS v4 frontend (zero heavy UI/chart frameworks) featuring a 300-point `Float64Array` native SVG traffic sparkline, three-stage scheduled day/night themes, custom wallpaper with controlled blur, pixel mascot sprite engine with visibility throttling, and pre-baked multi-state tray icons.

### Packaging, CI/CD & Auto-Update
- Added hardened next-launch updater with strict per-hop HTTPS GitHub allowlist, `latest.json` + `SHA256SUMS.txt` verification, Zip-Slip & symlink defenses, preserved user-data allowlist, and Windows portable same-volume `.exe.old` swap with full automatic rollback.
- Added cross-platform zero-dependency Node.js release scripts (`fetch_mihomo.mjs`, `extract_release_notes.mjs`, `stage_windows.mjs`, `stage_macos.mjs`, `stage_linux.mjs`, `build_latest_json.mjs`).
- Configured GitHub Actions CI (public sanitization gate, frontend build, workspace tests, Linux headless CLI `ldd` gate) and multi-platform Release workflows (Windows x64/arm64, macOS aarch64/x64, Linux x86_64, Draft Release publishing).
