# Changelog

All notable changes to **CatCloud** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Future post-beta iterations will be tracked here.

## [0.1.0] - 2026-11-25

### Campus Network Hardening & Honest TUN Privilege Gate
- **Pure-IP DoH 443 Default & Schema v2 -> v3 Auto-Migration**: Upgraded default `default_nameserver`, `direct_nameserver`, and `proxy_server_nameserver` from plaintext UDP 53 to pure-IP DoH 443 (`https://223.5.5.5/dns-query`, `https://1.12.12.12/dns-query`) with non-destructive migration preserving custom DNS settings, solving campus networks that block outbound UDP 53 while keeping `+.edu.cn` and LAN suffixes on `system` DNS.
- **Honest Virtual NIC (TUN) Privilege Gate**: Strictly separated persisted TUN intent (`tun_configured`) from effective runtime state (`tun_enabled`) across Core, CLI, Desktop, Tray, and all four UI surfaces (Overview, Sidebar, Floating Capsule, Settings). Standard non-elevated runs never falsely report TUN active and offer one-click UAC elevation or a clean "disable TUN for now" opt-out.
- **Runtime Controller Metadata & Zero-401 CLI Stethoscope**: Added atomic restricted `data/run/runtime-controller.json` metadata (with PID liveness verification, L2 secret rotation refresh, shifted port preservation, exit/crash cleanup, and `serde_yaml_ng` `runtime.yaml` fallback) so local `catcloud net doctor`, `net connections`, `net match`, and `config reload` authenticate seamlessly against the active desktop core without exposing secrets.

### Share Bundles, AI Assistant, Multi-Language UI & Domestic Relay Upgrades
- **Friend-Friendly & Agent-Friendly `.zip` Share Bundles (`catcloud-share/v1`)**: Select arbitrary proxy nodes and domestic `:443` relays to export as a portable `.zip` with human/agent-readable `README.md` + `manifest.json`, with one-click preview, deduplicated import, and Zip-Slip/symlink/Zip-Bomb protection (GUI + `catcloud share`).
- **Dedicated AI Assistant Menu, 4-Language UI & One-Click GitHub Issue Feedback**: Promoted **AI Assistant** to a top-level sidebar menu featuring 8 four-language (`zh-CN` / `en` / `ja` / `ru`) bundled guides, one-click sanitized onboarding & troubleshooting packs (with 256-entry key-event ring), and pre-filled sanitized GitHub Issue reporting.
- **Domestic `:443` Pre-Acceleration (AnyTLS / Hysteria2 / Global WinDivert)**: Added real per-relay upload/download speed testing via isolated temporary cores (`preaccel test --speed`), `tfo: true` + `AnyTLS` idle session pooling + conservative `Hysteria2` bandwidth defaults, unified master pre-acceleration switch across Overview/Capsule/PreAccel/Tray, pure-loopback WinDivert dataplane self-test with automatic anti-disconnect fallback and deduplicated security guidance, and domestic QUIC UDP 443 allow-before-reject rules for smooth domestic IM media loading.
- **Smart Multi-Group Health Pool & Live Capture Wizard**: Added dual-origin (`gstatic` + `Cloudflare`) watchdog with 1.5s retry-before-penalize, exponential cooldown (`60s -> 180s -> 600s`), probation recovery, EWMA anti-flapping, background task persistence across route/window switches, `1->2->3` live capture wizard with PE display-name extraction, subscription rename/merge, and non-polluting golden-node view sorting.

### Cross-Platform Packaging, CI/CD & Bundled Headless CLI
- **Out-of-the-Box Multi-Platform Bundles**: Bundled official verified `mihomo` and headless `catcloud` CLI directly into Windows (MSI, NSIS, Portable ZIP with `portable.flag` & QuickStart), macOS (Apple Silicon & Intel `.dmg` / `.app.tar.gz`), and Linux (`.AppImage` / `.deb` / `.rpm`), alongside standalone zero-GTK/WebKit CLI archives, `SHA256SUMS.txt`, and `latest.json` next-launch auto-update manifests.
- **Performance & Memory Footprint**: Destroyable WebView2 windowless tray mode (`<= 70 MB` RAM budget), active-node YAML pruning (`>90%` reduction in rule mode), `geodata-loader: memconservative`, adaptive `GOMEMLIMIT`, `Global -> Rule` heap reclaim guard, and OS-native zero-zombie subprocess cleanup (`JobGuard`).
