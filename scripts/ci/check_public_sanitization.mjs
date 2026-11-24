#!/usr/bin/env node
/**
 * CatCloud Public Repository Sanitization Gate
 * Cross-platform zero-dependency Node.js scanner for CI & local pre-commit checks.
 * Prevents leakage of personal filesystem paths, private keys, real proxy URIs,
 * subscription tokens, private vendor names, or non-placeholder public IPv4s.
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");

const TEXT_EXTS = new Set([
  ".rs", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".toml",
  ".yaml", ".yml", ".md", ".txt", ".html", ".css", ".ps1", ".sh", ".py",
  ".cfg", ".ini", ".env", ".gitignore", ".gitattributes",
]);

const SKIP_FILES = new Set([
  "scripts/ci/check_public_sanitization.mjs",
  "pnpm-lock.yaml",
  "package-lock.json",
  "Cargo.lock",
]);

const FORBIDDEN_PATTERNS = [
  {
    name: "personal_windows_path",
    re: /[A-Za-z]:[\\/]Users[\\/](?!<USER>|runner|Administrator|Public)[A-Za-z0-9_.-]+/i,
  },
  {
    name: "personal_unix_home_path",
    re: /(?:^|[\s"'`(])\/(?:Users|home)\/(?!<USER>|runner|ubuntu|root|catcloud)[A-Za-z0-9_.-]+/,
  },
  {
    name: "private_key_block",
    re: /-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|ED25519) )?PRIVATE KEY-----/,
  },
  {
    name: "minisign_secret_key",
    re: /untrusted comment:\s*minisign (?:secret|encrypted) key/i,
  },
  {
    name: "github_token",
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
  },
  {
    name: "subscription_token_url",
    re: /https?:\/\/[^\s"']+(?:token|sub|subscribe)=[A-Za-z0-9_-]{16,}/i,
  },
  {
    name: "live_proxy_uri_secret",
    re: /\b(?:vless|vmess|trojan|ss|ssr|hy2|hysteria2|tuic|anytls):\/\/(?!<|example|demo|test|user|pass|secret|uuid|placeholder|00000000)[A-Za-z0-9._:@%+=-]{20,}/i,
  },
  {
    name: "private_qq_email",
    re: /\b\d{6,12}@qq\.com\b/i,
  },
  {
    name: "private_local_brain",
    re: /plans_agy|\.gemini[\\/]antigravity[\\/]brain/i,
  },
  {
    name: "private_vendor_process",
    re: /mihomotag-serv|ShaYuCore|yeshayunCore/i,
  },
  {
    name: "private_vendor_name",
    re: /落云|夜煞云|鲨鱼云|TAGv2/i,
  },
];

const IPV4_RE = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
const SAFE_IPV4_PREFIXES = [
  "0.", "10.", "127.", "169.254.", "192.168.", "198.18.", "198.19.",
  "192.0.2.", "198.51.100.", "203.0.113.", "224.", "255.",
];
const SAFE_DNS_IPS = new Set([
  "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
  "223.5.5.5", "223.6.6.6", "119.29.29.29", "119.28.28.28",
  "1.12.12.12", "120.53.53.53",
  "114.114.114.114", "114.114.115.115", "180.76.76.76",
  "180.184.1.1", "180.184.2.2", "1.2.4.8", "210.2.4.8",
  "208.67.222.222", "208.67.220.220",
]);

function isSuspiciousPublicIp(m) {
  const parts = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (parts.some((p) => p > 255)) return false;
  const ip = parts.join(".");
  if (SAFE_DNS_IPS.has(ip)) return false;
  if (SAFE_IPV4_PREFIXES.some((pref) => ip.startsWith(pref))) return false;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false;
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false;
  if (parts[0] >= 240) return false;
  return true;
}

function listCandidateFiles() {
  const buf = execFileSync(
    "git",
    ["-c", "core.quotepath=false", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
    { cwd: ROOT }
  );
  return buf
    .toString("utf8")
    .split("\0")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((rel) => ({ rel: rel.replace(/\\/g, "/"), full: path.join(ROOT, rel) }))
    .filter(({ rel, full }) => {
      if (SKIP_FILES.has(rel)) return false;
      if (!fs.existsSync(full) || !fs.statSync(full).isFile()) return false;
      const ext = path.extname(full).toLowerCase();
      const base = path.basename(full);
      return TEXT_EXTS.has(ext) || base === "LICENSE" || base === "Makefile";
    });
}

function isVersionOrOidLiteral(line, match, relPath) {
  const start = match.index;
  const end = start + match[0].length;
  const before = line.slice(0, start);
  const after = line.slice(end);

  // Exclude 5+ segment dotted numeric sequences (e.g. ASN.1 OIDs like 1.3.6.1.5.5.7).
  if (/\d\.$/.test(before) || /^\.\d/.test(after)) {
    return true;
  }

  // Exclude explicit `v1.2.3.4` version literals directly prefixed with `v`/`V`.
  if (/(?:^|[^A-Za-z0-9_])[vV]$/.test(before)) {
    return true;
  }

  // Exclude values immediately following explicit version keys (e.g. `"version": "1.2.3.4"`).
  if (
    /(?:^|[\s"'`,{;(\[])(?:file_?version|product_?version|schema_?version|min_?version|max_?version|app_?version|sdk_?version|runtime_?version|version)\s*[:=]\s*["']?[vV]?$/i.test(
      before
    )
  ) {
    return true;
  }

  // Exclude User-Agent / toolchain / package version tokens directly glued by `/`, `@`, or `-`.
  if (
    /(?:chrome|edg|edge|safari|firefox|webkit|webview2|chromium|electron|tauri|mihomo|node|pnpm|rust|cargo)[/@-][vV]?$/i.test(
      before
    )
  ) {
    return true;
  }

  // Exclude 4-part version ranges inside package.json manifests.
  if (relPath.endsWith("package.json") && /["'][~^>=<]*$/.test(before)) {
    return true;
  }

  return false;
}

const violations = [];
for (const { rel, full } of listCandidateFiles()) {
  const text = fs.readFileSync(full, "utf8");
  const lines = text.split(/\r?\n/);
  for (let idx = 0; idx < lines.length; idx++) {
    const line = lines[idx];
    for (const pat of FORBIDDEN_PATTERNS) {
      if (pat.re.test(line)) {
        violations.push(`${rel}:${idx + 1}: [${pat.name}] sensitive pattern detected`);
      }
    }
    // Scan all source/config/doc files for unexpected public IPv4 literals
    IPV4_RE.lastIndex = 0;
    let m;
    while ((m = IPV4_RE.exec(line)) !== null) {
      if (isVersionOrOidLiteral(line, m, rel)) {
        continue;
      }
      if (isSuspiciousPublicIp(m)) {
        violations.push(`${rel}:${idx + 1}: [public_ipv4] unexpected IPv4 ${m[0]}`);
      }
    }
  }
}

if (violations.length > 0) {
  console.error("PUBLIC SANITIZATION GATE FAILED:");
  for (const v of violations) console.error("  -", v);
  process.exit(1);
}

console.log("PUBLIC SANITIZATION GATE PASSED (0 violations)");
