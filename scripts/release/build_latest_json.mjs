#!/usr/bin/env node
/**
 * Generate `latest.json` compatible with both:
 *   1. CatCloud's built-in next-launch updater (`crates/catcloud-core/src/updater.rs`)
 *   2. Tauri v2 Updater (`tauri-plugin-updater`)
 *
 * Scans `release-assets/` and verifies every included artifact against `SHA256SUMS.txt`.
 * Zero external npm dependencies (Node.js 20+ ESM).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractSection } from "./extract_release_notes.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");

const DEFAULT_REPO = "JuryBu/CatCloud";

function readDefaultVersion() {
  const conf = JSON.parse(fs.readFileSync(path.join(ROOT, "src-tauri", "tauri.conf.json"), "utf8"));
  return String(conf.version).replace(/^[vV]/, "");
}

function validateVersion(raw) {
  const clean = String(raw || "").trim().replace(/^[vV]/, "");
  if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/.test(clean)) {
    throw new Error(`Invalid SemVer version: '${raw}'`);
  }
  if (/^0\.0\.0(?:[-+].*)?$/.test(clean)) {
    throw new Error(`Release version 0.0.0 is forbidden: '${raw}'`);
  }
  return clean;
}

function validateRepo(raw) {
  const clean = String(raw || "").trim().replace(/^\/+|\/+$/g, "");
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(clean)) {
    throw new Error(`Invalid GitHub repository slug: '${raw}'`);
  }
  return clean;
}

/**
 * Parse `SHA256SUMS.txt` into a map keyed by basename (`<filename> -> <64-hex>`).
 * Supports both `release-assets/Foo.zip` and bare `Foo.zip` paths.
 */
export function parseSha256SumsFile(content) {
  const map = new Map();
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([0-9a-fA-F]{64})\s+\*?(.+)$/.exec(line);
    if (!match) {
      throw new Error(`Malformed SHA256SUMS line ${i + 1}: ${line}`);
    }
    const digest = match[1].toLowerCase();
    const rawPath = match[2].trim().replace(/\\/g, "/").replace(/^\.\//, "");
    const base = path.posix.basename(rawPath);
    if (!base) {
      throw new Error(`Missing filename on SHA256SUMS line ${i + 1}`);
    }
    map.set(base, digest);
  }
  if (map.size === 0) {
    throw new Error("SHA256SUMS.txt contains no valid entries");
  }
  return map;
}

function computeFileSha256(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function parseArgs(argv) {
  const opts = {
    version: readDefaultVersion(),
    repo: process.env.GITHUB_REPOSITORY || DEFAULT_REPO,
    assetsDir: path.join(ROOT, "release-assets"),
    checksums: path.join(ROOT, "SHA256SUMS.txt"),
    notesFile: null,
    changelog: path.join(ROOT, "CHANGELOG.md"),
    output: path.join(ROOT, "latest.json"),
    pubDate: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    requireSignatures: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--version") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.version = val;
      }
    } else if (arg === "--repo") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.repo = val;
      }
    } else if (arg === "--assets-dir") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.assetsDir = path.resolve(val);
      }
    } else if (arg === "--checksums") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.checksums = path.resolve(val);
      }
    } else if (arg === "--notes-file") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        opts.notesFile = val ? path.resolve(val) : null;
      }
    } else if (arg === "--changelog") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.changelog = path.resolve(val);
      }
    } else if (arg === "--output") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.output = path.resolve(val);
      }
    } else if (arg === "--pub-date") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.pubDate = val;
      }
    } else if (arg === "--require-signatures") {
      opts.requireSignatures = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node scripts/release/build_latest_json.mjs [options]

Options:
  --version <X.Y.Z>        Release version (default: from src-tauri/tauri.conf.json)
  --repo <owner/repo>      GitHub repository (default: ${DEFAULT_REPO})
  --assets-dir <path>      Directory containing staged release artifacts (default: ./release-assets)
  --checksums <path>       Path to SHA256SUMS.txt (default: ./SHA256SUMS.txt)
  --notes-file <path>      Pre-extracted Markdown release notes file
  --changelog <path>       Fallback CHANGELOG.md path when --notes-file is omitted
  --output <path>          Output latest.json path (default: ./latest.json)
  --pub-date <ISO8601>     UTC publication timestamp
  --require-signatures     Fail if primary desktop updater artifacts lack .sig signatures
`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  opts.version = validateVersion(opts.version);
  opts.repo = validateRepo(opts.repo);
  return opts;
}

/**
 * Platform-to-artifact selection rules in strict priority order.
 * Keys match Tauri Updater targets plus `-portable` / `-cli` entries consumed by CatCloud.
 */
function buildPlatformMatchers(version) {
  const v = version;
  return [
    {
      key: "windows-x86_64",
      primaryInstaller: true,
      candidates: [
        `CatCloud-${v}-windows-x64-setup.exe`,
        `CatCloud-${v}-windows-x64.msi`,
      ],
    },
    {
      key: "windows-x86_64-portable",
      primaryInstaller: false,
      candidates: [`CatCloud-${v}-windows-x64-portable.zip`],
    },
    {
      key: "windows-aarch64",
      primaryInstaller: true,
      candidates: [
        `CatCloud-${v}-windows-arm64-setup.exe`,
        `CatCloud-${v}-windows-arm64.msi`,
      ],
    },
    {
      key: "windows-aarch64-portable",
      primaryInstaller: false,
      candidates: [`CatCloud-${v}-windows-arm64-portable.zip`],
    },
    {
      key: "darwin-aarch64",
      primaryInstaller: true,
      candidates: [
        `CatCloud-${v}-macos-aarch64.app.tar.gz`,
        `CatCloud-${v}-macos-aarch64.dmg`,
      ],
    },
    {
      key: "darwin-x86_64",
      primaryInstaller: true,
      candidates: [
        `CatCloud-${v}-macos-x64.app.tar.gz`,
        `CatCloud-${v}-macos-x64.dmg`,
      ],
    },
    {
      key: "linux-x86_64",
      primaryInstaller: true,
      candidates: [
        `CatCloud-${v}-linux-x86_64.AppImage.tar.gz`,
        `CatCloud-${v}-linux-x86_64.AppImage`,
      ],
    },
    {
      key: "windows-x86_64-cli",
      primaryInstaller: false,
      candidates: ["catcloud-windows-x86_64.zip"],
    },
    {
      key: "windows-aarch64-cli",
      primaryInstaller: false,
      candidates: ["catcloud-windows-aarch64.zip"],
    },
    {
      key: "darwin-aarch64-cli",
      primaryInstaller: false,
      candidates: ["catcloud-macos-aarch64.tar.gz"],
    },
    {
      key: "darwin-x86_64-cli",
      primaryInstaller: false,
      candidates: ["catcloud-macos-x86_64.tar.gz"],
    },
    {
      key: "linux-x86_64-cli",
      primaryInstaller: false,
      candidates: ["catcloud-linux-x86_64.tar.gz"],
    },
  ];
}

function loadReleaseNotes(opts) {
  if (opts.notesFile && fs.existsSync(opts.notesFile)) {
    return fs.readFileSync(opts.notesFile, "utf8").trim();
  }
  if (fs.existsSync(opts.changelog)) {
    const md = fs.readFileSync(opts.changelog, "utf8");
    return extractSection(md, opts.version, { allowFallback: true }).notes;
  }
  return `CatCloud v${opts.version}`;
}

export function generateLatestManifest(opts) {
  if (!fs.existsSync(opts.assetsDir)) {
    throw new Error(`Assets directory does not exist: ${opts.assetsDir}`);
  }
  if (!fs.existsSync(opts.checksums)) {
    throw new Error(`Checksums file does not exist: ${opts.checksums}`);
  }

  const sumsMap = parseSha256SumsFile(fs.readFileSync(opts.checksums, "utf8"));
  const availableFiles = new Set(
    fs
      .readdirSync(opts.assetsDir)
      .filter((name) => fs.statSync(path.join(opts.assetsDir, name)).isFile())
  );

  const tag = `v${opts.version}`;
  const baseUrl = `https://github.com/${opts.repo}/releases/download/${tag}`;
  const platforms = {};

  for (const matcher of buildPlatformMatchers(opts.version)) {
    const chosen = matcher.candidates.find((name) => availableFiles.has(name));
    if (!chosen) continue;

    const fullPath = path.join(opts.assetsDir, chosen);
    const listedSha = sumsMap.get(chosen);
    if (!listedSha) {
      throw new Error(`Asset '${chosen}' exists in ${opts.assetsDir} but is missing from SHA256SUMS.txt`);
    }
    const actualSha = computeFileSha256(fullPath);
    if (actualSha !== listedSha) {
      throw new Error(
        `SHA-256 mismatch for '${chosen}': SHA256SUMS.txt=${listedSha}, disk=${actualSha}`
      );
    }

    const entry = {
      url: `${baseUrl}/${encodeURIComponent(chosen)}`,
      sha256: listedSha,
      filename: chosen,
    };

    const sigPath = path.join(opts.assetsDir, `${chosen}.sig`);
    if (fs.existsSync(sigPath)) {
      const sigText = fs.readFileSync(sigPath, "utf8").trim();
      if (sigText) {
        entry.signature = sigText;
      }
    } else if (opts.requireSignatures && matcher.primaryInstaller) {
      throw new Error(`Missing required minisign signature file: ${chosen}.sig`);
    }

    platforms[matcher.key] = entry;
  }

  if (Object.keys(platforms).length === 0) {
    throw new Error(
      `No matching release artifacts found in ${opts.assetsDir} for version ${opts.version}`
    );
  }

  return {
    version: opts.version,
    notes: loadReleaseNotes(opts),
    pub_date: opts.pubDate,
    sha256sums_url: `${baseUrl}/SHA256SUMS.txt`,
    platforms,
  };
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const manifest = generateLatestManifest(opts);
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
  fs.mkdirSync(path.dirname(opts.output), { recursive: true });
  const tmpPath = `${opts.output}.tmp.${process.pid}`;
  fs.writeFileSync(tmpPath, serialized, "utf8");
  fs.renameSync(tmpPath, opts.output);
  console.log(
    `[build_latest_json] Wrote ${opts.output} (v${manifest.version}, ${Object.keys(manifest.platforms).length} platform entries)`
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`[build_latest_json] ERROR: ${err.message}`);
    process.exit(1);
  }
}
