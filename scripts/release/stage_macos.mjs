#!/usr/bin/env node
/**
 * Stage macOS release artifacts into unified `release-assets/`:
 *   - `.dmg` disk image
 *   - `.app.tar.gz` bundle archive (+ optional `.sig`)
 *   - Headless `catcloud` CLI `.tar.gz` archive
 *
 * Zero external npm dependencies (Node.js 20+ ESM).
 */

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");

const ARCH_MAP = {
  "aarch64-apple-darwin": { shortArch: "aarch64", cliArch: "aarch64" },
  "x86_64-apple-darwin": { shortArch: "x64", cliArch: "x86_64" },
};

function readDefaultVersion() {
  const conf = JSON.parse(fs.readFileSync(path.join(ROOT, "src-tauri", "tauri.conf.json"), "utf8"));
  return String(conf.version).replace(/^[vV]/, "");
}

function findSingleEntry(dir, predicate) {
  if (!fs.existsSync(dir)) return null;
  const entries = fs
    .readdirSync(dir)
    .filter((name) => predicate(name))
    .sort();
  return entries.length > 0 ? path.join(dir, entries[0]) : null;
}

function copyWithOptionalSig(srcFile, destFile, staged) {
  fs.copyFileSync(srcFile, destFile);
  staged.push(path.basename(destFile));
  const sigSrc = `${srcFile}.sig`;
  if (fs.existsSync(sigSrc)) {
    const sigDest = `${destFile}.sig`;
    fs.copyFileSync(sigSrc, sigDest);
    staged.push(path.basename(sigDest));
  }
}

function parseArgs(argv) {
  const opts = {
    target: "aarch64-apple-darwin",
    version: readDefaultVersion(),
    targetDir: path.join(ROOT, "target"),
    outDir: path.join(ROOT, "release-assets"),
    mihomoBin: path.join(ROOT, "src-tauri", "resources", "bin", "mihomo"),
    dryRun: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--target") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.target = val;
      }
    } else if (arg === "--version") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim().replace(/^[vV]/, "");
        if (val) opts.version = val;
      }
    } else if (arg === "--target-dir") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.targetDir = path.resolve(val);
      }
    } else if (arg === "--out-dir") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.outDir = path.resolve(val);
      }
    } else if (arg === "--mihomo-bin") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.mihomoBin = path.resolve(val);
      }
    } else if (arg === "--dry-run") {
      opts.dryRun = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node scripts/release/stage_macos.mjs [options]

Options:
  --target <triple>    aarch64-apple-darwin | x86_64-apple-darwin
  --version <X.Y.Z>    Release SemVer without leading 'v'
  --target-dir <path>  Cargo target root (default: ./target)
  --out-dir <path>     Staging directory (default: ./release-assets)
  --mihomo-bin <path>  Bundled Mihomo executable path
  --dry-run            Print planned outputs without requiring compiled artifacts
`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!ARCH_MAP[opts.target]) {
    throw new Error(`Unsupported macOS target: ${opts.target}`);
  }
  return opts;
}

function resolveReleaseDir(targetDir, target) {
  const targetRelease = path.join(targetDir, target, "release");
  if (fs.existsSync(targetRelease)) return targetRelease;
  return path.join(targetDir, "release");
}

function createTarGz(cwd, entries, destArchive) {
  execFileSync("tar", ["-czf", destArchive, ...entries], {
    cwd,
    stdio: "inherit",
    env: { ...process.env, COPYFILE_DISABLE: "1" },
  });
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const { shortArch, cliArch } = ARCH_MAP[opts.target];
  const releaseDir = resolveReleaseDir(opts.targetDir, opts.target);
  const bundleDir = path.join(releaseDir, "bundle");

  const planned = {
    dmg: `CatCloud-${opts.version}-macos-${shortArch}.dmg`,
    appTarGz: `CatCloud-${opts.version}-macos-${shortArch}.app.tar.gz`,
    cliTarGz: `catcloud-macos-${cliArch}.tar.gz`,
  };

  if (opts.dryRun) {
    console.log(
      JSON.stringify({ dry_run: true, target: opts.target, release_dir: releaseDir, planned }, null, 2)
    );
    return;
  }

  fs.mkdirSync(opts.outDir, { recursive: true });
  const staged = [];

  // 1. DMG disk image
  const dmgSrc = findSingleEntry(path.join(bundleDir, "dmg"), (n) => n.toLowerCase().endsWith(".dmg"));
  if (!dmgSrc) {
    throw new Error(`DMG bundle not found under ${path.join(bundleDir, "dmg")}`);
  }
  copyWithOptionalSig(dmgSrc, path.join(opts.outDir, planned.dmg), staged);

  // 2. `.app.tar.gz` archive (reuse Tauri updater tarball if present, otherwise archive `.app`)
  const macosBundleDir = path.join(bundleDir, "macos");
  const existingAppTar = findSingleEntry(macosBundleDir, (n) => n.endsWith(".app.tar.gz"));
  const destAppTar = path.join(opts.outDir, planned.appTarGz);
  if (existingAppTar) {
    copyWithOptionalSig(existingAppTar, destAppTar, staged);
  } else {
    const appDir = findSingleEntry(macosBundleDir, (n) => n.endsWith(".app"));
    if (!appDir) {
      throw new Error(`macOS .app bundle not found under ${macosBundleDir}`);
    }
    createTarGz(macosBundleDir, [path.basename(appDir)], destAppTar);
    staged.push(planned.appTarGz);
  }

  // Verify bundled Mihomo presence if `.app` exists locally
  const appBundle = findSingleEntry(macosBundleDir, (n) => n.endsWith(".app"));
  if (appBundle) {
    const candidates = [
      path.join(appBundle, "Contents", "Resources", "resources", "bin", "mihomo"),
      path.join(appBundle, "Contents", "Resources", "bin", "mihomo"),
    ];
    if (!candidates.some((p) => fs.existsSync(p))) {
      console.warn(
        `[stage_macos] WARNING: Mihomo binary not detected inside ${appBundle}/Contents/Resources`
      );
    }
  }

  // 3. Headless CLI tarball
  const cliBin = path.join(releaseDir, "catcloud");
  if (!fs.existsSync(cliBin)) {
    throw new Error(`Headless CLI binary not found: ${cliBin}`);
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "catcloud-cli-macos-"));
  try {
    const cliDest = path.join(tmpDir, "catcloud");
    fs.copyFileSync(cliBin, cliDest);
    fs.chmodSync(cliDest, 0o755);
    const items = ["catcloud"];
    const licensePath = path.join(ROOT, "LICENSE");
    if (fs.existsSync(licensePath)) {
      fs.copyFileSync(licensePath, path.join(tmpDir, "LICENSE"));
      items.push("LICENSE");
    }
    createTarGz(tmpDir, items, path.join(opts.outDir, planned.cliTarGz));
    staged.push(planned.cliTarGz);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log(`[stage_macos] Staged ${staged.length} files into ${opts.outDir}:`);
  for (const name of staged) {
    console.log(`  - ${name}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`[stage_macos] ERROR: ${err.message}`);
    process.exit(1);
  }
}
