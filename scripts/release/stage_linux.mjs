#!/usr/bin/env node
/**
 * Stage Linux release artifacts into unified `release-assets/`:
 *   - `.AppImage` (+ optional `.AppImage.sig` / `.AppImage.tar.gz`)
 *   - `.deb` Debian/Ubuntu package
 *   - `.rpm` Fedora/RHEL/openSUSE package
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
  "x86_64-unknown-linux-gnu": { cliArch: "x86_64" },
  "aarch64-unknown-linux-gnu": { cliArch: "aarch64" },
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
    target: "x86_64-unknown-linux-gnu",
    version: readDefaultVersion(),
    targetDir: path.join(ROOT, "target"),
    outDir: path.join(ROOT, "release-assets"),
    mihomoBin: path.join(ROOT, "src-tauri", "resources", "bin", "mihomo"),
    dryRun: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--target" && argv[i + 1]) {
      opts.target = argv[++i];
    } else if (arg === "--version" && argv[i + 1]) {
      opts.version = argv[++i].replace(/^[vV]/, "");
    } else if (arg === "--target-dir" && argv[i + 1]) {
      opts.targetDir = path.resolve(argv[++i]);
    } else if (arg === "--out-dir" && argv[i + 1]) {
      opts.outDir = path.resolve(argv[++i]);
    } else if (arg === "--mihomo-bin" && argv[i + 1]) {
      opts.mihomoBin = path.resolve(argv[++i]);
    } else if (arg === "--dry-run") {
      opts.dryRun = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node scripts/release/stage_linux.mjs [options]

Options:
  --target <triple>    x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu
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
    throw new Error(`Unsupported Linux target: ${opts.target}`);
  }
  return opts;
}

function resolveReleaseDir(targetDir, target) {
  const targetRelease = path.join(targetDir, target, "release");
  if (fs.existsSync(targetRelease)) return targetRelease;
  return path.join(targetDir, "release");
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  const { cliArch } = ARCH_MAP[opts.target];
  const releaseDir = resolveReleaseDir(opts.targetDir, opts.target);
  const bundleDir = path.join(releaseDir, "bundle");

  const planned = {
    appImage: `CatCloud-${opts.version}-linux-${cliArch}.AppImage`,
    appImageTarGz: `CatCloud-${opts.version}-linux-${cliArch}.AppImage.tar.gz`,
    deb: `CatCloud-${opts.version}-linux-${cliArch}.deb`,
    rpm: `CatCloud-${opts.version}-linux-${cliArch}.rpm`,
    cliTarGz: `catcloud-linux-${cliArch}.tar.gz`,
  };

  if (opts.dryRun) {
    console.log(
      JSON.stringify({ dry_run: true, target: opts.target, release_dir: releaseDir, planned }, null, 2)
    );
    return;
  }

  fs.mkdirSync(opts.outDir, { recursive: true });
  const staged = [];

  // 1. AppImage (+ optional updater `.AppImage.tar.gz` & `.sig`)
  const appImageDir = path.join(bundleDir, "appimage");
  const appImageSrc = findSingleEntry(appImageDir, (n) => n.endsWith(".AppImage"));
  if (!appImageSrc) {
    throw new Error(`AppImage not found under ${appImageDir}`);
  }
  const destAppImage = path.join(opts.outDir, planned.appImage);
  copyWithOptionalSig(appImageSrc, destAppImage, staged);
  if (process.platform !== "win32") {
    fs.chmodSync(destAppImage, 0o755);
  }

  const appImageTarSrc = findSingleEntry(appImageDir, (n) => n.endsWith(".AppImage.tar.gz"));
  if (appImageTarSrc) {
    copyWithOptionalSig(appImageTarSrc, path.join(opts.outDir, planned.appImageTarGz), staged);
  }

  // 2. Debian package (.deb)
  const debSrc = findSingleEntry(path.join(bundleDir, "deb"), (n) => n.endsWith(".deb"));
  if (!debSrc) {
    throw new Error(`DEB package not found under ${path.join(bundleDir, "deb")}`);
  }
  fs.copyFileSync(debSrc, path.join(opts.outDir, planned.deb));
  staged.push(planned.deb);

  // 3. RPM package (.rpm)
  const rpmSrc = findSingleEntry(path.join(bundleDir, "rpm"), (n) => n.endsWith(".rpm"));
  if (!rpmSrc) {
    throw new Error(`RPM package not found under ${path.join(bundleDir, "rpm")}`);
  }
  fs.copyFileSync(rpmSrc, path.join(opts.outDir, planned.rpm));
  staged.push(planned.rpm);

  // 4. Headless CLI tarball
  const cliBin = path.join(releaseDir, "catcloud");
  if (!fs.existsSync(cliBin)) {
    throw new Error(`Headless CLI binary not found: ${cliBin}`);
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "catcloud-cli-linux-"));
  try {
    const cliDest = path.join(tmpDir, "catcloud");
    fs.copyFileSync(cliBin, cliDest);
    if (process.platform !== "win32") {
      fs.chmodSync(cliDest, 0o755);
    }
    const items = ["catcloud"];
    const licensePath = path.join(ROOT, "LICENSE");
    if (fs.existsSync(licensePath)) {
      fs.copyFileSync(licensePath, path.join(tmpDir, "LICENSE"));
      items.push("LICENSE");
    }
    execFileSync("tar", ["-czf", path.join(opts.outDir, planned.cliTarGz), ...items], {
      cwd: tmpDir,
      stdio: "inherit",
    });
    staged.push(planned.cliTarGz);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  console.log(`[stage_linux] Staged ${staged.length} files into ${opts.outDir}:`);
  for (const name of staged) {
    console.log(`  - ${name}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`[stage_linux] ERROR: ${err.message}`);
    process.exit(1);
  }
}
