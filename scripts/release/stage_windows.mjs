#!/usr/bin/env node
/**
 * Stage Windows release artifacts into unified `release-assets/`:
 *   - MSI installer (+ optional `.sig`)
 *   - NSIS setup installer (+ optional `.sig`)
 *   - Portable ZIP bundle (with `portable.flag`, `resources/bin/mihomo.exe`, `version.json`)
 *   - Headless `catcloud` CLI ZIP archive
 *
 * Zero external npm dependencies (Node.js 20+ ESM, includes built-in RFC 1951 Deflate ZIP writer).
 */

import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");

const ARCH_MAP = {
  "x86_64-pc-windows-msvc": { shortArch: "x64", cliArch: "x86_64" },
  "aarch64-pc-windows-msvc": { shortArch: "arm64", cliArch: "aarch64" },
};

// Standard IEEE 802.3 CRC-32 lookup table for deterministic ZIP creation.
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const year = Math.max(1980, date.getUTCFullYear());
  const dosTime =
    ((date.getUTCHours() & 0x1f) << 11) |
    ((date.getUTCMinutes() & 0x3f) << 5) |
    ((date.getUTCSeconds() >> 1) & 0x1f);
  const dosDate =
    (((year - 1980) & 0x7f) << 9) |
    (((date.getUTCMonth() + 1) & 0x0f) << 5) |
    (date.getUTCDate() & 0x1f);
  return { dosTime, dosDate };
}

/**
 * Create a compliant, POSIX-path ZIP archive using Node `zlib.deflateRawSync`.
 * Guarantees zero backslashes, zero symlinks, and compatibility with CatCloud's Rust updater.
 * @param {Array<{ name: string, data: Buffer }>} entries
 */
export function buildZipBuffer(entries) {
  const now = new Date();
  const { dosTime, dosDate } = dosDateTime(now);
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  for (const entry of entries) {
    const posixName = entry.name.replace(/\\/g, "/").replace(/^\/+/, "");
    if (!posixName || posixName.split("/").includes("..")) {
      throw new Error(`Unsafe ZIP entry name: ${entry.name}`);
    }
    const nameBuf = Buffer.from(posixName, "utf8");
    const raw = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data);
    const deflated = zlib.deflateRawSync(raw, { level: 9 });
    const useDeflate = deflated.length < raw.length;
    const payload = useDeflate ? deflated : raw;
    const method = useDeflate ? 8 : 0;
    const checksum = crc32(raw);

    // Local file header (30 bytes + filename)
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4); // version needed: 2.0
    lfh.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
    lfh.writeUInt16LE(method, 8);
    lfh.writeUInt16LE(dosTime, 10);
    lfh.writeUInt16LE(dosDate, 12);
    lfh.writeUInt32LE(checksum, 14);
    lfh.writeUInt32LE(payload.length, 18);
    lfh.writeUInt32LE(raw.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);

    localParts.push(lfh, nameBuf, payload);

    // Central directory file header (46 bytes + filename)
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(0x0314, 4); // version made by: Unix / 2.0
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0x0800, 8);
    cdh.writeUInt16LE(method, 10);
    cdh.writeUInt16LE(dosTime, 12);
    cdh.writeUInt16LE(dosDate, 14);
    cdh.writeUInt32LE(checksum, 16);
    cdh.writeUInt32LE(payload.length, 20);
    cdh.writeUInt32LE(raw.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38); // regular file permissions
    cdh.writeUInt32LE(offset, 42);

    centralParts.push(cdh, nameBuf);
    offset += lfh.length + nameBuf.length + payload.length;
  }

  const centralBuf = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, centralBuf, eocd]);
}

function readDefaultVersion() {
  const conf = JSON.parse(fs.readFileSync(path.join(ROOT, "src-tauri", "tauri.conf.json"), "utf8"));
  return String(conf.version).replace(/^[vV]/, "");
}

function findSingleFile(dir, predicate) {
  if (!fs.existsSync(dir)) return null;
  const files = fs
    .readdirSync(dir)
    .filter((name) => predicate(name))
    .sort();
  return files.length > 0 ? path.join(dir, files[0]) : null;
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
    target: "x86_64-pc-windows-msvc",
    version: readDefaultVersion(),
    targetDir: path.join(ROOT, "target"),
    outDir: path.join(ROOT, "release-assets"),
    mihomoBin: path.join(ROOT, "src-tauri", "resources", "bin", "mihomo.exe"),
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
      console.log(`Usage: node scripts/release/stage_windows.mjs [options]

Options:
  --target <triple>    x86_64-pc-windows-msvc | aarch64-pc-windows-msvc
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
    throw new Error(`Unsupported Windows target: ${opts.target}`);
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
  const { shortArch, cliArch } = ARCH_MAP[opts.target];
  const releaseDir = resolveReleaseDir(opts.targetDir, opts.target);
  const bundleDir = path.join(releaseDir, "bundle");

  const planned = {
    msi: `CatCloud-${opts.version}-windows-${shortArch}.msi`,
    nsis: `CatCloud-${opts.version}-windows-${shortArch}-setup.exe`,
    portableZip: `CatCloud-${opts.version}-windows-${shortArch}-portable.zip`,
    cliZip: `catcloud-windows-${cliArch}.zip`,
  };

  if (opts.dryRun) {
    console.log(
      JSON.stringify({ dry_run: true, target: opts.target, release_dir: releaseDir, planned }, null, 2)
    );
    return;
  }

  fs.mkdirSync(opts.outDir, { recursive: true });
  const staged = [];

  // 1. MSI installer
  const msiSrc = findSingleFile(path.join(bundleDir, "msi"), (n) => n.toLowerCase().endsWith(".msi"));
  if (!msiSrc) {
    throw new Error(`MSI installer not found under ${path.join(bundleDir, "msi")}`);
  }
  copyWithOptionalSig(msiSrc, path.join(opts.outDir, planned.msi), staged);

  // 2. NSIS setup installer
  const nsisSrc = findSingleFile(path.join(bundleDir, "nsis"), (n) =>
    n.toLowerCase().endsWith(".exe")
  );
  if (!nsisSrc) {
    throw new Error(`NSIS installer not found under ${path.join(bundleDir, "nsis")}`);
  }
  copyWithOptionalSig(nsisSrc, path.join(opts.outDir, planned.nsis), staged);

  // 3. Portable ZIP archive (with top-level folder, portable.flag, mihomo.exe, and version.json)
  const exeCandidates = [
    path.join(releaseDir, "CatCloud.exe"),
    path.join(releaseDir, "catcloud-desktop.exe"),
  ];
  const desktopExe = exeCandidates.find((p) => fs.existsSync(p));
  if (!desktopExe) {
    throw new Error(`Desktop binary not found (checked: ${exeCandidates.join(", ")})`);
  }
  if (!fs.existsSync(opts.mihomoBin)) {
    throw new Error(`Bundled Mihomo binary missing: ${opts.mihomoBin}`);
  }

  let mihomoVersion = null;
  const mihomoMetaPath = path.join(path.dirname(opts.mihomoBin), "mihomo.meta.json");
  if (fs.existsSync(mihomoMetaPath)) {
    try {
      mihomoVersion = JSON.parse(fs.readFileSync(mihomoMetaPath, "utf8")).version || null;
    } catch {
      mihomoVersion = null;
    }
  }

  const portableRoot = `CatCloud-${opts.version}-windows-${shortArch}-portable`;
  const portableEntries = [
    { name: `${portableRoot}/CatCloud.exe`, data: fs.readFileSync(desktopExe) },
    {
      name: `${portableRoot}/portable.flag`,
      data: Buffer.from("CatCloud portable mode marker. User data is stored in ./data/\n", "utf8"),
    },
    {
      name: `${portableRoot}/resources/bin/mihomo.exe`,
      data: fs.readFileSync(opts.mihomoBin),
    },
    {
      name: `${portableRoot}/version.json`,
      data: Buffer.from(
        `${JSON.stringify(
          {
            version: opts.version,
            target: opts.target,
            arch: shortArch,
            edition: "portable",
            mihomo_version: mihomoVersion,
            built_at: new Date().toISOString(),
          },
          null,
          2
        )}\n`,
        "utf8"
      ),
    },
  ];

  const webview2Dll = path.join(releaseDir, "WebView2Loader.dll");
  if (fs.existsSync(webview2Dll)) {
    portableEntries.push({
      name: `${portableRoot}/WebView2Loader.dll`,
      data: fs.readFileSync(webview2Dll),
    });
  }

  const licensePath = path.join(ROOT, "LICENSE");
  if (fs.existsSync(licensePath)) {
    portableEntries.push({
      name: `${portableRoot}/LICENSE`,
      data: fs.readFileSync(licensePath),
    });
  }

  const portableZipBuf = buildZipBuffer(portableEntries);
  fs.writeFileSync(path.join(opts.outDir, planned.portableZip), portableZipBuf);
  staged.push(planned.portableZip);

  // 4. Headless CLI ZIP archive
  const cliBin = path.join(releaseDir, "catcloud.exe");
  if (!fs.existsSync(cliBin)) {
    throw new Error(`Headless CLI binary not found: ${cliBin}`);
  }
  const cliEntries = [{ name: "catcloud.exe", data: fs.readFileSync(cliBin) }];
  if (fs.existsSync(licensePath)) {
    cliEntries.push({ name: "LICENSE", data: fs.readFileSync(licensePath) });
  }
  fs.writeFileSync(path.join(opts.outDir, planned.cliZip), buildZipBuffer(cliEntries));
  staged.push(planned.cliZip);

  console.log(`[stage_windows] Staged ${staged.length} files into ${opts.outDir}:`);
  for (const name of staged) {
    console.log(`  - ${name}`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`[stage_windows] ERROR: ${err.message}`);
    process.exit(1);
  }
}
