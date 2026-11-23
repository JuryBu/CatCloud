#!/usr/bin/env node
/**
 * Fetch, verify (SHA-256), and extract the official MetaCubeX/mihomo binary
 * into `src-tauri/resources/bin/mihomo(.exe)` for a given Rust target triple.
 *
 * Zero external npm dependencies (Node.js 20+ ESM).
 * Security guarantees:
 *   - Official GitHub HTTPS host allowlist validated on every redirect hop (max 5 hops)
 *   - Mandatory SHA-256 verification against `--sha256`, pinned checksums, or official `checksums.txt`
 *   - Bounded archive & extracted payload size caps, Zip-Slip path checks, atomic file placement
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");

export const DEFAULT_MIHOMO_VERSION = "v1.19.16";
export const MIHOMO_REPO = "MetaCubeX/mihomo";

const ALLOWED_HOSTS = new Set([
  "github.com",
  "api.github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
  "raw.githubusercontent.com",
]);

const MAX_REDIRECT_HOPS = 5;
const MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_EXTRACTED_BYTES = 128 * 1024 * 1024;
const MAX_CHECKSUMS_BYTES = 512 * 1024;
const MAX_RELEASE_META_BYTES = 4 * 1024 * 1024;

/**
 * Official verified SHA-256 digests for pinned MetaCubeX/mihomo releases
 * (sourced from GitHub Releases API `assets[].digest`, because MetaCubeX/mihomo
 * does not ship a `checksums.txt` asset).
 */
export const PINNED_MIHOMO_SHA256 = {
  "v1.19.16": {
    "mihomo-windows-amd64-compatible-v1.19.16.zip":
      "dba602f921c9b39cc7ee24ccc0191a4806b03ceb1644b1c5c2a31408687fdaa2",
    "mihomo-windows-arm64-v1.19.16.zip":
      "0cfb5d5ffd37fe54e1741b533d247703aa389610fa0b57675c6d42d7944176fa",
    "mihomo-darwin-arm64-v1.19.16.gz":
      "3cf103abd22495520979b51b9f09b8087ae56eb03722c93b9a2bbb6296f21038",
    "mihomo-darwin-amd64-compatible-v1.19.16.gz":
      "e9a125d8d164b68953e3d95bc91d42cbab47cabaabd82ccadee49241ed9224ea",
    "mihomo-linux-amd64-compatible-v1.19.16.gz":
      "3393345527c6628f47c295e2f1dfd182454800f964f3211f606d3aab0fdfc5a9",
    "mihomo-linux-arm64-v1.19.16.gz":
      "6d3763071003188dd2262b1220789996e56bd63ea4ad5564b31a486e880b7aa8",
  },
};

/**
 * Target triple -> official MetaCubeX/mihomo asset candidate naming order.
 * Prefers `-compatible` (GOAMD64=v1) for broad CPU compatibility on x86_64.
 */
const TARGET_SPECS = {
  "x86_64-pc-windows-msvc": {
    binaryName: "mihomo.exe",
    format: "zip",
    candidates: (v) => [
      `mihomo-windows-amd64-compatible-${v}.zip`,
      `mihomo-windows-amd64-v1-${v}.zip`,
      `mihomo-windows-amd64-${v}.zip`,
    ],
  },
  "aarch64-pc-windows-msvc": {
    binaryName: "mihomo.exe",
    format: "zip",
    candidates: (v) => [`mihomo-windows-arm64-${v}.zip`],
  },
  "aarch64-apple-darwin": {
    binaryName: "mihomo",
    format: "gz",
    candidates: (v) => [`mihomo-darwin-arm64-${v}.gz`],
  },
  "x86_64-apple-darwin": {
    binaryName: "mihomo",
    format: "gz",
    candidates: (v) => [
      `mihomo-darwin-amd64-compatible-${v}.gz`,
      `mihomo-darwin-amd64-v1-${v}.gz`,
      `mihomo-darwin-amd64-${v}.gz`,
    ],
  },
  "x86_64-unknown-linux-gnu": {
    binaryName: "mihomo",
    format: "gz",
    candidates: (v) => [
      `mihomo-linux-amd64-compatible-${v}.gz`,
      `mihomo-linux-amd64-v1-${v}.gz`,
      `mihomo-linux-amd64-${v}.gz`,
    ],
  },
  "aarch64-unknown-linux-gnu": {
    binaryName: "mihomo",
    format: "gz",
    candidates: (v) => [`mihomo-linux-arm64-${v}.gz`],
  },
};

function detectHostTarget() {
  const { platform, arch } = process;
  if (platform === "win32") {
    return arch === "arm64" ? "aarch64-pc-windows-msvc" : "x86_64-pc-windows-msvc";
  }
  if (platform === "darwin") {
    return arch === "arm64" ? "aarch64-apple-darwin" : "x86_64-apple-darwin";
  }
  if (platform === "linux") {
    return arch === "arm64" ? "aarch64-unknown-linux-gnu" : "x86_64-unknown-linux-gnu";
  }
  throw new Error(`Unsupported host platform/arch: ${platform}/${arch}`);
}

function parseArgs(argv) {
  const opts = {
    target: detectHostTarget(),
    version: process.env.MIHOMO_VERSION || DEFAULT_MIHOMO_VERSION,
    outDir: path.join(ROOT, "src-tauri", "resources", "bin"),
    sha256: null,
    dryRun: false,
    verifyLocal: false,
    force: false,
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
        const val = argv[++i].trim();
        if (val) opts.version = val;
      }
    } else if (arg === "--out-dir") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim();
        if (val) opts.outDir = path.resolve(val);
      }
    } else if (arg === "--sha256") {
      if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
        const val = argv[++i].trim().toLowerCase();
        opts.sha256 = val || null;
      }
    } else if (arg === "--dry-run") {
      opts.dryRun = true;
    } else if (arg === "--verify-local") {
      opts.verifyLocal = true;
    } else if (arg === "--force") {
      opts.force = true;
    } else if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  if (!opts.version.startsWith("v")) {
    opts.version = `v${opts.version}`;
  }
  if (!/^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(opts.version)) {
    throw new Error(`Invalid Mihomo version format: ${opts.version}`);
  }
  if (opts.sha256 && !/^[0-9a-f]{64}$/.test(opts.sha256)) {
    throw new Error(`Invalid --sha256 digest (expected 64 lowercase hex chars): ${opts.sha256}`);
  }
  if (!TARGET_SPECS[opts.target]) {
    throw new Error(
      `Unsupported target '${opts.target}'. Supported: ${Object.keys(TARGET_SPECS).join(", ")}`
    );
  }
  return opts;
}

function printUsage() {
  console.log(`Usage: node scripts/release/fetch_mihomo.mjs [options]

Options:
  --target <triple>    Rust target triple (default: host auto-detect)
  --version <vX.Y.Z>   Official MetaCubeX/mihomo release tag (default: ${DEFAULT_MIHOMO_VERSION})
  --out-dir <path>     Output directory (default: src-tauri/resources/bin)
  --sha256 <hex>       Optional explicit expected SHA-256 of the compressed archive
  --verify-local       Verify existing local binary against mihomo.meta.json without downloading
  --dry-run            Print resolved release URLs and verification plan without writing files
  --force              Re-download even when matching verified binary already exists
`);
}

function validateAllowedHttpsUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== "https:") {
    throw new Error(`Blocked non-HTTPS URL: ${rawUrl}`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`Blocked URL containing credentials: ${rawUrl}`);
  }
  if (parsed.port && parsed.port !== "443") {
    throw new Error(`Blocked non-443 port in URL: ${rawUrl}`);
  }
  const host = parsed.hostname.toLowerCase();
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error(`Blocked unauthorized host '${host}' in URL: ${rawUrl}`);
  }
  return parsed;
}

async function fetchAllowlistedBuffer(startUrl, maxBytes, acceptHeader = "*/*") {
  let currentUrl = startUrl;
  const baseHeaders = {
    "User-Agent": "CatCloud-Release-CI/0.1.0",
    Accept: acceptHeader,
  };
  if (process.env.GITHUB_TOKEN) {
    baseHeaders.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  }

  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    const parsed = validateAllowedHttpsUrl(currentUrl);
    // Forward GitHub token only to github.com / api.github.com, never to CDN object hosts.
    const headers = { ...baseHeaders };
    if (parsed.hostname !== "github.com" && parsed.hostname !== "api.github.com") {
      delete headers.Authorization;
    }

    const res = await fetch(currentUrl, {
      method: "GET",
      headers,
      redirect: "manual",
      signal: AbortSignal.timeout(60_000),
    });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) {
        throw new Error(`HTTP ${res.status} redirect missing Location header for ${currentUrl}`);
      }
      if (hop === MAX_REDIRECT_HOPS) {
        throw new Error(`Exceeded maximum redirect hops (${MAX_REDIRECT_HOPS}) for ${startUrl}`);
      }
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText} fetching ${currentUrl}`);
    }

    const contentLength = Number(res.headers.get("content-length") || "0");
    if (contentLength > maxBytes) {
      throw new Error(`Remote payload (${contentLength} bytes) exceeds limit (${maxBytes} bytes)`);
    }

    const chunks = [];
    let total = 0;
    for await (const chunk of res.body) {
      total += chunk.length;
      if (total > maxBytes) {
        throw new Error(`Download stream exceeded hard cap of ${maxBytes} bytes`);
      }
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks, total);
  }
  throw new Error(`Failed to resolve ${startUrl}`);
}

function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function verifySha256ConstantTime(actualHex, expectedHex, label) {
  const a = Buffer.from(actualHex.toLowerCase(), "utf8");
  const e = Buffer.from(expectedHex.toLowerCase(), "utf8");
  if (a.length !== e.length || !crypto.timingSafeEqual(a, e)) {
    throw new Error(`SHA-256 mismatch for ${label}: expected ${expectedHex}, got ${actualHex}`);
  }
}

/**
 * Parse official MetaCubeX/mihomo `checksums.txt` lines (`<64-hex>  <filename>`).
 */
export function parseChecksumsTxt(text) {
  const map = new Map();
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const match = /^([0-9a-fA-F]{64})\s+\*?(.+)$/.exec(line);
    if (!match) continue;
    const hash = match[1].toLowerCase();
    const filename = path.posix.basename(match[2].trim().replace(/\\/g, "/"));
    map.set(filename, hash);
  }
  return map;
}

/**
 * Minimal, zero-dependency ZIP single-executable extractor using Node `zlib.inflateRawSync`.
 * Validates Zip-Slip paths, rejects symlinks, and enforces `MAX_EXTRACTED_BYTES`.
 */
function extractBinaryFromZip(zipBuf, expectedExt) {
  // Locate End of Central Directory (EOCD) signature 0x06054b50 from tail.
  const minEocd = 22;
  const searchStart = Math.max(0, zipBuf.length - 65557);
  let eocdOffset = -1;
  for (let i = zipBuf.length - minEocd; i >= searchStart; i--) {
    if (zipBuf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset < 0) {
    throw new Error("Invalid ZIP archive: EOCD signature not found");
  }

  const totalEntries = zipBuf.readUInt16LE(eocdOffset + 10);
  const cdOffset = zipBuf.readUInt32LE(eocdOffset + 16);
  let cursor = cdOffset;

  for (let idx = 0; idx < totalEntries; idx++) {
    if (cursor + 46 > zipBuf.length || zipBuf.readUInt32LE(cursor) !== 0x02014b50) {
      throw new Error(`Invalid ZIP Central Directory header at entry ${idx}`);
    }
    const compressionMethod = zipBuf.readUInt16LE(cursor + 10);
    const compressedSize = zipBuf.readUInt32LE(cursor + 20);
    const uncompressedSize = zipBuf.readUInt32LE(cursor + 24);
    const nameLen = zipBuf.readUInt16LE(cursor + 28);
    const extraLen = zipBuf.readUInt16LE(cursor + 30);
    const commentLen = zipBuf.readUInt16LE(cursor + 32);
    const externalAttr = zipBuf.readUInt32LE(cursor + 38);
    const localHeaderOffset = zipBuf.readUInt32LE(cursor + 42);

    const name = zipBuf.subarray(cursor + 46, cursor + 46 + nameLen).toString("utf8");
    cursor += 46 + nameLen + extraLen + commentLen;

    // Reject control characters, Windows drive/ADS colons, path traversal, and POSIX symlinks.
    if (/[\x00-\x1f\x7f]/.test(name) || name.includes(":")) {
      throw new Error(`Blocked unsafe ZIP entry path: ${name}`);
    }
    const normalized = name.replace(/\\/g, "/");
    if (normalized.startsWith("/") || normalized.split("/").includes("..")) {
      throw new Error(`Blocked unsafe ZIP entry path: ${name}`);
    }
    const unixMode = (externalAttr >>> 16) & 0o170000;
    if (unixMode === 0o120000) {
      throw new Error(`Blocked symlink inside ZIP archive: ${name}`);
    }
    if (normalized.endsWith("/")) continue;

    const base = path.posix.basename(normalized).toLowerCase();
    const isMatch = expectedExt
      ? base.endsWith(expectedExt) && base.includes("mihomo")
      : base.includes("mihomo");
    if (!isMatch) continue;

    if (uncompressedSize > MAX_EXTRACTED_BYTES) {
      throw new Error(`ZIP entry '${name}' declared size ${uncompressedSize} exceeds cap`);
    }
    if (
      localHeaderOffset + 30 > zipBuf.length ||
      zipBuf.readUInt32LE(localHeaderOffset) !== 0x04034b50
    ) {
      throw new Error(`Corrupt ZIP local file header for '${name}'`);
    }

    const localNameLen = zipBuf.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = zipBuf.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + localNameLen + localExtraLen;
    const dataEnd = dataStart + compressedSize;
    if (dataEnd > zipBuf.length) {
      throw new Error(`Truncated ZIP payload for '${name}'`);
    }

    const rawSlice = zipBuf.subarray(dataStart, dataEnd);
    let outBuf;
    if (compressionMethod === 0) {
      outBuf = Buffer.from(rawSlice);
    } else if (compressionMethod === 8) {
      outBuf = zlib.inflateRawSync(rawSlice, { maxOutputLength: MAX_EXTRACTED_BYTES });
    } else {
      throw new Error(`Unsupported ZIP compression method ${compressionMethod} for '${name}'`);
    }
    if (outBuf.length !== uncompressedSize) {
      throw new Error(`Uncompressed size mismatch for '${name}'`);
    }
    return { entryName: name, buffer: outBuf };
  }

  throw new Error(`No matching Mihomo binary (${expectedExt || "any"}) found inside ZIP archive`);
}

function atomicWriteFile(destPath, buffer, executable) {
  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  const tmpPath = `${destPath}.tmp.${process.pid}`;
  let renamed = false;
  try {
    fs.writeFileSync(tmpPath, buffer);
    if (executable && process.platform !== "win32") {
      fs.chmodSync(tmpPath, 0o755);
    }
    fs.renameSync(tmpPath, destPath);
    renamed = true;
  } catch (err) {
    throw err;
  } finally {
    if (!renamed) {
      try {
        fs.rmSync(tmpPath, { force: true });
      } catch {
        // Ignore cleanup errors while propagating the original write/rename failure.
      }
    }
  }
}

function verifyLocalBinary(outDir, spec, opts) {
  const binPath = path.join(outDir, spec.binaryName);
  const metaPath = path.join(outDir, "mihomo.meta.json");
  if (!fs.existsSync(binPath)) {
    throw new Error(`Local Mihomo binary missing: ${binPath}`);
  }
  const actualBinHash = sha256Hex(fs.readFileSync(binPath));
  if (!fs.existsSync(metaPath)) {
    console.log(
      JSON.stringify(
        {
          ok: true,
          verified_meta: false,
          path: binPath,
          binary_sha256: actualBinHash,
        },
        null,
        2
      )
    );
    return true;
  }
  const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
  if (meta.target !== opts.target || meta.version !== opts.version) {
    throw new Error(
      `Local binary mismatch: found ${meta.version} (${meta.target}), expected ${opts.version} (${opts.target})`
    );
  }
  verifySha256ConstantTime(actualBinHash, meta.binary_sha256, binPath);
  console.log(
    JSON.stringify(
      {
        ok: true,
        verified_meta: true,
        path: binPath,
        version: meta.version,
        target: meta.target,
        asset: meta.asset,
        binary_sha256: actualBinHash,
      },
      null,
      2
    )
  );
  return true;
}

/**
 * Fetch official asset SHA-256 checksums for a MetaCubeX/mihomo release tag via
 * GitHub Releases API `assets[].digest` (plus `checksums.txt` if present).
 */
async function fetchOfficialReleaseChecksums(version, baseDownloadUrl) {
  const apiUrl = `https://api.github.com/repos/${MIHOMO_REPO}/releases/tags/${encodeURIComponent(version)}`;
  console.log(`[fetch_mihomo] Querying GitHub release metadata from ${apiUrl}`);
  const rawBuf = await fetchAllowlistedBuffer(
    apiUrl,
    MAX_RELEASE_META_BYTES,
    "application/vnd.github+json"
  );
  const release = JSON.parse(rawBuf.toString("utf8"));
  const assets = Array.isArray(release?.assets) ? release.assets : [];
  const checksumMap = new Map();
  let hasChecksumsTxt = false;

  for (const asset of assets) {
    const name = typeof asset?.name === "string" ? asset.name.trim() : "";
    if (!name) continue;
    if (name === "checksums.txt") {
      hasChecksumsTxt = true;
    }
    const digest = typeof asset?.digest === "string" ? asset.digest.trim() : "";
    const match = digest.match(/^sha256:([a-fA-F0-9]{64})$/);
    if (match) {
      checksumMap.set(name, match[1].toLowerCase());
    }
  }

  if (hasChecksumsTxt) {
    const checksumsUrl = `${baseDownloadUrl}/checksums.txt`;
    console.log(`[fetch_mihomo] Supplementing checksums from ${checksumsUrl}`);
    const checksumsBuf = await fetchAllowlistedBuffer(checksumsUrl, MAX_CHECKSUMS_BYTES);
    for (const [name, hash] of parseChecksumsTxt(checksumsBuf.toString("utf8"))) {
      if (!checksumMap.has(name)) {
        checksumMap.set(name, hash);
      }
    }
  }

  return { checksumMap, apiUrl };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const spec = TARGET_SPECS[opts.target];
  const destBinPath = path.join(opts.outDir, spec.binaryName);
  const destMetaPath = path.join(opts.outDir, "mihomo.meta.json");
  const candidates = spec.candidates(opts.version);
  const baseDownloadUrl = `https://github.com/${MIHOMO_REPO}/releases/download/${opts.version}`;
  const releaseApiUrl = `https://api.github.com/repos/${MIHOMO_REPO}/releases/tags/${encodeURIComponent(opts.version)}`;
  const pinnedForVersion = PINNED_MIHOMO_SHA256[opts.version] || null;

  if (opts.verifyLocal) {
    verifyLocalBinary(opts.outDir, spec, opts);
    return;
  }

  if (opts.dryRun) {
    const pinnedCandidate = pinnedForVersion
      ? candidates.find((c) => Object.prototype.hasOwnProperty.call(pinnedForVersion, c)) || null
      : null;
    console.log(
      JSON.stringify(
        {
          dry_run: true,
          repo: MIHOMO_REPO,
          version: opts.version,
          target: opts.target,
          output_binary: destBinPath,
          release_api_url: releaseApiUrl,
          pinned_asset: pinnedCandidate,
          pinned_sha256: pinnedCandidate ? pinnedForVersion[pinnedCandidate] : null,
          candidate_assets: candidates.map((c) => `${baseDownloadUrl}/${c}`),
          explicit_sha256: opts.sha256,
        },
        null,
        2
      )
    );
    return;
  }

  // Reuse already-verified local binary when version & target match unless --force is passed.
  if (!opts.force && fs.existsSync(destBinPath) && fs.existsSync(destMetaPath)) {
    try {
      const meta = JSON.parse(fs.readFileSync(destMetaPath, "utf8"));
      if (meta.version === opts.version && meta.target === opts.target && meta.binary_sha256) {
        const existingHash = sha256Hex(fs.readFileSync(destBinPath));
        verifySha256ConstantTime(existingHash, meta.binary_sha256, destBinPath);
        if (!opts.sha256 || meta.archive_sha256 === opts.sha256) {
          console.log(
            `[fetch_mihomo] Reusing verified local ${spec.binaryName} (${opts.version}, ${opts.target})`
          );
          return;
        }
      }
    } catch {
      // Fall through to clean re-download.
    }
  }

  let selectedAsset = null;
  let expectedArchiveSha256 = opts.sha256;
  let checksumSource = "explicit";

  if (pinnedForVersion) {
    for (const candidate of candidates) {
      if (Object.prototype.hasOwnProperty.call(pinnedForVersion, candidate)) {
        const pinnedHash = pinnedForVersion[candidate].toLowerCase();
        if (expectedArchiveSha256 && expectedArchiveSha256 !== pinnedHash) {
          throw new Error(
            `Explicit --sha256 (${expectedArchiveSha256}) conflicts with pinned official SHA-256 (${pinnedHash}) for ${candidate}`
          );
        }
        selectedAsset = candidate;
        expectedArchiveSha256 = pinnedHash;
        checksumSource = "pinned_table";
        break;
      }
    }
  }

  if (!selectedAsset || !expectedArchiveSha256) {
    const { checksumMap, apiUrl } = await fetchOfficialReleaseChecksums(
      opts.version,
      baseDownloadUrl
    );
    for (const candidate of candidates) {
      if (checksumMap.has(candidate)) {
        selectedAsset = candidate;
        const officialHash = checksumMap.get(candidate);
        if (expectedArchiveSha256 && expectedArchiveSha256 !== officialHash) {
          throw new Error(
            `Explicit --sha256 (${expectedArchiveSha256}) conflicts with official GitHub release digest (${officialHash}) for ${candidate}`
          );
        }
        expectedArchiveSha256 = officialHash;
        checksumSource = "github_release_api";
        break;
      }
    }

    if (!selectedAsset || !expectedArchiveSha256) {
      throw new Error(
        `Could not verify an official SHA-256 digest for any expected asset (${candidates.join(", ")}) from ${apiUrl}`
      );
    }
  }

  console.log(
    `[fetch_mihomo] Selected ${selectedAsset} (checksum source: ${checksumSource})`
  );

  const assetUrl = `${baseDownloadUrl}/${selectedAsset}`;
  console.log(`[fetch_mihomo] Downloading ${assetUrl}`);
  const archiveBuf = await fetchAllowlistedBuffer(assetUrl, MAX_ARCHIVE_BYTES);
  const actualArchiveSha256 = sha256Hex(archiveBuf);
  verifySha256ConstantTime(actualArchiveSha256, expectedArchiveSha256, selectedAsset);
  console.log(`[fetch_mihomo] Verified archive SHA-256: ${actualArchiveSha256}`);

  let binaryBuf;
  if (spec.format === "gz") {
    binaryBuf = zlib.gunzipSync(archiveBuf, { maxOutputLength: MAX_EXTRACTED_BYTES });
  } else if (spec.format === "zip") {
    const extracted = extractBinaryFromZip(archiveBuf, ".exe");
    binaryBuf = extracted.buffer;
  } else {
    throw new Error(`Unsupported archive format: ${spec.format}`);
  }

  if (!binaryBuf || binaryBuf.length < 1024 * 1024) {
    throw new Error(
      `Extracted Mihomo binary looks unexpectedly small (${binaryBuf?.length || 0} bytes)`
    );
  }

  const binarySha256 = sha256Hex(binaryBuf);
  atomicWriteFile(destBinPath, binaryBuf, true);

  const meta = {
    repo: MIHOMO_REPO,
    version: opts.version,
    target: opts.target,
    asset: selectedAsset,
    archive_sha256: actualArchiveSha256,
    binary_name: spec.binaryName,
    binary_sha256: binarySha256,
    binary_bytes: binaryBuf.length,
    fetched_at: new Date().toISOString(),
  };
  atomicWriteFile(destMetaPath, Buffer.from(`${JSON.stringify(meta, null, 2)}\n`, "utf8"), false);
  console.log(
    `[fetch_mihomo] Staged ${destBinPath} (${(binaryBuf.length / (1024 * 1024)).toFixed(2)} MiB, sha256=${binarySha256})`
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(`[fetch_mihomo] ERROR: ${err.message}`);
    process.exit(1);
  });
}
