#!/usr/bin/env node
/**
 * Extract release notes for a specific version from CHANGELOG.md.
 * Zero external npm dependencies (Node.js 20+ ESM).
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "..", "..");

function readDefaultVersion() {
  const tauriConfPath = path.join(ROOT, "src-tauri", "tauri.conf.json");
  if (fs.existsSync(tauriConfPath)) {
    const conf = JSON.parse(fs.readFileSync(tauriConfPath, "utf8"));
    if (conf.version) return String(conf.version);
  }
  const pkgPath = path.join(ROOT, "package.json");
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    if (pkg.version) return String(pkg.version);
  }
  throw new Error("Unable to determine default version from tauri.conf.json or package.json");
}

function normalizeVersion(raw) {
  const cleaned = String(raw || "").trim().replace(/^[vV]/, "");
  if (!cleaned) {
    throw new Error("Empty version string");
  }
  if (/^0\.0\.0(?:[-+].*)?$/.test(cleaned)) {
    throw new Error(`Version 0.0.0 is rejected: '${raw}'`);
  }
  return cleaned;
}

function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Extract the Markdown section matching `## [v?<version>]` (or `## v?<version>`).
 */
export function extractSection(markdown, version, { allowFallback = false } = {}) {
  const norm = normalizeVersion(version);
  const lines = markdown.split(/\r?\n/);
  const exactHeadingRe = new RegExp(
    `^##\\s+\\[?v?${escapeRegExp(norm)}\\]?(?:\\s+-\\s+(\\d{4}-\\d{2}-\\d{2}))?\\s*$`,
    "i"
  );
  const unreleasedHeadingRe = /^##\s+\[?Unreleased\]?\s*$/i;
  const anyH2Re = /^##\s+/;

  const findBlock = (re) => {
    let startIdx = -1;
    let date = null;
    for (let i = 0; i < lines.length; i++) {
      const m = re.exec(lines[i]);
      if (m) {
        startIdx = i + 1;
        date = m[1] || null;
        break;
      }
    }
    if (startIdx < 0) return null;
    let endIdx = lines.length;
    for (let i = startIdx; i < lines.length; i++) {
      if (anyH2Re.test(lines[i])) {
        endIdx = i;
        break;
      }
    }
    const body = lines.slice(startIdx, endIdx).join("\n").trim();
    return { date, body };
  };

  const defaultFallbackNotes = (ver) =>
    `- Maintenance updates and stability improvements for CatCloud v${ver}.`;

  let matched = findBlock(exactHeadingRe);
  let fallbackUsed = false;
  if ((!matched || !matched.body) && allowFallback) {
    const unreleased = findBlock(unreleasedHeadingRe);
    if (unreleased && unreleased.body) {
      matched = unreleased;
      fallbackUsed = true;
    } else {
      matched = {
        date: matched?.date || null,
        body: defaultFallbackNotes(norm),
      };
      fallbackUsed = true;
    }
  }
  if (!matched) {
    throw new Error(`Release notes section for version '${norm}' not found in changelog`);
  }
  if (!matched.body) {
    throw new Error(`Release notes section for version '${norm}' is empty`);
  }

  return {
    version: norm,
    tag: `v${norm}`,
    date: matched.date,
    fallback_used: fallbackUsed,
    notes: matched.body,
  };
}

function parseArgs(argv) {
  const opts = {
    version: null,
    changelog: path.join(ROOT, "CHANGELOG.md"),
    output: null,
    asJson: false,
    allowFallback: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--version" && argv[i + 1]) {
      opts.version = argv[++i];
    } else if (arg === "--changelog" && argv[i + 1]) {
      opts.changelog = path.resolve(argv[++i]);
    } else if (arg === "--output" && argv[i + 1]) {
      opts.output = path.resolve(argv[++i]);
    } else if (arg === "--json") {
      opts.asJson = true;
    } else if (arg === "--allow-fallback") {
      opts.allowFallback = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log(`Usage: node scripts/release/extract_release_notes.mjs [options]

Options:
  --version <X.Y.Z>    Target release version (default: from src-tauri/tauri.conf.json)
  --changelog <path>   Path to CHANGELOG.md (default: ./CHANGELOG.md)
  --output <path>      Optional output file path (default: stdout)
  --json               Emit structured JSON instead of raw Markdown
  --allow-fallback     Fall back to [Unreleased] section when exact version is absent
`);
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  if (!opts.version) {
    opts.version = readDefaultVersion();
  }
  return opts;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!fs.existsSync(opts.changelog)) {
    throw new Error(`Changelog file not found: ${opts.changelog}`);
  }
  const markdown = fs.readFileSync(opts.changelog, "utf8");
  const result = extractSection(markdown, opts.version, { allowFallback: opts.allowFallback });
  const rendered = opts.asJson ? `${JSON.stringify(result, null, 2)}\n` : `${result.notes}\n`;

  if (opts.output) {
    fs.mkdirSync(path.dirname(opts.output), { recursive: true });
    fs.writeFileSync(opts.output, rendered, "utf8");
    console.log(`[extract_release_notes] Wrote notes for v${result.version} -> ${opts.output}`);
  } else {
    process.stdout.write(rendered);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (err) {
    console.error(`[extract_release_notes] ERROR: ${err.message}`);
    process.exit(1);
  }
}
