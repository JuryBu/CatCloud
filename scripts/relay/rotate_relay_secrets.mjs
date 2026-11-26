#!/usr/bin/env node
/**
 * CatCloud Domestic Relay One-Click Secret Rotator
 *
 * Cross-platform zero-dependency Node.js ESM utility for rotating sing-box
 * domestic relay credentials (AnyTLS / Hysteria2 / Trojan / VLESS / TUIC)
 * over SSH after beta sharing or suspected exposure, with atomic remote
 * backup/validation/rollback and `mmrelay/v1` bundle generation.
 *
 * Security invariants:
 * - Zero hardcoded live hosts, keys, or secrets (RFC 5737 examples only).
 * - Fresh credentials are generated locally via Node CSPRNG and transmitted
 *   strictly over SSH stdin (never placed in SSH command-line arguments).
 * - Remote atomic replacement preserves original chmod/chown metadata, runs
 *   `sing-box check -c <tmp>` before replacing, and auto-executes rollback.sh
 *   if `systemctl restart` or `systemctl is-active` verification fails.
 * - Refuses to write `--out-file` inside any git repository unless the file
 *   name ends with `.mmrelay.json` (ignored by .gitignore), and writes 0o600.
 */

import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const MMRELAY_SCHEMA_V1 = "mmrelay/v1";
const MMRELAY_ROLE_DOMESTIC = "domestic_pre_accel";
const MMRELAY_URI_PREFIX = "mmrelay://v1/";
const DEFAULT_CONFIG_PATH = "/etc/catcloud-relay/config.json";
const DEFAULT_SERVICE_NAME = "catcloud-relay";
const DEFAULT_DRY_RUN_HOST = "203.0.113.10";
const DEFAULT_BACKUP_ROOT = "/etc/catcloud-relay/backups";

const SUPPORTED_PASSWORD_PROTOCOLS = new Set(["anytls", "hysteria2", "trojan"]);
const SUPPORTED_UUID_PROTOCOLS = new Set(["vless", "tuic"]);
const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SERVICE_NAME_RE = /^[A-Za-z0-9@._:-]+$/;
const EXPIRES_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const EXPIRES_RFC3339_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function printHelp() {
  const help = `CatCloud 国内中转一键密钥轮换与收回工具 (scripts/relay/rotate_relay_secrets.mjs)

用法:
  node scripts/relay/rotate_relay_secrets.mjs --host <IP/Host> [选项]
  node scripts/relay/rotate_relay_secrets.mjs --dry-run [选项]

核心连接与远端参数:
  --host <IP/Host>          目标国内云中转 IP 或主机名（真实模式必需；示例: 203.0.113.10）
  --user <ssh_user>         SSH 登录用户名（默认: root）
  --key <ssh_key_path>      SSH 私钥文件路径（可选，示例: <YOUR_SSH_KEY>）
  --port <ssh_port>         SSH 端口（默认: 22）
  --config <path>           远端 sing-box 配置文件路径（可重复传入多次，默认: /etc/catcloud-relay/config.json）
  --service <name>          需重启并验活的 systemd 服务名（可重复传入多次，默认: catcloud-relay）
  --sing-box-bin <path>     指定远端 sing-box 可执行文件路径（默认自动探测:
                            command -v sing-box || /opt/sing-box/sing-box || /usr/bin/sing-box）
  --use-sudo                远端文件读写、配置校验、替换与 systemctl 操作均通过 sudo -n 提权执行

生成的 mmrelay/v1 清单元数据:
  --name-prefix <label>     中转名称前缀（别名 --name，默认基于地区/主机自动生成）
  --provider <label>        云厂商标签（如 cloud-a / aliyun / tencent，默认: self-hosted）
  --region <label>          地域标签（如 CN-East / CN-South，默认: CN）
  --expires <YYYY-MM-DD>    可选到期日期（支持 YYYY-MM-DD 或 RFC3339）

安全演练与输出控制:
  --dry-run                 纯本地离线演练模式（绝不发起 SSH；使用内置 AnyTLS + Hysteria2 + VLESS
                            样例配置跑完完整轮换、强断言、备份/回退脚本生成与 mmrelay/v1 自检）
  --out-file <path>         导出全新 mmrelay/v1 JSON 文件（设 0o600 权限；若位于 git 仓库内，
                            文件名必须以 .mmrelay.json 结尾，否则强制报错拦截）
  --print-uri               在终端输出完整明文 mmrelay://v1/... 导入码（默认仅输出脱敏摘要）
  -h, --help                显示本帮助信息并退出

示例:
  # 1. 纯本地离线演练（不连接任何服务器）
  node scripts/relay/rotate_relay_secrets.mjs --dry-run

  # 2. 轮换现役国内云密钥并安全落盘 .mmrelay.json（默认终端脱敏）
  node scripts/relay/rotate_relay_secrets.mjs \\
    --host 203.0.113.10 --user root --key <YOUR_SSH_KEY> \\
    --provider cloud-a --region CN-East --name-prefix "CN-East-443" \\
    --expires 2027-08-12 --out-file ./cn-east.mmrelay.json

  # 3. 多配置/多服务/非 root sudo 场景并打印完整导入码
  node scripts/relay/rotate_relay_secrets.mjs \\
    --host 198.51.100.12 --user ubuntu --key <YOUR_SSH_KEY> --use-sudo \\
    --config /etc/catcloud-relay/config.json --config /etc/catcloud-relay/vless.json \\
    --service catcloud-relay --service catcloud-vless --print-uri
`;
  process.stdout.write(help);
}

function fail(message, exitCode = 1) {
  process.stderr.write(`[ERROR] ${message}\n`);
  process.exit(exitCode);
}

function parseCliArgs(argv) {
  const opts = {
    host: "",
    user: "root",
    key: "",
    port: 22,
    configs: [],
    services: [],
    singBoxBin: "",
    namePrefix: "",
    provider: "self-hosted",
    region: "CN",
    expires: "",
    useSudo: false,
    dryRun: false,
    outFile: "",
    printUri: false,
    help: false,
  };

  const valueFlags = new Set([
    "--host",
    "--user",
    "--key",
    "--port",
    "--config",
    "--service",
    "--sing-box-bin",
    "--name-prefix",
    "--name",
    "--provider",
    "--region",
    "--expires",
    "--out-file",
  ]);

  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    if (raw === "-h" || raw === "--help") {
      opts.help = true;
      continue;
    }
    if (raw === "--use-sudo") {
      opts.useSudo = true;
      continue;
    }
    if (raw === "--dry-run") {
      opts.dryRun = true;
      continue;
    }
    if (raw === "--print-uri") {
      opts.printUri = true;
      continue;
    }

    let flag = raw;
    let inlineVal = null;
    const eqIdx = raw.indexOf("=");
    if (raw.startsWith("--") && eqIdx > 2) {
      flag = raw.slice(0, eqIdx);
      inlineVal = raw.slice(eqIdx + 1);
    }

    if (!valueFlags.has(flag)) {
      fail(`未知参数: ${raw}（请运行 --help 查看支持的参数）`, 2);
    }

    let val;
    if (inlineVal !== null) {
      val = inlineVal;
    } else {
      if (i + 1 >= argv.length) {
        fail(`参数 ${flag} 缺少必需的值`, 2);
      }
      val = argv[++i];
    }

    if (typeof val !== "string" || val.includes("\0") || val.includes("\n") || val.includes("\r")) {
      fail(`参数 ${flag} 包含非法控制字符`, 2);
    }

    switch (flag) {
      case "--host":
        opts.host = val.trim();
        break;
      case "--user":
        opts.user = val.trim();
        break;
      case "--key":
        opts.key = val.trim();
        break;
      case "--port": {
        if (!/^\d+$/.test(val.trim())) {
          fail(`--port 必须是 1..65535 的整数，实际收到: ${val}`, 2);
        }
        const portNum = Number.parseInt(val.trim(), 10);
        if (portNum < 1 || portNum > 65535) {
          fail(`--port 必须在 1..65535 之间，实际收到: ${val}`, 2);
        }
        opts.port = portNum;
        break;
      }
      case "--config": {
        const trimmed = val.trim();
        if (!trimmed) {
          fail("--config 不能为空路径", 2);
        }
        if (!opts.configs.includes(trimmed)) {
          opts.configs.push(trimmed);
        }
        break;
      }
      case "--service": {
        const trimmed = val.trim();
        if (!trimmed || !SERVICE_NAME_RE.test(trimmed)) {
          fail(`--service 包含非法服务名字符: ${val}`, 2);
        }
        if (!opts.services.includes(trimmed)) {
          opts.services.push(trimmed);
        }
        break;
      }
      case "--sing-box-bin":
        opts.singBoxBin = val.trim();
        break;
      case "--name-prefix":
      case "--name":
        opts.namePrefix = val.trim();
        break;
      case "--provider":
        opts.provider = val.trim();
        break;
      case "--region":
        opts.region = val.trim();
        break;
      case "--expires":
        opts.expires = val.trim();
        break;
      case "--out-file":
        opts.outFile = val.trim();
        break;
      default:
        fail(`未处理参数: ${flag}`, 2);
    }
  }

  if (opts.help) {
    return opts;
  }

  if (opts.configs.length === 0) {
    opts.configs.push(DEFAULT_CONFIG_PATH);
  }
  if (opts.services.length === 0) {
    opts.services.push(DEFAULT_SERVICE_NAME);
  }

  if (!opts.host) {
    if (opts.dryRun) {
      opts.host = DEFAULT_DRY_RUN_HOST;
    } else {
      fail("缺少必需参数 --host <IP/Host>（示例: --host 203.0.113.10；或使用 --dry-run 本地演练）", 2);
    }
  }
  if (/\s/.test(opts.host) || opts.host.startsWith("-") || opts.host.includes("@")) {
    fail(`--host 非法（禁止空白、'@' 或以 '-' 开头防止 SSH 参数注入）: ${opts.host}`, 2);
  }
  if (!opts.user || /\s/.test(opts.user) || opts.user.startsWith("-") || opts.user.includes("@")) {
    fail(`--user 非法（禁止为空、空白、'@' 或以 '-' 开头防止 SSH 参数注入）: ${opts.user}`, 2);
  }
  if (opts.expires) {
    if (!isValidExpiryString(opts.expires)) {
      fail(
        `--expires 格式无效: "${opts.expires}"（须为 YYYY-MM-DD 或 RFC3339，例如 2027-08-12）`,
        2
      );
    }
  }
  if (!opts.namePrefix) {
    opts.namePrefix = `${opts.region || "CN"}-${opts.provider || "Relay"}`;
  }

  return opts;
}

function isValidExpiryString(raw) {
  if (EXPIRES_DATE_RE.test(raw)) {
    const [y, m, d] = raw.split("-").map((s) => Number.parseInt(s, 10));
    const dt = new Date(Date.UTC(y, m - 1, d));
    return (
      dt.getUTCFullYear() === y &&
      dt.getUTCMonth() === m - 1 &&
      dt.getUTCDate() === d
    );
  }
  if (EXPIRES_RFC3339_RE.test(raw)) {
    return !Number.isNaN(Date.parse(raw));
  }
  return false;
}

/**
 * Find enclosing git repository root by walking ancestor directories (handles
 * normal repos, submodules, worktrees, non-existent leaf dirs, and symlinks).
 */
function findEnclosingGitRoot(targetFilePath) {
  const absTarget = path.resolve(targetFilePath);
  let cursor = path.dirname(absTarget);

  // Resolve realpath on the deepest existing ancestor so symlinked targets inside
  // a git repo cannot bypass the guard.
  const trailingSegments = [];
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    trailingSegments.unshift(path.basename(cursor));
    cursor = parent;
  }

  let realBase = cursor;
  try {
    if (fs.existsSync(cursor)) {
      realBase = fs.realpathSync(cursor);
    }
  } catch {
    realBase = cursor;
  }

  let walk = path.join(realBase, ...trailingSegments);
  while (true) {
    const dotGit = path.join(walk, ".git");
    if (fs.existsSync(dotGit)) {
      // Ensure the target isn't somehow inside `.git` metadata itself; even if it were,
      // blocking writes inside a git repo without `.mmrelay.json` is strictly safer.
      return walk;
    }
    const parent = path.dirname(walk);
    if (parent === walk) {
      return null;
    }
    walk = parent;
  }
}

function pathContainsDotGitSegment(targetPath) {
  const segments = path
    .resolve(targetPath)
    .split(/[\\/]+/)
    .filter(Boolean);
  return segments.some((seg) => seg.toLowerCase() === ".git");
}

function resolveRealTargetPath(targetFilePath) {
  const absTarget = path.resolve(targetFilePath);
  let cursor = path.dirname(absTarget);
  const trailingSegments = [path.basename(absTarget)];
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    trailingSegments.unshift(path.basename(cursor));
    cursor = parent;
  }
  let realBase = cursor;
  try {
    if (fs.existsSync(cursor)) {
      realBase = fs.realpathSync(cursor);
    }
  } catch {
    realBase = cursor;
  }
  return path.join(realBase, ...trailingSegments);
}

/**
 * Hard safety guard: disallow writing credential bundles inside `.git/` metadata
 * or inside any git repo unless the file name strictly ends with `.mmrelay.json`
 * (which `.gitignore` ignores).
 */
function assertSafeOutFilePath(outFile) {
  if (!outFile) return null;
  const resolved = path.resolve(outFile);
  if (fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()) {
    fail(`--out-file 不能是已存在的目录: ${resolved}`, 2);
  }
  const realTarget = resolveRealTargetPath(resolved);
  if (pathContainsDotGitSegment(resolved) || pathContainsDotGitSegment(realTarget)) {
    fail(
      `安全拦截：--out-file 严禁指向或穿越 .git 元数据目录: ${resolved}`,
      2
    );
  }
  const baseName = path.basename(resolved);
  const gitRoot = findEnclosingGitRoot(resolved);
  if (gitRoot && !baseName.endsWith(".mmrelay.json")) {
    fail(
      `安全拦截：--out-file 目标路径位于 Git 仓库 (${gitRoot}) 内，但文件名 "${baseName}" 未以 ".mmrelay.json" 结尾！\n` +
        `为防止真实中转密钥意外提交到公开仓库，仓库内导出文件必须以 ".mmrelay.json" 结尾（已被 .gitignore 忽略），或将文件输出到仓库外目录。`,
      2
    );
  }
  return resolved;
}

function generateStrongPassword() {
  return crypto.randomBytes(24).toString("base64url");
}

function generateStrongUuid() {
  return crypto.randomUUID();
}

function makeTimestampTag(now = new Date()) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${now.getUTCFullYear()}${pad(now.getUTCMonth() + 1)}${pad(now.getUTCDate())}` +
    `T${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}Z`
  );
}

function maskSecret(secret) {
  if (!secret || typeof secret !== "string") return "<empty>";
  if (secret.length <= 8) return "****";
  return `${secret.slice(0, 4)}****${secret.slice(-2)} (${secret.length} chars)`;
}

function maskUri(uri) {
  return `${MMRELAY_URI_PREFIX}<REDACTED ${uri.length} chars; pass --print-uri to reveal>`;
}

function slugify(raw, fallback = "relay") {
  const clean = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return clean || fallback;
}

function protocolDisplayName(proto) {
  switch (proto) {
    case "anytls":
      return "AnyTLS";
    case "hysteria2":
      return "Hysteria2";
    case "trojan":
      return "Trojan";
    case "vless":
      return "VLESS";
    case "tuic":
      return "TUIC";
    default:
      return proto.toUpperCase();
  }
}

function normalizeProtocol(raw) {
  const lower = String(raw || "").trim().toLowerCase();
  if (lower === "hy2") return "hysteria2";
  return lower;
}

function posixShellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
}

/**
 * Pure-JS local mirror of the sing-box rotation + backup/rollback generator
 * used exclusively by `--dry-run` so dry-run validates every single invariant
 * completely offline without invoking SSH.
 */
function buildDryRunSampleConfigs() {
  return [
    {
      path: DEFAULT_CONFIG_PATH,
      modeOctal: "0600",
      uid: 0,
      gid: 0,
      doc: {
        log: { level: "warn" },
        inbounds: [
          {
            type: "anytls",
            tag: "relay-anytls-443",
            listen: "::",
            listen_port: 443,
            users: [{ name: "catcloud", password: "dryrun-old-anytls-password-0001" }],
            tls: {
              enabled: true,
              certificate_path: "/etc/catcloud-relay/cert.pem",
              key_path: "/etc/catcloud-relay/key.pem",
            },
          },
          {
            type: "hysteria2",
            tag: "relay-hy2-443",
            listen: "::",
            listen_port: 443,
            users: [{ name: "catcloud", password: "dryrun-old-hy2-password-0002" }],
            tls: {
              enabled: true,
              certificate_path: "/etc/catcloud-relay/cert.pem",
              key_path: "/etc/catcloud-relay/key.pem",
            },
          },
          {
            type: "vless",
            tag: "relay-vless-443",
            listen: "::",
            listen_port: 443,
            users: [
              {
                name: "catcloud",
                uuid: "00000000-0000-4000-8000-000000000001",
              },
            ],
            tls: {
              enabled: true,
              certificate_path: "/etc/catcloud-relay/cert.pem",
              key_path: "/etc/catcloud-relay/key.pem",
            },
          },
        ],
        outbounds: [{ type: "direct", tag: "direct" }],
      },
    },
  ];
}

function rotateConfigDocumentLocally(doc, cfgPath, credPool) {
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.inbounds)) {
    throw new Error(`配置 ${cfgPath} 缺少有效的 inbounds[] 数组`);
  }

  let rotatedInFile = 0;
  const rotatedInbounds = [];

  for (let idx = 0; idx < doc.inbounds.length; idx++) {
    const inbound = doc.inbounds[idx];
    if (!inbound || typeof inbound !== "object") continue;

    const proto = normalizeProtocol(inbound.type);
    const isPasswordProto = SUPPORTED_PASSWORD_PROTOCOLS.has(proto);
    const isUuidProto = SUPPORTED_UUID_PROTOCOLS.has(proto);
    if (!isPasswordProto && !isUuidProto) continue;

    const tag = String(inbound.tag || `${proto}-in-${idx + 1}`);
    const listenPort =
      Number.isInteger(inbound.listen_port) &&
      inbound.listen_port >= 1 &&
      inbound.listen_port <= 65535
        ? inbound.listen_port
        : 443;

    let inboundRotatedCount = 0;
    let primaryCredential = "";
    let primaryUuid = "";
    let primaryPassword = "";
    const previousCredentials = [];

    if (Array.isArray(inbound.users) && inbound.users.length > 0) {
      for (const user of inbound.users) {
        if (!user || typeof user !== "object") continue;
        if (isPasswordProto) {
          const oldPw = typeof user.password === "string" ? user.password : "";
          const newPw = credPool.nextPassword();
          if (oldPw) previousCredentials.push(oldPw);
          user.password = newPw;
          if (!primaryPassword) primaryPassword = newPw;
          if (!primaryCredential) primaryCredential = newPw;
          inboundRotatedCount += 1;
        } else if (proto === "vless") {
          const oldUuid = typeof user.uuid === "string" ? user.uuid : "";
          const newUuid = credPool.nextUuid();
          if (oldUuid) previousCredentials.push(oldUuid);
          user.uuid = newUuid;
          if (!primaryUuid) primaryUuid = newUuid;
          if (!primaryCredential) primaryCredential = newUuid;
          inboundRotatedCount += 1;
        } else if (proto === "tuic") {
          const oldUuid = typeof user.uuid === "string" ? user.uuid : "";
          const newUuid = credPool.nextUuid();
          if (oldUuid) previousCredentials.push(oldUuid);
          user.uuid = newUuid;
          if (!primaryUuid) primaryUuid = newUuid;
          inboundRotatedCount += 1;
          if (Object.prototype.hasOwnProperty.call(user, "password")) {
            const oldPw = typeof user.password === "string" ? user.password : "";
            const newPw = credPool.nextPassword();
            if (oldPw) previousCredentials.push(oldPw);
            user.password = newPw;
            if (!primaryPassword) primaryPassword = newPw;
            inboundRotatedCount += 1;
          }
          if (!primaryCredential) {
            primaryCredential = primaryPassword || primaryUuid;
          }
        }
      }
    }

    if (inboundRotatedCount > 0) {
      rotatedInFile += inboundRotatedCount;
      rotatedInbounds.push({
        config_path: cfgPath,
        tag,
        protocol: proto,
        port: listenPort,
        rotated_count: inboundRotatedCount,
        primary_credential: primaryCredential,
        primary_uuid: primaryUuid || null,
        primary_password: primaryPassword || null,
        previous_credentials: previousCredentials,
      });
    }
  }

  return { rotatedInFile, rotatedInbounds };
}

function buildRollbackScriptPreview(backupDir, fileBackups, services) {
  const lines = [
    "#!/usr/bin/env bash",
    "set -euo pipefail",
    `# Auto-generated rollback script for ${backupDir}`,
    "",
  ];
  for (const fb of fileBackups) {
    const qBackup = posixShellQuote(fb.backup_path);
    const qOrig = posixShellQuote(fb.original_path);
    const qTmp = posixShellQuote(`${fb.original_path}.rollback.tmp`);
    lines.push(`if [ ! -f ${qBackup} ]; then`);
    lines.push(`  echo "[ROLLBACK ERROR] missing backup file: ${fb.backup_path}" >&2`);
    lines.push("  exit 1");
    lines.push("fi");
    lines.push(`cp -- ${qBackup} ${qTmp}`);
    lines.push(`chmod ${fb.mode_octal} -- ${qTmp}`);
    lines.push(`chown ${fb.uid}:${fb.gid} -- ${qTmp}`);
    lines.push(`mv -f -- ${qTmp} ${qOrig}`);
    lines.push("");
  }
  for (const svc of services) {
    const qSvc = posixShellQuote(svc);
    lines.push(`systemctl restart ${qSvc}`);
    lines.push("ok=0");
    lines.push("for _ in $(seq 1 20); do");
    lines.push(`  if systemctl is-active --quiet ${qSvc}; then`);
    lines.push("    ok=1");
    lines.push("    break");
    lines.push("  fi");
    lines.push("  sleep 0.5");
    lines.push("done");
    lines.push('if [ "$ok" -ne 1 ]; then');
    lines.push(`  echo "[ROLLBACK ERROR] service failed to become active: ${svc}" >&2`);
    lines.push("  exit 1");
    lines.push("fi");
    lines.push("");
  }
  lines.push('echo "[ROLLBACK OK] restored previous relay configs and verified active services."');
  return lines.join("\n");
}

function runOfflineDryRun(opts) {
  const ts = makeTimestampTag();
  const backupDir = `${DEFAULT_BACKUP_ROOT}/rotate-${ts}`;
  const samples = buildDryRunSampleConfigs();

  // Map user-supplied --config paths onto the dry-run sample if customized.
  const targetConfigs = opts.configs.map((cfgPath, idx) => {
    const template = samples[idx] || samples[0];
    return {
      path: cfgPath,
      modeOctal: template.modeOctal,
      uid: template.uid,
      gid: template.gid,
      doc: JSON.parse(JSON.stringify(template.doc)),
    };
  });

  const credPool = {
    nextPassword: () => generateStrongPassword(),
    nextUuid: () => generateStrongUuid(),
  };

  let totalRotated = 0;
  const allRotatedInbounds = [];
  const fileBackups = [];
  const updatedJsonBlobs = [];

  for (let i = 0; i < targetConfigs.length; i++) {
    const item = targetConfigs[i];
    const beforeRaw = JSON.stringify(item.doc, null, 2) + "\n";
    const beforeSha256 = crypto.createHash("sha256").update(beforeRaw, "utf8").digest("hex");

    const { rotatedInFile, rotatedInbounds } = rotateConfigDocumentLocally(
      item.doc,
      item.path,
      credPool
    );

    totalRotated += rotatedInFile;
    allRotatedInbounds.push(...rotatedInbounds);

    const afterRaw = JSON.stringify(item.doc, null, 2) + "\n";
    const afterSha256 = crypto.createHash("sha256").update(afterRaw, "utf8").digest("hex");

    // Dry-run strong assertions on rotated JSON output:
    if (beforeSha256 === afterSha256) {
      throw new Error(`Dry-run 断言失败: 配置 ${item.path} 轮换后哈希未变化`);
    }
    for (const r of rotatedInbounds) {
      for (const oldCred of r.previous_credentials) {
        if (afterRaw.includes(oldCred)) {
          throw new Error(
            `Dry-run 断言失败: 旧凭据仍残留在轮换后的配置 ${item.path} 中`
          );
        }
      }
      if (r.protocol === "vless" && !UUID_V4_RE.test(r.primary_credential)) {
        throw new Error(`Dry-run 断言失败: VLESS 新凭据不是合规 UUID v4`);
      }
      if (
        SUPPORTED_PASSWORD_PROTOCOLS.has(r.protocol) &&
        !/^[A-Za-z0-9_-]{32}$/.test(r.primary_credential)
      ) {
        throw new Error(
          `Dry-run 断言失败: ${r.protocol} 新密码长度或字符集不符合 32 位 base64url`
        );
      }
    }

    const backupFileName = `config-${i}-${path.posix.basename(item.path)}`;
    fileBackups.push({
      original_path: item.path,
      backup_path: `${backupDir}/${backupFileName}`,
      sha256_before: beforeSha256,
      sha256_after: afterSha256,
      mode_octal: item.modeOctal,
      uid: item.uid,
      gid: item.gid,
    });
    updatedJsonBlobs.push({ path: item.path, bytes: Buffer.byteLength(afterRaw, "utf8") });
  }

  if (totalRotated < 1) {
    throw new Error("强断言失败: 总替换凭据数为 0（至少需要轮换 1 个 inbound 凭据）");
  }

  const rollbackScript = buildRollbackScriptPreview(backupDir, fileBackups, opts.services);

  return {
    mode: "dry_run",
    timestamp: ts,
    backup_dir: backupDir,
    rollback_script_path: `${backupDir}/rollback.sh`,
    rollback_script_preview: rollbackScript,
    sing_box_bin:
      opts.singBoxBin || "auto (command -v sing-box || /opt/sing-box/sing-box || /usr/bin/sing-box)",
    total_rotated: totalRotated,
    files: fileBackups,
    services_verified: opts.services,
    rotated_inbounds: allRotatedInbounds,
    updated_blobs: updatedJsonBlobs,
  };
}

/**
 * Remote Python 3.8+ executor sent via base64 wrapper; receives ALL config
 * paths, service names, and fresh CSPRNG credentials exclusively over stdin.
 */
const REMOTE_PYTHON_EXECUTOR = String.raw`
import hashlib
import json
import os
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid

RESULT_BEGIN = "__CATCLOUD_ROTATE_RESULT_BEGIN__"
RESULT_END = "__CATCLOUD_ROTATE_RESULT_END__"

PASSWORD_PROTOS = {"anytls", "hysteria2", "trojan"}
UUID_PROTOS = {"vless", "tuic"}


def die(msg, code=1, extra=None):
    payload = {"ok": False, "error": msg}
    if extra:
        payload.update(extra)
    sys.stderr.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.exit(code)


def resolve_sing_box_bin(explicit_bin):
    if explicit_bin:
        if os.path.isfile(explicit_bin) and os.access(explicit_bin, os.X_OK):
            return explicit_bin
        die("Specified --sing-box-bin not found or not executable: " + explicit_bin)
    candidates = [
        shutil.which("sing-box"),
        "/opt/sing-box/sing-box",
        "/usr/bin/sing-box",
    ]
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    die(
        "sing-box binary not found (checked PATH, /opt/sing-box/sing-box, /usr/bin/sing-box); "
        "pass --sing-box-bin <path> explicitly"
    )


def build_rollback_script(backup_dir, backups, services):
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "# Auto-generated rollback script for " + backup_dir,
        "",
    ]
    for b in backups:
        q_bk = shlex.quote(b["backup_path"])
        q_orig = shlex.quote(b["original_path"])
        q_tmp = shlex.quote(b["original_path"] + ".rollback.tmp")
        lines.extend([
            "if [ ! -f " + q_bk + " ]; then",
            "  echo " + shlex.quote("[ROLLBACK ERROR] missing backup: " + b["backup_path"]) + " >&2",
            "  exit 1",
            "fi",
            "cp -- " + q_bk + " " + q_tmp,
            "chown " + str(b["uid"]) + ":" + str(b["gid"]) + " -- " + q_tmp + " || true",
            "chmod " + b["mode_octal"] + " -- " + q_tmp,
            "mv -f -- " + q_tmp + " " + q_orig,
            "",
        ])
    for svc in services:
        q_svc = shlex.quote(svc)
        lines.extend([
            "systemctl restart " + q_svc,
            "ok=0",
            "for _ in $(seq 1 20); do",
            "  if systemctl is-active --quiet " + q_svc + "; then",
            "    ok=1",
            "    break",
            "  fi",
            "  sleep 0.5",
            "done",
            'if [ "$ok" -ne 1 ]; then',
            "  echo " + shlex.quote("[ROLLBACK ERROR] service not active: " + svc) + " >&2",
            "  exit 1",
            "fi",
            "",
        ])
    lines.append('echo "[ROLLBACK OK] restored previous configs and restarted services."')
    return "\n".join(lines) + "\n"


def wait_service_active(service_name, attempts=20, interval=0.5):
    for _ in range(attempts):
        chk = subprocess.run(
            ["systemctl", "is-active", "--quiet", service_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if chk.returncode == 0:
            # Double-check after a short settle window to catch immediate crash loops.
            time.sleep(1.0)
            rechk = subprocess.run(
                ["systemctl", "is-active", "--quiet", service_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if rechk.returncode == 0:
                return True
            return False
        time.sleep(interval)
    return False


def execute_rollback(rollback_script_path):
    res = subprocess.run(
        ["bash", rollback_script_path],
        capture_output=True,
        text=True,
    )
    return {
        "rollback_exit_code": res.returncode,
        "rollback_stdout": res.stdout.strip(),
        "rollback_stderr": res.stderr.strip(),
    }


def main():
    raw_in = sys.stdin.read()
    if not raw_in.strip():
        die("Empty stdin payload received by remote rotator")
    try:
        req = json.loads(raw_in)
    except Exception as exc:
        die("Invalid JSON stdin payload: " + str(exc))

    configs = req.get("configs") or []
    services = req.get("services") or []
    passwords = list(req.get("passwords") or [])
    uuids = list(req.get("uuids") or [])
    explicit_bin = req.get("sing_box_bin") or ""
    backup_root = req.get("backup_root") or "/etc/catcloud-relay/backups"
    ts = req.get("timestamp") or time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())

    if not configs:
        die("No config paths specified")
    if not services:
        die("No systemd service names specified")

    sing_box_bin = resolve_sing_box_bin(explicit_bin)

    pw_idx = 0
    uuid_idx = 0

    def next_password():
        nonlocal pw_idx
        if pw_idx < len(passwords):
            val = passwords[pw_idx]
            pw_idx += 1
            return val
        return secrets.token_urlsafe(24)

    def next_uuid():
        nonlocal uuid_idx
        if uuid_idx < len(uuids):
            val = uuids[uuid_idx]
            uuid_idx += 1
            return val
        return str(uuid.uuid4())

    # 1. Read, parse, and rotate in memory before touching anything on disk.
    loaded = []
    rotated_inbounds = []
    warnings = []
    seen_realpaths = {}
    total_rotated = 0

    for idx, cfg_path in enumerate(configs):
        if not os.path.isfile(cfg_path):
            die("Config file not found: " + cfg_path)
        real_path = os.path.realpath(cfg_path)
        if real_path in seen_realpaths:
            die(
                "Duplicate --config targets resolve to the same physical file: "
                + cfg_path
                + " and "
                + seen_realpaths[real_path]
                + " -> "
                + real_path
            )
        seen_realpaths[real_path] = cfg_path
        st = os.stat(real_path)
        mode_int = stat.S_IMODE(st.st_mode)
        mode_octal = format(mode_int, "04o")
        with open(real_path, "rb") as f:
            raw_bytes = f.read()
        sha_before = hashlib.sha256(raw_bytes).hexdigest()
        try:
            doc = json.loads(raw_bytes.decode("utf-8"))
        except Exception as exc:
            die("Failed to parse JSON config " + cfg_path + ": " + str(exc))

        inbounds = doc.get("inbounds")
        if not isinstance(inbounds, list):
            die("Config missing inbounds[] array: " + cfg_path)

        for ib_idx, inbound in enumerate(inbounds):
            if not isinstance(inbound, dict):
                continue
            raw_type = str(inbound.get("type", "")).strip().lower()
            proto = "hysteria2" if raw_type == "hy2" else raw_type
            is_pw = proto in PASSWORD_PROTOS
            is_uuid = proto in UUID_PROTOS
            if not is_pw and not is_uuid:
                continue

            tag = str(inbound.get("tag") or (proto + "-in-" + str(ib_idx + 1)))
            port = inbound.get("listen_port", 443)
            if not isinstance(port, int) or port < 1 or port > 65535:
                port = 443

            users = inbound.get("users")
            if not isinstance(users, list) or len(users) == 0:
                continue

            ib_rotated = 0
            primary_cred = ""
            primary_uuid = None
            primary_password = None

            for user in users:
                if not isinstance(user, dict):
                    continue
                if is_pw:
                    new_pw = next_password()
                    user["password"] = new_pw
                    if primary_password is None:
                        primary_password = new_pw
                    if not primary_cred:
                        primary_cred = new_pw
                    ib_rotated += 1
                elif proto == "vless":
                    new_u = next_uuid()
                    user["uuid"] = new_u
                    if primary_uuid is None:
                        primary_uuid = new_u
                    if not primary_cred:
                        primary_cred = new_u
                    ib_rotated += 1
                elif proto == "tuic":
                    new_u = next_uuid()
                    user["uuid"] = new_u
                    if primary_uuid is None:
                        primary_uuid = new_u
                    ib_rotated += 1
                    if "password" in user:
                        new_pw = next_password()
                        user["password"] = new_pw
                        if primary_password is None:
                            primary_password = new_pw
                        ib_rotated += 1
                    if not primary_cred:
                        primary_cred = primary_password or primary_uuid

            if ib_rotated > 0:
                total_rotated += ib_rotated
                rotated_inbounds.append({
                    "config_path": cfg_path,
                    "tag": tag,
                    "protocol": proto,
                    "port": port,
                    "rotated_count": ib_rotated,
                    "primary_credential": primary_cred,
                    "primary_uuid": primary_uuid,
                    "primary_password": primary_password,
                })

        new_bytes = (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        sha_after = hashlib.sha256(new_bytes).hexdigest()
        loaded.append({
            "index": idx,
            "requested_path": cfg_path,
            "original_path": real_path,
            "raw_before": raw_bytes,
            "raw_after": new_bytes,
            "sha256_before": sha_before,
            "sha256_after": sha_after,
            "mode_int": mode_int,
            "mode_octal": mode_octal,
            "uid": st.st_uid,
            "gid": st.st_gid,
        })

    if total_rotated < 1:
        die(
            "Assertion failed: 0 credentials rotated across all provided config files "
            "(expected >= 1 supported inbound with users[])."
        )

    # 2. Create atomic backup directory, store original files, SHA-256 sums, and rollback.sh.
    backup_dir = os.path.join(backup_root, "rotate-" + ts)
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    os.chmod(backup_dir, 0o700)

    backup_records = []
    sha_lines = []
    for item in loaded:
        base = os.path.basename(item["original_path"])
        bk_name = "config-{0}-{1}".format(item["index"], base)
        bk_path = os.path.join(backup_dir, bk_name)
        fd = os.open(bk_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, item["raw_before"])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(bk_path, 0o600)
        try:
            os.chown(bk_path, item["uid"], item["gid"])
        except PermissionError:
            pass
        sha_lines.append("{0}  {1}  # {2}".format(item["sha256_before"], bk_name, item["original_path"]))
        backup_records.append({
            "requested_path": item["requested_path"],
            "original_path": item["original_path"],
            "backup_path": bk_path,
            "sha256_before": item["sha256_before"],
            "sha256_after": item["sha256_after"],
            "mode_octal": item["mode_octal"],
            "uid": item["uid"],
            "gid": item["gid"],
        })

    with open(os.path.join(backup_dir, "sha256sums.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sha_lines) + "\n")
    with open(os.path.join(backup_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": ts,
                "sing_box_bin": sing_box_bin,
                "services": services,
                "files": backup_records,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    rollback_path = os.path.join(backup_dir, "rollback.sh")
    rollback_content = build_rollback_script(backup_dir, backup_records, services)
    rfd = os.open(rollback_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    try:
        os.write(rfd, rollback_content.encode("utf-8"))
        os.fsync(rfd)
    finally:
        os.close(rfd)
    os.chmod(rollback_path, 0o700)

    # 3. Write sibling temp files, copy exact mode + uid/gid, run 'sing-box check -c <tmp>'.
    staged = []
    try:
        for item in loaded:
            parent_dir = os.path.dirname(os.path.abspath(item["original_path"]))
            tmp_name = ".catcloud-rotate-{0}-{1}-{2}.tmp.json".format(ts, os.getpid(), item["index"])
            tmp_path = os.path.join(parent_dir, tmp_name)
            tfd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(tfd, item["raw_after"])
                os.fsync(tfd)
            finally:
                os.close(tfd)
            try:
                os.chown(tmp_path, item["uid"], item["gid"])
            except PermissionError:
                warnings.append(
                    "Unable to chown staged file " + tmp_path + " to " + str(item["uid"]) + ":" + str(item["gid"])
                )
            os.chmod(tmp_path, item["mode_int"])
            staged.append((tmp_path, item["original_path"]))

            chk = subprocess.run(
                [sing_box_bin, "check", "-c", tmp_path],
                capture_output=True,
                text=True,
            )
            if chk.returncode != 0:
                raise RuntimeError(
                    "sing-box check failed for "
                    + item["original_path"]
                    + ": "
                    + (chk.stderr.strip() or chk.stdout.strip() or "exit " + str(chk.returncode))
                )
    except Exception as exc:
        for tmp_path, _ in staged:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass
        die("Pre-replacement validation failed (live configs untouched): " + str(exc), 1, {
            "backup_dir": backup_dir,
            "rollback_script_path": rollback_path,
        })

    # 4. Atomically replace every config; rollback immediately on any replacement or restart failure.
    try:
        for tmp_path, orig_path in staged:
            os.replace(tmp_path, orig_path)
    except Exception as exc:
        for tmp_path, _ in staged:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass
        rb = execute_rollback(rollback_path)
        die("Atomic os.replace failed; executed automatic rollback: " + str(exc), 1, {
            "backup_dir": backup_dir,
            "rollback_script_path": rollback_path,
            "rollback_result": rb,
        })

    # 5. Restart services and verify 'systemctl is-active --quiet'; auto-rollback on failure.
    for svc in services:
        restart_res = subprocess.run(
            ["systemctl", "restart", svc],
            capture_output=True,
            text=True,
        )
        active_ok = restart_res.returncode == 0 and wait_service_active(svc)
        if not active_ok:
            journal = subprocess.run(
                ["journalctl", "-u", svc, "-n", "20", "--no-pager"],
                capture_output=True,
                text=True,
            )
            rb = execute_rollback(rollback_path)
            die(
                "Service restart/active verification failed for "
                + svc
                + "; executed automatic rollback via "
                + rollback_path,
                1,
                {
                    "failed_service": svc,
                    "restart_exit_code": restart_res.returncode,
                    "restart_stderr": restart_res.stderr.strip(),
                    "journal_tail": journal.stdout.strip()[-1500:],
                    "backup_dir": backup_dir,
                    "rollback_script_path": rollback_path,
                    "rollback_result": rb,
                },
            )

    result = {
        "ok": True,
        "mode": "remote_ssh",
        "timestamp": ts,
        "backup_dir": backup_dir,
        "rollback_script_path": rollback_path,
        "sing_box_bin": sing_box_bin,
        "total_rotated": total_rotated,
        "files": backup_records,
        "services_verified": services,
        "rotated_inbounds": rotated_inbounds,
        "warnings": warnings,
    }
    sys.stdout.write("\n" + RESULT_BEGIN + "\n")
    sys.stdout.write(json.dumps(result, ensure_ascii=False) + "\n")
    sys.stdout.write(RESULT_END + "\n")


if __name__ == "__main__":
    main()
`;

function runRemoteSshRotation(opts) {
  const ts = makeTimestampTag();

  // Pre-generate ample CSPRNG credentials locally and pass ONLY through stdin.
  const passwords = Array.from({ length: 64 }, () => generateStrongPassword());
  const uuids = Array.from({ length: 64 }, () => generateStrongUuid());

  const stdinPayload = JSON.stringify({
    configs: opts.configs,
    services: opts.services,
    sing_box_bin: opts.singBoxBin,
    backup_root: DEFAULT_BACKUP_ROOT,
    timestamp: ts,
    passwords,
    uuids,
  });

  const remoteScriptB64 = Buffer.from(REMOTE_PYTHON_EXECUTOR, "utf8").toString("base64");
  const pyBootstrap =
    `import base64; exec(compile(base64.b64decode('${remoteScriptB64}').decode('utf-8'), '<catcloud-rotate>', 'exec'))`;
  const remoteCmd = opts.useSudo
    ? `sudo -n python3 -c "${pyBootstrap}"`
    : `python3 -c "${pyBootstrap}"`;

  const sshArgs = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=15",
    "-o",
    "ServerAliveInterval=10",
    "-o",
    "ServerAliveCountMax=3",
    "-p",
    String(opts.port),
  ];
  if (opts.key) {
    sshArgs.push("-i", opts.key);
  }
  sshArgs.push("--", `${opts.user}@${opts.host}`, remoteCmd);

  const proc = spawnSync("ssh", sshArgs, {
    input: stdinPayload,
    encoding: "utf8",
    maxBuffer: 10 * 1024 * 1024,
  });

  if (proc.error) {
    fail(`无法启动 ssh 进程: ${proc.error.message}`);
  }

  if (proc.status !== 0) {
    const errText = (proc.stderr || proc.stdout || "").trim();
    fail(
      `远端密钥轮换失败 (SSH exit ${proc.status})${errText ? `:\n${errText}` : ""}`,
      proc.status || 1
    );
  }

  const stdout = proc.stdout || "";
  const beginMarker = "__CATCLOUD_ROTATE_RESULT_BEGIN__";
  const endMarker = "__CATCLOUD_ROTATE_RESULT_END__";
  const startIdx = stdout.indexOf(beginMarker);
  const endIdx = stdout.indexOf(endMarker);
  if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
    fail("远端执行器未返回预期的结构化结果标记，请检查远端输出。");
  }

  const jsonBody = stdout.slice(startIdx + beginMarker.length, endIdx).trim();
  let parsed;
  try {
    parsed = JSON.parse(jsonBody);
  } catch (err) {
    fail(`无法解析远端返回的 JSON 结果: ${err.message}`);
  }
  if (!parsed || parsed.ok !== true) {
    fail(`远端返回失败结果: ${parsed?.error || "unknown error"}`);
  }
  return parsed;
}

function buildMmRelayBundle(opts, rotatedInbounds) {
  const usedIds = new Set();
  const relays = [];
  const skippedNotes = [];
  let priority = 10;

  const hostSlug = slugify(opts.host, "host");
  const providerSlug = slugify(opts.provider, "relay");
  const regionSlug = slugify(opts.region, "cn");

  for (let i = 0; i < rotatedInbounds.length; i++) {
    const ib = rotatedInbounds[i];
    const proto = normalizeProtocol(ib.protocol);
    if (!["anytls", "hysteria2", "trojan", "vless", "tuic"].includes(proto)) {
      skippedNotes.push(`跳过不支持导出 mmrelay/v1 的协议: ${proto} (${ib.tag})`);
      continue;
    }

    const baseId = `relay-${providerSlug}-${regionSlug}-${proto}-${ib.port}`;
    let id = baseId;
    let suffix = 2;
    while (usedIds.has(id)) {
      id = `${baseId}-${suffix++}`;
    }
    usedIds.add(id);

    const protoLabel = protocolDisplayName(proto);
    const displayName =
      rotatedInbounds.length > 1
        ? `${opts.namePrefix} ${protoLabel} :${ib.port}`
        : `${opts.namePrefix} ${protoLabel}`;

    const entry = {
      id,
      name: displayName.trim(),
      provider: opts.provider,
      region: opts.region,
      server: opts.host,
      port: ib.port,
      protocol: proto,
      password: ib.primary_credential,
      sni: "",
      skip_cert_verify: true,
      priority,
      enabled: true,
    };
    if (opts.expires) {
      entry.expires_at = opts.expires;
    }

    if (proto === "tuic" && ib.primary_uuid && ib.primary_password) {
      skippedNotes.push(
        `TUIC inbound "${ib.tag}" 已同步轮换 uuid 与 password（mmrelay/v1 条目已填入新 password；注意：CatCloud 当前 TUIC 编译默认按 v4 token 语义，如远端为 TUIC v5 请优先选用同机 AnyTLS / Hysteria2 或在导入后核对协议版本）`
      );
    }

    relays.push(entry);
    priority += 10;
  }

  if (relays.length < 1) {
    fail(
      `未产出任何可导入的 mmrelay/v1 条目（主机 ${hostSlug} 轮换结果中无受支持协议）。`
    );
  }

  return {
    bundle: {
      schema: MMRELAY_SCHEMA_V1,
      role: MMRELAY_ROLE_DOMESTIC,
      relays,
    },
    notes: skippedNotes,
  };
}

function encodeAndVerifyMmRelayUri(bundle) {
  const compact = JSON.stringify(bundle);
  const encoded = Buffer.from(compact, "utf8").toString("base64url");
  const uri = `${MMRELAY_URI_PREFIX}${encoded}`;

  // Local self-check mirroring `crates/catcloud-core/src/preaccel/schema.rs`.
  const decodedJson = Buffer.from(uri.slice(MMRELAY_URI_PREFIX.length), "base64url").toString(
    "utf8"
  );
  const decoded = JSON.parse(decodedJson);

  if (decoded.schema !== MMRELAY_SCHEMA_V1 || decoded.role !== MMRELAY_ROLE_DOMESTIC) {
    throw new Error("mmrelay/v1 自检失败: schema/role 头部不匹配");
  }
  if (!Array.isArray(decoded.relays) || decoded.relays.length !== bundle.relays.length) {
    throw new Error("mmrelay/v1 自检失败: relays 数量不匹配");
  }
  for (const r of decoded.relays) {
    if (r.sni !== "") {
      throw new Error(`mmrelay/v1 自检失败: ${r.id} 的 sni 必须为空字符串`);
    }
    if (r.skip_cert_verify !== true) {
      throw new Error(`mmrelay/v1 自检失败: ${r.id} 的 skip_cert_verify 必须为 true`);
    }
    if (!r.password || typeof r.password !== "string") {
      throw new Error(`mmrelay/v1 自检失败: ${r.id} 缺少凭据`);
    }
    if (r.protocol === "vless" && !UUID_V4_RE.test(r.password)) {
      throw new Error(`mmrelay/v1 自检失败: VLESS 条目 ${r.id} 凭据不是合法 UUID v4`);
    }
  }

  return { uri, compactBytes: Buffer.byteLength(compact, "utf8") };
}

function writeOutFileAtomicSecure(resolvedOutPath, bundle) {
  const dir = path.dirname(resolvedOutPath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(
    dir,
    `.${path.basename(resolvedOutPath)}.${process.pid}.${Date.now()}.tmp`
  );
  const content = JSON.stringify(bundle, null, 2) + "\n";
  try {
    fs.writeFileSync(tmpPath, content, { encoding: "utf8", mode: 0o600 });
    try {
      fs.chmodSync(tmpPath, 0o600);
    } catch {
      // Best-effort on Windows filesystems without POSIX mode bits.
    }
    fs.renameSync(tmpPath, resolvedOutPath);
    try {
      fs.chmodSync(resolvedOutPath, 0o600);
    } catch {
      // Best-effort on Windows.
    }
  } catch (err) {
    try {
      if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath);
    } catch {
      // Ignore cleanup errors.
    }
    fail(`写入 --out-file 失败 (${resolvedOutPath}): ${err.message}`);
  }
}

function printSummary(opts, result, bundle, uriInfo, notes, resolvedOutPath) {
  const isDry = result.mode === "dry_run";
  const lines = [];
  lines.push("====================================================================");
  lines.push(
    isDry
      ? "[DRY-RUN] CatCloud 国内中转密钥轮换离线演练通过（未发起任何 SSH）"
      : "[OK] CatCloud 国内中转密钥轮换与服务验活完成"
  );
  lines.push("====================================================================");
  lines.push(`目标主机      : ${opts.host} (SSH ${opts.user}@${opts.host}:${opts.port}${opts.useSudo ? ", sudo -n" : ""})`);
  lines.push(`sing-box 路径 : ${result.sing_box_bin}`);
  lines.push(`总轮换凭据数  : ${result.total_rotated} (>= 1 断言通过)`);
  lines.push(`远端备份目录  : ${result.backup_dir}`);
  lines.push(`独立回退脚本  : ${result.rollback_script_path}`);
  lines.push(`已验活服务    : ${result.services_verified.join(", ")}`);
  lines.push("");

  lines.push("配置文件变更与 SHA-256 摘要:");
  for (const f of result.files) {
    lines.push(
      `  - ${f.original_path} (mode=${f.mode_octal}, uid:gid=${f.uid}:${f.gid})`
    );
    lines.push(`    before: ${f.sha256_before}`);
    lines.push(`    after : ${f.sha256_after}`);
    lines.push(`    backup: ${f.backup_path}`);
  }
  lines.push("");

  lines.push(`已生成 mmrelay/v1 清单（共 ${bundle.relays.length} 条，round-trip 校验通过）:`);
  for (const r of bundle.relays) {
    lines.push(
      `  - [priority=${r.priority}] ${r.name} | ${r.protocol} | ${r.server}:${r.port} | sni="" | skip_cert_verify=${r.skip_cert_verify} | cred=${maskSecret(r.password)}`
    );
  }
  if (notes.length > 0) {
    lines.push("");
    lines.push("附注:");
    for (const n of notes) {
      lines.push(`  * ${n}`);
    }
  }
  lines.push("");

  if (resolvedOutPath) {
    lines.push(`导出文件 (0600): ${resolvedOutPath}`);
  }

  if (opts.printUri) {
    lines.push("完整 mmrelay://v1 导入码（含新密钥，请勿公开转发）:");
    lines.push(uriInfo.uri);
  } else {
    lines.push(`mmrelay://v1 导入码（默认脱敏）: ${maskUri(uriInfo.uri)}`);
    lines.push("提示: 如需在终端直接打印完整导入码，请追加 --print-uri；或使用 --out-file <name>.mmrelay.json 安全导出。");
  }

  if (isDry && result.rollback_script_preview) {
    lines.push("");
    lines.push("--- [DRY-RUN] 预生成的远端 rollback.sh 预览 ---");
    lines.push(result.rollback_script_preview.trimEnd());
    lines.push("--- [DRY-RUN] rollback.sh 预览结束 ---");
  } else {
    lines.push("");
    lines.push("如需人工回退至轮换前配置，请在目标服务器执行:");
    lines.push(`  ${opts.useSudo ? "sudo " : ""}bash ${result.rollback_script_path}`);
  }

  process.stdout.write(lines.join("\n") + "\n");
}

function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  // Enforce the git-repo `.mmrelay.json` guard up front (including in --dry-run).
  const resolvedOutPath = assertSafeOutFilePath(opts.outFile);

  let result;
  if (opts.dryRun) {
    try {
      result = runOfflineDryRun(opts);
    } catch (err) {
      fail(`离线演练失败: ${err.message}`);
    }
  } else {
    result = runRemoteSshRotation(opts);
  }

  const { bundle, notes } = buildMmRelayBundle(opts, result.rotated_inbounds);
  const uriInfo = encodeAndVerifyMmRelayUri(bundle);

  if (resolvedOutPath) {
    writeOutFileAtomicSecure(resolvedOutPath, bundle);
  }

  printSummary(opts, result, bundle, uriInfo, notes, resolvedOutPath);
}

main();
