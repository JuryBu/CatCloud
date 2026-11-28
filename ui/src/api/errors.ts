/**
 * User-friendly error translation rules for Tauri IPC and runtime failures.
 */

export const FRIENDLY_ERROR_RULES: ReadonlyArray<{ pattern: RegExp; message: string }> = [
  {
    pattern:
      /\bNO_ENABLED_RELAY\b|no\s+enabled\s+(?:preaccel\s+)?relay|no\s+available\s+(?:domestic\s+)?relay|尚未(?:添加|配置|启用).*?(?:国内|提速|中转)|没有可用.*?(?:国内|提速|中转)/i,
    message: "还没有可用的国内提速线路，请先添加并启用至少一条提速线路",
  },
  {
    pattern:
      /probe[_\s-]?running|another\s+probe.*running|probe\s+already\s+running|benchmark.*already\s+running/i,
    message: "已有测速或对比任务正在进行，请稍候完成后再试",
  },
  {
    pattern:
      /update_staging_lock|update.*already\s+(?:in\s+progress|downloading)|already\s+staging/i,
    message: "应用更新正在后台下载中，请稍候完成后再试",
  },
  {
    pattern: /address\s+already\s+in\s+use|os\s+error\s+10048\b|eaddrinuse/i,
    message: "本地端口已被其它程序占用，请在设置中更换端口后重试",
  },
  {
    pattern: /os\s+error\s+10061\b|connection\s+refused|econnrefused/i,
    message: "本地服务或目标端口拒绝连接，请确认核心已启动或目标地址可用",
  },
  {
    pattern:
      /os\s+error\s+10054\b|os\s+error\s+10053\b|connection\s+reset|econnreset|broken\s+pipe|connection\s+aborted/i,
    message: "网络连接被意外中断，请检查网络或切换节点后重试",
  },
  {
    pattern:
      /os\s+error\s+10060\b|timed\s*out|etimedout|deadline\s+has\s+elapsed|operation\s+timeout|request\s+timeout/i,
    message: "连接超时，请检查网络状况或切换节点后重试",
  },
  {
    pattern:
      /dns\s+error|failed\s+to\s+lookup\s+address|no\s+such\s+host|enotfound|name\s+or\s+service\s+not\s+known|could\s+not\s+resolve\s+host|os\s+error\s+11001\b/i,
    message: "域名解析失败，请检查网络连接或确认网址是否正确",
  },
  {
    pattern:
      /invalid\s+peer\s+certificate|certificate\s+(?:verify|expired|invalid|unknown)|unknown\s+issuer|tls\s+handshake|ssl\s+handshake|unexpected\s+eof\s+during\s+handshake/i,
    message: "安全连接（TLS / 证书）握手失败，请检查系统时间或证书配置",
  },
  {
    pattern: /socks[45]?\s+error|proxy\s+connect|http\s+status\s+407|tunnel\s+connection\s+failed/i,
    message: "代理通道连接失败，请检查核心状态或中转线路配置",
  },
  {
    pattern: /unexpected\s+eof|early\s+eof|incomplete\s+message|channel\s+closed|hyper::error/i,
    message: "远端提前断开连接，请稍后重试",
  },
  {
    pattern:
      /<!doctype\s+html|<html\b|returned\s+html|html\s+(?:page|document|response)|webpage\s+instead\s+of/i,
    message:
      "订阅链接返回了网页内容而不是节点列表（可能链接已失效、需要登录或被防火墙拦截），请确认复制的是原始订阅链接",
  },
  {
    pattern:
      /clash\s+yaml\s+document\s+does\s+not\s+contain\s+a\s+['"]?proxies['"]?\s+section|does\s+not\s+contain\s+a\s+['"]?proxies['"]?\s+section|missing\s+['"]?proxies['"]?\s+section/i,
    message:
      "订阅内容里没有找到节点列表（缺少 proxies 配置段），请确认这不是纯分流规则文件或失效链接",
  },
  {
    pattern: /expected\s+yaml\s+mapping\s+at\s+top\s+level/i,
    message:
      "订阅返回的内容不是有效的节点配置格式（可能返回了网页提示或链接已过期），请检查订阅链接是否正确",
  },
  {
    pattern:
      /subscription\s+payload\s+is\s+empty|empty\s+subscription|no\s+valid\s+proxy\s+nodes/i,
    message: "订阅返回的内容为空或未包含可用节点，已保留现有节点未覆盖",
  },
  {
    pattern:
      /invalid\s+subscription\s+url|unsupported\s+subscription\s+scheme|relative\s+url\s+without\s+a\s+base/i,
    message: "订阅链接格式无效，请粘贴以 http:// 或 https:// 开头的完整订阅地址",
  },
  {
    pattern:
      /non-2xx\s+status\s*401\b|\b401\s+unauthorized\b|status\s+code\s*401\b|http\s+401\b/i,
    message: "订阅或目标地址需要登录认证（401），链接可能已过期或缺少校验参数",
  },
  {
    pattern:
      /non-2xx\s+status\s*403\b|\b403\s+forbidden\b|status\s+code\s*403\b|http\s+403\b/i,
    message: "目标服务器拒绝访问（403），订阅链接可能已失效、过期或受地区限制",
  },
  {
    pattern:
      /non-2xx\s+status\s*404\b|\b404\s+not\s+found\b|status\s+code\s*404\b|http\s+404\b/i,
    message: "目标地址不存在（404），请检查订阅链接是否复制完整",
  },
  {
    pattern:
      /non-2xx\s+status\s*429\b|\b429\s+too\s+many\s+requests\b|status\s+code\s*429\b|http\s+429\b/i,
    message: "请求过于频繁（429），请稍等片刻后再试",
  },
  {
    pattern:
      /non-2xx\s+status\s*50[0234]\b|\b50[0234]\b.*(?:bad\s+gateway|service\s+unavailable|gateway\s+timeout|internal\s+server)|status\s+code\s*50[0234]\b|http\s+50[0234]\b/i,
    message: "远端服务器暂时繁忙或不可用（5xx），请稍后重试",
  },
  {
    pattern: /non-2xx\s+status\s+\d+/i,
    message: "订阅服务器返回异常状态，请确认链接有效或稍后重试",
  },
  {
    pattern:
      /error\s+sending\s+request\s+for\s+url|client\s+error\s*\(connect\)|tcp\s+connect\s+error|network\s+is\s+unreachable|host\s+is\s+unreachable|os\s+error\s+10051\b|os\s+error\s+10065\b/i,
    message: "无法连接到目标服务器，请检查网络连接或切换节点后重试",
  },
  {
    pattern: /no\s+such\s+file\s+or\s+directory|cannot\s+find\s+the\s+(?:file|path)|os\s+error\s+[23]\b|enoent/i,
    message: "找不到指定的文件或目录，请确认路径是否正确",
  },
  {
    pattern:
      /permission\s+denied|access\s+is\s+denied|os\s+error\s+5\b|eacces|eperm|requires\s+elevation|os\s+error\s+740\b/i,
    message: "系统权限不足，请检查文件权限或尝试以管理员身份运行",
  },
  {
    pattern:
      /being\s+used\s+by\s+another\s+process|os\s+error\s+32\b|text\s+file\s+busy|sharing\s+violation/i,
    message: "目标文件正被其它程序占用，请关闭相关程序后重试",
  },
  {
    pattern: /no\s+space\s+left|disk\s+full|os\s+error\s+112\b/i,
    message: "磁盘空间不足，请清理空间后重试",
  },
  {
    pattern:
      /eof\s+while\s+parsing|expected\s+value\s+at\s+line|serde_json|trailing\s+characters|invalid\s+json|unexpected\s+token.*json/i,
    message: "返回内容或配置文件格式有误，请检查内容是否完整",
  },
  {
    pattern: /serde_yaml|while\s+scanning|mapping\s+values\s+are\s+not\s+allowed|invalid\s+yaml/i,
    message: "配置文件 YAML 格式有误，请检查缩进与语法",
  },
  {
    pattern: /database\s+is\s+locked|sqlite.*(?:locked|busy)/i,
    message: "本地数据正在写入，请稍等片刻后重试",
  },
  {
    pattern: /poisonerror|lock\s+poisoned/i,
    message: "后台任务状态异常，请重试或重启猫猫云梯",
  },
];

function matchFriendlyErrorRule(text: string): string | null {
  for (const rule of FRIENDLY_ERROR_RULES) {
    if (rule.pattern.test(text)) {
      return rule.message;
    }
  }
  return null;
}

function translateRawErrorMessage(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return "操作未完成，请稍后重试";
  // Preserve structured privilege elevation sentinel consumed by toggleTun / event handlers
  if (trimmed.includes("NEEDS_ADMIN:")) {
    return trimmed;
  }

  const cleaned = trimmed.replace(/^(?:Error|IPC error|invoke error):\s*/i, "").trim();
  const chinesePrefixMatch = /^([^\n:：]{2,32})[：:]\s*(.+)$/s.exec(cleaned);
  if (chinesePrefixMatch) {
    const prefix = chinesePrefixMatch[1].trim();
    const rest = chinesePrefixMatch[2].trim();
    const prefixHasChinese = /[\u4e00-\u9fa5]{2,}/.test(prefix);
    if (prefixHasChinese) {
      const mappedRest = matchFriendlyErrorRule(rest);
      if (mappedRest) {
        return `${prefix}：${mappedRest}`;
      }
    }
  }

  const mappedWhole = matchFriendlyErrorRule(cleaned);
  if (mappedWhole) {
    return mappedWhole;
  }

  return cleaned;
}

export function formatErrorMessage(err: unknown): string {
  let raw: string;
  if (err instanceof Error) {
    raw = err.message;
  } else if (typeof err === "string") {
    raw = err;
  } else if (err && typeof err === "object" && "message" in err && typeof err.message === "string") {
    raw = err.message;
  } else {
    try {
      raw = JSON.stringify(err);
    } catch {
      raw = String(err);
    }
  }
  return translateRawErrorMessage(raw);
}
