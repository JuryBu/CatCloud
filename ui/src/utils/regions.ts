export type ContinentId =
  | "all"
  | "common"
  | "asia"
  | "middle_east"
  | "europe"
  | "north_america"
  | "south_america"
  | "oceania"
  | "africa"
  | "other";

export type PhysicalContinentId = Exclude<ContinentId, "all" | "common">;

export interface ContinentMeta {
  id: ContinentId;
  label: string;
}

export const CONTINENT_ORDER: ReadonlyArray<ContinentMeta> = [
  { id: "all", label: "全部" },
  { id: "common", label: "常用" },
  { id: "asia", label: "亚洲" },
  { id: "middle_east", label: "中东" },
  { id: "europe", label: "欧洲" },
  { id: "north_america", label: "北美洲" },
  { id: "south_america", label: "南美洲" },
  { id: "oceania", label: "大洋洲" },
  { id: "africa", label: "非洲" },
  { id: "other", label: "其他" },
];

/**
 * 通用分洲分组标准：「常用」快捷地区按日常使用优先级排序。
 */
export const COMMON_REGION_ORDER: readonly string[] = [
  "HK",
  "TW",
  "SG",
  "JP",
  "US",
  "KR",
  "UK",
  "AU",
  "DE",
  "FR",
  "CA",
  "NL",
  "MY",
  "TH",
  "PH",
  "ID",
  "VN",
  "MX",
  "MO",
];

const COMMON_REGION_SET = new Set<string>(COMMON_REGION_ORDER);

export interface RegionMeta {
  label: string;
  continent: PhysicalContinentId;
}

export const REGION_META: Record<string, RegionMeta> = {
  // Asia
  HK: { label: "中国香港", continent: "asia" },
  TW: { label: "中国台湾", continent: "asia" },
  MO: { label: "中国澳门", continent: "asia" },
  CN: { label: "中国大陆", continent: "asia" },
  JP: { label: "日本", continent: "asia" },
  SG: { label: "新加坡", continent: "asia" },
  KR: { label: "韩国", continent: "asia" },
  MY: { label: "马来西亚", continent: "asia" },
  TH: { label: "泰国", continent: "asia" },
  VN: { label: "越南", continent: "asia" },
  PH: { label: "菲律宾", continent: "asia" },
  ID: { label: "印度尼西亚", continent: "asia" },
  IN: { label: "印度", continent: "asia" },
  KH: { label: "柬埔寨", continent: "asia" },
  MM: { label: "缅甸", continent: "asia" },
  LA: { label: "老挝", continent: "asia" },
  BT: { label: "不丹", continent: "asia" },
  BN: { label: "文莱", continent: "asia" },
  MN: { label: "蒙古", continent: "asia" },
  NP: { label: "尼泊尔", continent: "asia" },
  BD: { label: "孟加拉", continent: "asia" },
  PK: { label: "巴基斯坦", continent: "asia" },
  LK: { label: "斯里兰卡", continent: "asia" },
  MV: { label: "马尔代夫", continent: "asia" },
  TL: { label: "东帝汶", continent: "asia" },
  KZ: { label: "哈萨克斯坦", continent: "asia" },
  TJ: { label: "塔吉克斯坦", continent: "asia" },
  KG: { label: "吉尔吉斯斯坦", continent: "asia" },
  UZ: { label: "乌兹别克斯坦", continent: "asia" },
  TM: { label: "土库曼斯坦", continent: "asia" },
  KP: { label: "朝鲜", continent: "asia" },

  // Middle East (通用分洲分组标准独立大区)
  AE: { label: "阿联酋", continent: "middle_east" },
  SA: { label: "沙特阿拉伯", continent: "middle_east" },
  IL: { label: "以色列", continent: "middle_east" },
  TR: { label: "土耳其", continent: "middle_east" },
  QA: { label: "卡塔尔", continent: "middle_east" },
  KW: { label: "科威特", continent: "middle_east" },
  BH: { label: "巴林", continent: "middle_east" },
  OM: { label: "阿曼", continent: "middle_east" },
  JO: { label: "约旦", continent: "middle_east" },
  YE: { label: "也门", continent: "middle_east" },
  PS: { label: "巴勒斯坦", continent: "middle_east" },
  LB: { label: "黎巴嫩", continent: "middle_east" },
  IQ: { label: "伊拉克", continent: "middle_east" },
  AF: { label: "阿富汗", continent: "middle_east" },
  IR: { label: "伊朗", continent: "middle_east" },
  SY: { label: "叙利亚", continent: "middle_east" },
  AZ: { label: "阿塞拜疆", continent: "middle_east" },
  AM: { label: "亚美尼亚", continent: "middle_east" },
  GE: { label: "格鲁吉亚", continent: "middle_east" },
  CY: { label: "塞浦路斯", continent: "middle_east" },

  // Europe
  UK: { label: "英国", continent: "europe" },
  GB: { label: "英国", continent: "europe" },
  DE: { label: "德国", continent: "europe" },
  FR: { label: "法国", continent: "europe" },
  NL: { label: "荷兰", continent: "europe" },
  CH: { label: "瑞士", continent: "europe" },
  SE: { label: "瑞典", continent: "europe" },
  IT: { label: "意大利", continent: "europe" },
  ES: { label: "西班牙", continent: "europe" },
  IE: { label: "爱尔兰", continent: "europe" },
  RU: { label: "俄罗斯", continent: "europe" },
  DK: { label: "丹麦", continent: "europe" },
  NO: { label: "挪威", continent: "europe" },
  FI: { label: "芬兰", continent: "europe" },
  IS: { label: "冰岛", continent: "europe" },
  CZ: { label: "捷克", continent: "europe" },
  GR: { label: "希腊", continent: "europe" },
  PL: { label: "波兰", continent: "europe" },
  UA: { label: "乌克兰", continent: "europe" },
  HU: { label: "匈牙利", continent: "europe" },
  LU: { label: "卢森堡", continent: "europe" },
  AT: { label: "奥地利", continent: "europe" },
  BE: { label: "比利时", continent: "europe" },
  LT: { label: "立陶宛", continent: "europe" },
  LV: { label: "拉脱维亚", continent: "europe" },
  EE: { label: "爱沙尼亚", continent: "europe" },
  PT: { label: "葡萄牙", continent: "europe" },
  AD: { label: "安道尔", continent: "europe" },
  MT: { label: "马耳他", continent: "europe" },
  XK: { label: "科索沃", continent: "europe" },
  BG: { label: "保加利亚", continent: "europe" },
  HR: { label: "克罗地亚", continent: "europe" },
  RO: { label: "罗马尼亚", continent: "europe" },
  RS: { label: "塞尔维亚", continent: "europe" },
  SK: { label: "斯洛伐克", continent: "europe" },
  SI: { label: "斯洛文尼亚", continent: "europe" },
  MD: { label: "摩尔多瓦", continent: "europe" },
  AL: { label: "阿尔巴尼亚", continent: "europe" },
  MK: { label: "北马其顿", continent: "europe" },
  BA: { label: "波黑", continent: "europe" },
  ME: { label: "黑山", continent: "europe" },
  BY: { label: "白俄罗斯", continent: "europe" },
  MC: { label: "摩纳哥", continent: "europe" },
  SM: { label: "圣马力诺", continent: "europe" },
  LI: { label: "列支敦士登", continent: "europe" },
  GI: { label: "直布罗陀", continent: "europe" },
  IM: { label: "马恩岛", continent: "europe" },
  JE: { label: "泽西岛", continent: "europe" },
  GG: { label: "根西岛", continent: "europe" },
  FO: { label: "法罗群岛", continent: "europe" },
  VA: { label: "梵蒂冈", continent: "europe" },

  // North America
  US: { label: "美国", continent: "north_america" },
  CA: { label: "加拿大", continent: "north_america" },
  MX: { label: "墨西哥", continent: "north_america" },
  GL: { label: "格陵兰", continent: "north_america" },
  PA: { label: "巴拿马", continent: "north_america" },
  CR: { label: "哥斯达黎加", continent: "north_america" },
  JM: { label: "牙买加", continent: "north_america" },
  PR: { label: "波多黎各", continent: "north_america" },
  BM: { label: "百慕大", continent: "north_america" },
  BS: { label: "巴哈马", continent: "north_america" },
  CU: { label: "古巴", continent: "north_america" },
  DO: { label: "多米尼加", continent: "north_america" },
  GT: { label: "危地马拉", continent: "north_america" },
  HN: { label: "洪都拉斯", continent: "north_america" },
  SV: { label: "萨尔瓦多", continent: "north_america" },
  NI: { label: "尼加拉瓜", continent: "north_america" },
  BZ: { label: "伯利兹", continent: "north_america" },
  TT: { label: "特立尼达和多巴哥", continent: "north_america" },
  BB: { label: "巴巴多斯", continent: "north_america" },
  KY: { label: "开曼群岛", continent: "north_america" },
  VG: { label: "英属维尔京群岛", continent: "north_america" },
  HT: { label: "海地", continent: "north_america" },
  CW: { label: "库拉索", continent: "north_america" },

  // South America
  AR: { label: "阿根廷", continent: "south_america" },
  BR: { label: "巴西", continent: "south_america" },
  CL: { label: "智利", continent: "south_america" },
  CO: { label: "哥伦比亚", continent: "south_america" },
  PE: { label: "秘鲁", continent: "south_america" },
  UY: { label: "乌拉圭", continent: "south_america" },
  EC: { label: "厄瓜多尔", continent: "south_america" },
  VE: { label: "委内瑞拉", continent: "south_america" },
  PY: { label: "巴拉圭", continent: "south_america" },
  BO: { label: "玻利维亚", continent: "south_america" },
  GY: { label: "圭亚那", continent: "south_america" },
  SR: { label: "苏里南", continent: "south_america" },

  // Oceania
  AU: { label: "澳大利亚", continent: "oceania" },
  NZ: { label: "新西兰", continent: "oceania" },
  GU: { label: "关岛", continent: "oceania" },
  FJ: { label: "斐济", continent: "oceania" },
  PG: { label: "巴布亚新几内亚", continent: "oceania" },
  NC: { label: "新喀里多尼亚", continent: "oceania" },
  PF: { label: "法属波利尼西亚", continent: "oceania" },
  WS: { label: "萨摩亚", continent: "oceania" },
  TO: { label: "汤加", continent: "oceania" },
  VU: { label: "瓦努阿图", continent: "oceania" },

  // Africa
  ZA: { label: "南非", continent: "africa" },
  EG: { label: "埃及", continent: "africa" },
  NG: { label: "尼日利亚", continent: "africa" },
  KE: { label: "肯尼亚", continent: "africa" },
  MA: { label: "摩洛哥", continent: "africa" },
  TN: { label: "突尼斯", continent: "africa" },
  DZ: { label: "阿尔及利亚", continent: "africa" },
  GH: { label: "加纳", continent: "africa" },
  AO: { label: "安哥拉", continent: "africa" },
  ET: { label: "埃塞俄比亚", continent: "africa" },
  MU: { label: "毛里求斯", continent: "africa" },
  TZ: { label: "坦桑尼亚", continent: "africa" },
  UG: { label: "乌干达", continent: "africa" },
  SN: { label: "塞内加尔", continent: "africa" },
  CI: { label: "科特迪瓦", continent: "africa" },
  CM: { label: "喀麦隆", continent: "africa" },
  MZ: { label: "莫桑比克", continent: "africa" },
  ZW: { label: "津巴布韦", continent: "africa" },
  ZM: { label: "赞比亚", continent: "africa" },
  NA: { label: "纳米比亚", continent: "africa" },
  BW: { label: "博茨瓦纳", continent: "africa" },
  RW: { label: "卢旺达", continent: "africa" },
  LY: { label: "利比亚", continent: "africa" },
  SD: { label: "苏丹", continent: "africa" },
  MG: { label: "马达加斯加", continent: "africa" },
  SC: { label: "塞舌尔", continent: "africa" },
  RE: { label: "留尼汪", continent: "africa" },
  CD: { label: "刚果(金)", continent: "africa" },
  CG: { label: "刚果(布)", continent: "africa" },

  // Other
  AQ: { label: "南极洲", continent: "other" },
  UNK: { label: "其他", continent: "other" },
};

const CHINESE_NAME_FALLBACKS: ReadonlyArray<readonly [string, string]> = [
  ["台湾", "TW"], ["台灣", "TW"], ["台北", "TW"],
  ["香港", "HK"], ["澳门", "MO"], ["澳門", "MO"],
  ["日本", "JP"], ["东京", "JP"], ["大阪", "JP"],
  ["新加坡", "SG"], ["狮城", "SG"], ["韩国", "KR"], ["首尔", "KR"],
  ["美国", "US"], ["洛杉矶", "US"], ["圣何塞", "US"], ["西雅图", "US"], ["硅谷", "US"], ["纽约", "US"],
  ["英国", "UK"], ["伦敦", "UK"], ["德国", "DE"], ["法兰克福", "DE"],
  ["法国", "FR"], ["巴黎", "FR"], ["荷兰", "NL"], ["瑞士", "CH"], ["瑞典", "SE"],
  ["意大利", "IT"], ["西班牙", "ES"], ["爱尔兰", "IE"], ["白俄罗斯", "BY"], ["白俄羅斯", "BY"], ["俄罗斯", "RU"],
  ["加拿大", "CA"], ["澳大利亚", "AU"], ["澳洲", "AU"], ["新西兰", "NZ"],
  ["印度尼西亚", "ID"], ["印度尼西亞", "ID"], ["印尼", "ID"], ["印度", "IN"], ["土耳其", "TR"],
  ["马来西亚", "MY"], ["泰国", "TH"], ["越南", "VN"], ["菲律宾", "PH"],
  ["柬埔寨", "KH"], ["缅甸", "MM"], ["老挝", "LA"], ["文莱", "BN"], ["东帝汶", "TL"],
  ["蒙古", "MN"], ["不丹", "BT"], ["尼泊尔", "NP"], ["孟加拉", "BD"], ["巴基斯坦", "PK"], ["斯里兰卡", "LK"],
  ["哈萨克斯坦", "KZ"], ["乌兹别克斯坦", "UZ"], ["吉尔吉斯斯坦", "KG"], ["塔吉克斯坦", "TJ"],
  ["格陵兰", "GL"], ["墨西哥", "MX"], ["巴拿马", "PA"], ["哥斯达黎加", "CR"], ["牙买加", "JM"],
  ["智利", "CL"], ["阿根廷", "AR"], ["巴西", "BR"], ["哥伦比亚", "CO"], ["秘鲁", "PE"],
  ["乌拉圭", "UY"], ["厄瓜多尔", "EC"], ["委内瑞拉", "VE"],
  ["阿拉伯联合酋长国", "AE"], ["阿联酋", "AE"], ["迪拜", "AE"], ["沙特", "SA"],
  ["以色列", "IL"], ["巴勒斯坦", "PS"], ["卡塔尔", "QA"], ["科威特", "KW"],
  ["巴林", "BH"], ["阿曼", "OM"], ["约旦", "JO"], ["黎巴嫩", "LB"], ["伊拉克", "IQ"], ["也门", "YE"], ["阿富汗", "AF"],
  ["阿塞拜疆", "AZ"], ["亚美尼亚", "AM"], ["格鲁吉亚", "GE"], ["塞浦路斯", "CY"],
  ["丹麦", "DK"], ["挪威", "NO"], ["芬兰", "FI"], ["冰岛", "IS"], ["捷克", "CZ"],
  ["希腊", "GR"], ["波兰", "PL"], ["乌克兰", "UA"], ["匈牙利", "HU"], ["卢森堡", "LU"],
  ["奥地利", "AT"], ["比利时", "BE"], ["立陶宛", "LT"], ["葡萄牙", "PT"], ["罗马尼亚", "RO"],
  ["保加利亚", "BG"], ["克罗地亚", "HR"], ["塞尔维亚", "RS"], ["斯洛伐克", "SK"], ["斯洛文尼亚", "SI"],
  ["爱沙尼亚", "EE"], ["拉脱维亚", "LV"], ["摩尔多瓦", "MD"], ["阿尔巴尼亚", "AL"], ["安道尔", "AD"],
  ["马耳他", "MT"], ["科索沃", "XK"], ["波黑", "BA"], ["北马其顿", "MK"], ["黑山", "ME"],
  ["关岛", "GU"], ["斐济", "FJ"],
  ["南非", "ZA"], ["埃及", "EG"], ["尼日利亚", "NG"], ["肯尼亚", "KE"], ["摩洛哥", "MA"],
  ["突尼斯", "TN"], ["阿尔及利亚", "DZ"], ["加纳", "GH"], ["安哥拉", "AO"], ["埃塞俄比亚", "ET"],
  ["南极洲", "AQ"],
];

/**
 * Decode any Unicode Regional Indicator flag emoji pair (e.g. 🇰🇭 -> "KH", 🇬🇧 -> "UK").
 */
export function extractFlagRegionCode(name: string): string | null {
  const chars = Array.from(name);
  for (let i = 0; i < chars.length - 1; i++) {
    const a = chars[i].codePointAt(0) ?? 0;
    const b = chars[i + 1].codePointAt(0) ?? 0;
    if (a >= 0x1f1e6 && a <= 0x1f1ff && b >= 0x1f1e6 && b <= 0x1f1ff) {
      const code =
        String.fromCharCode(65 + (a - 0x1f1e6)) +
        String.fromCharCode(65 + (b - 0x1f1e6));
      return code === "GB" ? "UK" : code;
    }
  }
  return null;
}

export function normalizeRegionCode(code: string | null | undefined): string {
  const clean = (code ?? "").trim().toUpperCase();
  if (!clean) return "UNK";
  if (clean === "GB") return "UK";
  return clean;
}

/**
 * Resolve a node's accurate 2-letter region code even if legacy SQLite stored "UNK".
 */
export function resolveNodeRegionCode(node: {
  region_code?: string | null;
  name: string;
}): string {
  const stored = normalizeRegionCode(node.region_code);
  if (stored !== "UNK") return stored;

  const flagCode = extractFlagRegionCode(node.name);
  if (flagCode) return flagCode;

  for (const [kw, code] of CHINESE_NAME_FALLBACKS) {
    if (node.name.includes(kw)) return code;
  }

  return "UNK";
}

export function getRegionLabel(code: string): string {
  const norm = normalizeRegionCode(code);
  return REGION_META[norm]?.label ?? norm;
}

export function getRegionDisplay(code: string): string {
  const norm = normalizeRegionCode(code);
  const label = REGION_META[norm]?.label;
  if (!label) return norm;
  if (norm === "UNK") return label;
  return `${label} (${norm})`;
}

export function getRegionContinent(code: string): PhysicalContinentId {
  const norm = normalizeRegionCode(code);
  return REGION_META[norm]?.continent ?? "other";
}

export function isCommonRegion(code: string): boolean {
  return COMMON_REGION_SET.has(normalizeRegionCode(code));
}

export function getContinentLabel(id: ContinentId): string {
  return CONTINENT_ORDER.find((c) => c.id === id)?.label ?? "其他";
}

export function nodeMatchesContinentAndRegion(
  node: { region_code?: string | null; name: string },
  continent: ContinentId,
  region: string
): boolean {
  const code = resolveNodeRegionCode(node);
  if (region !== "all" && code !== normalizeRegionCode(region)) {
    return false;
  }
  if (continent === "all") return true;
  if (continent === "common") return isCommonRegion(code);
  return getRegionContinent(code) === continent;
}

export interface RegionCountEntry {
  code: string;
  label: string;
  count: number;
  continent: PhysicalContinentId;
}

export interface ContinentStatsSummary {
  total: number;
  continentCounts: Record<ContinentId, number>;
  regionsByContinent: Record<ContinentId, RegionCountEntry[]>;
  allRegions: RegionCountEntry[];
}

export function buildContinentRegionStats(
  nodes: ReadonlyArray<{ region_code?: string | null; name: string }>
): ContinentStatsSummary {
  const codeCounts = new Map<string, number>();
  for (const n of nodes) {
    const code = resolveNodeRegionCode(n);
    codeCounts.set(code, (codeCounts.get(code) ?? 0) + 1);
  }

  const allRegions: RegionCountEntry[] = Array.from(codeCounts.entries())
    .map(([code, count]) => ({
      code,
      label: getRegionLabel(code),
      count,
      continent: getRegionContinent(code),
    }))
    .sort((a, b) => {
      if (a.code === "UNK" && b.code !== "UNK") return 1;
      if (b.code === "UNK" && a.code !== "UNK") return -1;
      return b.count - a.count || a.label.localeCompare(b.label, "zh-CN");
    });

  const continentCounts: Record<ContinentId, number> = {
    all: nodes.length,
    common: 0,
    asia: 0,
    middle_east: 0,
    europe: 0,
    north_america: 0,
    south_america: 0,
    oceania: 0,
    africa: 0,
    other: 0,
  };

  const regionsByContinent: Record<ContinentId, RegionCountEntry[]> = {
    all: allRegions,
    common: [],
    asia: [],
    middle_east: [],
    europe: [],
    north_america: [],
    south_america: [],
    oceania: [],
    africa: [],
    other: [],
  };

  for (const entry of allRegions) {
    continentCounts[entry.continent] += entry.count;
    regionsByContinent[entry.continent].push(entry);
    if (isCommonRegion(entry.code)) {
      continentCounts.common += entry.count;
      regionsByContinent.common.push(entry);
    }
  }

  // 按通用分洲分组标准日常优先级排序 "common"
  regionsByContinent.common.sort((a, b) => {
    const ia = COMMON_REGION_ORDER.indexOf(a.code);
    const ib = COMMON_REGION_ORDER.indexOf(b.code);
    return (ia === -1 ? 999 : ia) - (ib === -1 ? 999 : ib);
  });

  return {
    total: nodes.length,
    continentCounts,
    regionsByContinent,
    allRegions,
  };
}
