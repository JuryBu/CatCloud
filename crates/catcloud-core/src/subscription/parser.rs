use crate::error::{CatError, CatResult};
use crate::models::{ProxyNode, SubscriptionKind, SubscriptionRecord};
use crate::storage::Storage;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;
use url::Url;

/// Maximum accepted subscription payload size (16 MiB).
pub const MAX_SUBSCRIPTION_BYTES: usize = 16 * 1024 * 1024;

/// Default User-Agent advertised when fetching remote subscription URLs.
pub const DEFAULT_SUBSCRIPTION_USER_AGENT: &str = "CatCloud/0.1 (clash.meta; mihomo)";

/// Parsed quota and expiration metadata from the `Subscription-Userinfo` HTTP header.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionUserInfo {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: u64,
    pub expire_timestamp: Option<i64>,
    pub expires_at: Option<String>,
}

impl SubscriptionUserInfo {
    /// Combined upload + download traffic in bytes (saturating).
    pub fn used_bytes(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }
}

/// Detected wire format of a subscription payload.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionPayloadFormat {
    ClashYaml,
    Base64UriList,
    PlainUriList,
}

/// Normalized output from parsing a subscription payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ParsedSubscription {
    pub format: SubscriptionPayloadFormat,
    pub nodes: Vec<ProxyNode>,
    pub userinfo: Option<SubscriptionUserInfo>,
    pub etag: Option<String>,
    pub warnings: Vec<String>,
}

/// Network transport options for fetching remote subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FetchOptions {
    /// When `true`, configure `reqwest` with `.no_proxy()` to bypass system proxies.
    pub no_proxy: bool,
    /// Optional explicit proxy URL used only when `no_proxy` is `false`.
    pub proxy_url: Option<String>,
    /// HTTP User-Agent header sent during fetch.
    pub user_agent: String,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            no_proxy: true,
            proxy_url: None,
            user_agent: DEFAULT_SUBSCRIPTION_USER_AGENT.to_string(),
        }
    }
}

/// Parse a `Subscription-Userinfo` header such as:
/// `upload=1024; download=2048; total=10737418240; expire=1798761600`.
pub fn parse_userinfo_header(header: &str) -> Option<SubscriptionUserInfo> {
    let trimmed = header.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut info = SubscriptionUserInfo::default();
    let mut matched_any = false;

    for segment in trimmed.split([';', ',']) {
        let part = segment.trim();
        if part.is_empty() {
            continue;
        }
        let Some((raw_k, raw_v)) = part.split_once('=') else {
            continue;
        };
        let key = raw_k.trim().to_ascii_lowercase();
        let val = raw_v.trim();
        if val.is_empty() {
            continue;
        }

        match key.as_str() {
            "upload" => {
                if let Some(n) = parse_nonneg_u64(val) {
                    info.upload_bytes = n;
                    matched_any = true;
                }
            }
            "download" => {
                if let Some(n) = parse_nonneg_u64(val) {
                    info.download_bytes = n;
                    matched_any = true;
                }
            }
            "total" => {
                if let Some(n) = parse_nonneg_u64(val) {
                    info.total_bytes = n;
                    matched_any = true;
                }
            }
            "expire" => {
                if let Some(ts) = parse_i64_flexible(val) {
                    matched_any = true;
                    if ts > 0 {
                        info.expire_timestamp = Some(ts);
                        info.expires_at = DateTime::<Utc>::from_timestamp(ts, 0)
                            .map(|dt| dt.to_rfc3339());
                    } else {
                        info.expire_timestamp = None;
                        info.expires_at = None;
                    }
                }
            }
            _ => {}
        }
    }

    matched_any.then_some(info)
}

/// Extract a traffic billing multiplier from a node name (defaults to `1.0`).
/// Supports forms like `0.5x`, `2x`, `x3`, `X1.5`, `1.5倍`, `0.2倍率`, `2×`.
pub fn extract_multiplier(name: &str) -> f64 {
    static SUFFIX_RE: OnceLock<Regex> = OnceLock::new();
    static PREFIX_RE: OnceLock<Regex> = OnceLock::new();

    let suffix_re = SUFFIX_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^0-9a-zA-Z.])(\d+(?:\.\d+)?)\s*(?:x|×|✕|倍(?:率)?)(?:$|[^0-9a-zA-Z])")
            .expect("valid suffix multiplier regex")
    });
    if let Some(caps) = suffix_re.captures(name) {
        if let Some(m) = caps.get(1) {
            if let Ok(v) = m.as_str().parse::<f64>() {
                if v.is_finite() && (0.0..=100.0).contains(&v) {
                    return v;
                }
            }
        }
    }

    let prefix_re = PREFIX_RE.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[^0-9a-zA-Z.])(?:x|×|✕)\s*(\d+(?:\.\d+)?)(?:$|[^0-9a-zA-Z])")
            .expect("valid prefix multiplier regex")
    });
    if let Some(caps) = prefix_re.captures(name) {
        if let Some(m) = caps.get(1) {
            if let Ok(v) = m.as_str().parse::<f64>() {
                if v.is_finite() && (0.0..=100.0).contains(&v) {
                    return v;
                }
            }
        }
    }

    1.0
}

/// Decode any standard Unicode Regional Indicator flag emoji pair (e.g. `🇰🇭` -> `"KH"`,
/// `🇳🇿` -> `"NZ"`, `🇬🇧` -> `"UK"`) into a two-letter uppercase ISO region code.
fn extract_flag_region_code(name: &str) -> Option<String> {
    let mut prev: Option<u8> = None;
    for ch in name.chars() {
        if ('\u{1F1E6}'..='\u{1F1FF}').contains(&ch) {
            let letter = b'A' + ((ch as u32 - 0x1F1E6) as u8);
            if let Some(first) = prev {
                let pair = [first, letter];
                let code = std::str::from_utf8(&pair).ok()?;
                return Some(if code == "GB" {
                    "UK".to_string()
                } else {
                    code.to_string()
                });
            }
            prev = Some(letter);
        } else {
            prev = None;
        }
    }
    None
}

/// Infer a two-letter ISO region code from a node display name (defaults to `"UNK"`).
pub fn detect_region_code(name: &str) -> String {
    // 1. Universal Unicode Regional Indicator flag emoji pair decoder (highest priority, covers 240+ flags)
    if let Some(code) = extract_flag_region_code(name) {
        return code;
    }

    let upper = name.to_ascii_uppercase();

    // 2. Chinese and full English place names (low false-positive rate; more specific names placed first)
    const PHRASE_RULES: &[(&[&str], &str)] = &[
        // East & Southeast Asia
        (&["台湾", "台灣", "台北", "臺北", "新北", "彰化", "高雄", "TAIWAN", "TAIPEI"], "TW"),
        (&["香港", "HONG KONG", "HONGKONG"], "HK"),
        (&["澳门", "澳門", "MACAU", "MACAO"], "MO"),
        (&["日本", "东京", "東京", "大阪", "埼玉", "名古屋", "JAPAN", "TOKYO", "OSAKA"], "JP"),
        (&["新加坡", "狮城", "獅城", "SINGAPORE"], "SG"),
        (&["韩国", "韓國", "首尔", "首爾", "春川", "KOREA", "SEOUL"], "KR"),
        (&["马来西亚", "馬來西亞", "吉隆坡", "MALAYSIA"], "MY"),
        (&["泰国", "泰國", "曼谷", "THAILAND", "BANGKOK"], "TH"),
        (&["越南", "河内", "胡志明", "VIETNAM"], "VN"),
        (&["菲律宾", "菲律賓", "马尼拉", "PHILIPPINES", "MANILA"], "PH"),
        (&["印度尼西亚", "印度尼西亞", "印尼", "雅加达", "INDONESIA", "JAKARTA"], "ID"),
        (&["柬埔寨", "金边", "CAMBODIA"], "KH"),
        (&["缅甸", "緬甸", "仰光", "MYANMAR", "BURMA"], "MM"),
        (&["老挝", "寮国", "寮國", "LAOS"], "LA"),
        (&["文莱", "汶莱", "汶萊", "BRUNEI"], "BN"),
        (&["东帝汶", "東帝汶", "TIMOR-LESTE", "EAST TIMOR"], "TL"),
        // South & Central Asia
        (&["印度", "孟买", "孟買", "新德里", "班加罗尔", "INDIA", "MUMBAI"], "IN"),
        (&["巴基斯坦", "PAKISTAN"], "PK"),
        (&["孟加拉", "BANGLADESH"], "BD"),
        (&["尼泊尔", "尼泊爾", "NEPAL"], "NP"),
        (&["斯里兰卡", "斯里蘭卡", "SRI LANKA"], "LK"),
        (&["不丹", "BHUTAN"], "BT"),
        (&["蒙古", "MONGOLIA"], "MN"),
        (&["哈萨克斯坦", "哈薩克斯坦", "哈萨克", "KAZAKHSTAN"], "KZ"),
        (&["乌兹别克斯坦", "烏茲別克斯坦", "UZBEKISTAN"], "UZ"),
        (&["吉尔吉斯斯坦", "KYRGYZSTAN"], "KG"),
        (&["塔吉克斯坦", "TAJIKISTAN"], "TJ"),
        (&["土库曼斯坦", "TURKMENISTAN"], "TM"),
        (&["阿富汗", "AFGHANISTAN"], "AF"),
        // Middle East & Caucasus
        (&["阿联酋", "阿聯酋", "阿拉伯联合酋长国", "迪拜", "杜拜", "阿布扎比", "UNITED ARAB EMIRATES", "DUBAI"], "AE"),
        (&["沙特", "沙乌地", "沙烏地", "利雅得", "SAUDI ARABIA", "SAUDI"], "SA"),
        (&["以色列", "特拉维夫", "ISRAEL"], "IL"),
        (&["巴勒斯坦", "PALESTINE"], "PS"),
        (&["土耳其", "伊斯坦布尔", "TURKEY", "TURKIYE", "ISTANBUL"], "TR"),
        (&["卡塔尔", "卡達", "多哈", "QATAR"], "QA"),
        (&["科威特", "KUWAIT"], "KW"),
        (&["巴林", "BAHRAIN"], "BH"),
        (&["罗马尼亚", "羅馬尼亞", "布加勒斯特", "ROMANIA"], "RO"),
        (&["阿曼", "OMAN"], "OM"),
        (&["约旦", "約旦", "JORDAN"], "JO"),
        (&["黎巴嫩", "LEBANON"], "LB"),
        (&["伊拉克", "IRAQ"], "IQ"),
        (&["也门", "葉門", "YEMEN"], "YE"),
        (&["亚美尼亚", "亞美尼亞", "ARMENIA"], "AM"),
        (&["阿塞拜疆", "AZERBAIJAN"], "AZ"),
        (&["格鲁吉亚", "喬治亞", "GEORGIA"], "GE"),
        // Europe (place compound names before substrings: 罗马尼亚>罗马, 都柏林>柏林, 白俄罗斯>俄罗斯)
        (&["爱尔兰", "愛爾蘭", "都柏林", "IRELAND", "DUBLIN"], "IE"),
        (&["英国", "英國", "伦敦", "倫敦", "UNITED KINGDOM", "BRITAIN", "LONDON"], "UK"),
        (&["德国", "德國", "法兰克福", "法蘭克福", "柏林", "GERMANY", "FRANKFURT"], "DE"),
        (&["法国", "法國", "巴黎", "马赛", "FRANCE", "PARIS"], "FR"),
        (&["荷兰", "荷蘭", "阿姆斯特丹", "NETHERLANDS", "AMSTERDAM"], "NL"),
        (&["瑞士", "苏黎世", "蘇黎世", "SWITZERLAND", "ZURICH"], "CH"),
        (&["瑞典", "斯德哥尔摩", "SWEDEN", "STOCKHOLM"], "SE"),
        (&["意大利", "義大利", "米兰", "米蘭", "罗马", "ITALY", "MILAN"], "IT"),
        (&["西班牙", "马德里", "馬德里", "巴塞罗那", "SPAIN", "MADRID"], "ES"),
        (&["白俄罗斯", "白俄羅斯", "BELARUS"], "BY"),
        (&["俄罗斯", "俄羅斯", "莫斯科", "圣彼得堡", "RUSSIA", "MOSCOW"], "RU"),
        (&["丹麦", "丹麥", "哥本哈根", "DENMARK"], "DK"),
        (&["挪威", "奥斯陆", "NORWAY", "OSLO"], "NO"),
        (&["芬兰", "芬蘭", "赫尔辛基", "FINLAND", "HELSINKI"], "FI"),
        (&["冰岛", "冰島", "雷克雅未克", "ICELAND"], "IS"),
        (&["捷克", "布拉格", "CZECH", "PRAGUE"], "CZ"),
        (&["希腊", "希臘", "雅典", "GREECE", "ATHENS"], "GR"),
        (&["波兰", "波蘭", "华沙", "華沙", "POLAND", "WARSAW"], "PL"),
        (&["乌克兰", "烏克蘭", "基辅", "UKRAINE", "KYIV"], "UA"),
        (&["匈牙利", "布达佩斯", "HUNGARY", "BUDAPEST"], "HU"),
        (&["卢森堡", "盧森堡", "LUXEMBOURG"], "LU"),
        (&["奥地利", "奧地利", "维也纳", "AUSTRIA", "VIENNA"], "AT"),
        (&["比利时", "比利時", "布鲁塞尔", "BELGIUM", "BRUSSELS"], "BE"),
        (&["立陶宛", "维尔纽斯", "LITHUANIA"], "LT"),
        (&["葡萄牙", "里斯本", "PORTUGAL", "LISBON"], "PT"),
        (&["保加利亚", "保加利亞", "索非亚", "BULGARIA"], "BG"),
        (&["克罗地亚", "克羅地亞", "克罗埃西亚", "CROATIA"], "HR"),
        (&["塞尔维亚", "塞爾維亞", "贝尔格莱德", "SERBIA"], "RS"),
        (&["斯洛伐克", "SLOVAKIA"], "SK"),
        (&["斯洛文尼亚", "斯洛維尼亞", "SLOVENIA"], "SI"),
        (&["爱沙尼亚", "愛沙尼亞", "塔林", "ESTONIA"], "EE"),
        (&["拉脱维亚", "拉脫維亞", "里加", "LATVIA"], "LV"),
        (&["摩尔多瓦", "摩爾多瓦", "MOLDOVA"], "MD"),
        (&["阿尔巴尼亚", "阿爾巴尼亞", "ALBANIA"], "AL"),
        (&["北马其顿", "北馬其頓", "马其顿", "NORTH MACEDONIA", "MACEDONIA"], "MK"),
        (&["波黑", "波斯尼亚", "波士尼亞", "BOSNIA"], "BA"),
        (&["塞浦路斯", "賽普勒斯", "CYPRUS"], "CY"),
        (&["马耳他", "馬爾他", "MALTA"], "MT"),
        (&["安道尔", "安道爾", "ANDORRA"], "AD"),
        (&["科索沃", "KOSOVO"], "XK"),
        (&["摩纳哥", "摩納哥", "MONACO"], "MC"),
        (&["圣马力诺", "聖馬利諾", "SAN MARINO"], "SM"),
        (&["直布罗陀", "直布羅陀", "GIBRALTAR"], "GI"),
        // North America
        (
            &[
                "美国", "美國", "洛杉矶", "洛杉磯", "圣何塞", "聖何塞", "西雅图", "西雅圖",
                "硅谷", "矽谷", "纽约", "紐約", "芝加哥", "达拉斯", "達拉斯", "凤凰城",
                "迈阿密", "亚特兰大", "华盛顿", "波士顿", "阿什本",
                "UNITED STATES", "AMERICA", "LOS ANGELES", "SAN JOSE", "SEATTLE", "NEW YORK",
                "SILICON VALLEY", "DALLAS", "CHICAGO", "MIAMI", "ASHBURN",
            ],
            "US",
        ),
        (&["加拿大", "多伦多", "多倫多", "温哥华", "溫哥華", "蒙特利尔", "CANADA", "TORONTO", "VANCOUVER"], "CA"),
        (&["墨西哥", "MEXICO"], "MX"),
        (&["格陵兰", "格陵蘭", "GREENLAND"], "GL"),
        (&["巴拿马", "巴拿馬", "PANAMA"], "PA"),
        (&["哥斯达黎加", "哥斯大黎加", "COSTA RICA"], "CR"),
        (&["牙买加", "牙買加", "JAMAICA"], "JM"),
        (&["波多黎各", "PUERTO RICO"], "PR"),
        (&["百慕大", "BERMUDA"], "BM"),
        (&["巴哈马", "巴哈馬", "BAHAMAS"], "BS"),
        (&["古巴", "CUBA"], "CU"),
        // South America
        (&["阿根廷", "布宜诺斯艾利斯", "ARGENTINA"], "AR"),
        (&["巴西", "圣保罗", "聖保羅", "BRAZIL"], "BR"),
        (&["智利", "圣地亚哥", "CHILE"], "CL"),
        (&["哥伦比亚", "哥倫比亞", "波哥大", "COLOMBIA"], "CO"),
        (&["秘鲁", "秘魯", "利马", "PERU"], "PE"),
        (&["乌拉圭", "烏拉圭", "URUGUAY"], "UY"),
        (&["厄瓜多尔", "厄瓜多爾", "ECUADOR"], "EC"),
        (&["委内瑞拉", "委內瑞拉", "VENEZUELA"], "VE"),
        (&["巴拉圭", "PARAGUAY"], "PY"),
        (&["玻利维亚", "玻利維亞", "BOLIVIA"], "BO"),
        // Oceania
        (&["澳大利亚", "澳大利亞", "澳洲", "悉尼", "墨尔本", "墨爾本", "AUSTRALIA", "SYDNEY", "MELBOURNE"], "AU"),
        (&["新西兰", "紐西蘭", "新西蘭", "奥克兰", "奧克蘭", "NEW ZEALAND", "AUCKLAND"], "NZ"),
        (&["关岛", "關島", "GUAM"], "GU"),
        (&["斐济", "斐濟", "FIJI"], "FJ"),
        (&["巴布亚新几内亚", "巴布亞紐幾內亞", "PAPUA NEW GUINEA"], "PG"),
        // Africa
        (&["南非", "约翰内斯堡", "开普敦", "SOUTH AFRICA", "JOHANNESBURG"], "ZA"),
        (&["埃及", "开罗", "EGYPT", "CAIRO"], "EG"),
        (&["尼日利亚", "奈及利亞", "拉各斯", "NIGERIA", "LAGOS"], "NG"),
        (&["肯尼亚", "肯亞", "内罗毕", "KENYA"], "KE"),
        (&["摩洛哥", "MOROCCO"], "MA"),
        (&["突尼斯", "突尼西亞", "TUNISIA"], "TN"),
        (&["阿尔及利亚", "阿爾及利亞", "ALGERIA"], "DZ"),
        (&["加纳", "迦納", "GHANA"], "GH"),
        (&["安哥拉", "ANGOLA"], "AO"),
        (&["埃塞俄比亚", "衣索比亞", "ETHIOPIA"], "ET"),
        (&["毛里求斯", "模里西斯", "MAURITIUS"], "MU"),
        (&["坦桑尼亚", "坦尚尼亞", "TANZANIA"], "TZ"),
        (&["乌干达", "烏干達", "UGANDA"], "UG"),
        // Special / Other
        (&["南极洲", "南極洲", "南极", "南極", "ANTARCTICA"], "AQ"),
    ];
    for &(patterns, code) in PHRASE_RULES {
        for &pat in patterns {
            if name.contains(pat) || upper.contains(pat) {
                return code.to_string();
            }
        }
    }

    // 3. Standalone ASCII region tokens with non-alphabetic boundaries
    const TOKEN_RULES: &[(&str, &str)] = &[
        ("TW", "TW"),
        ("TWN", "TW"),
        ("HK", "HK"),
        ("HKG", "HK"),
        ("MO", "MO"),
        ("JP", "JP"),
        ("JPN", "JP"),
        ("SG", "SG"),
        ("SGP", "SG"),
        ("KR", "KR"),
        ("KOR", "KR"),
        ("US", "US"),
        ("USA", "US"),
        ("UK", "UK"),
        ("GB", "UK"),
        ("GBR", "UK"),
        ("DE", "DE"),
        ("DEU", "DE"),
        ("FR", "FR"),
        ("NL", "NL"),
        ("CA", "CA"),
        ("AU", "AU"),
        ("IN", "IN"),
        ("TR", "TR"),
        ("MY", "MY"),
        ("TH", "TH"),
        ("VN", "VN"),
        ("PH", "PH"),
        ("RU", "RU"),
        ("AR", "AR"),
        ("BR", "BR"),
        ("CH", "CH"),
        ("SE", "SE"),
        ("IT", "IT"),
        ("ES", "ES"),
        ("IE", "IE"),
        ("KH", "KH"),
        ("MM", "MM"),
        ("NZ", "NZ"),
        ("DK", "DK"),
        ("FI", "FI"),
        ("CZ", "CZ"),
        ("GR", "GR"),
        ("PL", "PL"),
        ("UA", "UA"),
        ("HU", "HU"),
        ("LU", "LU"),
        ("BE", "BE"),
        ("LT", "LT"),
        ("PT", "PT"),
        ("BG", "BG"),
        ("HR", "HR"),
        ("RO", "RO"),
        ("RS", "RS"),
        ("SK", "SK"),
        ("LV", "LV"),
        ("IL", "IL"),
        ("AE", "AE"),
        ("SA", "SA"),
        ("QA", "QA"),
        ("KW", "KW"),
        ("BH", "BH"),
        ("JO", "JO"),
        ("KZ", "KZ"),
        ("UZ", "UZ"),
        ("PK", "PK"),
        ("BD", "BD"),
        ("NP", "NP"),
        ("LK", "LK"),
        ("MN", "MN"),
        ("MX", "MX"),
        ("CL", "CL"),
        ("ZA", "ZA"),
        ("EG", "EG"),
        ("NG", "NG"),
        ("KE", "KE"),
        ("XK", "XK"),
        ("BN", "BN"),
        ("TL", "TL"),
        ("GL", "GL"),
        ("AQ", "AQ"),
    ];
    for &(token, code) in TOKEN_RULES {
        if contains_ascii_token(&upper, token) {
            return code.to_string();
        }
    }

    "UNK".to_string()
}

/// Detect whether a node uses a native TLS/REALITY/443 transport profile
/// suitable for skipping domestic pre-acceleration when `skip_443_native` is enabled.
pub fn detect_is_443_native(
    protocol: &str,
    port: u16,
    raw_config: &serde_json::Value,
) -> bool {
    if port != 443 {
        return false;
    }

    let proto = normalize_protocol(protocol);
    let has_reality = raw_config
        .get("reality-opts")
        .is_some_and(|v| !v.is_null());
    let tls_flag = raw_config.get("tls").and_then(serde_json::Value::as_bool);

    match proto.as_str() {
        "trojan" | "anytls" | "hysteria2" | "tuic" | "hysteria" => true,
        "vless" => {
            if has_reality {
                true
            } else {
                // VLESS on port 443 defaults to TLS/REALITY unless explicitly disabled.
                tls_flag.unwrap_or(true)
            }
        }
        "vmess" | "http" | "socks5" => has_reality || tls_flag.unwrap_or(false),
        "ss" => {
            if has_reality || tls_flag.unwrap_or(false) {
                return true;
            }
            raw_config
                .get("plugin-opts")
                .and_then(|o| o.get("tls"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        }
        _ => has_reality || tls_flag.unwrap_or(false),
    }
}

/// Normalize protocol alias strings to canonical lowercase Mihomo names.
pub fn normalize_protocol(proto: &str) -> String {
    match proto.trim().to_ascii_lowercase().as_str() {
        "hy2" | "hysteria2" => "hysteria2".to_string(),
        "shadowsocks" | "ss" => "ss".to_string(),
        "socks" | "socks5" => "socks5".to_string(),
        other => other.to_string(),
    }
}

/// Extract descriptive tags from node display metadata.
pub fn extract_auto_tags(name: &str, multiplier: f64) -> Vec<String> {
    let upper = name.to_ascii_uppercase();
    let mut tags = Vec::new();
    let mut push = |tag: &str| {
        if !tags.iter().any(|t: &String| t == tag) {
            tags.push(tag.to_string());
        }
    };

    if name.contains("家宽")
        || name.contains("家寬")
        || name.contains("住宅")
        || upper.contains("RESIDENTIAL")
        || contains_ascii_token(&upper, "ISP")
    {
        push("residential");
    }
    if name.contains("原生") || upper.contains("NATIVE") {
        push("native");
    }
    if upper.contains("IPLC") || upper.contains("IEPL") || name.contains("专线") || name.contains("專線")
    {
        push("iplc");
    }
    if name.contains("中转") || name.contains("中轉") || upper.contains("RELAY") {
        push("relay");
    }
    if name.contains("直连") || name.contains("直連") || contains_ascii_token(&upper, "DIRECT") {
        push("direct");
    }
    if contains_ascii_token(&upper, "AI")
        || upper.contains("CHATGPT")
        || upper.contains("OPENAI")
        || upper.contains("CLAUDE")
        || upper.contains("GEMINI")
    {
        push("ai");
    }
    if multiplier == 0.0 || name.contains("免费") || name.contains("免費") {
        push("free");
    }

    tags
}

/// Parse a raw subscription payload (Clash/Mihomo YAML, Base64 URI list, or plain URI list).
///
/// Enforces strict refresh protection:
/// - Rejects payloads exceeding `MAX_SUBSCRIPTION_BYTES` (16 MiB)
/// - Rejects malformed YAML
/// - Rejects payloads that yield zero valid proxy nodes
pub fn parse_subscription_payload(
    sub_id: &str,
    raw: &[u8],
    userinfo_header: Option<&str>,
) -> CatResult<ParsedSubscription> {
    if sub_id.trim().is_empty() {
        return Err(CatError::Validation(
            "subscription id cannot be empty".to_string(),
        ));
    }
    if raw.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(CatError::Validation(format!(
            "subscription payload size {} bytes exceeds maximum allowed {} bytes",
            raw.len(),
            MAX_SUBSCRIPTION_BYTES
        )));
    }

    let text_raw = std::str::from_utf8(raw).map_err(|e| {
        CatError::Validation(format!("subscription payload is not valid UTF-8: {e}"))
    })?;
    let text = text_raw.strip_prefix('\u{FEFF}').unwrap_or(text_raw).trim();
    if text.is_empty() {
        return Err(CatError::Validation(
            "subscription payload is empty".to_string(),
        ));
    }

    let userinfo = userinfo_header.and_then(parse_userinfo_header);

    // 1. Plain URI list check (before YAML so URI lines with colons are never misclassified as YAML)
    if looks_like_uri_list(text) {
        let (nodes, warnings) = parse_uri_lines(sub_id, text);
        if nodes.is_empty() {
            return Err(CatError::Validation(
                "plain URI subscription parsed 0 valid nodes".to_string(),
            ));
        }
        return Ok(ParsedSubscription {
            format: SubscriptionPayloadFormat::PlainUriList,
            nodes,
            userinfo,
            etag: None,
            warnings,
        });
    }

    // 2. Explicit Clash/Mihomo YAML structure check (malformed YAML must return Err immediately)
    if looks_like_clash_yaml(text) {
        let yaml_val = parse_clash_yaml_value(text)?;
        let (nodes, warnings) = extract_nodes_from_clash_yaml(sub_id, &yaml_val)?;
        if nodes.is_empty() {
            return Err(CatError::Validation(
                "Clash YAML subscription parsed 0 valid nodes".to_string(),
            ));
        }
        return Ok(ParsedSubscription {
            format: SubscriptionPayloadFormat::ClashYaml,
            nodes,
            userinfo,
            etag: None,
            warnings,
        });
    }

    // 3. Base64-encoded URI list (or Base64-wrapped Clash YAML)
    if let Some(decoded_bytes) = decode_base64_flexible(text) {
        if decoded_bytes.len() > MAX_SUBSCRIPTION_BYTES {
            return Err(CatError::Validation(format!(
                "decoded subscription payload size {} bytes exceeds maximum {} bytes",
                decoded_bytes.len(),
                MAX_SUBSCRIPTION_BYTES
            )));
        }
        if let Ok(decoded_raw) = std::str::from_utf8(&decoded_bytes) {
            let decoded = decoded_raw.strip_prefix('\u{FEFF}').unwrap_or(decoded_raw).trim();
            if looks_like_uri_list(decoded) {
                let (nodes, warnings) = parse_uri_lines(sub_id, decoded);
                if nodes.is_empty() {
                    return Err(CatError::Validation(
                        "Base64 URI subscription parsed 0 valid nodes".to_string(),
                    ));
                }
                return Ok(ParsedSubscription {
                    format: SubscriptionPayloadFormat::Base64UriList,
                    nodes,
                    userinfo,
                    etag: None,
                    warnings,
                });
            }
            if looks_like_clash_yaml(decoded) {
                let yaml_val = parse_clash_yaml_value(decoded)?;
                let (nodes, warnings) = extract_nodes_from_clash_yaml(sub_id, &yaml_val)?;
                if nodes.is_empty() {
                    return Err(CatError::Validation(
                        "Base64-wrapped Clash YAML subscription parsed 0 valid nodes".to_string(),
                    ));
                }
                return Ok(ParsedSubscription {
                    format: SubscriptionPayloadFormat::ClashYaml,
                    nodes,
                    userinfo,
                    etag: None,
                    warnings,
                });
            }
        }
    }

    // 4. Fallback: try parsing as YAML in case the document uses anchors or unusual ordering
    let yaml_val = parse_clash_yaml_value(text)?;
    let (nodes, warnings) = extract_nodes_from_clash_yaml(sub_id, &yaml_val)?;
    if nodes.is_empty() {
        return Err(CatError::Validation(
            "subscription parsed 0 valid nodes".to_string(),
        ));
    }

    Ok(ParsedSubscription {
        format: SubscriptionPayloadFormat::ClashYaml,
        nodes,
        userinfo,
        etag: None,
        warnings,
    })
}

/// Fetch and parse a subscription using default options (`no_proxy = true`).
pub async fn fetch_and_parse_subscription(
    sub: &SubscriptionRecord,
    timeout: Duration,
) -> CatResult<ParsedSubscription> {
    fetch_and_parse_subscription_with_options(sub, timeout, &FetchOptions::default()).await
}

/// Fetch and parse a subscription with explicit transport options.
///
/// Strict refresh protection guarantees:
/// - Non-2xx HTTP status returns `Err`
/// - Network / read timeout returns `Err`
/// - Payload exceeding `MAX_SUBSCRIPTION_BYTES` (16 MiB) aborts streaming read and returns `Err`
/// - Malformed YAML or HTTP 200 with 0 valid nodes returns `Err`
pub async fn fetch_and_parse_subscription_with_options(
    sub: &SubscriptionRecord,
    timeout: Duration,
    opts: &FetchOptions,
) -> CatResult<ParsedSubscription> {
    if sub.id.trim().is_empty() {
        return Err(CatError::Validation(
            "subscription id cannot be empty".to_string(),
        ));
    }

    let source = sub.url_or_cmd.trim();
    if source.is_empty() {
        return Err(CatError::Validation(
            "subscription url_or_cmd cannot be empty".to_string(),
        ));
    }

    if sub.kind == SubscriptionKind::File {
        return read_local_subscription_file(&sub.id, source);
    }

    let parsed_url = Url::parse(source)
        .map_err(|e| CatError::Validation(format!("invalid subscription URL: {e}")))?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return Err(CatError::Validation(format!(
            "unsupported subscription URL scheme `{}` (expected http or https)",
            parsed_url.scheme()
        )));
    }

    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .user_agent(opts.user_agent.as_str());

    if opts.no_proxy {
        builder = builder.no_proxy();
    } else if let Some(ref proxy_url) = opts.proxy_url {
        let trimmed_proxy = proxy_url.trim();
        if !trimmed_proxy.is_empty() {
            let proxy = reqwest::Proxy::all(trimmed_proxy)?;
            builder = builder.proxy(proxy);
        }
    }

    let client = builder.build()?;
    let mut response = client.get(parsed_url).send().await?;

    let status = response.status();
    if !status.is_success() {
        return Err(CatError::Config(format!(
            "subscription HTTP request failed with non-2xx status {}",
            status.as_u16()
        )));
    }

    if let Some(content_len) = response.content_length() {
        if content_len > MAX_SUBSCRIPTION_BYTES as u64 {
            return Err(CatError::Validation(format!(
                "subscription Content-Length {} bytes exceeds maximum allowed {} bytes",
                content_len, MAX_SUBSCRIPTION_BYTES
            )));
        }
    }

    let userinfo_header = response
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    let etag = response
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BYTES {
            return Err(CatError::Validation(format!(
                "subscription response body exceeded maximum allowed {} bytes",
                MAX_SUBSCRIPTION_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }

    let mut parsed = parse_subscription_payload(&sub.id, &body, userinfo_header.as_deref())?;
    parsed.etag = etag;
    Ok(parsed)
}

/// Atomically persist a validated `ParsedSubscription` into SQLite while preserving
/// existing user groups, user rules, and probe history of surviving nodes.
pub fn apply_parsed_subscription(
    storage: &mut Storage,
    sub: &SubscriptionRecord,
    parsed: &ParsedSubscription,
) -> CatResult<usize> {
    if parsed.nodes.is_empty() {
        return Err(CatError::Validation(
            "refusing to apply subscription update with 0 valid nodes".to_string(),
        ));
    }

    if storage.get_subscription(&sub.id)?.is_none() {
        storage.upsert_subscription(sub)?;
    }

    let count = storage.replace_subscription_nodes(&sub.id, &parsed.nodes)?;
    let now = Utc::now().to_rfc3339();
    let used = parsed.userinfo.as_ref().map(SubscriptionUserInfo::used_bytes);
    let total = parsed
        .userinfo
        .as_ref()
        .and_then(|u| (u.total_bytes > 0).then_some(u.total_bytes));
    let expires_at = parsed
        .userinfo
        .as_ref()
        .and_then(|u| u.expires_at.as_deref());

    storage.update_subscription_refresh_status(
        &sub.id,
        Some(&now),
        parsed.etag.as_deref(),
        None,
        used,
        total,
        expires_at,
    )?;

    Ok(count)
}

fn read_local_subscription_file(sub_id: &str, source: &str) -> CatResult<ParsedSubscription> {
    let path_buf = if source.starts_with("file://") {
        let parsed = Url::parse(source)
            .map_err(|e| CatError::Validation(format!("invalid file URL: {e}")))?;
        parsed
            .to_file_path()
            .map_err(|_| CatError::Validation("file URL cannot be converted to local path".into()))?
    } else {
        Path::new(source).to_path_buf()
    };

    if !path_buf.is_file() {
        return Err(CatError::NotFound(format!(
            "subscription file not found: {}",
            path_buf.display()
        )));
    }

    let meta = std::fs::metadata(&path_buf)?;
    if meta.len() > MAX_SUBSCRIPTION_BYTES as u64 {
        return Err(CatError::Validation(format!(
            "subscription file size {} bytes exceeds maximum allowed {} bytes",
            meta.len(),
            MAX_SUBSCRIPTION_BYTES
        )));
    }

    let raw = std::fs::read(&path_buf)?;
    parse_subscription_payload(sub_id, &raw, None)
}

// ============================================================================
// Two-stage serde_yaml_ng parsing (with anchor merge) & Clash proxy extraction
// ============================================================================

/// Parse YAML text using `serde_yaml_ng` two-stage parsing (`from_str` + `apply_merge`)
/// so YAML anchors and `<<: *anchor` merges are fully expanded before inspection.
pub(crate) fn parse_clash_yaml_value(text: &str) -> CatResult<serde_yaml_ng::Value> {
    let mut val: serde_yaml_ng::Value = serde_yaml_ng::from_str(text)?;
    val.apply_merge()?;
    Ok(val)
}

/// Convert a `serde_yaml_ng::Value` into a `serde_json::Value` safely, coercing
/// non-string mapping keys to strings.
pub(crate) fn yaml_value_to_json(val: &serde_yaml_ng::Value) -> serde_json::Value {
    match val {
        serde_yaml_ng::Value::Null => serde_json::Value::Null,
        serde_yaml_ng::Value::Bool(b) => serde_json::Value::Bool(*b),
        serde_yaml_ng::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                serde_json::Value::Number(serde_json::Number::from(u))
            } else if let Some(i) = n.as_i64() {
                serde_json::Value::Number(serde_json::Number::from(i))
            } else if let Some(f) = n.as_f64() {
                serde_json::Number::from_f64(f)
                    .map(serde_json::Value::Number)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        }
        serde_yaml_ng::Value::String(s) => serde_json::Value::String(s.clone()),
        serde_yaml_ng::Value::Sequence(seq) => {
            serde_json::Value::Array(seq.iter().map(yaml_value_to_json).collect())
        }
        serde_yaml_ng::Value::Mapping(map) => {
            let mut obj = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                let key_str = yaml_key_to_string(k);
                obj.insert(key_str, yaml_value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        serde_yaml_ng::Value::Tagged(tagged) => yaml_value_to_json(&tagged.value),
    }
}

fn yaml_key_to_string(key: &serde_yaml_ng::Value) -> String {
    match key {
        serde_yaml_ng::Value::String(s) => s.clone(),
        serde_yaml_ng::Value::Bool(b) => b.to_string(),
        serde_yaml_ng::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u.to_string()
            } else if let Some(i) = n.as_i64() {
                i.to_string()
            } else if let Some(f) = n.as_f64() {
                f.to_string()
            } else {
                "null".to_string()
            }
        }
        serde_yaml_ng::Value::Null => "null".to_string(),
        other => serde_yaml_ng::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

pub(crate) fn extract_nodes_from_clash_yaml(
    sub_id: &str,
    yaml_val: &serde_yaml_ng::Value,
) -> CatResult<(Vec<ProxyNode>, Vec<String>)> {
    let Some(root_map) = yaml_val.as_mapping() else {
        return Err(CatError::Validation(
            "expected YAML mapping at top level".to_string(),
        ));
    };

    let proxies_val = root_map
        .get(serde_yaml_ng::Value::String("proxies".to_string()))
        .or_else(|| root_map.get(serde_yaml_ng::Value::String("Proxy".to_string())));

    let Some(proxies_val) = proxies_val else {
        return Err(CatError::Validation(
            "Clash YAML document does not contain a `proxies` section".to_string(),
        ));
    };

    let Some(seq) = proxies_val.as_sequence() else {
        if proxies_val.is_null() {
            return Ok((Vec::new(), vec!["`proxies` field is null".to_string()]));
        }
        return Err(CatError::Validation(
            "`proxies` field in Clash YAML must be a sequence".to_string(),
        ));
    };

    let mut nodes = Vec::with_capacity(seq.len());
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::with_capacity(seq.len());

    for (idx, item) in seq.iter().enumerate() {
        let json_item = yaml_value_to_json(item);
        let Some(obj) = json_item.as_object() else {
            warnings.push(format!("skipped proxies[{idx}]: entry is not a mapping"));
            continue;
        };
        match node_from_clash_json(sub_id, obj, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(reason) => warnings.push(format!("skipped proxies[{idx}]: {reason}")),
        }
    }

    Ok((nodes, warnings))
}

/// Convert a Clash/Mihomo JSON proxy object into a normalized `ProxyNode`.
pub(crate) fn node_from_clash_json(
    sub_id: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let raw_type = obj
        .get("type")
        .or_else(|| obj.get("protocol"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing `type` field".to_string())?;
    let protocol = normalize_protocol(raw_type);

    let server = obj
        .get("server")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "missing `server` field".to_string())?
        .to_string();

    let port = obj
        .get("port")
        .and_then(json_to_u16)
        .filter(|&p| p > 0)
        .ok_or_else(|| "missing or invalid `port` field".to_string())?;

    let name = obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{protocol}-{server}:{port}"));

    let mut normalized_obj = obj.clone();
    normalized_obj.insert("name".to_string(), serde_json::Value::String(name.clone()));
    normalized_obj.insert(
        "type".to_string(),
        serde_json::Value::String(protocol.clone()),
    );
    normalized_obj.insert(
        "server".to_string(),
        serde_json::Value::String(server.clone()),
    );
    normalized_obj.insert(
        "port".to_string(),
        serde_json::Value::Number(serde_json::Number::from(port)),
    );

    Ok(build_proxy_node(
        sub_id,
        name,
        protocol,
        server,
        port,
        serde_json::Value::Object(normalized_obj),
        used_ids,
    ))
}

/// Build a normalized `ProxyNode` with auto-inferred region, multiplier, 443-native flag,
/// descriptive tags, and deterministic collision-free ID.
pub(crate) fn build_proxy_node(
    sub_id: &str,
    name: String,
    protocol: String,
    server: String,
    port: u16,
    raw_config: serde_json::Value,
    used_ids: &mut HashSet<String>,
) -> ProxyNode {
    let protocol = normalize_protocol(&protocol);
    let region_code = detect_region_code(&name);
    let multiplier = extract_multiplier(&name);
    let is_443_native = detect_is_443_native(&protocol, port, &raw_config);
    let tags = extract_auto_tags(&name, multiplier);
    let id = stable_node_id(sub_id, &protocol, &server, port, &name, used_ids);

    ProxyNode {
        id,
        sub_id: sub_id.to_string(),
        name,
        protocol,
        server,
        port,
        raw_config,
        region_code,
        multiplier,
        is_443_native,
        preaccel_eligible: true,
        preaccel_override: None,
        tags,
        enabled: true,
    }
}

/// Generate a deterministic, collision-free node ID for stable incremental sync across refreshes.
pub(crate) fn stable_node_id(
    sub_id: &str,
    protocol: &str,
    server: &str,
    port: u16,
    name: &str,
    used_ids: &mut HashSet<String>,
) -> String {
    let mut attempt = 0u32;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(sub_id.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(protocol.as_bytes());
        hasher.update(b"\x1f");
        hasher.update(server.to_ascii_lowercase().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(port.to_string().as_bytes());
        hasher.update(b"\x1f");
        hasher.update(name.as_bytes());
        if attempt > 0 {
            hasher.update(b"\x1f");
            hasher.update(attempt.to_string().as_bytes());
        }
        let digest = hex::encode(hasher.finalize());
        let candidate = format!("node_{}", &digest[..16]);
        if used_ids.insert(candidate.clone()) {
            return candidate;
        }
        attempt = attempt.saturating_add(1);
    }
}

// ============================================================================
// Multi-protocol URI parser (vless / vmess / trojan / ss / hy2 / tuic / anytls)
// ============================================================================

fn parse_uri_lines(sub_id: &str, text: &str) -> (Vec<ProxyNode>, Vec<String>) {
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::new();

    for (line_no, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !has_supported_uri_scheme(line) {
            warnings.push(format!(
                "skipped line {}: unsupported or non-proxy URI",
                line_no + 1
            ));
            continue;
        }
        match parse_proxy_uri_line(sub_id, line, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(err) => warnings.push(format!("skipped line {}: {err}", line_no + 1)),
        }
    }

    (nodes, warnings)
}

/// Parse a single proxy share URI into a normalized `ProxyNode`.
pub(crate) fn parse_proxy_uri_line(
    sub_id: &str,
    line: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let trimmed = line.trim();
    let Some((raw_scheme, _)) = trimmed.split_once("://") else {
        return Err("missing URI scheme".to_string());
    };
    match raw_scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless_uri(sub_id, trimmed, used_ids),
        "vmess" => parse_vmess_uri(sub_id, trimmed, used_ids),
        "trojan" => parse_trojan_uri(sub_id, trimmed, used_ids),
        "ss" => parse_ss_uri(sub_id, trimmed, used_ids),
        "hy2" | "hysteria2" => parse_hysteria2_uri(sub_id, trimmed, used_ids),
        "tuic" => parse_tuic_uri(sub_id, trimmed, used_ids),
        "anytls" => parse_anytls_uri(sub_id, trimmed, used_ids),
        other => Err(format!("unsupported scheme `{other}`")),
    }
}

fn parse_vless_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let parsed = Url::parse(uri).map_err(|e| format!("invalid vless URI: {e}"))?;
    let uuid = percent_decode(parsed.username());
    if uuid.is_empty() {
        return Err("vless URI missing uuid".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("vless URI has invalid port 0".to_string());
    }
    let name = extract_fragment_name(&parsed, "vless", &server, port);

    let params = collect_query_params(&parsed);
    let security = query_get(&params, "security")
        .unwrap_or("")
        .to_ascii_lowercase();
    let tls = matches!(security.as_str(), "tls" | "reality" | "xtls")
        || query_bool(&params, "tls").unwrap_or(false)
        || (security.is_empty() && port == 443);

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("vless"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("uuid".into(), serde_json::json!(uuid));
    cfg.insert("tls".into(), serde_json::json!(tls));
    cfg.insert("udp".into(), serde_json::json!(true));

    if let Some(sni) = query_get(&params, "sni").or_else(|| query_get(&params, "servername")) {
        if !sni.is_empty() {
            cfg.insert("servername".into(), serde_json::json!(sni));
        }
    }
    if let Some(flow) = query_get(&params, "flow") {
        if !flow.is_empty() {
            cfg.insert("flow".into(), serde_json::json!(flow));
        }
    }
    if let Some(fp) = query_get(&params, "fp") {
        if !fp.is_empty() {
            cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
        }
    }
    if let Some(skip) = query_bool(&params, "allowInsecure")
        .or_else(|| query_bool(&params, "insecure"))
        .or_else(|| query_bool(&params, "skip-cert-verify"))
    {
        cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
    }
    if let Some(alpn) = query_get(&params, "alpn") {
        let list: Vec<String> = alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !list.is_empty() {
            cfg.insert("alpn".into(), serde_json::json!(list));
        }
    }

    if security == "reality" || query_get(&params, "pbk").is_some() {
        let mut reality = serde_json::Map::new();
        if let Some(pbk) = query_get(&params, "pbk") {
            reality.insert("public-key".into(), serde_json::json!(pbk));
        }
        if let Some(sid) = query_get(&params, "sid") {
            reality.insert("short-id".into(), serde_json::json!(sid));
        }
        if !reality.is_empty() {
            cfg.insert("reality-opts".into(), serde_json::Value::Object(reality));
        }
    }

    apply_transport_params(&mut cfg, &params);

    Ok(build_proxy_node(
        sub_id,
        name,
        "vless".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn parse_vmess_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let body = uri
        .get(8..)
        .ok_or_else(|| "malformed vmess URI".to_string())?
        .trim();

    // Standard V2RayN vmess://base64(json)
    if let Some(decoded) = decode_base64_flexible(body) {
        if let Ok(json_str) = std::str::from_utf8(&decoded) {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_str::<serde_json::Value>(json_str)
            {
                let server = map
                    .get("add")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "vmess JSON missing `add` server".to_string())?
                    .to_string();
                let port = map
                    .get("port")
                    .and_then(json_to_u16)
                    .filter(|&p| p > 0)
                    .ok_or_else(|| "vmess JSON missing valid `port`".to_string())?;
                let uuid = map
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "vmess JSON missing `id`".to_string())?
                    .to_string();
                let name = map
                    .get("ps")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("vmess-{server}:{port}"));
                let alter_id = map.get("aid").and_then(json_to_u64).unwrap_or(0);
                let cipher = map
                    .get("scy")
                    .or_else(|| map.get("cipher"))
                    .and_then(serde_json::Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("auto");
                let tls_str = map
                    .get("tls")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let tls = tls_str.eq_ignore_ascii_case("tls")
                    || tls_str.eq_ignore_ascii_case("true")
                    || map
                        .get("tls")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);

                let mut cfg = serde_json::Map::new();
                cfg.insert("name".into(), serde_json::json!(name));
                cfg.insert("type".into(), serde_json::json!("vmess"));
                cfg.insert("server".into(), serde_json::json!(server));
                cfg.insert("port".into(), serde_json::json!(port));
                cfg.insert("uuid".into(), serde_json::json!(uuid));
                cfg.insert("alterId".into(), serde_json::json!(alter_id));
                cfg.insert("cipher".into(), serde_json::json!(cipher));
                cfg.insert("tls".into(), serde_json::json!(tls));
                cfg.insert("udp".into(), serde_json::json!(true));

                if let Some(sni) = map
                    .get("sni")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("servername".into(), serde_json::json!(sni));
                }
                if let Some(fp) = map
                    .get("fp")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
                }

                let net = map
                    .get("net")
                    .and_then(serde_json::Value::as_str)
                    .map(|s| s.trim().to_ascii_lowercase())
                    .unwrap_or_else(|| "tcp".to_string());
                if net != "tcp" && !net.is_empty() {
                    cfg.insert("network".into(), serde_json::json!(net));
                }

                let path = map
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let host = map
                    .get("host")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());

                if net == "ws" {
                    let mut ws_opts = serde_json::Map::new();
                    if let Some(p) = path {
                        ws_opts.insert("path".into(), serde_json::json!(p));
                    }
                    if let Some(h) = host {
                        ws_opts.insert("headers".into(), serde_json::json!({ "Host": h }));
                    }
                    if !ws_opts.is_empty() {
                        cfg.insert("ws-opts".into(), serde_json::Value::Object(ws_opts));
                    }
                } else if net == "grpc" {
                    if let Some(p) = path {
                        cfg.insert(
                            "grpc-opts".into(),
                            serde_json::json!({ "grpc-service-name": p }),
                        );
                    }
                }

                return Ok(build_proxy_node(
                    sub_id,
                    name,
                    "vmess".to_string(),
                    server,
                    port,
                    serde_json::Value::Object(cfg),
                    used_ids,
                ));
            }
        }
    }

    // Fallback URL-style vmess://uuid@host:port?...#name
    let parsed = Url::parse(uri).map_err(|e| format!("invalid vmess URI: {e}"))?;
    let uuid = percent_decode(parsed.username());
    if uuid.is_empty() {
        return Err("vmess URI missing uuid".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("vmess URI has invalid port 0".to_string());
    }
    let name = extract_fragment_name(&parsed, "vmess", &server, port);
    let params = collect_query_params(&parsed);
    let tls = query_get(&params, "security")
        .is_some_and(|s| s.eq_ignore_ascii_case("tls"))
        || query_bool(&params, "tls").unwrap_or(false);

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("vmess"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("uuid".into(), serde_json::json!(uuid));
    cfg.insert("alterId".into(), serde_json::json!(0));
    cfg.insert("cipher".into(), serde_json::json!("auto"));
    cfg.insert("tls".into(), serde_json::json!(tls));
    cfg.insert("udp".into(), serde_json::json!(true));
    if let Some(sni) = query_get(&params, "sni") {
        if !sni.is_empty() {
            cfg.insert("servername".into(), serde_json::json!(sni));
        }
    }
    apply_transport_params(&mut cfg, &params);

    Ok(build_proxy_node(
        sub_id,
        name,
        "vmess".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn parse_trojan_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let parsed = Url::parse(uri).map_err(|e| format!("invalid trojan URI: {e}"))?;
    let password = percent_decode(parsed.username());
    if password.is_empty() {
        return Err("trojan URI missing password".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("trojan URI has invalid port 0".to_string());
    }
    let name = extract_fragment_name(&parsed, "trojan", &server, port);
    let params = collect_query_params(&parsed);

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("trojan"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("password".into(), serde_json::json!(password));
    cfg.insert("udp".into(), serde_json::json!(true));

    if let Some(sni) = query_get(&params, "sni").or_else(|| query_get(&params, "peer")) {
        if !sni.is_empty() {
            cfg.insert("sni".into(), serde_json::json!(sni));
        }
    }
    if let Some(skip) = query_bool(&params, "allowInsecure")
        .or_else(|| query_bool(&params, "insecure"))
        .or_else(|| query_bool(&params, "skip-cert-verify"))
    {
        cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
    }
    if let Some(fp) = query_get(&params, "fp") {
        if !fp.is_empty() {
            cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
        }
    }
    if let Some(alpn) = query_get(&params, "alpn") {
        let list: Vec<String> = alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !list.is_empty() {
            cfg.insert("alpn".into(), serde_json::json!(list));
        }
    }
    apply_transport_params(&mut cfg, &params);

    Ok(build_proxy_node(
        sub_id,
        name,
        "trojan".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn parse_ss_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let without_scheme = uri
        .get(5..)
        .ok_or_else(|| "malformed ss URI".to_string())?;
    let (before_frag, frag_opt) = match without_scheme.split_once('#') {
        Some((l, r)) => (l, Some(percent_decode(r))),
        None => (without_scheme, None),
    };
    let (main_part, query_opt) = match before_frag.split_once('?') {
        Some((l, r)) => (l, Some(r)),
        None => (before_frag, None),
    };

    let (cipher, password, server, port) = if let Some((userinfo_part, host_port_part)) =
        main_part.rsplit_once('@')
    {
        // SIP002: ss://base64(method:password)@host:port or plaintext method:password@host:port
        let decoded_userinfo = if userinfo_part.contains(':') {
            percent_decode(userinfo_part)
        } else if let Some(bytes) = decode_base64_flexible(userinfo_part) {
            String::from_utf8(bytes)
                .map_err(|_| "ss userinfo base64 is not UTF-8".to_string())?
        } else {
            return Err("invalid ss userinfo encoding".to_string());
        };
        let (method, pass) = decoded_userinfo
            .split_once(':')
            .ok_or_else(|| "ss userinfo missing method:password separator".to_string())?;
        let (host, port) = split_host_port(host_port_part)?;
        (method.to_string(), pass.to_string(), host, port)
    } else {
        // Legacy format: ss://base64(method:password@host:port)
        let bytes = decode_base64_flexible(main_part)
            .ok_or_else(|| "invalid legacy ss base64 payload".to_string())?;
        let decoded = String::from_utf8(bytes)
            .map_err(|_| "legacy ss base64 is not UTF-8".to_string())?;
        let (cred, host_port_part) = decoded
            .rsplit_once('@')
            .ok_or_else(|| "legacy ss payload missing `@` separator".to_string())?;
        let (method, pass) = cred
            .split_once(':')
            .ok_or_else(|| "legacy ss credential missing `:`".to_string())?;
        let (host, port) = split_host_port(host_port_part)?;
        (method.to_string(), pass.to_string(), host, port)
    };

    if cipher.trim().is_empty() {
        return Err("ss URI missing cipher".to_string());
    }
    let name = frag_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("ss-{server}:{port}"));

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("ss"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("cipher".into(), serde_json::json!(cipher));
    cfg.insert("password".into(), serde_json::json!(password));
    cfg.insert("udp".into(), serde_json::json!(true));

    if let Some(q) = query_opt {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k.eq_ignore_ascii_case("plugin") {
                    let decoded_plugin = percent_decode(v);
                    let mut parts = decoded_plugin.split(';');
                    if let Some(plugin_name) = parts.next().map(str::trim).filter(|s| !s.is_empty())
                    {
                        let mapped_name = match plugin_name {
                            "obfs-local" | "simple-obfs" => "obfs",
                            other => other,
                        };
                        cfg.insert("plugin".into(), serde_json::json!(mapped_name));
                        let mut opts = serde_json::Map::new();
                        for opt in parts {
                            if let Some((ok, ov)) = opt.split_once('=') {
                                let key = match (mapped_name, ok.trim()) {
                                    ("obfs", "obfs") => "mode",
                                    ("obfs", "obfs-host") => "host",
                                    (_, other) => other,
                                };
                                opts.insert(key.to_string(), serde_json::json!(ov.trim()));
                            } else if !opt.trim().is_empty() {
                                opts.insert(opt.trim().to_string(), serde_json::json!(true));
                            }
                        }
                        if !opts.is_empty() {
                            cfg.insert("plugin-opts".into(), serde_json::Value::Object(opts));
                        }
                    }
                }
            }
        }
    }

    Ok(build_proxy_node(
        sub_id,
        name,
        "ss".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn parse_hysteria2_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let parsed = Url::parse(uri).map_err(|e| format!("invalid hysteria2 URI: {e}"))?;
    let password = match parsed.password() {
        Some(p) => format!("{}:{}", percent_decode(parsed.username()), percent_decode(p)),
        None => percent_decode(parsed.username()),
    };
    if password.is_empty() {
        return Err("hysteria2 URI missing auth password".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("hysteria2 URI has invalid port 0".to_string());
    }
    let name = extract_fragment_name(&parsed, "hysteria2", &server, port);
    let params = collect_query_params(&parsed);

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("hysteria2"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("password".into(), serde_json::json!(password));

    if let Some(sni) = query_get(&params, "sni") {
        if !sni.is_empty() {
            cfg.insert("sni".into(), serde_json::json!(sni));
        }
    }
    if let Some(skip) = query_bool(&params, "insecure")
        .or_else(|| query_bool(&params, "allowInsecure"))
        .or_else(|| query_bool(&params, "skip-cert-verify"))
    {
        cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
    }
    if let Some(obfs) = query_get(&params, "obfs") {
        if !obfs.is_empty() {
            cfg.insert("obfs".into(), serde_json::json!(obfs));
        }
    }
    if let Some(obfs_pw) = query_get(&params, "obfs-password") {
        if !obfs_pw.is_empty() {
            cfg.insert("obfs-password".into(), serde_json::json!(obfs_pw));
        }
    }
    if let Some(mport) = query_get(&params, "mport") {
        if !mport.is_empty() {
            cfg.insert("ports".into(), serde_json::json!(mport));
        }
    }
    if let Some(alpn) = query_get(&params, "alpn") {
        let list: Vec<String> = alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !list.is_empty() {
            cfg.insert("alpn".into(), serde_json::json!(list));
        }
    }

    Ok(build_proxy_node(
        sub_id,
        name,
        "hysteria2".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn parse_tuic_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let parsed = Url::parse(uri).map_err(|e| format!("invalid tuic URI: {e}"))?;
    let uuid = percent_decode(parsed.username());
    let password = parsed.password().map(percent_decode).unwrap_or_default();
    if uuid.is_empty() {
        return Err("tuic URI missing uuid".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("tuic URI has invalid port 0".to_string());
    }
    let name = extract_fragment_name(&parsed, "tuic", &server, port);
    let params = collect_query_params(&parsed);

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("tuic"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("uuid".into(), serde_json::json!(uuid));
    if !password.is_empty() {
        cfg.insert("password".into(), serde_json::json!(password));
    }

    if let Some(sni) = query_get(&params, "sni") {
        if !sni.is_empty() {
            cfg.insert("sni".into(), serde_json::json!(sni));
        }
    }
    if let Some(cc) = query_get(&params, "congestion_control")
        .or_else(|| query_get(&params, "congestion-controller"))
    {
        if !cc.is_empty() {
            cfg.insert("congestion-controller".into(), serde_json::json!(cc));
        }
    }
    if let Some(udp_mode) =
        query_get(&params, "udp_relay_mode").or_else(|| query_get(&params, "udp-relay-mode"))
    {
        if !udp_mode.is_empty() {
            cfg.insert("udp-relay-mode".into(), serde_json::json!(udp_mode));
        }
    }
    if let Some(skip) = query_bool(&params, "allow_insecure")
        .or_else(|| query_bool(&params, "allowInsecure"))
        .or_else(|| query_bool(&params, "insecure"))
    {
        cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
    }
    if let Some(alpn) = query_get(&params, "alpn") {
        let list: Vec<String> = alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !list.is_empty() {
            cfg.insert("alpn".into(), serde_json::json!(list));
        }
    }

    Ok(build_proxy_node(
        sub_id,
        name,
        "tuic".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn parse_anytls_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let parsed = Url::parse(uri).map_err(|e| format!("invalid anytls URI: {e}"))?;
    let password = match parsed.password() {
        Some(p) => format!("{}:{}", percent_decode(parsed.username()), percent_decode(p)),
        None => percent_decode(parsed.username()),
    };
    if password.is_empty() {
        return Err("anytls URI missing password".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("anytls URI has invalid port 0".to_string());
    }
    let name = extract_fragment_name(&parsed, "anytls", &server, port);
    let params = collect_query_params(&parsed);

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!("anytls"));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));
    cfg.insert("password".into(), serde_json::json!(password));
    cfg.insert("udp".into(), serde_json::json!(true));

    if let Some(sni) = query_get(&params, "sni") {
        if !sni.is_empty() {
            cfg.insert("sni".into(), serde_json::json!(sni));
        }
    }
    if let Some(skip) = query_bool(&params, "insecure")
        .or_else(|| query_bool(&params, "allowInsecure"))
        .or_else(|| query_bool(&params, "skip-cert-verify"))
    {
        cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
    }
    if let Some(fp) = query_get(&params, "fp") {
        if !fp.is_empty() {
            cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
        }
    }
    if let Some(alpn) = query_get(&params, "alpn") {
        let list: Vec<String> = alpn
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !list.is_empty() {
            cfg.insert("alpn".into(), serde_json::json!(list));
        }
    }

    Ok(build_proxy_node(
        sub_id,
        name,
        "anytls".to_string(),
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn apply_transport_params(
    cfg: &mut serde_json::Map<String, serde_json::Value>,
    params: &[(String, String)],
) {
    let network = query_get(params, "type")
        .or_else(|| query_get(params, "net"))
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    if !network.is_empty() && network != "tcp" {
        cfg.insert("network".into(), serde_json::json!(network));
    }

    match network.as_str() {
        "ws" => {
            let mut ws_opts = serde_json::Map::new();
            if let Some(path) = query_get(params, "path") {
                if !path.is_empty() {
                    ws_opts.insert("path".into(), serde_json::json!(path));
                }
            }
            if let Some(host) = query_get(params, "host") {
                if !host.is_empty() {
                    ws_opts.insert("headers".into(), serde_json::json!({ "Host": host }));
                }
            }
            if !ws_opts.is_empty() {
                cfg.insert("ws-opts".into(), serde_json::Value::Object(ws_opts));
            }
        }
        "grpc" => {
            if let Some(svc) = query_get(params, "serviceName")
                .or_else(|| query_get(params, "service-name"))
                .or_else(|| query_get(params, "path"))
            {
                if !svc.is_empty() {
                    cfg.insert(
                        "grpc-opts".into(),
                        serde_json::json!({ "grpc-service-name": svc }),
                    );
                }
            }
        }
        "h2" | "http" => {
            let mut h2_opts = serde_json::Map::new();
            if let Some(path) = query_get(params, "path") {
                if !path.is_empty() {
                    h2_opts.insert("path".into(), serde_json::json!(path));
                }
            }
            if let Some(host) = query_get(params, "host") {
                if !host.is_empty() {
                    let hosts: Vec<String> = host
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                    if !hosts.is_empty() {
                        h2_opts.insert("host".into(), serde_json::json!(hosts));
                    }
                }
            }
            if !h2_opts.is_empty() {
                cfg.insert("h2-opts".into(), serde_json::Value::Object(h2_opts));
            }
        }
        _ => {}
    }
}

// ============================================================================
// Low-level decoding & utility helpers
// ============================================================================

pub(crate) fn looks_like_uri_list(text: &str) -> bool {
    let mut non_empty = 0usize;
    let mut uri_hits = 0usize;
    for line in text.lines().take(64) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        non_empty += 1;
        if has_supported_uri_scheme(t) {
            uri_hits += 1;
        }
    }
    non_empty > 0 && uri_hits > 0 && !looks_like_clash_yaml(text)
}

pub(crate) fn looks_like_clash_yaml(text: &str) -> bool {
    for line in text.lines().take(128) {
        let trimmed = line.trim_start();
        if trimmed.starts_with("proxies:")
            || trimmed.starts_with("Proxy:")
            || trimmed.starts_with("proxy-groups:")
            || trimmed.starts_with("rules:")
            || trimmed.starts_with("mixed-port:")
            || trimmed.starts_with("external-controller:")
            || trimmed.starts_with("prepend-rules:")
            || trimmed.starts_with("append-rules:")
        {
            return true;
        }
    }
    false
}

pub(crate) fn has_supported_uri_scheme(line: &str) -> bool {
    let Some((scheme, _)) = line.split_once("://") else {
        return false;
    };
    matches!(
        scheme.to_ascii_lowercase().as_str(),
        "vless" | "vmess" | "trojan" | "ss" | "hy2" | "hysteria2" | "tuic" | "anytls"
    )
}

pub(crate) fn decode_base64_flexible(input: &str) -> Option<Vec<u8>> {
    let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 4 {
        return None;
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(&compact) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }

    // Retry after normalizing padding when upstream omits trailing '='
    let unpadded = compact.trim_end_matches('=');
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(unpadded) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }
    None
}

fn contains_ascii_token(haystack_upper: &str, token: &str) -> bool {
    let bytes = haystack_upper.as_bytes();
    for (start, _) in haystack_upper.match_indices(token) {
        let end = start + token.len();
        let left_ok = start == 0 || !bytes[start - 1].is_ascii_alphabetic();
        let right_ok = end == bytes.len() || !bytes[end].is_ascii_alphabetic();
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

fn extract_host(url: &Url) -> Result<String, String> {
    let host = url
        .host_str()
        .ok_or_else(|| "URI missing host".to_string())?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if host.is_empty() {
        return Err("URI has empty host".to_string());
    }
    Ok(host.to_string())
}

fn extract_fragment_name(url: &Url, protocol: &str, server: &str, port: u16) -> String {
    url.fragment()
        .map(percent_decode)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{protocol}-{server}:{port}"))
}

fn collect_query_params(url: &Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn query_get<'a>(params: &'a [(String, String)], key: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.as_str())
}

fn query_bool(params: &[(String, String)], key: &str) -> Option<bool> {
    let val = query_get(params, key)?.trim().to_ascii_lowercase();
    match val.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn split_host_port(raw: &str) -> Result<(String, u16), String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port_part) = rest
            .split_once("]:")
            .ok_or_else(|| "IPv6 host:port missing closing bracket or port".to_string())?;
        let port: u16 = port_part
            .parse()
            .map_err(|_| format!("invalid port `{port_part}`"))?;
        if host.is_empty() || port == 0 {
            return Err("invalid IPv6 host or port".to_string());
        }
        Ok((host.to_string(), port))
    } else {
        let (host, port_part) = trimmed
            .rsplit_once(':')
            .ok_or_else(|| "missing `:port` in host:port".to_string())?;
        let port: u16 = port_part
            .parse()
            .map_err(|_| format!("invalid port `{port_part}`"))?;
        if host.is_empty() || port == 0 {
            return Err("invalid host or port".to_string());
        }
        Ok((host.to_string(), port))
    }
}

pub(crate) fn json_to_u16(val: &serde_json::Value) -> Option<u16> {
    if let Some(u) = val.as_u64() {
        u16::try_from(u).ok()
    } else if let Some(s) = val.as_str() {
        s.trim().parse::<u16>().ok()
    } else {
        None
    }
}

pub(crate) fn json_to_u64(val: &serde_json::Value) -> Option<u64> {
    if let Some(u) = val.as_u64() {
        Some(u)
    } else if let Some(s) = val.as_str() {
        s.trim().parse::<u64>().ok()
    } else {
        None
    }
}

fn parse_nonneg_u64(raw: &str) -> Option<u64> {
    if let Ok(v) = raw.parse::<u64>() {
        return Some(v);
    }
    let f = raw.parse::<f64>().ok()?;
    if f.is_finite() && f >= 0.0 && f <= u64::MAX as f64 {
        Some(f.round() as u64)
    } else {
        None
    }
}

fn parse_i64_flexible(raw: &str) -> Option<i64> {
    if let Ok(v) = raw.parse::<i64>() {
        return Some(v);
    }
    let f = raw.parse::<f64>().ok()?;
    if f.is_finite() && f >= i64::MIN as f64 && f <= i64::MAX as f64 {
        Some(f.round() as i64)
    } else {
        None
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b'%' && idx + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[idx + 1]), hex_val(bytes[idx + 2])) {
                out.push((hi << 4) | lo);
                idx += 3;
                continue;
            }
        }
        out.push(bytes[idx]);
        idx += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_region_code_universal_flags_and_global_chinese_names() {
        // Universal Unicode Regional Indicator flag decoding
        assert_eq!(detect_region_code("🇰🇭 柬埔寨丨3x KH"), "KH");
        assert_eq!(detect_region_code("🇳🇿 新西兰"), "NZ");
        assert_eq!(detect_region_code("🇵🇱 波兰"), "PL");
        assert_eq!(detect_region_code("🇩🇰 丹麦 01"), "DK");
        assert_eq!(detect_region_code("🇦🇪 阿联酋 迪拜"), "AE");
        assert_eq!(detect_region_code("🇮🇱 以色列"), "IL");
        assert_eq!(detect_region_code("🇽🇰 科索沃"), "XK");
        // GB flag stays mapped to UK for backwards compatibility
        assert_eq!(detect_region_code("🇬🇧 London 01"), "UK");

        // Flagless Chinese place names (including Belarus vs Russia & Indonesia vs India ordering)
        assert_eq!(detect_region_code("格陵兰 01"), "GL");
        assert_eq!(detect_region_code("东帝汶 线路"), "TL");
        assert_eq!(detect_region_code("文莱 2x"), "BN");
        assert_eq!(detect_region_code("南极洲 科研站"), "AQ");
        assert_eq!(detect_region_code("墨西哥 节点"), "MX");
        assert_eq!(detect_region_code("智利 圣地亚哥"), "CL");
        assert_eq!(detect_region_code("阿联酋 迪拜"), "AE");
        assert_eq!(detect_region_code("缅甸 仰光"), "MM");
        assert_eq!(detect_region_code("新西兰 奥克兰"), "NZ");
        assert_eq!(detect_region_code("柬埔寨 金边"), "KH");
        assert_eq!(detect_region_code("白俄罗斯 明斯克"), "BY");
        assert_eq!(detect_region_code("印度尼西亚 雅加达"), "ID");
        assert_eq!(detect_region_code("印度 孟买"), "IN");

        // Non-geographic custom names must remain UNK
        assert_eq!(detect_region_code("Node-Custom-01"), "UNK");
        assert_eq!(detect_region_code("Dedicated-Edge-02"), "UNK");
        assert_eq!(detect_region_code("Custom-Relay-01"), "UNK");
    }
}
