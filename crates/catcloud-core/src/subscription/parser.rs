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

/// Default HTTP timeout used when fetching remote subscription URLs.
pub const DEFAULT_SUBSCRIPTION_TIMEOUT: Duration = Duration::from_secs(20);

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
    SingBoxJson,
    Base64UriList,
    PlainUriList,
}

/// Raw HTTP payload and metadata returned from fetching a subscription URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FetchedSubscription {
    pub body: Vec<u8>,
    pub userinfo_header: Option<String>,
    pub etag: Option<String>,
    pub used_proxy: Option<String>,
}

impl FetchedSubscription {
    /// Parse the fetched raw body into normalized proxy nodes and preserve `etag`.
    pub fn parse(&self, sub_id: &str) -> CatResult<ParsedSubscription> {
        let mut parsed =
            parse_subscription_payload(sub_id, &self.body, self.userinfo_header.as_deref())?;
        parsed.etag = self.etag.clone();
        Ok(parsed)
    }
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

/// Parse a raw subscription payload (Clash/Mihomo YAML, sing-box JSON, Base64 URI list, or plain URI list).
///
/// Enforces strict refresh protection:
/// - Rejects payloads exceeding `MAX_SUBSCRIPTION_BYTES` (16 MiB)
/// - Rejects HTML interception / login / error pages with clear Chinese guidance
/// - Rejects malformed YAML/JSON
/// - Rejects payloads that yield zero valid proxy nodes
pub fn parse_subscription_payload(
    sub_id: &str,
    raw: &[u8],
    userinfo_header: Option<&str>,
) -> CatResult<ParsedSubscription> {
    if sub_id.trim().is_empty() {
        return Err(CatError::Validation("订阅标识不能为空".to_string()));
    }
    if raw.len() > MAX_SUBSCRIPTION_BYTES {
        return Err(CatError::Validation(format!(
            "订阅内容过大（{} 字节，超过 16 MiB 上限），请确认链接指向的是代理订阅而非大文件",
            raw.len()
        )));
    }

    let text_raw = std::str::from_utf8(raw).map_err(|_| {
        CatError::Validation(
            "订阅内容不是有效的 UTF-8 文本，可能是压缩包或损坏文件".to_string(),
        )
    })?;
    let text = text_raw.strip_prefix('\u{FEFF}').unwrap_or(text_raw).trim();
    if text.is_empty() {
        return Err(CatError::Validation(
            "订阅返回内容为空，请确认订阅链接未过期且账号下有可用节点".to_string(),
        ));
    }

    // 0. Detect HTML login/interception/error pages before any YAML/URI heuristics
    if looks_like_html_document(text) {
        return Err(CatError::Validation(
            "订阅链接返回了网页而非节点列表（可能链接已失效、需要登录或被防火墙拦截）"
                .to_string(),
        ));
    }

    let userinfo = userinfo_header.and_then(parse_userinfo_header);

    // 1. Plain URI list check (before YAML so URI lines with colons are never misclassified as YAML)
    if looks_like_uri_list(text) {
        let (nodes, warnings) = parse_uri_lines(sub_id, text);
        if nodes.is_empty() {
            return Err(CatError::Validation(
                "节点链接列表中未解析到任何有效节点，请检查链接格式是否完整".to_string(),
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

    // 2. JSON subscription payload (sing-box `outbounds` or Clash JSON `proxies`)
    if text.starts_with('{') {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(text) {
            if let Some((nodes, warnings)) = extract_nodes_from_singbox_json(sub_id, &json_val) {
                if nodes.is_empty() {
                    return Err(CatError::Validation(
                        "sing-box JSON 订阅中未找到任何可用的代理节点（outbounds 为空）"
                            .to_string(),
                    ));
                }
                return Ok(ParsedSubscription {
                    format: SubscriptionPayloadFormat::SingBoxJson,
                    nodes,
                    userinfo,
                    etag: None,
                    warnings,
                });
            }
            if let Some((nodes, warnings)) = extract_nodes_from_clash_json_root(sub_id, &json_val) {
                if nodes.is_empty() {
                    return Err(CatError::Validation(
                        "JSON 订阅配置中未找到任何可用节点（proxies 为空）".to_string(),
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

    // 3. Explicit Clash/Mihomo YAML structure check (malformed YAML must return Err immediately)
    if looks_like_clash_yaml(text) {
        let yaml_val = parse_clash_yaml_value(text)?;
        let (nodes, warnings) = extract_nodes_from_clash_yaml(sub_id, &yaml_val)?;
        if nodes.is_empty() {
            return Err(CatError::Validation(
                "订阅配置中未找到任何可用节点（proxies 为空），请确认订阅套餐未到期".to_string(),
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

    // 4. Base64-encoded URI list (or Base64-wrapped Clash YAML / sing-box JSON)
    if let Some(decoded_bytes) = decode_base64_flexible(text) {
        if decoded_bytes.len() > MAX_SUBSCRIPTION_BYTES {
            return Err(CatError::Validation(format!(
                "解码后的订阅内容过大（{} 字节，超过 16 MiB 上限）",
                decoded_bytes.len()
            )));
        }
        if let Ok(decoded_raw) = std::str::from_utf8(&decoded_bytes) {
            let decoded = decoded_raw.strip_prefix('\u{FEFF}').unwrap_or(decoded_raw).trim();
            if looks_like_html_document(decoded) {
                return Err(CatError::Validation(
                    "订阅链接返回了网页而非节点列表（可能链接已失效、需要登录或被防火墙拦截）"
                        .to_string(),
                ));
            }
            if looks_like_uri_list(decoded) {
                let (nodes, warnings) = parse_uri_lines(sub_id, decoded);
                if nodes.is_empty() {
                    return Err(CatError::Validation(
                        "Base64 订阅内容中未解析到任何有效节点".to_string(),
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
            if decoded.starts_with('{') {
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(decoded) {
                    if let Some((nodes, warnings)) =
                        extract_nodes_from_singbox_json(sub_id, &json_val)
                    {
                        if nodes.is_empty() {
                            return Err(CatError::Validation(
                                "Base64 解码后的 sing-box 配置中未找到任何可用节点".to_string(),
                            ));
                        }
                        return Ok(ParsedSubscription {
                            format: SubscriptionPayloadFormat::SingBoxJson,
                            nodes,
                            userinfo,
                            etag: None,
                            warnings,
                        });
                    }
                }
            }
            if looks_like_clash_yaml(decoded) {
                let yaml_val = parse_clash_yaml_value(decoded)?;
                let (nodes, warnings) = extract_nodes_from_clash_yaml(sub_id, &yaml_val)?;
                if nodes.is_empty() {
                    return Err(CatError::Validation(
                        "Base64 解码后的订阅配置中未找到任何可用节点".to_string(),
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

    // 5. Fallback: try parsing as YAML in case the document uses anchors or unusual ordering
    let yaml_val = parse_clash_yaml_value(text)?;
    let (nodes, warnings) = extract_nodes_from_clash_yaml(sub_id, &yaml_val)?;
    if nodes.is_empty() {
        return Err(CatError::Validation(
            "订阅内容中未解析到任何有效节点，请确认复制的是完整订阅链接".to_string(),
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

enum SingleFetchError {
    Retryable(String),
    Fatal(CatError),
}

fn strip_clash_install_config_query(s: &str) -> Option<&str> {
    let (scheme, rest) = s.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("clash") && !scheme.eq_ignore_ascii_case("clashmeta") {
        return None;
    }
    let (authority_path, query) = rest.split_once('?')?;
    let host_path = authority_path.trim_end_matches('/');
    if !host_path.eq_ignore_ascii_case("install-config") {
        return None;
    }
    Some(query)
}

fn find_query_param_tail_ascii_ci<'a>(query: &'a str, key_eq: &str) -> Option<&'a str> {
    let q_bytes = query.as_bytes();
    let k_bytes = key_eq.as_bytes();
    if q_bytes.len() < k_bytes.len() {
        return None;
    }
    if q_bytes[..k_bytes.len()].eq_ignore_ascii_case(k_bytes) {
        return Some(&query[k_bytes.len()..]);
    }
    let mut idx = 0usize;
    while idx < q_bytes.len() {
        if q_bytes[idx] == b'&' {
            let start = idx + 1;
            let end = start + k_bytes.len();
            if end <= q_bytes.len() && q_bytes[start..end].eq_ignore_ascii_case(k_bytes) {
                return Some(&query[end..]);
            }
        }
        idx += 1;
    }
    None
}

fn starts_with_http_scheme_ascii_ci(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() >= 7 && b[..7].eq_ignore_ascii_case(b"http://"))
        || (b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"https://"))
}

fn split_before_ascii_ci<'a>(haystack: &'a str, needle: &str) -> &'a str {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return haystack;
    }
    for i in 0..=(h.len() - n.len()) {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return &haystack[..i];
        }
    }
    haystack
}

/// Normalize user-pasted subscription input URLs, unwrapping `clash://install-config?url=...`
/// and `clashmeta://install-config?url=...` deep links into standard `http(s)://` URLs.
///
/// When `url=` begins directly with unencoded `http://` or `https://`, extracts up to `&name=`
/// (or end-of-string) so inner query parameters like `&flag=clash` are never truncated.
/// When `url=` is percent-encoded, extracts the parameter and percent-decodes it.
pub fn normalize_subscription_input_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let Some(query) = strip_clash_install_config_query(trimmed) else {
        return trimmed.to_string();
    };

    let Some(raw_url_tail) = find_query_param_tail_ascii_ci(query, "url=") else {
        return trimmed.to_string();
    };

    if starts_with_http_scheme_ascii_ci(raw_url_tail) {
        let extracted = split_before_ascii_ci(raw_url_tail, "&name=").trim();
        if !extracted.is_empty() {
            return extracted.to_string();
        }
        return trimmed.to_string();
    }

    let encoded_segment = raw_url_tail
        .split_once('&')
        .map(|(head, _)| head)
        .unwrap_or(raw_url_tail)
        .trim();
    if encoded_segment.is_empty() {
        return trimmed.to_string();
    }

    let mut decoded = percent_decode(encoded_segment).trim().to_string();
    if !starts_with_http_scheme_ascii_ci(&decoded)
        && decoded.to_ascii_lowercase().starts_with("http")
        && decoded.contains('%')
    {
        decoded = percent_decode(&decoded).trim().to_string();
    }

    if starts_with_http_scheme_ascii_ci(&decoded) {
        decoded
    } else {
        trimmed.to_string()
    }
}

fn format_url_parse_error_zh(err: url::ParseError) -> String {
    match err {
        url::ParseError::RelativeUrlWithoutBase => {
            "订阅链接缺少协议头，请确认以 http:// 或 https:// 开头".to_string()
        }
        url::ParseError::EmptyHost => {
            "订阅链接缺少服务器域名或地址，请确认完整复制了链接".to_string()
        }
        url::ParseError::InvalidPort => {
            "订阅链接中的端口号无效，请检查链接是否复制完整".to_string()
        }
        url::ParseError::InvalidDomainCharacter
        | url::ParseError::InvalidIpv4Address
        | url::ParseError::InvalidIpv6Address => {
            "订阅链接中的服务器地址格式无效，请检查是否混入了多余空格或特殊字符".to_string()
        }
        _ => "订阅链接格式不正确，请确认完整复制了有效的订阅链接".to_string(),
    }
}

fn validate_subscription_http_url(url: &str) -> CatResult<Url> {
    let normalized = normalize_subscription_input_url(url);
    let source = normalized.trim();
    if source.is_empty() {
        return Err(CatError::Validation(
            "订阅链接不能为空，请先粘贴有效的 http:// 或 https:// 订阅地址".to_string(),
        ));
    }
    let parsed_url = Url::parse(source).map_err(|e| {
        tracing::debug!(error = %e, "subscription URL parse failed");
        CatError::Validation(format_url_parse_error_zh(e))
    })?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return Err(CatError::Validation(format!(
            "不支持的订阅链接协议「{}」，请使用 http:// 或 https:// 开头的订阅链接",
            parsed_url.scheme()
        )));
    }
    Ok(parsed_url)
}

fn format_http_status_zh(status: reqwest::StatusCode) -> String {
    match status.as_u16() {
        400 => "订阅服务器拒绝了请求（HTTP 400），请检查订阅链接是否复制完整".to_string(),
        401 => "订阅认证失败（HTTP 401），链接里的访问令牌可能已失效或被重置".to_string(),
        403 => "订阅服务器拒绝访问（HTTP 403），可能被防火墙拦截、需要通过代理拉取或账号权限不足"
            .to_string(),
        404 => "订阅链接不存在或已失效（HTTP 404），请回服务商官网重新获取最新订阅地址"
            .to_string(),
        410 => "该订阅链接已被服务商下线（HTTP 410），请重新获取最新订阅地址".to_string(),
        429 => "订阅刷新过于频繁，服务器暂时限流（HTTP 429），请稍等几分钟再试".to_string(),
        500 => "订阅服务器内部出错（HTTP 500），请稍后再试或联系服务商".to_string(),
        502 => "订阅服务器网关异常（HTTP 502），上游服务可能正在维护或需要切换代理重试"
            .to_string(),
        503 => "订阅服务暂时不可用（HTTP 503），服务器可能过载或维护中，请稍后再试".to_string(),
        504 => "订阅服务器响应超时（HTTP 504），请稍后再试".to_string(),
        code => format!("订阅服务器返回异常状态（HTTP {code}），请检查链接是否正常或稍后再试"),
    }
}

fn format_reqwest_error_zh(err: &reqwest::Error) -> String {
    if err.is_timeout() {
        return "连接超时（目标服务器长时间未响应）".to_string();
    }
    let raw = err.to_string();
    let lower = raw.to_ascii_lowercase();
    if lower.contains("dns")
        || lower.contains("failed to lookup")
        || lower.contains("no such host")
        || lower.contains("name or service not known")
    {
        return "域名无法解析（可能被网络屏蔽或订阅域名已变更）".to_string();
    }
    if lower.contains("connection refused") || lower.contains("actively refused") {
        return "目标地址拒绝连接（若使用本地代理，请确认对应端口已开启）".to_string();
    }
    if lower.contains("connection reset")
        || lower.contains("forcibly closed")
        || lower.contains("broken pipe")
        || lower.contains("unexpected eof")
    {
        return "网络连接被对方重置或意外中断（可能受到网络干扰）".to_string();
    }
    if lower.contains("tls")
        || lower.contains("ssl")
        || lower.contains("certificate")
        || lower.contains("handshake")
        || lower.contains("rustls")
    {
        return "安全连接（TLS）握手失败（可能受到网络拦截或证书异常）".to_string();
    }
    if lower.contains("proxy") {
        return "代理连接失败（请确认本地代理端口及配置正常）".to_string();
    }
    if err.is_connect() {
        return "无法建立网络连接".to_string();
    }
    if err.is_redirect() {
        return "订阅链接重定向次数过多，可能存在循环跳转".to_string();
    }
    if err.is_body() || err.is_decode() {
        return "读取订阅响应内容中断或解码异常".to_string();
    }
    tracing::debug!(error = %raw, "unclassified subscription reqwest error");
    "网络请求失败（请检查网络连接或切换代理后重试）".to_string()
}

fn sanitize_proxy_label(raw_proxy: &str) -> String {
    if let Ok(mut parsed) = Url::parse(raw_proxy) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
        }
        parsed.to_string().trim_end_matches('/').to_string()
    } else {
        raw_proxy.trim().to_string()
    }
}

fn effective_connect_timeout(timeout: Duration, has_more: bool) -> Duration {
    if has_more {
        Duration::from_secs(6).min(timeout)
    } else {
        timeout
    }
}

fn looks_like_non_subscription_json(text: &str) -> bool {
    if !text.starts_with('{') {
        return false;
    }
    let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    !(map.contains_key("outbounds") || map.contains_key("proxies") || map.contains_key("Proxy"))
}

async fn fetch_url_single_attempt(
    parsed_url: &Url,
    timeout: Duration,
    opts: &FetchOptions,
    has_more: bool,
) -> Result<FetchedSubscription, SingleFetchError> {
    let connect_timeout = effective_connect_timeout(timeout, has_more);
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(connect_timeout)
        .user_agent(opts.user_agent.as_str());

    let mut used_proxy: Option<String> = None;
    if opts.no_proxy {
        builder = builder.no_proxy();
    } else if let Some(ref proxy_url) = opts.proxy_url {
        let trimmed_proxy = proxy_url.trim();
        if !trimmed_proxy.is_empty() {
            let proxy = reqwest::Proxy::all(trimmed_proxy).map_err(|e| {
                tracing::debug!(
                    proxy = %sanitize_proxy_label(trimmed_proxy),
                    error = %e,
                    "invalid subscription proxy configuration"
                );
                SingleFetchError::Retryable(format!(
                    "代理地址「{}」配置无效，请检查协议与端口格式",
                    sanitize_proxy_label(trimmed_proxy),
                ))
            })?;
            builder = builder.proxy(proxy);
            used_proxy = Some(trimmed_proxy.to_string());
        }
    }

    let client = builder.build().map_err(|e| {
        tracing::debug!(error = %e, "failed to initialize reqwest client");
        SingleFetchError::Retryable(format!(
            "初始化网络客户端失败：{}",
            format_reqwest_error_zh(&e)
        ))
    })?;
    let mut response = client
        .get(parsed_url.clone())
        .send()
        .await
        .map_err(|e| SingleFetchError::Retryable(format_reqwest_error_zh(&e)))?;

    let status = response.status();
    if !status.is_success() {
        let msg = format_http_status_zh(status);
        let code = status.as_u16();
        if matches!(code, 403 | 407 | 408 | 429 | 500 | 502 | 503 | 504 | 520..=526)
            || (has_more && opts.no_proxy && code == 404)
        {
            return Err(SingleFetchError::Retryable(msg));
        }
        return Err(SingleFetchError::Fatal(CatError::Config(msg)));
    }

    if let Some(content_len) = response.content_length() {
        if content_len > MAX_SUBSCRIPTION_BYTES as u64 {
            return Err(SingleFetchError::Fatal(CatError::Validation(format!(
                "订阅内容过大（{} 字节，超过 16 MiB 上限），已自动中止下载",
                content_len
            ))));
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
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| SingleFetchError::Retryable(format_reqwest_error_zh(&e)))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_SUBSCRIPTION_BYTES {
            return Err(SingleFetchError::Fatal(CatError::Validation(
                "订阅响应体积超过 16 MiB 上限，已自动中止下载".to_string(),
            )));
        }
        body.extend_from_slice(&chunk);
    }

    if has_more {
        if body.is_empty() {
            return Err(SingleFetchError::Retryable(
                "订阅返回内容为空（可能受到网络拦截或需切换代理拉取）".to_string(),
            ));
        }
        if let Ok(text_raw) = std::str::from_utf8(&body) {
            let text = text_raw.strip_prefix('\u{FEFF}').unwrap_or(text_raw).trim();
            if text.is_empty() {
                return Err(SingleFetchError::Retryable(
                    "订阅返回内容为空（可能受到网络拦截或需切换代理拉取）".to_string(),
                ));
            }
            if looks_like_html_document(text) {
                return Err(SingleFetchError::Retryable(
                    "订阅链接返回了网页而非节点列表（可能链接已失效、需要登录或被防火墙拦截）"
                        .to_string(),
                ));
            }
            if looks_like_non_subscription_json(text) {
                return Err(SingleFetchError::Retryable(
                    "订阅接口返回了非节点 JSON 响应（可能被防火墙拦截或限制地区访问）"
                        .to_string(),
                ));
            }
        }
    }

    Ok(FetchedSubscription {
        body,
        userinfo_header,
        etag,
        used_proxy,
    })
}

/// Fetch a single remote subscription URL using the provided transport options and default timeout.
pub async fn fetch_subscription_url(
    url: &str,
    opts: &FetchOptions,
) -> CatResult<FetchedSubscription> {
    let normalized_url = normalize_subscription_input_url(url);
    let parsed_url = validate_subscription_http_url(&normalized_url)?;
    match fetch_url_single_attempt(&parsed_url, DEFAULT_SUBSCRIPTION_TIMEOUT, opts, false).await {
        Ok(fetched) => Ok(fetched),
        Err(SingleFetchError::Fatal(err)) => Err(err),
        Err(SingleFetchError::Retryable(reason)) => Err(CatError::Config(reason)),
    }
}

/// Fetch a subscription URL trying `proxy_candidates` in order (`None` = direct with `no_proxy=true`,
/// `Some(proxy)` = via that proxy). Returns on the first successful route; automatically falls back
/// across network timeouts, connection resets, TLS failures, or transient HTTP/HTML blocks.
pub async fn fetch_subscription_url_with_fallback(
    url: &str,
    proxy_candidates: &[Option<String>],
    base_opts: &FetchOptions,
) -> CatResult<FetchedSubscription> {
    let normalized_url = normalize_subscription_input_url(url);
    fetch_subscription_url_with_fallback_timeout(
        &normalized_url,
        DEFAULT_SUBSCRIPTION_TIMEOUT,
        proxy_candidates,
        base_opts,
    )
    .await
}

/// Same as `fetch_subscription_url_with_fallback`, with an explicit per-attempt timeout.
pub async fn fetch_subscription_url_with_fallback_timeout(
    url: &str,
    timeout: Duration,
    proxy_candidates: &[Option<String>],
    base_opts: &FetchOptions,
) -> CatResult<FetchedSubscription> {
    let normalized_url = normalize_subscription_input_url(url);
    let parsed_url = validate_subscription_http_url(&normalized_url)?;

    let mut normalized: Vec<Option<String>> = Vec::with_capacity(proxy_candidates.len().max(1));
    let mut seen_direct = false;
    let mut seen_proxies: HashSet<String> = HashSet::new();
    for candidate in proxy_candidates {
        match candidate {
            None => {
                if !seen_direct {
                    seen_direct = true;
                    normalized.push(None);
                }
            }
            Some(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let key = trimmed.to_ascii_lowercase();
                if seen_proxies.insert(key) {
                    normalized.push(Some(trimmed.to_string()));
                }
            }
        }
    }
    if normalized.is_empty() {
        normalized.push(None);
    }

    let total = normalized.len();
    let mut attempts: Vec<(String, String)> = Vec::with_capacity(total);
    for (idx, candidate) in normalized.into_iter().enumerate() {
        let has_more = idx + 1 < total;
        let (label, attempt_opts) = match candidate {
            None => (
                "直连".to_string(),
                FetchOptions {
                    no_proxy: true,
                    proxy_url: None,
                    user_agent: base_opts.user_agent.clone(),
                },
            ),
            Some(proxy) => (
                format!("经代理 {}", sanitize_proxy_label(&proxy)),
                FetchOptions {
                    no_proxy: false,
                    proxy_url: Some(proxy),
                    user_agent: base_opts.user_agent.clone(),
                },
            ),
        };

        match fetch_url_single_attempt(&parsed_url, timeout, &attempt_opts, has_more).await {
            Ok(fetched) => return Ok(fetched),
            Err(SingleFetchError::Fatal(err)) => return Err(err),
            Err(SingleFetchError::Retryable(reason)) => {
                attempts.push((label, reason));
            }
        }
    }

    if attempts.len() == 1 {
        let (label, reason) = &attempts[0];
        return Err(CatError::Config(format!("拉取订阅失败（{label}）：{reason}")));
    }

    let all_html = attempts
        .iter()
        .all(|(_, reason)| reason.contains("返回了网页而非节点列表"));
    if all_html {
        return Err(CatError::Validation(
            "订阅链接返回了网页而非节点列表（可能链接已失效、需要登录或被防火墙拦截）"
                .to_string(),
        ));
    }

    let summary = attempts
        .iter()
        .map(|(label, reason)| format!("{label}：{reason}"))
        .collect::<Vec<_>>()
        .join("；");
    Err(CatError::Config(format!(
        "订阅拉取失败，已依次尝试多条网络路径仍未成功（{summary}）。请检查订阅链接是否有效，或先开启代理后重试"
    )))
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
/// - Malformed YAML/JSON, HTML error pages, or HTTP 200 with 0 valid nodes returns `Err`
pub async fn fetch_and_parse_subscription_with_options(
    sub: &SubscriptionRecord,
    timeout: Duration,
    opts: &FetchOptions,
) -> CatResult<ParsedSubscription> {
    if sub.id.trim().is_empty() {
        return Err(CatError::Validation("订阅标识不能为空".to_string()));
    }

    let source = sub.url_or_cmd.trim();
    if source.is_empty() {
        return Err(CatError::Validation(
            "订阅链接或路径不能为空".to_string(),
        ));
    }

    if sub.kind == SubscriptionKind::File {
        return read_local_subscription_file(&sub.id, source);
    }

    let normalized_url = normalize_subscription_input_url(source);
    let parsed_url = validate_subscription_http_url(&normalized_url)?;
    let fetched = match fetch_url_single_attempt(&parsed_url, timeout, opts, false).await {
        Ok(f) => f,
        Err(SingleFetchError::Fatal(err)) => return Err(err),
        Err(SingleFetchError::Retryable(reason)) => return Err(CatError::Config(reason)),
    };
    fetched.parse(&sub.id)
}

/// Fetch and parse a subscription trying `proxy_candidates` in order (direct / local proxy / system proxy).
pub async fn fetch_and_parse_subscription_with_fallback(
    sub: &SubscriptionRecord,
    timeout: Duration,
    proxy_candidates: &[Option<String>],
    base_opts: &FetchOptions,
) -> CatResult<ParsedSubscription> {
    if sub.id.trim().is_empty() {
        return Err(CatError::Validation("订阅标识不能为空".to_string()));
    }
    let source = sub.url_or_cmd.trim();
    if source.is_empty() {
        return Err(CatError::Validation("订阅链接或路径不能为空".to_string()));
    }
    if sub.kind == SubscriptionKind::File {
        return read_local_subscription_file(&sub.id, source);
    }
    let normalized_url = normalize_subscription_input_url(source);
    let fetched = fetch_subscription_url_with_fallback_timeout(
        &normalized_url,
        timeout,
        proxy_candidates,
        base_opts,
    )
    .await?;
    fetched.parse(&sub.id)
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
            "未解析到有效节点，已取消更新以保留原有节点数据".to_string(),
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
        let parsed = Url::parse(source).map_err(|e| {
            tracing::debug!(error = %e, "local subscription file:// URL parse failed");
            CatError::Validation("本地文件地址格式不正确，请确认路径是否完整有效".to_string())
        })?;
        parsed
            .to_file_path()
            .map_err(|_| CatError::Validation("无法将 file:// 地址转换为本机文件路径".into()))?
    } else {
        Path::new(source).to_path_buf()
    };

    if !path_buf.is_file() {
        return Err(CatError::NotFound(format!(
            "找不到本地订阅文件：{}",
            path_buf.display()
        )));
    }

    let meta = std::fs::metadata(&path_buf)?;
    if meta.len() > MAX_SUBSCRIPTION_BYTES as u64 {
        return Err(CatError::Validation(format!(
            "本地订阅文件过大（{} 字节，超过 16 MiB 上限）",
            meta.len()
        )));
    }

    let raw = std::fs::read(&path_buf)?;
    parse_subscription_payload(sub_id, &raw, None)
}

// ============================================================================
// Two-stage serde_yaml_ng parsing (with anchor merge) & Clash / sing-box extraction
// ============================================================================

/// Parse YAML text using `serde_yaml_ng` two-stage parsing (`from_str` + `apply_merge`)
/// so YAML anchors and `<<: *anchor` merges are fully expanded before inspection.
pub(crate) fn parse_clash_yaml_value(text: &str) -> CatResult<serde_yaml_ng::Value> {
    let mut val: serde_yaml_ng::Value = serde_yaml_ng::from_str(text).map_err(|e| {
        tracing::debug!(error = %e, "subscription YAML parse failed");
        CatError::Validation(
            "订阅 YAML 格式有误，无法解析（请确认内容为完整的 Clash/Mihomo 配置文件）"
                .to_string(),
        )
    })?;
    val.apply_merge().map_err(|e| {
        tracing::debug!(error = %e, "subscription YAML anchor merge failed");
        CatError::Validation(
            "订阅 YAML 锚点合并失败，配置中可能存在无效的引用定义".to_string(),
        )
    })?;
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
            "订阅内容不是有效的 Clash YAML 配置格式，请确认复制的是完整订阅链接".to_string(),
        ));
    };

    let proxies_val = root_map
        .get(serde_yaml_ng::Value::String("proxies".to_string()))
        .or_else(|| root_map.get(serde_yaml_ng::Value::String("Proxy".to_string())));

    let Some(proxies_val) = proxies_val else {
        return Err(CatError::Validation(
            "订阅配置中缺少 proxies 节点列表，请确认该链接为有效的代理订阅".to_string(),
        ));
    };

    let Some(seq) = proxies_val.as_sequence() else {
        if proxies_val.is_null() {
            return Ok((Vec::new(), vec!["proxies 字段为空".to_string()]));
        }
        return Err(CatError::Validation(
            "订阅配置中的 proxies 字段格式不正确（应为节点数组）".to_string(),
        ));
    };

    let mut nodes = Vec::with_capacity(seq.len());
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::with_capacity(seq.len());

    for (idx, item) in seq.iter().enumerate() {
        let json_item = yaml_value_to_json(item);
        let Some(obj) = json_item.as_object() else {
            warnings.push(format!("已跳过第 {} 条节点：格式不是键值对对象", idx + 1));
            continue;
        };
        match node_from_clash_json(sub_id, obj, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(reason) => warnings.push(format!("已跳过第 {} 条节点：{reason}", idx + 1)),
        }
    }

    Ok((nodes, warnings))
}

fn extract_nodes_from_clash_json_root(
    sub_id: &str,
    json_val: &serde_json::Value,
) -> Option<(Vec<ProxyNode>, Vec<String>)> {
    let arr = json_val.get("proxies").and_then(serde_json::Value::as_array)?;
    let mut nodes = Vec::with_capacity(arr.len());
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            warnings.push(format!("已跳过第 {} 条节点：格式不是对象", idx + 1));
            continue;
        };
        match node_from_clash_json(sub_id, obj, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(reason) => warnings.push(format!("已跳过第 {} 条节点：{reason}", idx + 1)),
        }
    }
    Some((nodes, warnings))
}

/// Extract proxy nodes from a standard sing-box JSON document containing an `outbounds` array,
/// translating sing-box fields (`server_port`, object `tls`, `transport`, `reality`, `obfs`, etc.)
/// into Mihomo-compatible `raw_config` maps.
pub(crate) fn extract_nodes_from_singbox_json(
    sub_id: &str,
    json_val: &serde_json::Value,
) -> Option<(Vec<ProxyNode>, Vec<String>)> {
    let outbounds = json_val
        .get("outbounds")
        .and_then(serde_json::Value::as_array)?;
    let mut nodes = Vec::new();
    let mut warnings = Vec::new();
    let mut used_ids = HashSet::new();

    for (idx, item) in outbounds.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            continue;
        };
        let raw_type = obj
            .get("type")
            .or_else(|| obj.get("protocol"))
            .and_then(serde_json::Value::as_str)
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if matches!(
            raw_type.as_str(),
            "" | "direct"
                | "block"
                | "dns"
                | "selector"
                | "urltest"
                | "freedom"
                | "blackhole"
                | "loopback"
        ) {
            continue;
        }
        if let Some(node) = node_from_singbox_outbound(sub_id, obj, &mut used_ids) {
            nodes.push(node);
        } else {
            let tag = obj
                .get("tag")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("未命名");
            warnings.push(format!(
                "已跳过 sing-box outbounds[{}]（{tag}）：协议暂不支持或缺少必要连接参数",
                idx + 1
            ));
        }
    }
    Some((nodes, warnings))
}

fn json_value_to_header_strings(val: &serde_json::Value) -> Vec<String> {
    match val {
        serde_json::Value::String(s) => {
            let t = s.trim();
            if t.is_empty() {
                Vec::new()
            } else {
                vec![t.to_string()]
            }
        }
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|item| match item {
                serde_json::Value::String(s) => {
                    let t = s.trim();
                    (!t.is_empty()).then(|| t.to_string())
                }
                serde_json::Value::Number(n) => Some(n.to_string()),
                serde_json::Value::Bool(b) => Some(b.to_string()),
                _ => None,
            })
            .collect(),
        serde_json::Value::Number(n) => vec![n.to_string()],
        serde_json::Value::Bool(b) => vec![b.to_string()],
        _ => Vec::new(),
    }
}

/// Normalize Mihomo `ws-opts.headers` (`map[string]string`):
/// array values are flattened to a scalar string (first non-empty item for `Host`,
/// comma-joined for multi-value headers).
pub(crate) fn normalize_ws_headers_map(
    headers: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::with_capacity(headers.len());
    for (k, v) in headers {
        let key = k.trim();
        if key.is_empty() {
            continue;
        }
        let vals = json_value_to_header_strings(v);
        if vals.is_empty() {
            continue;
        }
        let scalar = if key.eq_ignore_ascii_case("host") || vals.len() == 1 {
            vals[0].clone()
        } else {
            vals.join(", ")
        };
        out.insert(key.to_string(), serde_json::Value::String(scalar));
    }
    out
}

/// Normalize Mihomo `http-opts.headers` (`map[string][]string`):
/// scalar values are wrapped into single-element arrays, and optional sing-box
/// `transport.host` entries are merged into the `Host` array.
fn normalize_http_headers_map(
    headers: Option<&serde_json::Map<String, serde_json::Value>>,
    transport_host: Option<&serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    let mut host_values: Vec<String> = Vec::new();
    if let Some(map) = headers {
        for (k, v) in map {
            let key = k.trim();
            if key.is_empty() {
                continue;
            }
            let vals = json_value_to_header_strings(v);
            if vals.is_empty() {
                continue;
            }
            if key.eq_ignore_ascii_case("host") {
                for h in vals {
                    if !host_values.contains(&h) {
                        host_values.push(h);
                    }
                }
            } else {
                out.insert(key.to_string(), serde_json::json!(vals));
            }
        }
    }
    if let Some(host_val) = transport_host {
        for h in json_value_to_header_strings(host_val) {
            if !host_values.contains(&h) {
                host_values.push(h);
            }
        }
    }
    if !host_values.is_empty() {
        out.insert("Host".to_string(), serde_json::json!(host_values));
    }
    out
}

fn format_hy2_bandwidth(val: &serde_json::Value) -> Option<String> {
    if let Some(n) = val.as_u64() {
        return (n > 0).then(|| format!("{n} Mbps"));
    }
    if let Some(f) = val.as_f64() {
        if f.is_finite() && f > 0.0 {
            let rounded = f.round() as u64;
            return (rounded > 0).then(|| format!("{rounded} Mbps"));
        }
        return None;
    }
    let s = val.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(n) = s.parse::<u64>() {
        return (n > 0).then(|| format!("{n} Mbps"));
    }
    let num_prefix: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if !num_prefix.is_empty() {
        if let Ok(v) = num_prefix.parse::<f64>() {
            if !v.is_finite() || v <= 0.0 {
                return None;
            }
        }
    }
    Some(s.to_string())
}

/// Convert a single sing-box JSON outbound object into a Mihomo-compatible `ProxyNode`.
///
/// Guarantees that object-form sing-box `tls: { enabled: true, ... }` and `transport: { ... }`
/// are flattened into Mihomo-standard fields (`tls: bool`, `servername`/`sni`, `skip-cert-verify`,
/// `reality-opts`, `network`, `ws-opts`, `grpc-opts`, `h2-opts`, etc.) so downstream Mihomo
/// config compilation never fails on schema mismatch.
pub(crate) fn node_from_singbox_outbound(
    sub_id: &str,
    obj: &serde_json::Map<String, serde_json::Value>,
    used_ids: &mut HashSet<String>,
) -> Option<ProxyNode> {
    let raw_type = obj
        .get("type")
        .or_else(|| obj.get("protocol"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let raw_lower = raw_type.to_ascii_lowercase();
    if !matches!(
        raw_lower.as_str(),
        "shadowsocks"
            | "ss"
            | "vmess"
            | "vless"
            | "trojan"
            | "hysteria2"
            | "hy2"
            | "tuic"
            | "anytls"
            | "socks"
            | "socks5"
            | "http"
    ) {
        tracing::debug!(
            outbound_type = %raw_lower,
            "skipping unsupported sing-box outbound type"
        );
        return None;
    }

    let server = obj
        .get("server")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let port = obj
        .get("server_port")
        .or_else(|| obj.get("port"))
        .and_then(json_to_u16)
        .filter(|&p| p > 0)?;

    let protocol = normalize_protocol(&raw_lower);

    // Enforce protocol-required credentials so incomplete nodes never break `mihomo -t`.
    let has_uuid = non_empty_str(obj.get("uuid")).is_some();
    let has_password = non_empty_str(obj.get("password")).is_some();
    let has_ss_cipher = non_empty_str(obj.get("method").or_else(|| obj.get("cipher"))).is_some();
    match protocol.as_str() {
        "ss" if !has_ss_cipher || !has_password => {
            tracing::debug!(
                protocol = %protocol,
                has_cipher = has_ss_cipher,
                has_password = has_password,
                "skipping sing-box ss outbound missing required cipher or password"
            );
            return None;
        }
        "vless" | "vmess" | "tuic" if !has_uuid => {
            tracing::debug!(
                protocol = %protocol,
                "skipping sing-box outbound missing required uuid"
            );
            return None;
        }
        "trojan" | "hysteria2" | "anytls" if !has_password => {
            tracing::debug!(
                protocol = %protocol,
                "skipping sing-box outbound missing required password"
            );
            return None;
        }
        _ => {}
    }

    let name = obj
        .get("tag")
        .or_else(|| obj.get("name"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{protocol}-{server}:{port}"));

    let mut cfg = serde_json::Map::new();
    cfg.insert("name".into(), serde_json::json!(name));
    cfg.insert("type".into(), serde_json::json!(protocol));
    cfg.insert("server".into(), serde_json::json!(server));
    cfg.insert("port".into(), serde_json::json!(port));

    let udp_disabled = obj
        .get("network")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|n| n.trim().eq_ignore_ascii_case("tcp"));
    if matches!(
        protocol.as_str(),
        "vless" | "vmess" | "trojan" | "ss" | "socks5" | "anytls"
    ) {
        cfg.insert("udp".into(), serde_json::json!(!udp_disabled));
    }

    if let Some(uuid) = non_empty_str(obj.get("uuid")) {
        cfg.insert("uuid".into(), serde_json::json!(uuid));
    }
    if let Some(password) = non_empty_str(obj.get("password")) {
        cfg.insert("password".into(), serde_json::json!(password));
    }
    if let Some(username) = non_empty_str(obj.get("username")) {
        cfg.insert("username".into(), serde_json::json!(username));
    }
    if let Some(flow) = non_empty_str(obj.get("flow")) {
        cfg.insert("flow".into(), serde_json::json!(flow));
    }
    if let Some(pe) = non_empty_str(
        obj.get("packet_encoding")
            .or_else(|| obj.get("packet-encoding")),
    ) {
        cfg.insert("packet-encoding".into(), serde_json::json!(pe));
    }

    match protocol.as_str() {
        "ss" => {
            if let Some(method) = non_empty_str(obj.get("method").or_else(|| obj.get("cipher"))) {
                cfg.insert("cipher".into(), serde_json::json!(method));
            }
            if let Some(plugin) = non_empty_str(obj.get("plugin")) {
                let mapped = match plugin {
                    "obfs-local" | "simple-obfs" => "obfs",
                    other => other,
                };
                cfg.insert("plugin".into(), serde_json::json!(mapped));
                if let Some(po) = obj.get("plugin_opts").or_else(|| obj.get("plugin-opts")) {
                    if let Some(po_obj) = po.as_object() {
                        if !po_obj.is_empty() {
                            cfg.insert(
                                "plugin-opts".into(),
                                serde_json::Value::Object(po_obj.clone()),
                            );
                        }
                    } else if let Some(po_str) = po.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        let mut opts = serde_json::Map::new();
                        for part in po_str.split(';') {
                            if let Some((ok, ov)) = part.split_once('=') {
                                let key = match (mapped, ok.trim()) {
                                    ("obfs", "obfs") => "mode",
                                    ("obfs", "obfs-host") => "host",
                                    (_, other) => other,
                                };
                                opts.insert(key.to_string(), serde_json::json!(ov.trim()));
                            } else if !part.trim().is_empty() {
                                opts.insert(part.trim().to_string(), serde_json::json!(true));
                            }
                        }
                        if !opts.is_empty() {
                            cfg.insert("plugin-opts".into(), serde_json::Value::Object(opts));
                        }
                    }
                }
            }
        }
        "vmess" => {
            let cipher = non_empty_str(obj.get("security").or_else(|| obj.get("cipher")))
                .unwrap_or("auto");
            cfg.insert("cipher".into(), serde_json::json!(cipher));
            let alter_id = obj
                .get("alter_id")
                .or_else(|| obj.get("alterId"))
                .and_then(json_to_u64)
                .unwrap_or(0);
            cfg.insert("alterId".into(), serde_json::json!(alter_id));
        }
        "hysteria2" => {
            if let Some(up_val) = obj.get("up_mbps").or_else(|| obj.get("up")) {
                if let Some(bw) = format_hy2_bandwidth(up_val) {
                    cfg.insert("up".into(), serde_json::json!(bw));
                }
            }
            if let Some(down_val) = obj.get("down_mbps").or_else(|| obj.get("down")) {
                if let Some(bw) = format_hy2_bandwidth(down_val) {
                    cfg.insert("down".into(), serde_json::json!(bw));
                }
            }
            if let Some(obfs_val) = obj.get("obfs") {
                if let Some(obfs_obj) = obfs_val.as_object() {
                    if let Some(t) = non_empty_str(obfs_obj.get("type")) {
                        cfg.insert("obfs".into(), serde_json::json!(t));
                    }
                    if let Some(pw) = non_empty_str(obfs_obj.get("password")) {
                        cfg.insert("obfs-password".into(), serde_json::json!(pw));
                    }
                } else if let Some(t) = non_empty_str(Some(obfs_val)) {
                    cfg.insert("obfs".into(), serde_json::json!(t));
                }
            }
            if let Some(pw) = non_empty_str(obj.get("obfs-password")) {
                cfg.insert("obfs-password".into(), serde_json::json!(pw));
            }
            if let Some(ports_val) = obj.get("server_ports").or_else(|| obj.get("ports")) {
                if let Some(arr) = ports_val.as_array() {
                    let joined: Vec<String> = arr
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(|s| s.trim().replace(':', "-"))
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !joined.is_empty() {
                        cfg.insert("ports".into(), serde_json::json!(joined.join(",")));
                    }
                } else if let Some(s) = non_empty_str(Some(ports_val)) {
                    cfg.insert("ports".into(), serde_json::json!(s.replace(':', "-")));
                }
            }
        }
        "tuic" => {
            if let Some(cc) = non_empty_str(
                obj.get("congestion_control")
                    .or_else(|| obj.get("congestion-controller")),
            ) {
                cfg.insert("congestion-controller".into(), serde_json::json!(cc));
            }
            if let Some(mode) = non_empty_str(
                obj.get("udp_relay_mode")
                    .or_else(|| obj.get("udp-relay-mode")),
            ) {
                cfg.insert("udp-relay-mode".into(), serde_json::json!(mode));
            }
            if let Some(z) = obj
                .get("zero_rtt_handshake")
                .or_else(|| obj.get("reduce-rtt"))
                .and_then(serde_json::Value::as_bool)
            {
                cfg.insert("reduce-rtt".into(), serde_json::json!(z));
            }
        }
        _ => {}
    }

    // Flatten sing-box `tls` object (or bool) into Mihomo-compatible fields.
    let uses_sni_key = matches!(
        protocol.as_str(),
        "trojan" | "hysteria2" | "hysteria" | "tuic" | "anytls"
    );
    let mut effective_tls = uses_sni_key;
    if let Some(tls_val) = obj.get("tls") {
        if let Some(tls_obj) = tls_val.as_object() {
            let tls_enabled = tls_obj
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let reality_obj = tls_obj
                .get("reality")
                .and_then(serde_json::Value::as_object);
            let reality_enabled = reality_obj.is_some_and(|r| {
                r.get("enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false)
                    || non_empty_str(r.get("public_key").or_else(|| r.get("public-key"))).is_some()
            });
            effective_tls = tls_enabled || reality_enabled || uses_sni_key;
            if !uses_sni_key {
                cfg.insert("tls".into(), serde_json::json!(tls_enabled || reality_enabled));
            }
            if let Some(sni) = non_empty_str(
                tls_obj
                    .get("server_name")
                    .or_else(|| tls_obj.get("servername"))
                    .or_else(|| tls_obj.get("sni")),
            ) {
                cfg.insert(
                    if uses_sni_key { "sni" } else { "servername" }.into(),
                    serde_json::json!(sni),
                );
            }
            if let Some(insecure) = tls_obj
                .get("insecure")
                .or_else(|| tls_obj.get("skip-cert-verify"))
                .and_then(serde_json::Value::as_bool)
            {
                cfg.insert("skip-cert-verify".into(), serde_json::json!(insecure));
            }
            if let Some(alpn_val) = tls_obj.get("alpn") {
                if let Some(arr) = alpn_val.as_array() {
                    let list: Vec<String> = arr
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToOwned::to_owned)
                        .collect();
                    if !list.is_empty() {
                        cfg.insert("alpn".into(), serde_json::json!(list));
                    }
                } else if let Some(s) = non_empty_str(Some(alpn_val)) {
                    cfg.insert("alpn".into(), serde_json::json!([s]));
                }
            }
            if let Some(fp) = tls_obj
                .get("utls")
                .and_then(serde_json::Value::as_object)
                .filter(|u| u.get("enabled").and_then(serde_json::Value::as_bool) != Some(false))
                .and_then(|u| non_empty_str(u.get("fingerprint")))
                .or_else(|| non_empty_str(tls_obj.get("fingerprint")))
            {
                cfg.insert("client-fingerprint".into(), serde_json::json!(fp));
            }
            if reality_enabled {
                if let Some(r) = reality_obj {
                    let mut rmap = serde_json::Map::new();
                    if let Some(pbk) =
                        non_empty_str(r.get("public_key").or_else(|| r.get("public-key")))
                    {
                        rmap.insert("public-key".into(), serde_json::json!(pbk));
                    }
                    if let Some(sid) =
                        non_empty_str(r.get("short_id").or_else(|| r.get("short-id")))
                    {
                        rmap.insert("short-id".into(), serde_json::json!(sid));
                    }
                    if !rmap.is_empty() {
                        cfg.insert("reality-opts".into(), serde_json::Value::Object(rmap));
                    }
                }
            }
        } else if let Some(b) = tls_val.as_bool() {
            effective_tls = b;
            if !uses_sni_key {
                cfg.insert("tls".into(), serde_json::json!(b));
            }
        }
    }

    // Also preserve flat Mihomo-style TLS hints if present without a sing-box `tls` object.
    if !cfg.contains_key("sni") && !cfg.contains_key("servername") {
        if let Some(sni) = non_empty_str(
            obj.get("server_name")
                .or_else(|| obj.get("servername"))
                .or_else(|| obj.get("sni")),
        ) {
            cfg.insert(
                if uses_sni_key { "sni" } else { "servername" }.into(),
                serde_json::json!(sni),
            );
        }
    }
    if !cfg.contains_key("skip-cert-verify") {
        if let Some(skip) = obj
            .get("skip-cert-verify")
            .or_else(|| obj.get("insecure"))
            .and_then(serde_json::Value::as_bool)
        {
            cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
        }
    }

    // Flatten sing-box `transport` object into Mihomo `network` + `ws-opts` / `grpc-opts` / `h2-opts`.
    if let Some(tr) = obj.get("transport").and_then(serde_json::Value::as_object) {
        let tr_type = non_empty_str(tr.get("type"))
            .unwrap_or("")
            .to_ascii_lowercase();
        match tr_type.as_str() {
            "ws" => {
                cfg.insert("network".into(), serde_json::json!("ws"));
                let mut ws_opts = serde_json::Map::new();
                if let Some(path) = non_empty_str(tr.get("path")) {
                    ws_opts.insert("path".into(), serde_json::json!(path));
                }
                if let Some(headers) = tr.get("headers").and_then(serde_json::Value::as_object) {
                    let norm_headers = normalize_ws_headers_map(headers);
                    if !norm_headers.is_empty() {
                        ws_opts.insert("headers".into(), serde_json::Value::Object(norm_headers));
                    }
                }
                if let Some(ed) = tr
                    .get("max_early_data")
                    .or_else(|| tr.get("max-early-data"))
                    .and_then(json_to_u64)
                {
                    ws_opts.insert("max-early-data".into(), serde_json::json!(ed));
                }
                if let Some(edh) = non_empty_str(
                    tr.get("early_data_header_name")
                        .or_else(|| tr.get("early-data-header-name")),
                ) {
                    ws_opts.insert("early-data-header-name".into(), serde_json::json!(edh));
                }
                if !ws_opts.is_empty() {
                    cfg.insert("ws-opts".into(), serde_json::Value::Object(ws_opts));
                }
            }
            "grpc" => {
                cfg.insert("network".into(), serde_json::json!("grpc"));
                if let Some(svc) = non_empty_str(
                    tr.get("service_name")
                        .or_else(|| tr.get("service-name"))
                        .or_else(|| tr.get("path")),
                ) {
                    cfg.insert(
                        "grpc-opts".into(),
                        serde_json::json!({ "grpc-service-name": svc }),
                    );
                }
            }
            "http" | "h2" => {
                if effective_tls || tr_type == "h2" {
                    cfg.insert("network".into(), serde_json::json!("h2"));
                    let mut h2_opts = serde_json::Map::new();
                    if let Some(path) = non_empty_str(tr.get("path")) {
                        h2_opts.insert("path".into(), serde_json::json!(path));
                    }
                    if let Some(host_val) = tr.get("host") {
                        let hosts = json_value_to_header_strings(host_val);
                        if !hosts.is_empty() {
                            h2_opts.insert("host".into(), serde_json::json!(hosts));
                        }
                    }
                    if !h2_opts.is_empty() {
                        cfg.insert("h2-opts".into(), serde_json::Value::Object(h2_opts));
                    }
                } else {
                    cfg.insert("network".into(), serde_json::json!("http"));
                    let mut http_opts = serde_json::Map::new();
                    if let Some(path_val) = tr.get("path") {
                        let paths = json_value_to_header_strings(path_val);
                        if !paths.is_empty() {
                            http_opts.insert("path".into(), serde_json::json!(paths));
                        }
                    }
                    if let Some(method) = non_empty_str(tr.get("method")) {
                        http_opts.insert("method".into(), serde_json::json!(method));
                    }
                    let norm_headers = normalize_http_headers_map(
                        tr.get("headers").and_then(serde_json::Value::as_object),
                        tr.get("host"),
                    );
                    if !norm_headers.is_empty() {
                        http_opts.insert("headers".into(), serde_json::Value::Object(norm_headers));
                    }
                    if !http_opts.is_empty() {
                        cfg.insert("http-opts".into(), serde_json::Value::Object(http_opts));
                    }
                }
            }
            "httpupgrade" => {
                cfg.insert("network".into(), serde_json::json!("ws"));
                let mut ws_opts = serde_json::Map::new();
                ws_opts.insert("v2ray-http-upgrade".into(), serde_json::json!(true));
                if let Some(path) = non_empty_str(tr.get("path")) {
                    ws_opts.insert("path".into(), serde_json::json!(path));
                }
                let mut headers_map = tr
                    .get("headers")
                    .and_then(serde_json::Value::as_object)
                    .map(normalize_ws_headers_map)
                    .unwrap_or_default();
                if !headers_map.keys().any(|k| k.eq_ignore_ascii_case("host")) {
                    if let Some(host) = tr
                        .get("host")
                        .and_then(|v| json_value_to_header_strings(v).into_iter().next())
                    {
                        headers_map.insert("Host".to_string(), serde_json::json!(host));
                    }
                }
                if !headers_map.is_empty() {
                    ws_opts.insert("headers".into(), serde_json::Value::Object(headers_map));
                }
                cfg.insert("ws-opts".into(), serde_json::Value::Object(ws_opts));
            }
            _ => {}
        }
    }

    Some(build_proxy_node(
        sub_id,
        name,
        protocol,
        server,
        port,
        serde_json::Value::Object(cfg),
        used_ids,
    ))
}

fn non_empty_str(val: Option<&serde_json::Value>) -> Option<&str> {
    val.and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
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
        .ok_or_else(|| "缺少节点协议类型（type）".to_string())?;
    let protocol = normalize_protocol(raw_type);

    let server = obj
        .get("server")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "缺少服务器地址（server）".to_string())?
        .to_string();

    let port = obj
        .get("port")
        .and_then(json_to_u16)
        .filter(|&p| p > 0)
        .ok_or_else(|| "缺少有效端口（port）".to_string())?;

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
                "已跳过第 {} 行：暂不支持的协议或非节点链接",
                line_no + 1
            ));
            continue;
        }
        match parse_proxy_uri_line(sub_id, line, &mut used_ids) {
            Ok(node) => nodes.push(node),
            Err(err) => warnings.push(format!("已跳过第 {} 行：{err}", line_no + 1)),
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
        return Err("节点链接缺少协议前缀（例如 vless://、trojan://）".to_string());
    };
    match raw_scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless_uri(sub_id, trimmed, used_ids),
        "vmess" => parse_vmess_uri(sub_id, trimmed, used_ids),
        "trojan" => parse_trojan_uri(sub_id, trimmed, used_ids),
        "ss" => parse_ss_uri(sub_id, trimmed, used_ids),
        "hy2" | "hysteria2" => parse_hysteria2_uri(sub_id, trimmed, used_ids),
        "tuic" => parse_tuic_uri(sub_id, trimmed, used_ids),
        "anytls" => parse_anytls_uri(sub_id, trimmed, used_ids),
        other => Err(format!("暂不支持的节点协议「{other}」")),
    }
}

fn parse_vless_uri(
    sub_id: &str,
    uri: &str,
    used_ids: &mut HashSet<String>,
) -> Result<ProxyNode, String> {
    let parsed = Url::parse(uri).map_err(|e| {
        tracing::debug!(error = %e, "vless URI parse failed");
        "VLESS 节点链接格式有误，请检查地址与端口是否完整".to_string()
    })?;
    let uuid = percent_decode(parsed.username());
    if uuid.is_empty() {
        return Err("VLESS 节点链接缺少 UUID".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("VLESS 节点链接端口无效（不能为 0）".to_string());
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
    if let Some(skip) = query_skip_cert_verify(&params) {
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
    let raw_body = uri
        .get(8..)
        .ok_or_else(|| "VMess 节点链接格式不完整".to_string())?
        .trim();

    // Strip optional trailing `#remark` before Base64 decoding (some panels append `#节点名`).
    let (body_no_frag, frag_remark) = match raw_body.split_once('#') {
        Some((b, f)) => {
            let decoded = percent_decode(f).trim().to_string();
            (b.trim(), (!decoded.is_empty()).then_some(decoded))
        }
        None => (raw_body, None),
    };

    // Standard V2RayN vmess://base64(json)[#remark]
    if let Some(decoded) = decode_base64_flexible(body_no_frag) {
        if let Ok(json_str) = std::str::from_utf8(&decoded) {
            if let Ok(serde_json::Value::Object(map)) =
                serde_json::from_str::<serde_json::Value>(json_str)
            {
                let server = map
                    .get("add")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "VMess 节点缺少服务器地址（add）".to_string())?
                    .to_string();
                let port = map
                    .get("port")
                    .and_then(json_to_u16)
                    .filter(|&p| p > 0)
                    .ok_or_else(|| "VMess 节点缺少有效端口（port）".to_string())?;
                let uuid = map
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "VMess 节点缺少 UUID（id）".to_string())?
                    .to_string();
                let name = map
                    .get("ps")
                    .and_then(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .or_else(|| frag_remark.clone())
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
                if let Some(skip) = json_bool_flexible(
                    map.get("skip-cert-verify")
                        .or_else(|| map.get("allowInsecure"))
                        .or_else(|| map.get("allow_insecure"))
                        .or_else(|| map.get("insecure")),
                ) {
                    cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
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
    let parsed = Url::parse(uri).map_err(|e| {
        tracing::debug!(error = %e, "vmess URI parse failed");
        "VMess 节点链接格式有误，请检查编码或地址格式".to_string()
    })?;
    let uuid = percent_decode(parsed.username());
    if uuid.is_empty() {
        return Err("VMess 节点链接缺少 UUID".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("VMess 节点链接端口无效（不能为 0）".to_string());
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
    if let Some(skip) = query_skip_cert_verify(&params) {
        cfg.insert("skip-cert-verify".into(), serde_json::json!(skip));
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
    let parsed = Url::parse(uri).map_err(|e| {
        tracing::debug!(error = %e, "trojan URI parse failed");
        "Trojan 节点链接格式有误，请检查地址与端口是否完整".to_string()
    })?;
    let password = percent_decode(parsed.username());
    if password.is_empty() {
        return Err("Trojan 节点链接缺少密码".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("Trojan 节点链接端口无效（不能为 0）".to_string());
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
    if let Some(skip) = query_skip_cert_verify(&params) {
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
        .ok_or_else(|| "Shadowsocks 节点链接格式不完整".to_string())?;
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
                .map_err(|_| "Shadowsocks 节点凭据解码失败（非 UTF-8）".to_string())?
        } else {
            return Err("Shadowsocks 节点凭据编码无效".to_string());
        };
        let (method, pass) = decoded_userinfo
            .split_once(':')
            .ok_or_else(|| "Shadowsocks 节点缺少「加密方式:密码」分隔符".to_string())?;
        let (host, port) = split_host_port(host_port_part)?;
        (method.to_string(), pass.to_string(), host, port)
    } else {
        // Legacy format: ss://base64(method:password@host:port)
        let bytes = decode_base64_flexible(main_part)
            .ok_or_else(|| "Shadowsocks 节点 Base64 编码无效".to_string())?;
        let decoded = String::from_utf8(bytes)
            .map_err(|_| "Shadowsocks 节点解码内容非 UTF-8".to_string())?;
        let (cred, host_port_part) = decoded
            .rsplit_once('@')
            .ok_or_else(|| "Shadowsocks 节点缺少 `@` 地址分隔符".to_string())?;
        let (method, pass) = cred
            .split_once(':')
            .ok_or_else(|| "Shadowsocks 节点凭据缺少 `:` 分隔符".to_string())?;
        let (host, port) = split_host_port(host_port_part)?;
        (method.to_string(), pass.to_string(), host, port)
    };

    if cipher.trim().is_empty() {
        return Err("Shadowsocks 节点缺少加密方式（cipher）".to_string());
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
    let parsed = Url::parse(uri).map_err(|e| {
        tracing::debug!(error = %e, "hysteria2 URI parse failed");
        "Hysteria2 节点链接格式有误，请检查地址与端口是否完整".to_string()
    })?;
    let password = match parsed.password() {
        Some(p) => format!("{}:{}", percent_decode(parsed.username()), percent_decode(p)),
        None => percent_decode(parsed.username()),
    };
    if password.is_empty() {
        return Err("Hysteria2 节点链接缺少认证密码".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("Hysteria2 节点链接端口无效（不能为 0）".to_string());
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
    if let Some(skip) = query_skip_cert_verify(&params) {
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
    let parsed = Url::parse(uri).map_err(|e| {
        tracing::debug!(error = %e, "tuic URI parse failed");
        "TUIC 节点链接格式有误，请检查地址与端口是否完整".to_string()
    })?;
    let uuid = percent_decode(parsed.username());
    let password = parsed.password().map(percent_decode).unwrap_or_default();
    if uuid.is_empty() {
        return Err("TUIC 节点链接缺少 UUID".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("TUIC 节点链接端口无效（不能为 0）".to_string());
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
    if let Some(skip) = query_skip_cert_verify(&params) {
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
    let parsed = Url::parse(uri).map_err(|e| {
        tracing::debug!(error = %e, "anytls URI parse failed");
        "AnyTLS 节点链接格式有误，请检查地址与端口是否完整".to_string()
    })?;
    let password = match parsed.password() {
        Some(p) => format!("{}:{}", percent_decode(parsed.username()), percent_decode(p)),
        None => percent_decode(parsed.username()),
    };
    if password.is_empty() {
        return Err("AnyTLS 节点链接缺少密码".to_string());
    }
    let server = extract_host(&parsed)?;
    let port = parsed.port().unwrap_or(443);
    if port == 0 {
        return Err("AnyTLS 节点链接端口无效（不能为 0）".to_string());
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
    if let Some(skip) = query_skip_cert_verify(&params) {
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

pub(crate) fn looks_like_html_document(text: &str) -> bool {
    let trimmed = text.trim_start();
    if trimmed.is_empty() {
        return false;
    }
    let prefix_end = trimmed
        .char_indices()
        .nth(1024)
        .map(|(idx, _)| idx)
        .unwrap_or(trimmed.len());
    let head_lower = trimmed[..prefix_end].to_ascii_lowercase();
    if head_lower.starts_with("<!doctype html")
        || head_lower.starts_with("<html")
        || head_lower.starts_with("<head")
        || head_lower.starts_with("<body")
        || (head_lower.starts_with("<?xml")
            && (head_lower.contains("<html") || head_lower.contains("<body")))
    {
        return true;
    }
    head_lower.contains("<!doctype html")
        || (head_lower.contains("<html")
            && (head_lower.contains("<head")
                || head_lower.contains("<body")
                || head_lower.contains("<title")
                || head_lower.contains("</html>")))
}

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
        .ok_or_else(|| "节点链接缺少服务器地址".to_string())?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    if host.is_empty() {
        return Err("节点链接中的服务器地址为空".to_string());
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

fn query_skip_cert_verify(params: &[(String, String)]) -> Option<bool> {
    query_bool(params, "allowInsecure")
        .or_else(|| query_bool(params, "allow_insecure"))
        .or_else(|| query_bool(params, "insecure"))
        .or_else(|| query_bool(params, "skip-cert-verify"))
        .or_else(|| query_bool(params, "skip_cert_verify"))
}

fn json_bool_flexible(val: Option<&serde_json::Value>) -> Option<bool> {
    let v = val?;
    if let Some(b) = v.as_bool() {
        return Some(b);
    }
    if let Some(n) = v.as_u64() {
        return Some(n != 0);
    }
    if let Some(s) = v.as_str() {
        return match s.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        };
    }
    None
}

fn split_host_port(raw: &str) -> Result<(String, u16), String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port_part) = rest
            .split_once("]:")
            .ok_or_else(|| "IPv6 地址缺少闭合括号或端口".to_string())?;
        let port: u16 = port_part
            .parse()
            .map_err(|_| format!("节点端口无效（{port_part}）"))?;
        if host.is_empty() || port == 0 {
            return Err("IPv6 服务器地址或端口无效".to_string());
        }
        Ok((host.to_string(), port))
    } else {
        let (host, port_part) = trimmed
            .rsplit_once(':')
            .ok_or_else(|| "节点地址缺少 `:端口` 部分".to_string())?;
        let port: u16 = port_part
            .parse()
            .map_err(|_| format!("节点端口无效（{port_part}）"))?;
        if host.is_empty() || port == 0 {
            return Err("服务器地址或端口无效".to_string());
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

    #[test]
    fn vmess_uri_strips_trailing_remark_and_fallback_name() {
        let vmess_no_ps = serde_json::json!({
            "v": "2",
            "ps": "",
            "add": "203.0.113.31",
            "port": 443,
            "id": "00000000-0000-4000-8000-000000000101",
            "aid": 0,
            "net": "ws",
            "path": "/ws",
            "tls": "tls"
        });
        let uri_with_remark = format!(
            "vmess://{}#%E6%97%A5%E6%9C%AC%20%E4%B8%9C%E4%BA%AC%200.5x",
            STANDARD.encode(vmess_no_ps.to_string().as_bytes())
        );
        let parsed = parse_subscription_payload("sub-vmess-frag", uri_with_remark.as_bytes(), None)
            .expect("vmess with trailing #remark must decode cleanly");
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.nodes[0].name, "日本 东京 0.5x");
        assert_eq!(parsed.nodes[0].region_code, "JP");
        assert!((parsed.nodes[0].multiplier - 0.5).abs() < 1e-6);

        // When JSON `ps` is already set, prefer `ps` while still stripping `#remark`.
        let vmess_with_ps = serde_json::json!({
            "v": "2",
            "ps": "SG Primary 1x",
            "add": "203.0.113.32",
            "port": 443,
            "id": "00000000-0000-4000-8000-000000000102",
            "aid": 0,
            "tls": "tls"
        });
        let uri_both = format!(
            "vmess://{}#IgnoredRemark",
            STANDARD.encode(vmess_with_ps.to_string().as_bytes())
        );
        let parsed2 = parse_subscription_payload("sub-vmess-ps", uri_both.as_bytes(), None)
            .expect("vmess with ps and #remark must succeed");
        assert_eq!(parsed2.nodes[0].name, "SG Primary 1x");
    }

    #[test]
    fn uri_parsers_accept_allow_insecure_underscore_and_aliases() {
        let lines = [
            "vless://00000000-0000-4000-8000-000000000201@203.0.113.41:443?security=tls&allow_insecure=1#JP-VLESS",
            "trojan://pass-tr@203.0.113.42:443?sni=tr.example.invalid&allow_insecure=true#SG-Trojan",
            "hy2://pass-hy2@203.0.113.43:443?sni=hy2.example.invalid&allow_insecure=1#TW-Hy2",
            "anytls://pass-any@203.0.113.44:443?sni=any.example.invalid&allow_insecure=1#HK-AnyTLS",
            "tuic://00000000-0000-4000-8000-000000000202:pw@203.0.113.45:443?sni=tuic.example.invalid&insecure=1#US-TUIC",
        ]
        .join("\n");

        let parsed = parse_subscription_payload("sub-insecure", lines.as_bytes(), None)
            .expect("all URI protocols must accept allow_insecure/insecure");
        assert_eq!(parsed.nodes.len(), 5);
        for node in &parsed.nodes {
            assert_eq!(
                node.raw_config
                    .get("skip-cert-verify")
                    .and_then(serde_json::Value::as_bool),
                Some(true),
                "node {} missing skip-cert-verify=true",
                node.name
            );
        }
    }

    #[test]
    fn singbox_json_subscription_converts_to_mihomo_compatible_fields() {
        let singbox = serde_json::json!({
            "outbounds": [
                { "type": "direct", "tag": "direct" },
                { "type": "selector", "tag": "proxy", "outbounds": ["JP Reality 0.5x"] },
                {
                    "type": "vless",
                    "tag": "JP Reality 0.5x",
                    "server": "203.0.113.71",
                    "server_port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000301",
                    "flow": "xtls-rprx-vision",
                    "tls": {
                        "enabled": true,
                        "server_name": "edge.example.invalid",
                        "insecure": false,
                        "utls": { "enabled": true, "fingerprint": "chrome" },
                        "reality": {
                            "enabled": true,
                            "public_key": "pbk-test-key",
                            "short_id": "1a2b"
                        }
                    }
                },
                {
                    "type": "vmess",
                    "tag": "SG WS 1x",
                    "server": "203.0.113.72",
                    "server_port": 8443,
                    "uuid": "00000000-0000-4000-8000-000000000302",
                    "security": "auto",
                    "alter_id": 0,
                    "tls": {
                        "enabled": true,
                        "server_name": "ws.example.invalid",
                        "insecure": true
                    },
                    "transport": {
                        "type": "ws",
                        "path": "/chat",
                        "headers": { "Host": "ws.example.invalid" }
                    }
                },
                {
                    "type": "hysteria2",
                    "tag": "TW Hy2 2x",
                    "server": "203.0.113.73",
                    "server_port": 443,
                    "password": "hy2-placeholder-pass",
                    "up_mbps": 50,
                    "down_mbps": 200,
                    "obfs": { "type": "salamander", "password": "obfs-placeholder" },
                    "tls": {
                        "enabled": true,
                        "server_name": "hy2.example.invalid",
                        "insecure": true
                    }
                }
            ]
        })
        .to_string();

        let parsed = parse_subscription_payload("sub-sb", singbox.as_bytes(), None)
            .expect("sing-box JSON subscription must parse");
        assert_eq!(parsed.format, SubscriptionPayloadFormat::SingBoxJson);
        assert_eq!(parsed.nodes.len(), 3);

        let vless = &parsed.nodes[0];
        assert_eq!(vless.protocol, "vless");
        assert_eq!(vless.port, 443);
        assert_eq!(vless.raw_config.get("tls").and_then(|v| v.as_bool()), Some(true));
        assert!(vless.raw_config.get("server_port").is_none());
        assert_eq!(
            vless.raw_config.get("servername").and_then(|v| v.as_str()),
            Some("edge.example.invalid")
        );
        assert_eq!(
            vless.raw_config.get("flow").and_then(|v| v.as_str()),
            Some("xtls-rprx-vision")
        );
        assert_eq!(
            vless
                .raw_config
                .get("reality-opts")
                .and_then(|r| r.get("public-key"))
                .and_then(|v| v.as_str()),
            Some("pbk-test-key")
        );
        assert_eq!(
            vless
                .raw_config
                .get("client-fingerprint")
                .and_then(|v| v.as_str()),
            Some("chrome")
        );

        let vmess = &parsed.nodes[1];
        assert_eq!(vmess.raw_config.get("tls").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            vmess.raw_config.get("skip-cert-verify").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            vmess.raw_config.get("network").and_then(|v| v.as_str()),
            Some("ws")
        );
        assert!(vmess.raw_config.get("transport").is_none());
        assert_eq!(
            vmess
                .raw_config
                .get("ws-opts")
                .and_then(|w| w.get("path"))
                .and_then(|v| v.as_str()),
            Some("/chat")
        );

        let hy2 = &parsed.nodes[2];
        assert_eq!(hy2.protocol, "hysteria2");
        assert_eq!(hy2.raw_config.get("sni").and_then(|v| v.as_str()), Some("hy2.example.invalid"));
        assert_eq!(hy2.raw_config.get("obfs").and_then(|v| v.as_str()), Some("salamander"));
        assert_eq!(
            hy2.raw_config.get("obfs-password").and_then(|v| v.as_str()),
            Some("obfs-placeholder")
        );
        assert!(hy2.raw_config.get("tls").is_none());
    }

    #[test]
    fn html_empty_and_missing_proxies_return_friendly_chinese_errors() {
        let html_err = parse_subscription_payload(
            "sub-html",
            b"<!DOCTYPE html><html><head><title>Login</title></head><body>Please sign in</body></html>",
            None,
        )
        .expect_err("HTML document must fail");
        assert!(
            html_err
                .to_string()
                .contains("订阅链接返回了网页而非节点列表"),
            "unexpected error: {html_err}"
        );

        let empty_err = parse_subscription_payload("sub-empty", b"   ", None)
            .expect_err("empty body must fail");
        assert!(empty_err.to_string().contains("订阅返回内容为空"));

        let no_proxies_err = parse_subscription_payload("sub-noprox", b"port: 7890\nmode: rule\n", None)
            .expect_err("YAML without proxies must fail");
        assert!(no_proxies_err.to_string().contains("缺少 proxies"));

        let bad_scheme_err = validate_subscription_http_url("ftp://example.invalid/sub")
            .expect_err("non-http scheme must fail");
        assert!(bad_scheme_err.to_string().contains("不支持的订阅链接协议"));
    }

    #[tokio::test]
    async fn fetch_subscription_url_with_fallback_recovers_and_summarizes_failures() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let valid_yaml = concat!(
            "proxies:\n",
            "  - name: \"JP Fallback 1x\"\n",
            "    type: trojan\n",
            "    server: 203.0.113.90\n",
            "    port: 443\n",
            "    password: \"placeholder-pass\"\n"
        );
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nETag: \"fb-v1\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            valid_yaml.len(),
            valid_yaml
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock server");
        let addr = listener.local_addr().expect("mock addr");
        let server_task = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });

        // First candidate points to a closed local port; second candidate is direct (`None`) and must succeed.
        let closed_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind temp port");
        let closed_port = closed_listener.local_addr().expect("temp addr").port();
        drop(closed_listener);

        let url = format!("http://127.0.0.1:{}/sub.yaml", addr.port());
        let candidates = vec![
            Some(format!("http://127.0.0.1:{closed_port}")),
            None,
        ];
        let fetched = fetch_subscription_url_with_fallback_timeout(
            &url,
            Duration::from_secs(3),
            &candidates,
            &FetchOptions::default(),
        )
        .await
        .expect("fallback from unreachable proxy to direct must succeed");
        let _ = server_task.await;
        assert_eq!(fetched.used_proxy, None);
        assert_eq!(fetched.etag.as_deref(), Some("\"fb-v1\""));
        let parsed = fetched.parse("sub-fb").expect("parse fetched subscription");
        assert_eq!(parsed.nodes.len(), 1);
        assert_eq!(parsed.etag.as_deref(), Some("\"fb-v1\""));

        // When all candidates fail, return a clear Chinese summary mentioning both routes.
        let dead_url = format!("http://127.0.0.1:{closed_port}/sub.yaml");
        let err = fetch_subscription_url_with_fallback_timeout(
            &dead_url,
            Duration::from_millis(600),
            &[None, Some(format!("http://127.0.0.1:{closed_port}"))],
            &FetchOptions::default(),
        )
        .await
        .expect_err("all dead candidates must fail");
        let msg = err.to_string();
        assert!(msg.contains("直连"), "expected direct summary in: {msg}");
        assert!(msg.contains("经代理"), "expected proxy summary in: {msg}");
    }

    #[test]
    fn user_facing_validation_errors_have_no_raw_english_leakage() {
        let invalid_port = validate_subscription_http_url("https://sub.example.invalid:99999/feed")
            .expect_err("invalid port must fail");
        match invalid_port {
            CatError::Validation(msg) => {
                assert!(msg.contains("端口号无效"), "unexpected msg: {msg}");
                assert!(!msg.to_ascii_lowercase().contains("invalid port"));
            }
            other => panic!("expected CatError::Validation, got {other:?}"),
        }

        let missing_scheme = validate_subscription_http_url("sub.example.invalid/feed")
            .expect_err("missing scheme must fail");
        match missing_scheme {
            CatError::Validation(msg) => {
                assert!(msg.contains("缺少协议头"), "unexpected msg: {msg}");
                assert!(!msg.to_ascii_lowercase().contains("relative url"));
            }
            other => panic!("expected CatError::Validation, got {other:?}"),
        }

        let bad_yaml = parse_clash_yaml_value("proxies:\n  - name: [unterminated\n")
            .expect_err("malformed YAML must fail");
        match bad_yaml {
            CatError::Validation(msg) => {
                assert!(msg.contains("订阅 YAML 格式有误"), "unexpected msg: {msg}");
                assert!(!msg.to_ascii_lowercase().contains("expected"));
                assert!(!msg.to_ascii_lowercase().contains("did not find"));
            }
            other => panic!("expected CatError::Validation, got {other:?}"),
        }

        let bad_file_url = read_local_subscription_file("sub-file", "file://[::1:bad")
            .expect_err("malformed file:// URL must fail");
        match bad_file_url {
            CatError::Validation(msg) => {
                assert!(msg.contains("本地文件地址格式不正确"), "unexpected msg: {msg}");
                assert!(!msg.to_ascii_lowercase().contains("invalid"));
            }
            other => panic!("expected CatError::Validation, got {other:?}"),
        }
    }

    #[test]
    fn normalize_subscription_input_url_unwraps_clash_and_clashmeta_deep_links() {
        // Unencoded nested URL with inner `&flag=clash` followed by `&name=...`
        assert_eq!(
            normalize_subscription_input_url(
                "clash://install-config?url=https://sub.example.invalid/api/v1/sub?token=placeholder&flag=clash&name=MySub"
            ),
            "https://sub.example.invalid/api/v1/sub?token=placeholder&flag=clash"
        );

        // Unencoded nested URL extending to end of string (no `&name=`)
        assert_eq!(
            normalize_subscription_input_url(
                "clashmeta://install-config?url=https://sub.example.invalid/sub?token=placeholder&flag=clash&types=all"
            ),
            "https://sub.example.invalid/sub?token=placeholder&flag=clash&types=all"
        );

        // Percent-encoded nested URL with trailing `&name=`
        assert_eq!(
            normalize_subscription_input_url(
                "clash://install-config?url=https%3A%2F%2Fsub.example.invalid%2Fsub%3Ftoken%3Dplaceholder%26flag%3Dclash&name=%E6%B5%8B%E8%AF%95"
            ),
            "https://sub.example.invalid/sub?token=placeholder&flag=clash"
        );

        // Case-insensitive scheme/path with leading `name=` parameter before `url=`
        assert_eq!(
            normalize_subscription_input_url(
                "  CLASHMETA://install-config/?name=Demo&url=http://127.0.0.1:8080/sub?a=1&flag=clash  "
            ),
            "http://127.0.0.1:8080/sub?a=1&flag=clash"
        );

        // Plain HTTP(S) URLs remain intact
        assert_eq!(
            normalize_subscription_input_url(" https://sub.example.invalid/feed?flag=clash "),
            "https://sub.example.invalid/feed?flag=clash"
        );

        // End-to-end validation preserves inner `&flag=clash`
        let validated = validate_subscription_http_url(
            "clash://install-config?url=https://sub.example.invalid/sub?token=placeholder&flag=clash&name=Test",
        )
        .expect("unwrapped clash:// deep link must pass URL validation");
        assert_eq!(
            validated.as_str(),
            "https://sub.example.invalid/sub?token=placeholder&flag=clash"
        );
    }

    #[test]
    fn singbox_outbound_enforces_whitelist_credentials_headers_hy2_bandwidth_and_utls() {
        let singbox = serde_json::json!({
            "outbounds": [
                // Unsupported outbound types must be skipped
                { "type": "wireguard", "tag": "WG-Skip", "server": "203.0.113.10", "server_port": 51820 },
                { "type": "shadowtls", "tag": "STLS-Skip", "server": "203.0.113.11", "server_port": 443 },
                { "type": "tor", "tag": "Tor-Skip", "server": "203.0.113.12", "server_port": 9050 },
                { "type": "ssh", "tag": "SSH-Skip", "server": "203.0.113.13", "server_port": 22 },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" },
                { "type": "dns", "tag": "dns" },
                { "type": "selector", "tag": "proxy" },
                { "type": "urltest", "tag": "auto" },

                // Incomplete credentials must be skipped
                { "type": "shadowsocks", "tag": "SS-NoPass", "server": "203.0.113.20", "server_port": 8388, "method": "aes-256-gcm" },
                { "type": "ss", "tag": "SS-NoMethod", "server": "203.0.113.21", "server_port": 8388, "password": "placeholder" },
                { "type": "vless", "tag": "VLESS-NoUUID", "server": "203.0.113.22", "server_port": 443 },
                { "type": "vmess", "tag": "VMess-NoUUID", "server": "203.0.113.23", "server_port": 443 },
                { "type": "tuic", "tag": "TUIC-NoUUID", "server": "203.0.113.24", "server_port": 443, "password": "placeholder" },
                { "type": "trojan", "tag": "Trojan-NoPass", "server": "203.0.113.25", "server_port": 443 },
                { "type": "hysteria2", "tag": "Hy2-NoPass", "server": "203.0.113.26", "server_port": 443 },
                { "type": "anytls", "tag": "AnyTLS-NoPass", "server": "203.0.113.27", "server_port": 443 },

                // Valid WS node with array headers + utls.enabled=false (must not emit client-fingerprint)
                {
                    "type": "vless",
                    "tag": "JP WS ArrayHeaders",
                    "server": "203.0.113.30",
                    "server_port": 443,
                    "uuid": "00000000-0000-4000-8000-000000000401",
                    "tls": {
                        "enabled": true,
                        "server_name": "ws.example.invalid",
                        "utls": { "enabled": false, "fingerprint": "chrome" }
                    },
                    "transport": {
                        "type": "ws",
                        "path": "/ws",
                        "headers": {
                            "Host": ["primary.example.invalid", "backup.example.invalid"],
                            "X-Multi": ["v1", "v2"]
                        }
                    }
                },

                // Valid plain HTTP transport (no TLS): scalar headers wrapped as Vec<String>, host merged into Host array
                {
                    "type": "vmess",
                    "tag": "SG Plain HTTP",
                    "server": "203.0.113.31",
                    "server_port": 80,
                    "uuid": "00000000-0000-4000-8000-000000000402",
                    "tls": { "enabled": false },
                    "transport": {
                        "type": "http",
                        "path": "/api",
                        "host": ["h1.example.invalid", "h2.example.invalid"],
                        "headers": {
                            "User-Agent": "CatCloudTest",
                            "Host": "h0.example.invalid"
                        }
                    }
                },

                // Valid Hysteria2 with 0 bandwidth (must omit up/down) and utls without explicit enabled flag
                {
                    "type": "hy2",
                    "tag": "TW Hy2 ZeroBw",
                    "server": "203.0.113.32",
                    "server_port": 443,
                    "password": "placeholder-hy2-pass",
                    "up_mbps": 0,
                    "down_mbps": 0,
                    "tls": {
                        "enabled": true,
                        "server_name": "hy2.example.invalid",
                        "utls": { "fingerprint": "firefox" }
                    }
                },

                // Valid socks/http whitelisted outbounds without mandatory auth
                {
                    "type": "socks",
                    "tag": "US Socks",
                    "server": "203.0.113.33",
                    "server_port": 1080
                },
                {
                    "type": "http",
                    "tag": "UK Http",
                    "server": "203.0.113.34",
                    "server_port": 8080
                }
            ]
        })
        .to_string();

        let parsed = parse_subscription_payload("sub-sb-strict", singbox.as_bytes(), None)
            .expect("valid sing-box nodes should survive strict filtering");
        assert_eq!(parsed.nodes.len(), 5);

        let vless = &parsed.nodes[0];
        assert_eq!(vless.name, "JP WS ArrayHeaders");
        assert!(
            vless.raw_config.get("client-fingerprint").is_none(),
            "utls.enabled=false must omit client-fingerprint"
        );
        let ws_headers = vless
            .raw_config
            .get("ws-opts")
            .and_then(|w| w.get("headers"))
            .and_then(serde_json::Value::as_object)
            .expect("ws-opts.headers must exist");
        assert_eq!(
            ws_headers.get("Host").and_then(serde_json::Value::as_str),
            Some("primary.example.invalid")
        );
        assert_eq!(
            ws_headers.get("X-Multi").and_then(serde_json::Value::as_str),
            Some("v1, v2")
        );

        let vmess = &parsed.nodes[1];
        assert_eq!(vmess.name, "SG Plain HTTP");
        assert_eq!(
            vmess.raw_config.get("network").and_then(serde_json::Value::as_str),
            Some("http")
        );
        let http_headers = vmess
            .raw_config
            .get("http-opts")
            .and_then(|h| h.get("headers"))
            .and_then(serde_json::Value::as_object)
            .expect("http-opts.headers must exist");
        assert_eq!(
            http_headers.get("User-Agent"),
            Some(&serde_json::json!(["CatCloudTest"]))
        );
        assert_eq!(
            http_headers.get("Host"),
            Some(&serde_json::json!([
                "h0.example.invalid",
                "h1.example.invalid",
                "h2.example.invalid"
            ]))
        );

        let hy2 = &parsed.nodes[2];
        assert_eq!(hy2.name, "TW Hy2 ZeroBw");
        assert!(hy2.raw_config.get("up").is_none(), "0 up_mbps must not emit 0 Mbps");
        assert!(hy2.raw_config.get("down").is_none(), "0 down_mbps must not emit 0 Mbps");
        assert_eq!(
            hy2.raw_config
                .get("client-fingerprint")
                .and_then(serde_json::Value::as_str),
            Some("firefox")
        );

        assert_eq!(parsed.nodes[3].protocol, "socks5");
        assert_eq!(parsed.nodes[4].protocol, "http");
    }

    #[tokio::test]
    async fn fetch_fallback_retries_direct_empty_non_sub_json_and_404_and_caps_connect_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        assert_eq!(
            effective_connect_timeout(Duration::from_secs(20), true),
            Duration::from_secs(6)
        );
        assert_eq!(
            effective_connect_timeout(Duration::from_secs(3), true),
            Duration::from_secs(3)
        );
        assert_eq!(
            effective_connect_timeout(Duration::from_secs(20), false),
            Duration::from_secs(20)
        );

        assert!(looks_like_non_subscription_json(r#"{"error":"blocked"}"#));
        assert!(looks_like_non_subscription_json(r#"{"code":403,"msg":"waf"}"#));
        assert!(!looks_like_non_subscription_json(r#"{"outbounds":[]}"#));
        assert!(!looks_like_non_subscription_json(r#"{"proxies":[]}"#));

        let valid_yaml = concat!(
            "proxies:\n",
            "  - name: \"JP ProxyRecovered 1x\"\n",
            "    type: trojan\n",
            "    server: 203.0.113.95\n",
            "    port: 443\n",
            "    password: \"placeholder-pass\"\n"
        );
        let proxy_ok_resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/yaml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            valid_yaml.len(),
            valid_yaml
        );

        let waf_body = r#"{"code":403,"error":"waf_deny"}"#;
        let direct_bad_responses = [
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                waf_body.len(),
                waf_body
            ),
            "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot found"
                .to_string(),
        ];

        for direct_resp in direct_bad_responses {
            let direct_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock direct server");
            let direct_port = direct_listener.local_addr().expect("direct addr").port();
            let direct_task = tokio::spawn(async move {
                if let Ok((mut sock, _)) = direct_listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(direct_resp.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            });

            let proxy_listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock proxy server");
            let proxy_port = proxy_listener.local_addr().expect("proxy addr").port();
            let resp_clone = proxy_ok_resp.clone();
            let proxy_task = tokio::spawn(async move {
                if let Ok((mut sock, _)) = proxy_listener.accept().await {
                    let mut buf = [0u8; 2048];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock.write_all(resp_clone.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            });

            let target_url = format!("http://127.0.0.1:{direct_port}/sub");
            let proxy_url = format!("http://127.0.0.1:{proxy_port}");
            let fetched = fetch_subscription_url_with_fallback_timeout(
                &target_url,
                Duration::from_secs(3),
                &[None, Some(proxy_url.clone())],
                &FetchOptions::default(),
            )
            .await
            .expect("fallback to proxy candidate must succeed after direct block/404/empty");
            let _ = direct_task.await;
            let _ = proxy_task.await;
            assert_eq!(fetched.used_proxy.as_deref(), Some(proxy_url.as_str()));
            let parsed = fetched.parse("sub-fb-block").expect("parse recovered payload");
            assert_eq!(parsed.nodes.len(), 1);
        }
    }
}
