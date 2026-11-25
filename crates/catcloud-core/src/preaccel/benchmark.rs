use serde::{Deserialize, Serialize};

/// Single bandwidth measurement tagged with its destination TCP/UDP port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PortSpeedSample {
    pub label: String,
    pub port: u16,
    pub mbps: f64,
    pub latency_ms: Option<f64>,
}

impl PortSpeedSample {
    pub fn new(label: impl Into<String>, port: u16, mbps: f64) -> Self {
        Self {
            label: label.into(),
            port,
            mbps,
            latency_ms: None,
        }
    }

    pub fn with_latency(mut self, latency_ms: f64) -> Self {
        self.latency_ms = Some(latency_ms);
        self
    }
}

/// Statistical confidence level for a 443 vs non-443 throttling diagnosis.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleConfidence {
    InsufficientData,
    Medium,
    High,
}

/// Quantitative diagnostic comparing `:443` vs non-`:443` throughput to decide whether
/// domestic pre-acceleration is recommended on the current network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BandwidthThrottleReport {
    pub port_443_mbps: f64,
    pub non_443_mbps: f64,
    pub speedup_ratio: f64,
    pub throttled_detected: bool,
    pub recommendation_zh: String,
    pub sample_count_443: usize,
    pub sample_count_non_443: usize,
    pub confidence: ThrottleConfidence,
}

/// Minimum speedup ratio (`port_443 / non_443`) paired with absolute delta to flag general throttling.
const GENERAL_SPEEDUP_THRESHOLD: f64 = 1.8;
const GENERAL_MIN_DELTA_MBPS: f64 = 5.0;

/// Secondary threshold for low-bandwidth non-443 QoS caps (e.g. campus 5-15 Mbps non-443 cap).
const LOW_BANDWIDTH_CAP_MBPS: f64 = 15.0;
const LOW_BANDWIDTH_SPEEDUP_THRESHOLD: f64 = 1.5;
const LOW_BANDWIDTH_MIN_443_MBPS: f64 = 20.0;

/// Analyze `:443` vs non-`:443` speed samples using robust medians to detect non-443 QoS throttling.
pub fn analyze_443_throttle(
    port_443_samples: &[PortSpeedSample],
    non_443_samples: &[PortSpeedSample],
) -> BandwidthThrottleReport {
    let valid_443 = collect_valid_mbps(port_443_samples);
    let valid_non_443 = collect_valid_mbps(non_443_samples);

    let sample_count_443 = valid_443.len();
    let sample_count_non_443 = valid_non_443.len();

    let Some(port_443_mbps) = median(&valid_443) else {
        return BandwidthThrottleReport {
            port_443_mbps: 0.0,
            non_443_mbps: median(&valid_non_443).map(round2).unwrap_or(0.0),
            speedup_ratio: 1.0,
            throttled_detected: false,
            recommendation_zh: "缺少有效的 443 端口测速样本，暂无法判定是否存在非 443 限速；请补充 443 端口样本后复测。".to_string(),
            sample_count_443,
            sample_count_non_443,
            confidence: ThrottleConfidence::InsufficientData,
        };
    };

    let Some(non_443_mbps) = median(&valid_non_443) else {
        return BandwidthThrottleReport {
            port_443_mbps: round2(port_443_mbps),
            non_443_mbps: 0.0,
            speedup_ratio: 1.0,
            throttled_detected: false,
            recommendation_zh: "缺少有效的非 443 端口测速样本，暂无法判定是否存在非 443 限速；请补充非 443 端口样本后复测。".to_string(),
            sample_count_443,
            sample_count_non_443,
            confidence: ThrottleConfidence::InsufficientData,
        };
    };

    let confidence = if sample_count_443 >= 3 && sample_count_non_443 >= 3 {
        ThrottleConfidence::High
    } else {
        ThrottleConfidence::Medium
    };

    let raw_ratio = if non_443_mbps <= 0.05 {
        if port_443_mbps >= GENERAL_MIN_DELTA_MBPS {
            (port_443_mbps / 0.05).min(999.0)
        } else {
            1.0
        }
    } else {
        (port_443_mbps / non_443_mbps).min(999.0)
    };

    let delta = port_443_mbps - non_443_mbps;
    let throttled_detected = (raw_ratio >= GENERAL_SPEEDUP_THRESHOLD
        && delta >= GENERAL_MIN_DELTA_MBPS)
        || (non_443_mbps <= LOW_BANDWIDTH_CAP_MBPS
            && port_443_mbps >= LOW_BANDWIDTH_MIN_443_MBPS
            && raw_ratio >= LOW_BANDWIDTH_SPEEDUP_THRESHOLD);

    let p443_r = round2(port_443_mbps);
    let non443_r = round2(non_443_mbps);
    let ratio_r = round2(raw_ratio);

    let recommendation_zh = if throttled_detected && raw_ratio >= 3.0 {
        format!(
            "检测到严重的非 443 端口限速（443 中位带宽 {p443_r:.1} Mbps，非 443 仅 {non443_r:.1} Mbps，提速比 {ratio_r:.2}x）。强烈建议开启国内提速，并保持「自动跳过原生 443 节点」开启。"
        )
    } else if throttled_detected {
        format!(
            "检测到非 443 端口存在明显限速（443 中位带宽 {p443_r:.1} Mbps，非 443 为 {non443_r:.1} Mbps，提速比 {ratio_r:.2}x）。建议启用国内提速以提升非 443 节点速率。"
        )
    } else {
        format!(
            "443 端口（{p443_r:.1} Mbps）与非 443 端口（{non443_r:.1} Mbps）速率接近（比值 {ratio_r:.2}x），当前网络未检测到明显非 443 限速，可按需关闭国内提速或仅对特定节点单独开启。"
        )
    };

    BandwidthThrottleReport {
        port_443_mbps: p443_r,
        non_443_mbps: non443_r,
        speedup_ratio: ratio_r,
        throttled_detected,
        recommendation_zh,
        sample_count_443,
        sample_count_non_443,
        confidence,
    }
}

/// Partition a mixed slice of port samples into `port == 443` vs `port != 443` and run throttle analysis.
pub fn analyze_mixed_port_samples(samples: &[PortSpeedSample]) -> BandwidthThrottleReport {
    let mut port_443 = Vec::new();
    let mut non_443 = Vec::new();
    for sample in samples {
        if sample.port == 443 {
            port_443.push(sample.clone());
        } else {
            non_443.push(sample.clone());
        }
    }
    analyze_443_throttle(&port_443, &non_443)
}

fn collect_valid_mbps(samples: &[PortSpeedSample]) -> Vec<f64> {
    let mut values: Vec<f64> = samples
        .iter()
        .map(|s| s.mbps)
        .filter(|v| v.is_finite() && *v >= 0.0)
        .collect();
    values.sort_by(|a, b| a.total_cmp(b));
    values
}

fn median(sorted: &[f64]) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[mid])
    } else {
        Some((sorted[mid - 1] + sorted[mid]) * 0.5)
    }
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}
