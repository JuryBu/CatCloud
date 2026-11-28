import { ChevronDown, ChevronRight } from "lucide-react";
import type { AppConfig } from "../../api/tauri";
import { isBoolPref, usePersistedState } from "../../utils/uiPrefs";
import { Card, INPUT_CLS, SegButtons, SwitchRow, Toggle } from "./SettingsPrimitives";
import type { DnsEnhancedMode, ExtendedSettings } from "./settingsPatch";

export interface DnsTabProps {
  draft: AppConfig;
  ext: ExtendedSettings;
  patchDraft: (patch: Partial<AppConfig>) => void;
  patchExt: <K extends keyof ExtendedSettings>(k: K, v: ExtendedSettings[K]) => void;
  onDnsListenChange: (nextAddr: string) => void;
}

export function DnsTab({
  draft,
  ext,
  patchDraft,
  patchExt,
  onDnsListenChange,
}: DnsTabProps) {
  const [showAdvancedDns, setShowAdvancedDns] = usePersistedState<boolean>(
    "settings.showAdvancedDns",
    false,
    isBoolPref
  );

  return (
    <div className="space-y-4">
      <Card title="IPv6 独立开关" sub="核心转发与域名解析分开控制，互不干扰">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <SwitchRow
            title="核心 IPv6 转发"
            desc="允许代理内核使用 IPv6 线路建立连接"
            checked={draft.ipv6_core_enabled}
            onChange={(v) => patchDraft({ ipv6_core_enabled: v })}
          />
          <SwitchRow
            title="DNS 返回 IPv6 地址"
            desc="控制域名解析是否同时查询并返回 IPv6 地址"
            checked={draft.ipv6_dns_enabled}
            onChange={(v) => patchDraft({ ipv6_dns_enabled: v })}
          />
        </div>
      </Card>

      <Card title="常用 DNS 开关" sub="推荐保持默认开启，自动防域名解析异常并配合分流">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <SwitchRow
            title="接管并覆写 DNS"
            desc="使用统一防污染 DNS 替代订阅自带配置"
            checked={ext.overrideDns}
            onChange={(v) => patchExt("overrideDns", v)}
          />
          <SwitchRow
            title="遵循分流规则"
            desc="让域名解析自动配合你的网站分流规则"
            checked={ext.respectRules}
            onChange={(v) => patchExt("respectRules", v)}
          />
          <SwitchRow
            title="启用自定义 Hosts"
            desc="加载配置文件内的域名与地址映射"
            checked={ext.useHosts}
            onChange={(v) => patchExt("useHosts", v)}
          />
          <SwitchRow
            title="同步系统 Hosts"
            desc="同时读取本机系统的域名映射表"
            checked={ext.useSystemHosts}
            onChange={(v) => patchExt("useSystemHosts", v)}
          />
        </div>
      </Card>

      {/* Collapsible Advanced DNS Settings */}
      <section className="cc-card cc-glass overflow-hidden rounded-2xl">
        <button
          type="button"
          onClick={() => setShowAdvancedDns((open) => !open)}
          className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-[var(--surface)]/60"
        >
          <div>
            <div className="text-sm font-semibold text-[var(--text)]">
              高级 DNS 设置（普通用户无需修改）
            </div>
            <p className="mt-0.5 text-[11px] text-[var(--muted)]">
              自定义解析模式、排除域名、上游加密 DNS 与海外防污染过滤规则
            </p>
          </div>
          <span className="inline-flex shrink-0 items-center gap-1 rounded-lg border border-[var(--line)] bg-[var(--surface)] px-2.5 py-1 text-[11px] font-medium text-[var(--text-secondary)]">
            {showAdvancedDns ? "收起" : "展开"}
            {showAdvancedDns ? (
              <ChevronDown className="h-3.5 w-3.5" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5" />
            )}
          </span>
        </button>

        {showAdvancedDns && (
          <div className="grid grid-cols-1 gap-4 border-t border-[var(--line)] p-4 min-[1160px]:grid-cols-2">
            <div className="min-w-0 space-y-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/50 p-3.5">
              <div className="text-xs font-semibold text-[var(--text)]">解析模式与本地监听</div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <SwitchRow
                  title="优先 HTTP/3"
                  desc="加密 DNS 优先走 HTTP/3 通道"
                  checked={ext.preferH3}
                  onChange={(v) => patchExt("preferH3", v)}
                />
                <div className="flex flex-col justify-center gap-1 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 px-3 py-2">
                  <span className="text-[11px] text-[var(--muted)]">解析模式</span>
                  <SegButtons<DnsEnhancedMode>
                    value={ext.enhancedMode}
                    onChange={(v) => patchExt("enhancedMode", v)}
                    options={[
                      ["fake-ip", "虚拟 IP（推荐）"],
                      ["redir-host", "真实 IP"],
                    ]}
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                <label className="min-w-0 text-[11px] text-[var(--muted)]">
                  DNS 监听地址
                  <input
                    value={ext.dnsListen}
                    onChange={(e) => onDnsListenChange(e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="min-w-0 text-[11px] text-[var(--muted)]">
                  虚拟 IP 网段
                  <input
                    value={ext.fakeIpRange}
                    onChange={(e) => patchExt("fakeIpRange", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              </div>
              <label className="block text-[11px] text-[var(--muted)]">
                虚拟 IP 排除域名（逗号分隔）
                <textarea
                  rows={3}
                  value={ext.fakeIpFilter}
                  onChange={(e) => patchExt("fakeIpFilter", e.target.value)}
                  className={`${INPUT_CLS} mt-1 cc-mono`}
                />
              </label>
            </div>

            <div className="space-y-3 rounded-xl border border-[var(--line)] bg-[var(--surface)]/50 p-3.5">
              <div className="text-xs font-semibold text-[var(--text)]">上游 DNS 与防污染过滤</div>
              <div className="space-y-2">
                {(
                  [
                    ["defaultNameserver", "基础引导 DNS（用于解析加密 DNS 域名）"],
                    ["nameserverPolicy", "按域名指定 DNS（每行一条策略）"],
                    ["nameserver", "默认上游 DNS（常规查询）"],
                    ["fallback", "备用海外 DNS（防污染回退）"],
                    ["proxyServerNameserver", "节点域名专用 DNS"],
                  ] as const
                ).map(([key, label]) => (
                  <label key={key} className="block text-[11px] text-[var(--muted)]">
                    {label}
                    <input
                      value={ext[key]}
                      onChange={(e) => patchExt(key, e.target.value)}
                      className={`${INPUT_CLS} mt-1 cc-mono`}
                    />
                  </label>
                ))}
              </div>
              <div className="space-y-2 rounded-xl border border-[var(--line)] bg-[var(--surface)]/70 p-2.5">
                <div className="flex items-center justify-between text-xs font-medium text-[var(--text)]">
                  <span>海外防污染过滤</span>
                  <Toggle
                    checked={ext.fallbackFilterGeoip}
                    onChange={(v) => patchExt("fallbackFilterGeoip", v)}
                    label="启用地区过滤"
                  />
                </div>
                <label className="block text-[11px] text-[var(--muted)]">
                  直连地区代码
                  <input
                    value={ext.fallbackFilterGeoipCode}
                    onChange={(e) => patchExt("fallbackFilterGeoipCode", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="block text-[11px] text-[var(--muted)]">
                  异常 IP 网段过滤
                  <input
                    value={ext.fallbackFilterIpcidr}
                    onChange={(e) => patchExt("fallbackFilterIpcidr", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
                <label className="block text-[11px] text-[var(--muted)]">
                  强制走备用 DNS 的域名
                  <input
                    value={ext.fallbackFilterDomain}
                    onChange={(e) => patchExt("fallbackFilterDomain", e.target.value)}
                    className={`${INPUT_CLS} mt-1 cc-mono`}
                  />
                </label>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
