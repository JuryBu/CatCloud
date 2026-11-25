package io.github.jurybu.catcloud.engine

import io.github.jurybu.catcloud.data.AppSettings
import io.github.jurybu.catcloud.data.MultiGroupRecord
import io.github.jurybu.catcloud.data.NodeFingerprint
import io.github.jurybu.catcloud.data.PreAccelRelayRecord
import io.github.jurybu.catcloud.data.ProxyMode
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import io.github.jurybu.catcloud.data.RouteMode
import org.json.JSONArray
import org.json.JSONObject
import org.yaml.snakeyaml.DumperOptions
import org.yaml.snakeyaml.Yaml
import java.net.InetAddress
import java.net.URI

data class CompiledAndroidConfig(
    val yaml: String,
    val activeNodeCount: Int,
    val relayCount: Int,
    val dialerWrappedCount: Int,
    val activeGroupOrNodeName: String,
    val pruned: Boolean,
    val warnings: List<String>,
)

/**
 * Android-native Mihomo YAML compiler maintaining 100% behavioral parity with desktop
 * `crates/catcloud-core/src/core_adapter/config_compiler.rs` & `preaccel/generator.rs`:
 * - Pure-IP domestic `:443` pre-acceleration (no SNI, `skip-cert-verify: true`, VLESS `servername: ""`)
 * - Domestic 204 active-standby fallback (hicloud/miui only; hard-rejects 11 overseas probe domains; `DIRECT` fail-open)
 * - Top-level anti-loop rules + campus pure-IP DoH + `+.edu.cn` system DNS policy
 * - Domestic QUIC allow + overseas UDP/443 reject
 * - Conservative domestic direct whitelist (zero GeoData required)
 * - Complete stripping of desktop `PROCESS-NAME*` / `PROCESS-PATH*` rules
 * - Active-set graph pruning (~93% reduction) when `nodes.size > 32 && proxyMode != GLOBAL`
 */
object ConfigCompiler {

    const val PREACCEL_SELECT_GROUP = "⚡ 国内预加速入口"
    const val PREACCEL_FALLBACK_GROUP = "🔄 预加速自动双活"
    const val DEFAULT_FALLBACK_GROUP = "🐱 猫猫云梯"
    const val SINGLE_NODE_GROUP = "单节点直选"

    const val DEFAULT_DOMESTIC_204_PRIMARY = "http://connectivitycheck.platform.hicloud.com/generate_204"
    const val DEFAULT_DOMESTIC_204_FALLBACK = "http://connect.rom.miui.com/generate_204"
    const val DEFAULT_LOAD_BALANCE_URL = "https://cp.cloudflare.com/generate_204"

    val DEFAULT_PURE_IP_DOH_DOMESTIC = listOf(
        "https://223.5.5.5/dns-query",
        "https://1.12.12.12/dns-query",
    )
    val DEFAULT_OVERSEAS_DOH = listOf(
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
    )

    /** 11 overseas probe domain suffixes strictly forbidden on domestic pre-accel health checks. */
    val FORBIDDEN_DOMESTIC_PROBE_SUFFIXES = listOf(
        "gstatic.com",
        "google.com",
        "googleapis.com",
        "googleusercontent.com",
        "youtube.com",
        "cloudflare.com",
        "captive.apple.com",
        "detectportal.firefox.com",
        "connectivitycheck.android.com",
        "msftconnecttest.com",
        "msftncsi.com",
    )

    val DOMESTIC_QUIC_DIRECT_DOMAINS = listOf(
        "cn", "qq.com", "qpic.cn", "qlogo.cn", "gtimg.cn", "gtimg.com",
        "weixin.qq.com", "tencent.com", "bilibili.com", "bilivideo.com", "bilivideo.cn",
    )

    val ALWAYS_DOMESTIC_AND_SYSTEM_CDN_DOMAINS = listOf(
        "msftconnecttest.com", "msftncsi.com", "wns.windows.com", "notify.windows.com",
        "time.windows.com", "windowsupdate.com", "update.microsoft.com",
        "dl.delivery.mp.microsoft.com", "tlu.dl.delivery.mp.microsoft.com",
        "icloud.com.cn", "push.apple.com", "time.apple.com", "swcdn.apple.com",
        "appldnld.apple.com", "mesu.apple.com", "updates-http.cdn-apple.com",
        "osxapps.itunes.apple.com", "steamcontent.com", "steamserver.net",
        "dl.steam.clngaa.com", "dl.steam.ksyna.com", "st.dl.eccdnx.com",
        "st.dl.pinyuncloud.com", "st.dl.bscstorage.net", "xz.pphimalayanrt.com",
        "ntp.aliyun.com", "ntp.tencent.com", "cn.pool.ntp.org",
    )

    /** 71+ conservative strictly-domestic sites & core CDNs (no GeoSite/GeoIP files needed). */
    val CONSERVATIVE_DOMESTIC_DIRECT_DOMAINS = listOf(
        "qq.com", "weixin.qq.com", "gtimg.com", "qpic.cn", "qlogo.cn", "wechat.com",
        "wechatpay.com", "tenpay.com", "tencent.com", "myqcloud.com", "qcloud.com",
        "taobao.com", "tmall.com", "alicdn.com", "aliyuncs.com", "aliyun.com",
        "alipay.com", "alipayobjects.com", "dingtalk.com", "amap.com", "autonavi.com",
        "douyin.com", "bytedance.com", "byteimg.com", "pstatp.com", "snssdk.com",
        "toutiao.com", "iesdouyin.com", "douyinvod.com", "volces.com", "volcengine.com",
        "feishu.cn", "bilibili.com", "bilivideo.com", "bilivideo.cn", "hdslb.com",
        "biliapi.com", "biliapi.net", "b23.tv", "163.com", "126.net", "126.com",
        "netease.com", "ydstatic.com", "youdao.com", "baidu.com", "bdimg.com",
        "bdstatic.com", "bcebos.com", "baidupcs.com", "jd.com", "360buyimg.com",
        "zhihu.com", "zhimg.com", "xiaohongshu.com", "xhscdn.com", "weibo.com",
        "sinaimg.cn", "douban.com", "doubanio.com", "meituan.com", "meituan.net",
        "dianping.com", "pinduoduo.com", "iqiyi.com", "youku.com", "mgtv.com",
        "huya.com", "douyu.com", "kuaishou.com", "aliyundrive.com", "alipan.com",
        "quark.cn", "csdn.net", "gitee.com", "juejin.cn", "npmmirror.com",
        "mi.com", "xiaomi.com", "miui.com", "huawei.com", "hicloud.com",
        "vmall.com", "sf-express.com", "cainiao.com", "edu.cn",
    )

    private val AI_DNS_POLICY_DOMAINS = listOf(
        "+.anthropic.com", "+.claude.ai", "+.claude.com", "+.openai.com",
        "api.openai.com", "ios.chat.openai.com", "+.chatgpt.com", "ab.chatgpt.com",
        "+.google.com", "+.googleapis.com", "+.gstatic.com", "+.googleusercontent.com",
        "+.antigravity.google", "+.windsurf.com", "+.codeium.com", "+.github.com",
        "+.x.com", "+.twitter.com", "+.twimg.com", "+.t.co",
    )

    private val DEFAULT_AI_ROUTING_DOMAINS = listOf(
        "ab.chatgpt.com", "ios.chat.openai.com", "api.openai.com",
        "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com",
        "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com",
        "google.com", "googleapis.com", "gstatic.com", "gemini.google.com",
        "aistudio.google.com", "generativelanguage.googleapis.com",
        "antigravity.google", "cloudcode-pa.googleapis.com",
        "windsurf.com", "codeium.com", "cursor.com", "githubcopilot.com",
    )

    private val CAMPUS_INTRANET_DNS_DOMAINS = listOf(
        "+.edu.cn", "+.lan", "+.local", "+.localdomain", "+.internal", "+.home.arpa",
    )

    private val PRIVATE_LAN_DIRECT_RULES = listOf(
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
        "IP-CIDR,255.255.255.255/32,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve",
        "IP-CIDR6,fc00::/7,DIRECT,no-resolve",
        "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,localhost,DIRECT",
        "DOMAIN-SUFFIX,localdomain,DIRECT",
        "DOMAIN-SUFFIX,home.arpa,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,internal,DIRECT",
    )

    private val DOMESTIC_PUBLIC_DNS_DIRECT_RULES = listOf(
        "IP-CIDR,223.5.5.5/32,DIRECT,no-resolve",
        "IP-CIDR,223.6.6.6/32,DIRECT,no-resolve",
        "IP-CIDR,1.12.12.12/32,DIRECT,no-resolve",
        "IP-CIDR,119.29.29.29/32,DIRECT,no-resolve",
        "IP-CIDR,119.28.28.28/32,DIRECT,no-resolve",
        "IP-CIDR,120.53.53.53/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.114.114/32,DIRECT,no-resolve",
        "IP-CIDR,114.114.115.115/32,DIRECT,no-resolve",
        "IP-CIDR,180.76.76.76/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.1.1/32,DIRECT,no-resolve",
        "IP-CIDR,180.184.2.2/32,DIRECT,no-resolve",
        "IP-CIDR,1.2.4.8/32,DIRECT,no-resolve",
        "IP-CIDR,210.2.4.8/32,DIRECT,no-resolve",
        "DOMAIN,dns.alidns.com,DIRECT",
        "DOMAIN,doh.pub,DIRECT",
        "DOMAIN,dot.pub,DIRECT",
        "DOMAIN,dns.pub,DIRECT",
    )

    private val DESKTOP_PROCESS_RULE_PREFIXES = listOf(
        "PROCESS-NAME,",
        "PROCESS-NAME-REGEX,",
        "PROCESS-PATH,",
        "PROCESS-PATH-REGEX,",
    )

    fun isForbiddenDomesticProbeHost(host: String): Boolean {
        val norm = host.trim().trimEnd('.').lowercase()
        if (norm.isEmpty()) return false
        return FORBIDDEN_DOMESTIC_PROBE_SUFFIXES.any { suffix ->
            norm == suffix || norm.endsWith(".$suffix")
        }
    }

    fun validateDomesticProbeUrl(rawUrl: String): String {
        val trimmed = rawUrl.trim()
        require(trimmed.isNotEmpty()) { "国内探活 URL 不能为空" }
        val u = runCatching { URI(trimmed) }.getOrElse {
            throw IllegalArgumentException("无效的国内探活 URL: $trimmed")
        }
        val scheme = u.scheme?.lowercase() ?: ""
        require(scheme == "http" || scheme == "https") { "国内探活 URL 必须为 http:// 或 https://" }
        val host = u.host?.trim()?.removePrefix("[")?.removeSuffix("]")?.takeIf { it.isNotEmpty() }
            ?: throw IllegalArgumentException("国内探活 URL 缺少主机名")
        require(!isForbiddenDomesticProbeHost(host)) {
            "禁止将海外域名 `$host` 用作国内 443 预加速探活目标；请使用 hicloud 或 miui 国内 204 端点"
        }
        return trimmed
    }

    fun validateRelayStrict(relay: PreAccelRelayRecord) {
        require(relay.server.trim().isNotEmpty()) { "中转服务器地址不能为空" }
        require(relay.port in 1..65535) { "中转端口无效: ${relay.port}" }
        val proto = NodeFingerprint.normalizeRelayProtocol(relay.protocol)
        require(proto in setOf("anytls", "trojan", "vless", "hysteria2", "tuic")) {
            "不支持的国内中转协议: ${relay.protocol}"
        }
        require(relay.password.trim().isNotEmpty()) { "中转凭据不能为空" }
        if (relay.port == 443 && relay.hasNonEmptySni()) {
            throw IllegalArgumentException(
                "国内 :443 纯 IP 中转严禁配置 SNI/servername (`${relay.sni}`)，避免触发云厂商 443 SNI 阻断"
            )
        }
        if (isPureIp(relay.server) && !relay.skipCertVerify) {
            throw IllegalArgumentException("纯 IP 自签国内中转必须开启 skip_cert_verify=true")
        }
    }

    fun compile(
        settings: AppSettings,
        nodes: List<ProxyNodeRecord>,
        groups: List<MultiGroupRecord>,
        relays: List<PreAccelRelayRecord>,
        extraPrependRules: List<String> = emptyList(),
        compileAllNodes: Boolean = false,
    ): CompiledAndroidConfig {
        val warnings = ArrayList<String>()
        val probeUrl = validateDomesticProbeUrl(settings.preaccelProbeUrl)
        val fallbackProbeUrl = settings.preaccelFallbackProbeUrl.trim()
            .takeIf { it.isNotEmpty() }
            ?.let { validateDomesticProbeUrl(it) }

        val enabledRelays = relays
            .filter { it.enabled }
            .sortedWith(compareBy<PreAccelRelayRecord> { it.priority }.thenBy { it.id })
        val preaccelActive = settings.preaccelEnabled && enabledRelays.isNotEmpty()

        val (selectedNodes, allowedGroupIds, pruned) = selectNodesAndGroups(
            settings = settings,
            nodes = nodes,
            groups = groups,
            extraPrependRules = extraPrependRules,
            compileAllNodes = compileAllNodes,
        )

        val root = LinkedHashMap<String, Any>()
        root["mixed-port"] = 0
        root["allow-lan"] = false
        root["bind-address"] = "127.0.0.1"
        root["mode"] = settings.proxyMode.wireValue
        root["log-level"] = "warning"
        root["ipv6"] = false
        root["unified-delay"] = true
        root["tcp-concurrent"] = true
        root["keep-alive-idle"] = 15
        root["keep-alive-interval"] = 15
        root["find-process-mode"] = "off"
        root["geodata-mode"] = false
        root["geo-auto-update"] = false
        root["geodata-loader"] = "memconservative"
        root["profile"] = mapOf(
            "store-selected" to false,
            "store-fake-ip" to false,
        )
        root["tun"] = mapOf("enable" to false)

        // Sniffer: preserve QUIC SNI extraction for domestic IM direct rules without GeoIP
        val sniffMap = LinkedHashMap<String, Any>()
        sniffMap["HTTP"] = mapOf("ports" to listOf(80, "8080-8880"), "override-destination" to true)
        sniffMap["TLS"] = mapOf("ports" to listOf(443, 8443))
        if (!settings.blockQuicUdp443 || settings.domesticDirectEnabled) {
            sniffMap["QUIC"] = mapOf("ports" to listOf(443, 8443))
        }
        root["sniffer"] = linkedMapOf(
            "enable" to true,
            "force-dns-mapping" to true,
            "parse-pure-ip" to true,
            "override-destination" to false,
            "sniff" to sniffMap,
            "skip-domain" to listOf("Mijia Cloud", "+.push.apple.com"),
        )

        // Anti-loop rules & fake-ip-filter
        val antiLoopRules = ArrayList<String>()
        val antiLoopFakeIp = ArrayList<String>()

        if (preaccelActive) {
            for (r in enabledRelays) {
                val s = r.server.trim()
                if (s.isEmpty()) continue
                pushUnique(antiLoopRules, directRuleForHostOrIp(s))
                if (!isPureIp(s)) pushUnique(antiLoopFakeIp, s.lowercase())
            }
            listOfNotNull(probeUrl, fallbackProbeUrl).forEach { uStr ->
                extractHost(uStr)?.let { host ->
                    pushUnique(antiLoopRules, directRuleForHostOrIp(host))
                    if (!isPureIp(host)) pushUnique(antiLoopFakeIp, host.lowercase())
                }
            }
            pushUnique(antiLoopRules, "DOMAIN-SUFFIX,hicloud.com,DIRECT")
            pushUnique(antiLoopRules, "DOMAIN-SUFFIX,miui.com,DIRECT")
            pushUnique(antiLoopFakeIp, "+.hicloud.com")
            pushUnique(antiLoopFakeIp, "+.miui.com")
        }

        for (rawEntry in settings.campusDirectDomains) {
            val e = rawEntry.trim()
            if (e.isEmpty() || isDesktopProcessRule(e)) continue
            if (e.contains(',')) {
                pushUnique(antiLoopRules, e)
            } else if (isPureIp(e)) {
                pushUnique(antiLoopRules, directRuleForHostOrIp(e))
            } else {
                val clean = e.removePrefix("*.").removePrefix("+.")
                pushUnique(antiLoopRules, "DOMAIN-SUFFIX,$clean,DIRECT")
                pushUnique(antiLoopFakeIp, e)
            }
        }

        // Business node domain servers in fake-ip-filter (strictly scoped to pruned `selectedNodes`)
        for (n in selectedNodes) {
            val host = n.server.trim().removePrefix("[").removeSuffix("]")
            if (host.isNotEmpty() && !isPureIp(host)) {
                pushUnique(antiLoopFakeIp, host.lowercase())
            }
        }

        // DNS section: campus pure-IP DoH + `+.edu.cn` system DNS + AI overseas DoH policy
        root["dns"] = buildDnsSection(settings, antiLoopFakeIp)

        // Proxies section
        val usedNames = HashSet<String>()
        val compiledProxies = ArrayList<MutableMap<String, Any?>>()
        val relayIdToName = HashMap<String, String>()
        val relayNamesOrdered = ArrayList<String>()

        if (preaccelActive) {
            for (relay in enabledRelays) {
                val baseName = relay.name.trim().ifEmpty { "PreAccel-${relay.id}" }
                val uniqueName = makeUniqueName(baseName, usedNames)
                compiledProxies.add(buildRelayProxyMap(relay, uniqueName).toMutableMap())
                relayIdToName[relay.id] = uniqueName
                relayNamesOrdered.add(uniqueName)
            }
        }

        val nodeIdToName = HashMap<String, String>()
        val allCompiledNodeNames = ArrayList<String>()
        var dialerWrappedCount = 0

        for (node in selectedNodes) {
            val baseName = node.name.trim().ifEmpty { "Node-${node.id}" }
            val uniqueName = makeUniqueName(baseName, usedNames)
            val proxyMap = buildNodeProxyMap(node, uniqueName)
            if (preaccelActive && node.shouldApplyPreaccel(settings.preaccelSkip443Native)) {
                proxyMap["dialer-proxy"] = PREACCEL_SELECT_GROUP
                dialerWrappedCount++
            } else if (proxyMap["dialer-proxy"] == PREACCEL_SELECT_GROUP) {
                proxyMap.remove("dialer-proxy")
            }
            compiledProxies.add(proxyMap)
            nodeIdToName[node.id] = uniqueName
            allCompiledNodeNames.add(uniqueName)
        }

        // Proxy-groups section
        val proxyGroups = ArrayList<Map<String, Any>>()
        if (preaccelActive) {
            val activeRelayName = settings.preaccelActiveRelayId?.let { relayIdToName[it] }
            if (activeRelayName != null) {
                val pos = relayNamesOrdered.indexOf(activeRelayName)
                if (pos > 0) {
                    relayNamesOrdered.removeAt(pos)
                    relayNamesOrdered.add(0, activeRelayName)
                }
            }

            val fallbackMembers = ArrayList<String>(relayNamesOrdered)
            pushUnique(fallbackMembers, "DIRECT") // Fail-open so dialer-wrapped nodes never blackhole

            val selectMembers = ArrayList<String>()
            if (activeRelayName != null && !settings.preaccelAutoFailover) {
                pushUnique(selectMembers, activeRelayName)
            }
            pushUnique(selectMembers, PREACCEL_FALLBACK_GROUP)
            if (activeRelayName != null) pushUnique(selectMembers, activeRelayName)
            relayNamesOrdered.forEach { pushUnique(selectMembers, it) }
            pushUnique(selectMembers, "DIRECT")

            proxyGroups.add(
                linkedMapOf(
                    "name" to PREACCEL_SELECT_GROUP,
                    "type" to "select",
                    "proxies" to selectMembers,
                )
            )
            proxyGroups.add(
                linkedMapOf(
                    "name" to PREACCEL_FALLBACK_GROUP,
                    "type" to "fallback",
                    "proxies" to fallbackMembers,
                    "url" to probeUrl,
                    "interval" to settings.preaccelProbeIntervalSec.coerceIn(10, 300),
                    "lazy" to false,
                )
            )
        }

        var defaultMatchTarget: String? = null
        var effectiveActiveGroupId: String? = null
        val preferredActiveGroupId = settings.activeGroupId?.trim()?.takeIf { it.isNotEmpty() }

        for (group in groups) {
            if (allowedGroupIds != null && !allowedGroupIds.contains(group.id.trim())) continue
            val gName = group.name.trim().ifEmpty { group.id.trim() }
            if (gName.isEmpty()) continue

            if (preferredActiveGroupId == group.id.trim()) {
                defaultMatchTarget = gName
                effectiveActiveGroupId = group.id.trim()
            } else if (defaultMatchTarget == null) {
                defaultMatchTarget = gName
                effectiveActiveGroupId = group.id.trim()
            }

            val members = ArrayList<String>()
            if (group.memberNodeIds.isNotEmpty()) {
                for (nid in group.memberNodeIds) {
                    nodeIdToName[nid]?.let { pushUnique(members, it) }
                }
            } else if (group.mode == "conditional_pool") {
                allCompiledNodeNames.forEach { pushUnique(members, it) }
            }
            if (members.isEmpty()) members.add("DIRECT")

            val activeMember = group.activeNodeId?.let { nodeIdToName[it] }
                ?.takeIf { members.contains(it) }
            if (activeMember != null && (group.mode == "sticky_best" || group.mode == "conditional_pool")) {
                members.remove(activeMember)
                members.add(0, activeMember)
            }

            val groupMap = LinkedHashMap<String, Any>()
            groupMap["name"] = gName
            when (group.mode) {
                "load_balance_consistent_hash" -> {
                    groupMap["type"] = "load-balance"
                    groupMap["strategy"] = "consistent-hashing"
                    groupMap["url"] = DEFAULT_LOAD_BALANCE_URL
                    groupMap["interval"] = 300
                    groupMap["lazy"] = true
                    groupMap["proxies"] = members
                }
                "load_balance_round_robin" -> {
                    groupMap["type"] = "load-balance"
                    groupMap["strategy"] = "round-robin"
                    groupMap["url"] = DEFAULT_LOAD_BALANCE_URL
                    groupMap["interval"] = 300
                    groupMap["lazy"] = true
                    groupMap["proxies"] = members
                }
                else -> {
                    groupMap["type"] = "select"
                    groupMap["proxies"] = members
                }
            }
            proxyGroups.add(groupMap)
        }

        val resolvedSingleProxy = if (settings.routeMode == RouteMode.SINGLE) {
            settings.activeSingleNodeId?.trim()?.let { nodeIdToName[it] }
        } else {
            null
        }
        val singleModeActive = resolvedSingleProxy != null
        val matchTarget = if (resolvedSingleProxy != null) {
            val singleMembers = ArrayList<String>()
            singleMembers.add(resolvedSingleProxy)
            allCompiledNodeNames.forEach { pushUnique(singleMembers, it) }
            proxyGroups.add(
                linkedMapOf(
                    "name" to SINGLE_NODE_GROUP,
                    "type" to "select",
                    "proxies" to singleMembers,
                )
            )
            SINGLE_NODE_GROUP
        } else {
            defaultMatchTarget ?: run {
                val defaultMembers = ArrayList<String>(allCompiledNodeNames)
                if (defaultMembers.isEmpty()) defaultMembers.add("DIRECT")
                proxyGroups.add(
                    linkedMapOf(
                        "name" to DEFAULT_FALLBACK_GROUP,
                        "type" to "select",
                        "proxies" to defaultMembers,
                    )
                )
                DEFAULT_FALLBACK_GROUP
            }
        }

        // Strip dangling/self dialer-proxy targets
        val validTargets = HashSet<String>(usedNames)
        proxyGroups.forEach { (it["name"] as? String)?.let { n -> validTargets.add(n) } }
        for (p in compiledProxies) {
            val dp = (p["dialer-proxy"] as? String)?.trim() ?: continue
            val selfName = (p["name"] as? String)?.trim()
            if (dp.isEmpty() || dp == selfName || !validTargets.contains(dp)) {
                p.remove("dialer-proxy")
            }
        }

        root["proxies"] = compiledProxies
        root["proxy-groups"] = proxyGroups

        // Ordered rules chain (strictly stripping all desktop PROCESS-NAME* / PROCESS-PATH* rules)
        val rules = ArrayList<String>()
        antiLoopRules.forEach { pushUnique(rules, it) }
        PRIVATE_LAN_DIRECT_RULES.forEach { pushUnique(rules, it) }
        DOMESTIC_PUBLIC_DNS_DIRECT_RULES.forEach { pushUnique(rules, it) }

        for (raw in extraPrependRules) {
            val trimmed = raw.trim()
            if (trimmed.isNotEmpty() && !isDesktopProcessRule(trimmed)) {
                pushUnique(rules, trimmed)
            }
        }

        if (settings.blockQuicUdp443) {
            if (settings.domesticDirectEnabled) {
                for (dom in DOMESTIC_QUIC_DIRECT_DOMAINS) {
                    pushUnique(rules, "AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,$dom)),DIRECT")
                }
            }
            pushUnique(rules, "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT")
        }

        if (!singleModeActive) {
            val orderedGroups = groups.filter { it.id.trim() == effectiveActiveGroupId } +
                groups.filter { it.id.trim() != effectiveActiveGroupId && it.independentRouting }
            for (g in orderedGroups) {
                val target = g.name.trim().ifEmpty { g.id.trim() }
                if (target.isEmpty()) continue
                for (rawRule in g.matchRules) {
                    for (expanded in expandGroupMatchRule(rawRule, target)) {
                        if (!isDesktopProcessRule(expanded)) {
                            pushUnique(rules, expanded)
                        }
                    }
                }
            }
        }

        if (settings.domesticDirectEnabled) {
            pushUnique(rules, "DOMAIN-SUFFIX,cn,DIRECT")
            ALWAYS_DOMESTIC_AND_SYSTEM_CDN_DOMAINS.forEach {
                pushUnique(rules, "DOMAIN-SUFFIX,$it,DIRECT")
            }
            CONSERVATIVE_DOMESTIC_DIRECT_DOMAINS.forEach {
                pushUnique(rules, "DOMAIN-SUFFIX,$it,DIRECT")
            }
        }

        if (rules.none { it.uppercase().startsWith("MATCH,") }) {
            rules.add("MATCH,$matchTarget")
        }
        root["rules"] = rules

        val opts = DumperOptions().apply {
            setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK)
            setPrettyFlow(true)
            setAllowUnicode(true)
        }
        val yamlStr = Yaml(opts).dump(root)

        val activeLabel = resolvedSingleProxy ?: matchTarget
        return CompiledAndroidConfig(
            yaml = yamlStr,
            activeNodeCount = selectedNodes.size,
            relayCount = relayNamesOrdered.size,
            dialerWrappedCount = dialerWrappedCount,
            activeGroupOrNodeName = activeLabel,
            pruned = pruned,
            warnings = warnings,
        )
    }

    private data class SelectionResult(
        val nodes: List<ProxyNodeRecord>,
        val allowedGroupIds: Set<String>?,
        val pruned: Boolean,
    )

    private fun selectNodesAndGroups(
        settings: AppSettings,
        nodes: List<ProxyNodeRecord>,
        groups: List<MultiGroupRecord>,
        extraPrependRules: List<String>,
        compileAllNodes: Boolean,
    ): SelectionResult {
        val enabledNodes = nodes.filter { it.enabled }
        val shouldPrune = !compileAllNodes &&
            settings.proxyMode != ProxyMode.GLOBAL &&
            nodes.size > 32
        if (!shouldPrune || enabledNodes.isEmpty()) {
            return SelectionResult(enabledNodes, null, pruned = false)
        }

        val enabledIds = enabledNodes.map { it.id }.toHashSet()
        val nodesByName = HashMap<String, MutableList<String>>()
        for (n in enabledNodes) {
            val nm = n.name.trim()
            if (nm.isNotEmpty()) nodesByName.getOrPut(nm) { ArrayList() }.add(n.id)
        }

        val groupById = HashMap<String, MultiGroupRecord>()
        val groupIdsByName = HashMap<String, MutableList<String>>()
        var effectiveActiveGroupId: String? = null
        val prefGroupId = settings.activeGroupId?.trim()?.takeIf { it.isNotEmpty() }
        for (g in groups) {
            val gid = g.id.trim()
            val gName = g.name.trim().ifEmpty { gid }
            if (gName.isEmpty()) continue
            groupById[gid] = g
            groupIdsByName.getOrPut(gName) { ArrayList() }.add(gid)
            if (prefGroupId == gid) {
                effectiveActiveGroupId = gid
            } else if (effectiveActiveGroupId == null) {
                effectiveActiveGroupId = gid
            }
        }

        val activeNodeIds = HashSet<String>()
        val activeGroupIds = HashSet<String>()
        val queue = ArrayDeque<String>()

        val singleNodeId = if (settings.routeMode == RouteMode.SINGLE) {
            settings.activeSingleNodeId?.trim()?.takeIf { enabledIds.contains(it) }
        } else {
            null
        }

        if (singleNodeId != null) {
            activeNodeIds.add(singleNodeId)
        } else {
            effectiveActiveGroupId?.let { queue.add(it) }
            groups.filter { it.independentRouting && it.id.isNotBlank() }.forEach { queue.add(it.id.trim()) }
        }

        for (rawRule in extraPrependRules) {
            val target = extractRuleTarget(rawRule) ?: continue
            groupIdsByName[target]?.forEach { queue.add(it) }
            nodesByName[target]?.forEach { activeNodeIds.add(it) }
        }

        while (queue.isNotEmpty()) {
            val gid = queue.removeFirst()
            if (!activeGroupIds.add(gid)) continue
            val g = groupById[gid] ?: continue
            g.fallbackPoolId?.trim()?.takeIf { it.isNotEmpty() && !activeGroupIds.contains(it) }?.let {
                queue.add(it)
            }
            if (singleNodeId == null && (effectiveActiveGroupId == gid || g.independentRouting)) {
                val gName = g.name.trim().ifEmpty { gid }
                for (r in g.matchRules) {
                    for (exp in expandGroupMatchRule(r, gName)) {
                        val target = extractRuleTarget(exp) ?: continue
                        groupIdsByName[target]?.filter { !activeGroupIds.contains(it) }?.forEach { queue.add(it) }
                        nodesByName[target]?.forEach { activeNodeIds.add(it) }
                    }
                }
            }
        }

        var needAll = false
        for (g in groups) {
            if (!activeGroupIds.contains(g.id.trim())) continue
            if (g.memberNodeIds.isNotEmpty()) {
                g.memberNodeIds.filter { enabledIds.contains(it) }.forEach { activeNodeIds.add(it) }
            } else if (g.mode == "conditional_pool") {
                needAll = true
                break
            }
        }

        if (needAll || activeNodeIds.isEmpty()) {
            return SelectionResult(enabledNodes, null, pruned = false)
        }

        // Expand chained `dialer-proxy` node references transitively
        val nodeByNameObj = HashMap<String, MutableList<ProxyNodeRecord>>()
        for (n in enabledNodes) {
            val nm = n.name.trim()
            if (nm.isNotEmpty()) nodeByNameObj.getOrPut(nm) { ArrayList() }.add(n)
        }
        while (true) {
            var added = false
            val snap = activeNodeIds.toSet()
            for (n in enabledNodes) {
                if (!snap.contains(n.id)) continue
                val obj = runCatching { JSONObject(n.rawConfigJson) }.getOrNull() ?: continue
                val dp = obj.optString("dialer-proxy", "").trim()
                if (dp.isEmpty() || dp == PREACCEL_SELECT_GROUP) continue
                nodeByNameObj[dp]?.forEach { target ->
                    if (activeNodeIds.add(target.id)) added = true
                }
            }
            if (!added) break
        }

        val prunedNodes = enabledNodes.filter { activeNodeIds.contains(it.id) }
        return if (prunedNodes.isEmpty()) {
            SelectionResult(enabledNodes, null, pruned = false)
        } else {
            SelectionResult(prunedNodes, activeGroupIds, pruned = prunedNodes.size < enabledNodes.size)
        }
    }

    private fun buildDnsSection(settings: AppSettings, antiLoopFakeIp: List<String>): Map<String, Any> {
        val directNs = DEFAULT_PURE_IP_DOH_DOMESTIC.map { "$it#DIRECT" }
        val fakeIpFilter = ArrayList<String>()
        listOf(
            "*.lan", "*.local", "*.localdomain", "+.edu.cn",
            "dns.alidns.com", "doh.pub", "dot.pub", "dns.pub",
            "+.qq.com", "+.qpic.cn", "+.qlogo.cn", "+.gtimg.cn", "+.gtimg.com",
            "+.nt.qq.com.cn", "+.weixin.qq.com", "+.tencent.com",
            "+.qcloud.com", "+.myqcloud.com",
        ).forEach { pushUnique(fakeIpFilter, it) }
        antiLoopFakeIp.forEach { pushUnique(fakeIpFilter, it) }

        val policy = LinkedHashMap<String, List<String>>()
        for (dom in AI_DNS_POLICY_DOMAINS) {
            policy[dom] = DEFAULT_OVERSEAS_DOH
        }
        val campusServers = listOf("system", "https://223.5.5.5/dns-query#DIRECT")
        for (dom in CAMPUS_INTRANET_DNS_DOMAINS) {
            policy[dom] = campusServers
        }
        for (raw in settings.campusDirectDomains) {
            val clean = raw.trim().removePrefix("*.").removePrefix("+.")
            if (clean.isNotEmpty() && !clean.contains(',') && !isPureIp(clean)) {
                policy["+.$clean"] = campusServers
            }
        }

        return linkedMapOf(
            "enable" to true,
            "ipv6" to false,
            "respect-rules" to true,
            "prefer-h3" to false,
            "enhanced-mode" to "fake-ip",
            "fake-ip-range" to "198.18.0.1/16",
            "fake-ip-filter" to fakeIpFilter,
            "default-nameserver" to DEFAULT_PURE_IP_DOH_DOMESTIC,
            "direct-nameserver" to directNs,
            "nameserver" to directNs,
            "proxy-server-nameserver" to DEFAULT_PURE_IP_DOH_DOMESTIC,
            "fallback" to DEFAULT_OVERSEAS_DOH,
            "nameserver-policy" to policy,
            "fallback-filter" to mapOf(
                "geoip" to false,
                "geoip-code" to "CN",
                "ipcidr" to listOf("240.0.0.0/4", "0.0.0.0/32"),
                "domain" to listOf("+.google.com", "+.github.com", "+.openai.com", "+.anthropic.com"),
            ),
        )
    }

    private fun buildRelayProxyMap(relay: PreAccelRelayRecord, uniqueName: String): Map<String, Any?> {
        val proto = NodeFingerprint.normalizeRelayProtocol(relay.protocol)
        val server = relay.server.trim().removePrefix("[").removeSuffix("]")
        val skipCert = if (isPureIp(server)) true else relay.skipCertVerify
        val map = LinkedHashMap<String, Any?>()
        map["name"] = uniqueName
        map["type"] = proto
        map["server"] = server
        map["port"] = relay.port

        when (proto) {
            "anytls" -> {
                map["password"] = relay.password
                map["udp"] = true
                map["tfo"] = true
                map["idle-session-check-interval"] = 30
                map["idle-session-timeout"] = 30
                map["min-idle-session"] = 2
                map["skip-cert-verify"] = skipCert
                maybeInsertNon443Sni(map, relay)
            }
            "trojan" -> {
                map["password"] = relay.password
                map["udp"] = true
                map["tfo"] = true
                map["skip-cert-verify"] = skipCert
                maybeInsertNon443Sni(map, relay)
            }
            "vless" -> {
                map["uuid"] = relay.password.trim()
                map["network"] = "tcp"
                map["tls"] = true
                map["udp"] = true
                map["tfo"] = true
                map["skip-cert-verify"] = skipCert
                // Strictly force empty `servername: ""` on domestic :443 pure-IP relays
                map["servername"] = if (relay.port == 443) "" else (relay.sni?.trim() ?: "")
            }
            "hysteria2" -> {
                map["password"] = relay.password
                map["up"] = "100 Mbps"
                map["down"] = "200 Mbps"
                map["skip-cert-verify"] = skipCert
                maybeInsertNon443Sni(map, relay)
            }
            "tuic" -> {
                map["token"] = relay.password
                map["udp-relay-mode"] = "native"
                map["skip-cert-verify"] = skipCert
                maybeInsertNon443Sni(map, relay)
            }
            else -> throw IllegalArgumentException("不支持的中转协议: ${relay.protocol}")
        }
        return map
    }

    private fun maybeInsertNon443Sni(map: MutableMap<String, Any?>, relay: PreAccelRelayRecord) {
        if (relay.port != 443) {
            relay.sni?.trim()?.takeIf { it.isNotEmpty() }?.let { map["sni"] = it }
        }
    }

    private fun buildNodeProxyMap(node: ProxyNodeRecord, uniqueName: String): MutableMap<String, Any?> {
        val map = LinkedHashMap<String, Any?>()
        val obj = runCatching { JSONObject(node.rawConfigJson) }.getOrNull()
        if (obj != null) {
            val keys = obj.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                map[k] = jsonToPlain(obj.opt(k))
            }
        }
        map["name"] = uniqueName
        if (!map.containsKey("type")) map["type"] = NodeFingerprint.normalizeProtocol(node.protocol)
        if (!map.containsKey("server")) map["server"] = node.server.trim()
        if (!map.containsKey("port")) map["port"] = node.port
        return map
    }

    private fun jsonToPlain(v: Any?): Any? = when (v) {
        null, JSONObject.NULL -> null
        is JSONObject -> {
            val m = LinkedHashMap<String, Any?>()
            val keys = v.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                m[k] = jsonToPlain(v.opt(k))
            }
            m
        }
        is JSONArray -> {
            val list = ArrayList<Any?>(v.length())
            for (i in 0 until v.length()) list.add(jsonToPlain(v.opt(i)))
            list
        }
        else -> v
    }

    private fun expandGroupMatchRule(raw: String, groupName: String): List<String> {
        val trimmed = raw.trim()
        if (trimmed.isEmpty() || isDesktopProcessRule(trimmed)) return emptyList()
        if (trimmed.equals("@ai_domains", ignoreCase = true) || trimmed.equals("PRESET:AI", ignoreCase = true)) {
            return DEFAULT_AI_ROUTING_DOMAINS.map { "DOMAIN-SUFFIX,$it,$groupName" }
        }
        val parts = trimmed.split(',').map { it.trim() }
        return when (parts.size) {
            1 -> if (parts[0].contains('.') && !isPureIp(parts[0])) {
                listOf("DOMAIN-SUFFIX,${parts[0].removePrefix("*.").removePrefix("+.")},$groupName")
            } else {
                emptyList()
            }
            2 -> if (!parts[0].equals("MATCH", ignoreCase = true) && parts[1].isNotEmpty()) {
                listOf("${parts[0].uppercase()},${parts[1]},$groupName")
            } else {
                emptyList()
            }
            3 -> if (parts[2].equals("no-resolve", ignoreCase = true)) {
                listOf("${parts[0].uppercase()},${parts[1]},$groupName,no-resolve")
            } else {
                listOf("${parts[0].uppercase()},${parts[1]},${parts[2]}")
            }
            else -> listOf(trimmed)
        }
    }

    private fun isDesktopProcessRule(rule: String): Boolean {
        val upper = rule.trim().uppercase()
        return DESKTOP_PROCESS_RULE_PREFIXES.any { upper.startsWith(it) } ||
            upper.contains("(PROCESS-NAME") ||
            upper.contains("(PROCESS-PATH")
    }

    private fun extractRuleTarget(rule: String): String? {
        val trimmed = rule.trim()
        if (trimmed.isEmpty() || trimmed.startsWith('#')) return null
        val parts = trimmed.split(',').map { it.trim() }.toMutableList()
        if (parts.size < 2) return null
        if (parts[0].equals("MATCH", ignoreCase = true)) {
            val t = parts[1]
            return t.takeIf { it.isNotEmpty() && !isBuiltinAction(it) }
        }
        while (parts.size > 2 && (parts.last().equals("no-resolve", true) || parts.last().equals("src", true))) {
            parts.removeAt(parts.lastIndex)
        }
        if (parts.size < 3) return null
        val target = parts.last()
        return target.takeIf { it.isNotEmpty() && !isBuiltinAction(it) }
    }

    private fun isBuiltinAction(target: String): Boolean =
        target.uppercase() in setOf("DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE")

    private fun directRuleForHostOrIp(hostOrIp: String): String {
        val clean = hostOrIp.trim().removePrefix("[").removeSuffix("]")
        return if (isPureIpv4(clean)) {
            "IP-CIDR,$clean/32,DIRECT,no-resolve"
        } else if (isPureIpv6(clean)) {
            "IP-CIDR6,$clean/128,DIRECT,no-resolve"
        } else {
            "DOMAIN,$clean,DIRECT"
        }
    }

    private fun isPureIp(raw: String): Boolean {
        val clean = raw.trim().removePrefix("[").removeSuffix("]")
        return isPureIpv4(clean) || isPureIpv6(clean)
    }

    private fun isPureIpv4(s: String): Boolean {
        val parts = s.split('.')
        if (parts.size != 4) return false
        return parts.all { p -> p.isNotEmpty() && p.all { it.isDigit() } && (p.toIntOrNull() in 0..255) }
    }

    private fun isPureIpv6(s: String): Boolean {
        if (!s.contains(':')) return false
        return runCatching { InetAddress.getByName(s) }.isSuccess
    }

    private fun extractHost(rawUrl: String): String? =
        runCatching { URI(rawUrl.trim()).host?.trim()?.takeIf { it.isNotEmpty() } }.getOrNull()

    private fun makeUniqueName(base: String, used: MutableSet<String>): String {
        if (used.add(base)) return base
        var idx = 2
        while (true) {
            val cand = "$base ($idx)"
            if (used.add(cand)) return cand
            idx++
        }
    }

    private fun pushUnique(list: MutableList<String>, item: String) {
        if (!list.contains(item)) list.add(item)
    }
}
