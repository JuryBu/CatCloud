package io.github.jurybu.catcloud

import io.github.jurybu.catcloud.data.AppSettings
import io.github.jurybu.catcloud.data.MultiGroupRecord
import io.github.jurybu.catcloud.data.PreAccelRelayRecord
import io.github.jurybu.catcloud.data.ProxyMode
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import io.github.jurybu.catcloud.data.RouteMode
import io.github.jurybu.catcloud.engine.ConfigCompiler
import io.github.jurybu.catcloud.vpn.CatCloudVpnService
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.yaml.snakeyaml.LoaderOptions
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.constructor.SafeConstructor

class ConfigCompilerTest {

    private fun sampleNode(
        id: String,
        name: String,
        port: Int = 8443,
        is443: Boolean = false,
        server: String = "203.0.113.50",
        dialerProxy: String? = null,
    ): ProxyNodeRecord {
        val raw = JSONObject().apply {
            put("name", name)
            put("type", "trojan")
            put("server", server)
            put("port", port)
            put("password", "demo-password")
            put("udp", true)
            if (dialerProxy != null) put("dialer-proxy", dialerProxy)
        }
        return ProxyNodeRecord(
            id = id,
            name = name,
            protocol = "trojan",
            server = server,
            port = port,
            rawConfigJson = raw.toString(),
            is443Native = is443,
            enabled = true,
        )
    }

    private fun sampleRelay(
        id: String,
        name: String,
        proto: String,
        server: String,
        sni: String? = null,
    ): PreAccelRelayRecord = PreAccelRelayRecord(
        id = id,
        name = name,
        provider = "demo",
        region = "CN-EAST",
        server = server,
        port = 443,
        protocol = proto,
        password = if (proto == "vless") "00000000-0000-4000-8000-000000000099" else "demo-relay-pass",
        sni = sni,
        skipCertVerify = true,
        priority = 10,
        enabled = true,
    )

    @Suppress("UNCHECKED_CAST")
    private fun parseYaml(yaml: String): Map<String, Any?> =
        Yaml(SafeConstructor(LoaderOptions())).load<Map<String, Any?>>(yaml)

    @Test
    fun enforcesPureIp443NoSniAndDomestic204AndStripsProcessNameRules() {
        // Strict validator rejects SNI on domestic :443 relay
        try {
            ConfigCompiler.validateRelayStrict(
                sampleRelay("bad", "BadRelay", "anytls", "198.51.100.10", sni = "forbidden.example.invalid")
            )
            fail("Expected validation error for non-empty SNI on domestic :443 relay")
        } catch (_: IllegalArgumentException) {
            // Expected
        }

        // All 11 overseas probe domains must be rejected for domestic pre-accel probe URL
        for (overseas in listOf(
            "https://www.gstatic.com/generate_204",
            "https://www.google.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
            "http://captive.apple.com/hotspot-detect.html",
            "http://detectportal.firefox.com/canonical.html",
            "http://connectivitycheck.android.com/generate_204",
            "http://www.msftconnecttest.com/connecttest.txt",
            "http://www.msftncsi.com/ncsi.txt",
        )) {
            try {
                ConfigCompiler.validateDomesticProbeUrl(overseas)
                fail("Overseas probe URL must be rejected: $overseas")
            } catch (_: IllegalArgumentException) {
                // Expected
            }
        }

        val settings = AppSettings(
            proxyMode = ProxyMode.RULE,
            routeMode = RouteMode.SINGLE,
            activeSingleNodeId = "n1",
            preaccelEnabled = true,
            preaccelSkip443Native = true,
            domesticDirectEnabled = true,
            blockQuicUdp443 = true,
        )
        val relays = listOf(
            sampleRelay("r-any", "Relay-AnyTLS", "anytls", "198.51.100.10", sni = "must-be-ignored.invalid"),
            sampleRelay("r-vless", "Relay-VLESS", "vless", "198.51.100.11", sni = "must-be-empty.invalid"),
            sampleRelay("r-hy2", "Relay-HY2", "hysteria2", "198.51.100.12", sni = "must-be-ignored.invalid"),
        )
        val nodes = listOf(
            sampleNode("n1", "Node-8443", port = 8443, is443 = false),
            sampleNode("n2", "Node-443-Native", port = 443, is443 = true),
        )

        val compiled = ConfigCompiler.compile(
            settings = settings,
            nodes = nodes,
            groups = emptyList(),
            relays = relays,
            extraPrependRules = listOf(
                "PROCESS-NAME,catcloud-probe-core.exe,DIRECT",
                "PROCESS-PATH,/usr/bin/demo,DIRECT",
                "DOMAIN-SUFFIX,campus.example.edu.cn,DIRECT",
            ),
        )
        assertEquals(3, compiled.relayCount)
        assertEquals(1, compiled.dialerWrappedCount) // n1 wrapped, n2 (443 native) skipped
        assertEquals(ConfigCompiler.SINGLE_NODE_GROUP, compiled.controllerGroupName)
        assertEquals("Node-8443", compiled.activeGroupOrNodeName)

        val doc = parseYaml(compiled.yaml)
        assertEquals("off", doc["find-process-mode"])
        assertEquals("memconservative", doc["geodata-loader"])
        @Suppress("UNCHECKED_CAST")
        val tun = doc["tun"] as Map<String, Any?>
        assertEquals(false, tun["enable"])

        @Suppress("UNCHECKED_CAST")
        val proxies = doc["proxies"] as List<Map<String, Any?>>
        val anyTlsProxy = proxies.first { it["name"] == "Relay-AnyTLS" }
        assertEquals(2, anyTlsProxy["min-idle-session"])
        assertEquals(true, anyTlsProxy["skip-cert-verify"])
        assertFalse(anyTlsProxy.containsKey("sni"))

        val vlessProxy = proxies.first { it["name"] == "Relay-VLESS" }
        assertEquals("", vlessProxy["servername"])
        assertEquals(true, vlessProxy["skip-cert-verify"])

        val hy2Proxy = proxies.first { it["name"] == "Relay-HY2" }
        assertEquals("100 Mbps", hy2Proxy["up"])
        assertEquals("200 Mbps", hy2Proxy["down"])
        assertFalse(hy2Proxy.containsKey("sni"))

        @Suppress("UNCHECKED_CAST")
        val groups = doc["proxy-groups"] as List<Map<String, Any?>>
        val fbGroup = groups.first { it["name"] == ConfigCompiler.PREACCEL_FALLBACK_GROUP }
        assertEquals(ConfigCompiler.DEFAULT_DOMESTIC_204_PRIMARY, fbGroup["url"])
        @Suppress("UNCHECKED_CAST")
        val fbMembers = fbGroup["proxies"] as List<String>
        assertEquals("DIRECT", fbMembers.last()) // fail-open

        @Suppress("UNCHECKED_CAST")
        val rules = doc["rules"] as List<String>
        assertTrue(rules.none { it.uppercase().startsWith("PROCESS-NAME") || it.uppercase().startsWith("PROCESS-PATH") })
        assertTrue(rules.contains("IP-CIDR,198.51.100.10/32,DIRECT,no-resolve"))
        assertTrue(rules.contains("DOMAIN-SUFFIX,cn,DIRECT"))
        assertTrue(rules.contains("AND,((NETWORK,UDP),(DST-PORT,443),(DOMAIN-SUFFIX,qq.com)),DIRECT"))
        assertTrue(rules.contains("AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"))

        @Suppress("UNCHECKED_CAST")
        val dns = doc["dns"] as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val nsPolicy = dns["nameserver-policy"] as Map<String, List<String>>
        assertEquals(listOf("system", "https://223.5.5.5/dns-query#DIRECT"), nsPolicy["+.edu.cn"])
    }

    @Test
    fun prunesActiveSetOver32NodesInRuleModeAndKeepsAllInGlobalMode() {
        val nodes = (1..60).map { i ->
            sampleNode(
                id = "n-$i",
                name = "Node-$i",
                server = "node$i.example.invalid",
                dialerProxy = if (i == 1) "Node-2" else null,
            )
        }
        val group = MultiGroupRecord(
            id = "g-main",
            name = "MainGroup",
            memberNodeIds = listOf("n-1", "n-3"),
            activeNodeId = "n-1",
        )

        val ruleSettings = AppSettings(
            proxyMode = ProxyMode.RULE,
            routeMode = RouteMode.GROUP,
            activeGroupId = "g-main",
        )
        val prunedCompiled = ConfigCompiler.compile(ruleSettings, nodes, listOf(group), emptyList())
        assertTrue(prunedCompiled.pruned)
        // Only n-1, n-3 (group members) + n-2 (transitive dialer-proxy of n-1) survive = 3 / 60 (~95% pruned!)
        assertEquals(3, prunedCompiled.activeNodeCount)
        assertEquals("MainGroup", prunedCompiled.controllerGroupName)
        assertTrue(prunedCompiled.yaml.contains("node1.example.invalid"))
        assertTrue(prunedCompiled.yaml.contains("node2.example.invalid"))
        assertFalse(prunedCompiled.yaml.contains("node55.example.invalid"))

        val globalSettings = ruleSettings.copy(proxyMode = ProxyMode.GLOBAL)
        val globalCompiled = ConfigCompiler.compile(globalSettings, nodes, listOf(group), emptyList())
        assertFalse(globalCompiled.pruned)
        assertEquals(60, globalCompiled.activeNodeCount)
        assertEquals("MainGroup", globalCompiled.controllerGroupName)
    }

    @Test
    fun compilesLoopbackMixedProxyAuthAndRetainsExtraIncludedNodesInControllerGroup() {
        val nodes = (1..60).map { i ->
            sampleNode(id = "n-$i", name = "Node-$i", server = "node$i.example.invalid")
        }
        val group = MultiGroupRecord(
            id = "g-main",
            name = "MainGroup",
            memberNodeIds = listOf("n-1"),
            activeNodeId = "n-1",
        )
        val groupSettings = AppSettings(
            proxyMode = ProxyMode.RULE,
            routeMode = RouteMode.GROUP,
            activeGroupId = "g-main",
        )

        val compiledGroup = ConfigCompiler.compile(
            settings = groupSettings,
            nodes = nodes,
            groups = listOf(group),
            relays = emptyList(),
            extraIncludedNodeIds = setOf("n-45", "n-50"),
            localMixedPort = 28888,
            localMixedSecret = "demo-mixed-secret-01",
        )
        assertTrue(compiledGroup.pruned)
        assertEquals(3, compiledGroup.activeNodeCount)
        assertEquals("MainGroup", compiledGroup.controllerGroupName)
        assertEquals(28888, compiledGroup.localMixedPort)
        assertEquals("demo-mixed-secret-01", compiledGroup.localMixedSecret)

        val doc = parseYaml(compiledGroup.yaml)
        assertEquals(28888, doc["mixed-port"])
        assertEquals("127.0.0.1", doc["bind-address"])
        assertEquals(listOf("catcloud:demo-mixed-secret-01"), doc["authentication"])

        @Suppress("UNCHECKED_CAST")
        val proxyGroups = doc["proxy-groups"] as List<Map<String, Any?>>
        val mainGroupMap = proxyGroups.first { it["name"] == "MainGroup" }
        @Suppress("UNCHECKED_CAST")
        val members = mainGroupMap["proxies"] as List<String>
        assertEquals("Node-1", members.first())
        assertTrue(members.contains("Node-45"))
        assertTrue(members.contains("Node-50"))
        assertFalse(members.contains("Node-55"))

        // Verify CatCloudVpnService YAML extractor matches compiled mixed-port & secret accurately
        assertEquals(28888 to "demo-mixed-secret-01", CatCloudVpnService.extractLoopbackMixedConfig(compiledGroup.yaml))

        // RouteMode.SINGLE always exposes SINGLE_NODE_GROUP as controllerGroupName and includes extra nodes
        val singleSettings = AppSettings(
            proxyMode = ProxyMode.RULE,
            routeMode = RouteMode.SINGLE,
            activeSingleNodeId = "n-1",
        )
        val compiledSingle = ConfigCompiler.compile(
            settings = singleSettings,
            nodes = nodes,
            groups = emptyList(),
            relays = emptyList(),
            extraIncludedNodeIds = setOf("n-40"),
        )
        assertEquals(ConfigCompiler.SINGLE_NODE_GROUP, compiledSingle.controllerGroupName)
        assertEquals("Node-1", compiledSingle.activeGroupOrNodeName)
        val singleDoc = parseYaml(compiledSingle.yaml)
        @Suppress("UNCHECKED_CAST")
        val singleGroups = singleDoc["proxy-groups"] as List<Map<String, Any?>>
        val singleGroupMap = singleGroups.first { it["name"] == ConfigCompiler.SINGLE_NODE_GROUP }
        @Suppress("UNCHECKED_CAST")
        val singleMembers = singleGroupMap["proxies"] as List<String>
        assertEquals("Node-1", singleMembers.first())
        assertTrue(singleMembers.contains("Node-40"))

        // RouteMode.GROUP with no groups falls back to DEFAULT_FALLBACK_GROUP
        val fallbackCompiled = ConfigCompiler.compile(
            settings = groupSettings,
            nodes = nodes.take(3),
            groups = emptyList(),
            relays = emptyList(),
        )
        assertEquals(ConfigCompiler.DEFAULT_FALLBACK_GROUP, fallbackCompiled.controllerGroupName)

        // Loopback port allocator yields valid ephemeral port
        assertTrue(ConfigCompiler.allocateLoopbackPort() in 1..65535)
    }
}
