package io.github.jurybu.catcloud

import io.github.jurybu.catcloud.data.NodeFingerprint
import io.github.jurybu.catcloud.data.PreAccelRelayRecord
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NodeFingerprintTest {

    @Test
    fun nodeFingerprintIs64HexAndIgnoresDisplayMetadata() {
        val rawA = JSONObject().apply {
            put("name", "JP Tokyo 0.5x")
            put("type", "vless")
            put("server", "203.0.113.10")
            put("port", 443)
            put("uuid", "00000000-0000-4000-8000-000000000001")
            put("tls", true)
            put("servername", "Edge.Example.Invalid")
            put("network", "ws")
            put("ws-opts", JSONObject().apply {
                put("path", "/ws")
                put("headers", JSONObject().put("Host", "CDN.Example.Invalid"))
            })
            put("dialer-proxy", "⚡ 国内预加速入口")
            put("skip-cert-verify", true)
        }
        val rawB = JSONObject().apply {
            put("name", "Renamed Tokyo Node #2")
            put("type", "VLESS")
            put("server", "203.0.113.10")
            put("port", 443)
            put("uuid", "00000000-0000-4000-8000-000000000001")
            put("tls", true)
            put("sni", "edge.example.invalid")
            put("network", "WS")
            put("ws-opts", JSONObject().apply {
                put("Headers", JSONObject().put("host", "cdn.example.invalid"))
                put("PATH", "/ws")
            })
            put("skip-cert-verify", false)
        }

        val nodeA = ProxyNodeRecord(
            id = "n1",
            name = "JP Tokyo 0.5x",
            protocol = "vless",
            server = "203.0.113.10",
            port = 443,
            rawConfigJson = rawA.toString(),
        )
        val nodeB = ProxyNodeRecord(
            id = "n2",
            name = "Renamed Tokyo Node #2",
            protocol = "vless",
            server = "203.0.113.10",
            port = 443,
            rawConfigJson = rawB.toString(),
        )

        val fpA = NodeFingerprint.computeNodeFingerprint(nodeA)
        val fpB = NodeFingerprint.computeNodeFingerprint(nodeB)
        assertEquals(64, fpA.length)
        assertTrue(fpA.all { it in '0'..'9' || it in 'a'..'f' })
        assertEquals(fpA, fpB)

        // Changing UUID or reality-opts MUST produce a different fingerprint
        val rawDiffUuid = JSONObject(rawA.toString()).put("uuid", "00000000-0000-4000-8000-000000000002")
        val fpDiff = NodeFingerprint.computeNodeFingerprint(nodeA.copy(rawConfigJson = rawDiffUuid.toString()))
        assertNotEquals(fpA, fpDiff)
    }

    @Test
    fun protocolAliasesAndImplicitTlsNormalizeIdentically() {
        val hy2A = ProxyNodeRecord(
            id = "h1",
            name = "HY2-A",
            protocol = "hy2",
            server = "203.0.113.20",
            port = 443,
            rawConfigJson = JSONObject().put("password", "demo-pass").put("tls", true).toString(),
        )
        val hy2B = ProxyNodeRecord(
            id = "h2",
            name = "HY2-B",
            protocol = "hysteria2",
            server = "203.0.113.20",
            port = 443,
            rawConfigJson = JSONObject().put("password", "demo-pass").toString(),
        )
        assertEquals(
            NodeFingerprint.computeNodeFingerprint(hy2A),
            NodeFingerprint.computeNodeFingerprint(hy2B),
        )
    }

    @Test
    fun relayDedupFingerprintAndMetadataExtractors() {
        val r1 = PreAccelRelayRecord(
            id = "r1",
            name = "CN-East-1",
            server = " 198.51.100.10 ",
            port = 443,
            protocol = "HY2",
            password = "demo-password-1",
        )
        val r2 = PreAccelRelayRecord(
            id = "r2",
            name = "CN-East-Renamed",
            server = "198.51.100.10",
            port = 443,
            protocol = "hysteria2",
            password = "demo-password-2",
        )
        assertEquals(
            NodeFingerprint.relayDedupFingerprint(r1),
            NodeFingerprint.relayDedupFingerprint(r2),
        )
        assertEquals("hysteria2|198.51.100.10|443", NodeFingerprint.relayDedupKeyString(r1))

        assertEquals("JP", NodeFingerprint.detectRegionCode("🇯🇵 东京 0.5x"))
        assertEquals("SG", NodeFingerprint.detectRegionCode("新加坡狮城 2x"))
        assertEquals(0.5, NodeFingerprint.extractMultiplier("🇯🇵 东京 0.5x"), 1e-6)
        assertEquals(2.0, NodeFingerprint.extractMultiplier("HK 2倍"), 1e-6)
    }
}
