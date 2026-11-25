package io.github.jurybu.catcloud

import io.github.jurybu.catcloud.data.LogRingStore
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import io.github.jurybu.catcloud.engine.SpeedTester
import io.github.jurybu.catcloud.engine.ThroughputResult
import io.github.jurybu.catcloud.sync.LanSyncClient
import io.github.jurybu.catcloud.sync.ParsedSyncUri
import io.github.jurybu.catcloud.sync.PublicOnlyDns
import io.github.jurybu.catcloud.sync.SyncRole
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class LanSyncClientSecurityTest {

    @Test
    fun publicOnlyDnsAllowsPublicIpsAndBlocksMixedRebindingOrSpecialIps() {
        val publicDns = PublicOnlyDns {
            listOf(InetAddress.getByName("1.1.1.1"), InetAddress.getByName("8.8.8.8"))
        }
        assertEquals(2, publicDns.lookup("relay.example.org").size)

        val blockedCases = listOf(
            listOf(InetAddress.getByName("1.1.1.1"), InetAddress.getByName("127.0.0.1")),
            listOf(InetAddress.getByName("1.1.1.1"), InetAddress.getByName("169.254.169.254")),
            listOf(InetAddress.getByName("192.168.1.1")),
            listOf(InetAddress.getByName("64:ff9b::1.1.1.1")),
            listOf(InetAddress.getByName("2001:db8::1")),
            listOf(InetAddress.getByName("::127.0.0.1")),
            listOf(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 0, 1))),
        )
        for (addrs in blockedCases) {
            val dns = PublicOnlyDns { addrs }
            try {
                dns.lookup("rebind.example.org")
                fail("PublicOnlyDns must block non-public IP set: $addrs")
            } catch (ioe: IOException) {
                assertTrue(ioe.message.orEmpty().contains("Blocked non-public relay IP"))
            }
        }
    }

    @Test
    fun relayManualRedirectGuardBlocksDowngradeSsrfExcessHopsAndAllowsValidPublicHops() {
        // 1. Redirect downgrade to http:// must be blocked
        val downgradeClient = LanSyncClient(
            relayClient = mockRedirectClient(
                mapOf(
                    "https://relay.example.org/start" to MockResp(302, location = "http://relay.example.org/plain"),
                )
            )
        )
        assertThrows<SecurityException>("HTTP downgrade redirect must be blocked") {
            downgradeClient.executeRelayGetWithRedirects("https://relay.example.org/start")
        }

        // 2. Redirect to cloud metadata / loopback / protocol-relative private IP must be blocked
        for (evilLocation in listOf(
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/internal.ccsync",
            "//192.168.1.10/ssrf.ccsync",
            "https://[64:ff9b::1.1.1.1]/nat64.ccsync",
        )) {
            val ssrfClient = LanSyncClient(
                relayClient = mockRedirectClient(
                    mapOf("https://relay.example.org/start" to MockResp(302, location = evilLocation))
                )
            )
            assertThrows<SecurityException>("SSRF redirect to $evilLocation must be blocked") {
                ssrfClient.executeRelayGetWithRedirects("https://relay.example.org/start")
            }
        }

        // 3. Exceeding 3 redirect hops must be rejected with IOException
        val tooManyHopsClient = LanSyncClient(
            relayClient = mockRedirectClient(
                mapOf(
                    "https://relay.example.org/h0" to MockResp(302, location = "https://relay.example.org/h1"),
                    "https://relay.example.org/h1" to MockResp(302, location = "https://relay.example.org/h2"),
                    "https://relay.example.org/h2" to MockResp(302, location = "https://relay.example.org/h3"),
                    "https://relay.example.org/h3" to MockResp(302, location = "https://relay.example.org/h4"),
                    "https://relay.example.org/h4" to MockResp(200, body = "ok".toByteArray()),
                )
            )
        )
        assertThrows<IOException>("More than 3 redirects must be rejected") {
            tooManyHopsClient.executeRelayGetWithRedirects("https://relay.example.org/h0")
        }

        // 4. Valid 2-hop public HTTPS redirect (including relative Location) succeeds
        val expectedPayload = "encrypted-envelope-demo".toByteArray(Charsets.UTF_8)
        val validClient = LanSyncClient(
            relayClient = mockRedirectClient(
                mapOf(
                    "https://relay.example.org/a/entry" to MockResp(302, location = "/cdn/hop2"),
                    "https://relay.example.org/cdn/hop2" to MockResp(307, location = "https://cdn.example.net/final.ccsync"),
                    "https://cdn.example.net/final.ccsync" to MockResp(200, body = expectedPayload),
                )
            )
        )
        val (finalUrl, bytes) = validClient.executeRelayGetWithRedirects("https://relay.example.org/a/entry")
        assertEquals("https://cdn.example.net/final.ccsync", finalUrl)
        assertArrayEquals(expectedPayload, bytes)
    }

    @Test
    fun pushBySyncUriRacesReadOnlyInfoAndPostsBundleExactlyOnce() = runBlocking {
        val sid = "0123456789abcdef"
        val key = ByteArray(32) { (it + 3).toByte() }
        val postCount = AtomicInteger(0)
        val infoCount = AtomicInteger(0)

        val serverFast = startMockLanPushServer(sid = sid, delayInfoMs = 0L, infoCount = infoCount, postCount = postCount)
        val serverSlow = startMockLanPushServer(sid = sid, delayInfoMs = 180L, infoCount = infoCount, postCount = postCount)
        try {
            val client = LanSyncClient()
            val parsed = ParsedSyncUri(
                role = SyncRole.PUSH,
                keyBytes = key,
                sid = sid,
                hosts = listOf("127.0.0.1"),
                port = serverSlow.port,
                customEndpoint = "http://127.0.0.1:${serverFast.port}",
            )
            val winner = client.pushBySyncUri(parsed, "demo-zip-payload".toByteArray())
            assertTrue(winner.startsWith("http://127.0.0.1:"))
            assertEquals("POST /sync/v1/bundle must be delivered exactly once", 1, postCount.get())
            assertTrue(infoCount.get() >= 1)
        } finally {
            serverFast.close()
            serverSlow.close()
        }
    }

    @Test
    fun pushBySyncUriSkipsMismatchedSidEndpointDuringInfoRace() = runBlocking {
        val expectedSid = "0123456789abcdef"
        val key = ByteArray(32) { (it + 9).toByte() }
        val wrongPostCount = AtomicInteger(0)
        val rightPostCount = AtomicInteger(0)
        val dummyInfo = AtomicInteger(0)

        val wrongServer = startMockLanPushServer(sid = "fedcba9876543210", delayInfoMs = 0L, infoCount = dummyInfo, postCount = wrongPostCount)
        val rightServer = startMockLanPushServer(sid = expectedSid, delayInfoMs = 40L, infoCount = dummyInfo, postCount = rightPostCount)
        try {
            val client = LanSyncClient()
            val parsed = ParsedSyncUri(
                role = SyncRole.PUSH,
                keyBytes = key,
                sid = expectedSid,
                hosts = listOf("127.0.0.1"),
                port = rightServer.port,
                customEndpoint = "http://127.0.0.1:${wrongServer.port}",
            )
            val winner = client.pushBySyncUri(parsed, "demo-zip-payload".toByteArray())
            assertEquals("http://127.0.0.1:${rightServer.port}", winner)
            assertEquals(0, wrongPostCount.get())
            assertEquals(1, rightPostCount.get())
        } finally {
            wrongServer.close()
            rightServer.close()
        }
    }

    @Test
    fun logRingStoreMergesUiAndVpnProcessLogFiles() {
        val tmpDir = Files.createTempDirectory("catcloud-logs-test").toFile()
        try {
            val uiLog = LogRingStore(tmpDir, filePrefix = "catcloud-ui")
            val vpnLog = LogRingStore(tmpDir, filePrefix = "catcloud-vpn")
            uiLog.append("UI", "ui-started secret=supersecret123")
            vpnLog.append("VPN", "vpn-started Bearer abcdef12345678")

            val merged = LogRingStore.readMergedRecentLines(tmpDir, maxLines = 50)
            assertEquals(2, merged.size)
            assertTrue(merged.any { it.contains("[UI] ui-started secret=<REDACTED>") })
            assertTrue(merged.any { it.contains("[VPN] vpn-started Bearer <REDACTED>") })
        } finally {
            tmpDir.deleteRecursively()
        }
    }

    @Test
    fun speedTesterRejectsDirectFallbackWhenMixedPortUnavailable() = runBlocking {
        val tester = SpeedTester()
        val node = ProxyNodeRecord(
            id = "n1",
            name = "DemoNode",
            protocol = "trojan",
            server = "203.0.113.50",
            port = 443,
            rawConfigJson = "{}",
        )
        val results = ArrayList<ThroughputResult>()
        tester.runSerialThroughputTest(
            nodes = listOf(node),
            restPort = 0,
            restSecret = "",
            targetGroupName = "单节点直选",
            usePreAccel = false,
            onPauseWatchdog = {},
            onProgress = { _, _, _ -> },
            onNodeResult = { results.add(it) },
            mixedPort = 0,
            mixedSecret = "",
        )
        assertEquals(1, results.size)
        assertNull(results[0].downMbps)
        assertNull(results[0].upMbps)
        assertNotNull(results[0].error)
        assertTrue(results[0].error!!.contains("mixedPort=0"))
    }

    private data class MockResp(
        val code: Int,
        val location: String? = null,
        val body: ByteArray = ByteArray(0),
    )

    private fun mockRedirectClient(table: Map<String, MockResp>): OkHttpClient =
        OkHttpClient.Builder()
            .followRedirects(false)
            .followSslRedirects(false)
            .addInterceptor { chain ->
                val url = chain.request().url.toString()
                val m = table[url] ?: MockResp(404)
                val builder = Response.Builder()
                    .request(chain.request())
                    .protocol(Protocol.HTTP_1_1)
                    .code(m.code)
                    .message("Mock")
                    .body(m.body.toResponseBody("application/octet-stream".toMediaType()))
                if (m.location != null) {
                    builder.header("Location", m.location)
                }
                builder.build()
            }
            .build()

    private class TinyLanPushServer(
        private val socket: ServerSocket,
        private val exec: ExecutorService,
        private val running: AtomicBoolean,
    ) : AutoCloseable {
        val port: Int get() = socket.localPort
        override fun close() {
            running.set(false)
            runCatching { socket.close() }
            exec.shutdownNow()
        }
    }

    private fun startMockLanPushServer(
        sid: String,
        delayInfoMs: Long,
        infoCount: AtomicInteger,
        postCount: AtomicInteger,
    ): TinyLanPushServer {
        val ss = ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"))
        val exec = Executors.newCachedThreadPool()
        val running = AtomicBoolean(true)
        exec.submit {
            while (running.get()) {
                val client = try {
                    ss.accept()
                } catch (_: IOException) {
                    break
                }
                exec.submit {
                    client.use { sock ->
                        sock.soTimeout = 5000
                        val input = BufferedInputStream(sock.getInputStream())
                        val headerBuf = StringBuilder()
                        var prev = -1
                        var cur: Int
                        while (true) {
                            cur = input.read()
                            if (cur == -1) break
                            headerBuf.append(cur.toChar())
                            if (headerBuf.length >= 4 && headerBuf.endsWith("\r\n\r\n")) break
                            prev = cur
                        }
                        val headerLines = headerBuf.toString().split("\r\n")
                        val requestLine = headerLines.firstOrNull().orEmpty()
                        val contentLength = headerLines
                            .firstOrNull { it.lowercase().startsWith("content-length:") }
                            ?.substringAfter(':')
                            ?.trim()
                            ?.toIntOrNull()
                            ?: 0
                        if (contentLength > 0) {
                            var remaining = contentLength
                            val skipBuf = ByteArray(4096)
                            while (remaining > 0) {
                                val r = input.read(skipBuf, 0, minOf(skipBuf.size, remaining))
                                if (r <= 0) break
                                remaining -= r
                            }
                        }
                        val payloadBytes = when {
                            requestLine.contains("/sync/v1/info") -> {
                                infoCount.incrementAndGet()
                                if (delayInfoMs > 0) {
                                    try {
                                        Thread.sleep(delayInfoMs)
                                    } catch (_: InterruptedException) {
                                        return@submit
                                    }
                                }
                                """{"sid":"$sid","role":"push"}""".toByteArray(Charsets.UTF_8)
                            }
                            requestLine.contains("/sync/v1/bundle") -> {
                                postCount.incrementAndGet()
                                """{"ok":true}""".toByteArray(Charsets.UTF_8)
                            }
                            else -> """{"error":"not_found"}""".toByteArray(Charsets.UTF_8)
                        }
                        val status = if (requestLine.contains("/sync/v1/")) "200 OK" else "404 Not Found"
                        val respHead = ("HTTP/1.1 $status\r\n" +
                            "Content-Type: application/json\r\n" +
                            "Content-Length: ${payloadBytes.size}\r\n" +
                            "Connection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
                        val out = sock.getOutputStream()
                        out.write(respHead)
                        out.write(payloadBytes)
                        out.flush()
                    }
                }
            }
        }
        return TinyLanPushServer(ss, exec, running)
    }

    private inline fun <reified T : Throwable> assertThrows(msg: String, block: () -> Unit) {
        try {
            block()
            fail(msg)
        } catch (t: Throwable) {
            if (t !is T) {
                fail("$msg (expected ${T::class.java.simpleName}, got ${t::class.java.simpleName}: ${t.message})")
            }
        }
    }
}
