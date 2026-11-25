package io.github.jurybu.catcloud.engine

import io.github.jurybu.catcloud.data.ProxyNodeRecord
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.ConnectionPool
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URLEncoder
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

data class ThroughputResult(
    val nodeId: String,
    val latencyMs: Int?,
    val downMbps: Double?,
    val upMbps: Double?,
    val error: String? = null,
)

/**
 * Dual-mode Android speed tester aligned with Stage 18 Section 3.6:
 * 1. Default lightweight concurrent ping (`concurrency <= 6`, `timeout = 3500ms`).
 * 2. Optional serial multi-node throughput test (`concurrency = 1`, `<= 2 MiB` down / `<= 1 MiB` up,
 *    `512 KiB` slow-link early stop, pauses dual-origin watchdog while running, deterministic `Call.cancel()` on stop/leave).
 */
class SpeedTester(
    private val httpClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(3500, TimeUnit.MILLISECONDS)
        .readTimeout(10_000, TimeUnit.MILLISECONDS)
        .writeTimeout(10_000, TimeUnit.MILLISECONDS)
        .build(),
) {

    private val activeCall = AtomicReference<Call?>(null)
    private val cancelled = AtomicBoolean(false)

    fun cancelActive() {
        cancelled.set(true)
        activeCall.getAndSet(null)?.cancel()
    }

    /**
     * Lightweight latency test across nodes (max concurrency = 6, timeout = 3500ms).
     * Uses Mihomo local controller `/proxies/<name>/delay` when VPN is running, or falls back to
     * direct TCP connect RTT when disconnected.
     */
    suspend fun testLatencies(
        nodes: List<ProxyNodeRecord>,
        restPort: Int,
        restSecret: String,
        onNodeDone: (nodeId: String, latencyMs: Int?) -> Unit,
    ) = withContext(Dispatchers.IO) {
        cancelled.set(false)
        val sem = Semaphore(MAX_PING_CONCURRENCY)
        coroutineScope {
            nodes.map { node ->
                async {
                    if (cancelled.get()) return@async
                    sem.withPermit {
                        if (cancelled.get()) return@withPermit
                        val delay = if (restPort > 0 && restSecret.isNotBlank()) {
                            probeViaController(node.name, restPort, restSecret)
                                ?: probeTcpConnectRtt(node.server, node.port)
                        } else {
                            probeTcpConnectRtt(node.server, node.port)
                        }
                        onNodeDone(node.id, delay)
                    }
                }
            }.awaitAll()
        }
    }

    /**
     * Quick TCP handshake latency probe for domestic pre-acceleration relays.
     */
    suspend fun testRelayTcpLatencyMs(
        host: String,
        port: Int,
        timeoutMs: Int = PING_TIMEOUT_MS,
    ): Int? = withContext(Dispatchers.IO) {
        probeTcpConnectRtt(host, port, timeoutMs)
    }

    /**
     * Alias matching the frozen cross-module contract for serial multi-node throughput testing.
     */
    suspend fun runSerialThroughputTest(
        nodes: List<ProxyNodeRecord>,
        restPort: Int,
        restSecret: String,
        targetGroupName: String,
        usePreAccel: Boolean,
        onPauseWatchdog: suspend (paused: Boolean) -> Unit,
        onProgress: (index: Int, total: Int, node: ProxyNodeRecord) -> Unit,
        onNodeResult: (ThroughputResult) -> Unit,
        mixedPort: Int = 0,
        mixedSecret: String = "",
        restoreNodeName: String? = null,
        restorePreAccelTarget: String? = null,
    ) = testThroughputSerial(
        nodes = nodes,
        restPort = restPort,
        restSecret = restSecret,
        targetGroupName = targetGroupName,
        usePreAccel = usePreAccel,
        onPauseWatchdog = onPauseWatchdog,
        onProgress = onProgress,
        onNodeResult = onNodeResult,
        mixedPort = mixedPort,
        mixedSecret = mixedSecret,
        restoreNodeName = restoreNodeName,
        restorePreAccelTarget = restorePreAccelTarget,
    )

    /**
     * Serial multi-node real download/upload throughput test routed strictly through the Mihomo
     * loopback `mixed-port` HTTP proxy (never falsely measuring direct ISP speed):
     * - Strictly serial (`concurrency = 1`)
     * - Per-node hard cap: `2 MiB` download, `1 MiB` upload
     * - Early stop at `512 KiB` when slow (`> 3.5s`), chunked upload (`contentLength = -1L`)
     * - Invokes [onPauseWatchdog] before start, restores original node/pre-accel selection and
     *   resumes watchdog inside `finally` under [NonCancellable]
     * - Immediately cancels active OkHttp [Call] on pause/cancel while preserving completed results
     */
    suspend fun testThroughputSerial(
        nodes: List<ProxyNodeRecord>,
        restPort: Int,
        restSecret: String,
        targetGroupName: String,
        usePreAccel: Boolean,
        onPauseWatchdog: suspend (paused: Boolean) -> Unit,
        onProgress: (index: Int, total: Int, node: ProxyNodeRecord) -> Unit,
        onNodeResult: (ThroughputResult) -> Unit,
        mixedPort: Int = 0,
        mixedSecret: String = "",
        restoreNodeName: String? = null,
        restorePreAccelTarget: String? = null,
    ) = withContext(Dispatchers.IO) {
        cancelled.set(false)
        if (mixedPort !in 1..65535) {
            val errMsg = "未启用本地回环测速代理端口（mixedPort=$mixedPort），已拒绝直连假测"
            for ((idx, node) in nodes.withIndex()) {
                if (cancelled.get()) break
                onProgress(idx, nodes.size, node)
                onNodeResult(
                    ThroughputResult(
                        nodeId = node.id,
                        latencyMs = null,
                        downMbps = null,
                        upMbps = null,
                        error = errMsg,
                    )
                )
            }
            return@withContext
        }

        val tunnelPool = ConnectionPool(2, 15, TimeUnit.SECONDS)
        val tunnelBuilder = httpClient.newBuilder()
            .connectionPool(tunnelPool)
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", mixedPort)))
        if (mixedSecret.isNotBlank()) {
            val basicCred = Credentials.basic("catcloud", mixedSecret)
            tunnelBuilder.proxyAuthenticator { _, response ->
                if (response.request.header("Proxy-Authorization") != null) {
                    null
                } else {
                    response.request.newBuilder()
                        .header("Proxy-Authorization", basicCred)
                        .build()
                }
            }
        }
        val tunnelClient = tunnelBuilder.build()

        val canUseController = restPort in 1..65535 && restSecret.isNotBlank()
        val effectiveRestoreNode = restoreNodeName?.trim()?.takeIf { it.isNotEmpty() }
            ?: if (canUseController && targetGroupName.isNotBlank()) {
                queryCurrentProxyNow(targetGroupName, restPort, restSecret)
            } else {
                null
            }
        val effectiveRestorePreAccel = restorePreAccelTarget?.trim()?.takeIf { it.isNotEmpty() }
            ?: if (canUseController && !usePreAccel) {
                queryCurrentProxyNow(ConfigCompiler.PREACCEL_SELECT_GROUP, restPort, restSecret)
            } else {
                null
            }

        onPauseWatchdog(true)
        try {
            val total = nodes.size
            for ((idx, node) in nodes.withIndex()) {
                if (cancelled.get()) break
                onProgress(idx, total, node)

                // Switch active proxy in controller before tunneling through mixed-port
                if (canUseController && targetGroupName.isNotBlank()) {
                    val switched = runCatching {
                        selectProxyViaController(targetGroupName, node.name, restPort, restSecret)
                    }.getOrDefault(false)
                    if (!switched) {
                        onNodeResult(
                            ThroughputResult(
                                nodeId = node.id,
                                latencyMs = null,
                                downMbps = null,
                                upMbps = null,
                                error = "无法在代理组「$targetGroupName」中切换到节点「${node.name}」",
                            )
                        )
                        continue
                    }
                    if (!usePreAccel) {
                        runCatching {
                            selectProxyViaController(ConfigCompiler.PREACCEL_SELECT_GROUP, "DIRECT", restPort, restSecret)
                        }
                    }
                }

                // Evict pooled Keep-Alive connections so each node opens a fresh tunnel through Mihomo
                tunnelPool.evictAll()

                val latency = if (canUseController) {
                    probeViaController(node.name, restPort, restSecret)
                } else {
                    probeTcpConnectRtt(node.server, node.port)
                }

                if (cancelled.get()) break
                var nodeError: String? = null
                val downMbps = runCatching { measureDownloadMbps(tunnelClient) }.getOrElse { err ->
                    nodeError = err.message ?: "下载测速失败"
                    null
                }
                if (cancelled.get()) break
                val upMbps = runCatching { measureUploadMbps(tunnelClient) }.getOrElse { err ->
                    if (nodeError == null) nodeError = err.message ?: "上传测速失败"
                    null
                }

                onNodeResult(
                    ThroughputResult(
                        nodeId = node.id,
                        latencyMs = latency,
                        downMbps = downMbps,
                        upMbps = upMbps,
                        error = if (downMbps == null && upMbps == null) nodeError else null,
                    )
                )
            }
        } catch (ce: CancellationException) {
            cancelActive()
            throw ce
        } finally {
            activeCall.getAndSet(null)?.cancel()
            tunnelPool.evictAll()
            withContext(NonCancellable) {
                if (canUseController) {
                    if (!effectiveRestorePreAccel.isNullOrBlank()) {
                        runCatching {
                            selectProxyViaController(
                                ConfigCompiler.PREACCEL_SELECT_GROUP,
                                effectiveRestorePreAccel,
                                restPort,
                                restSecret,
                            )
                        }
                    }
                    if (targetGroupName.isNotBlank() && !effectiveRestoreNode.isNullOrBlank()) {
                        runCatching {
                            selectProxyViaController(
                                targetGroupName,
                                effectiveRestoreNode,
                                restPort,
                                restSecret,
                            )
                        }
                    }
                }
                runCatching { onPauseWatchdog(false) }
            }
        }
    }

    private fun queryCurrentProxyNow(groupName: String, restPort: Int, restSecret: String): String? {
        val encGroup = URLEncoder.encode(groupName, "UTF-8").replace("+", "%20")
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/proxies/$encGroup")
            .header("Authorization", "Bearer $restSecret")
            .get()
            .build()
        return runCatching {
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                JSONObject(resp.body?.string().orEmpty())
                    .optString("now", "")
                    .trim()
                    .takeIf { it.isNotEmpty() }
            }
        }.getOrNull()
    }

    private fun probeViaController(proxyName: String, restPort: Int, restSecret: String): Int? {
        val encName = URLEncoder.encode(proxyName, "UTF-8").replace("+", "%20")
        val encUrl = URLEncoder.encode(LATENCY_PROBE_URL, "UTF-8")
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/proxies/$encName/delay?url=$encUrl&timeout=$PING_TIMEOUT_MS")
            .header("Authorization", "Bearer $restSecret")
            .get()
            .build()
        return runCatching {
            httpClient.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@use null
                val body = resp.body?.string().orEmpty()
                val delay = JSONObject(body).optInt("delay", -1)
                if (delay > 0) delay else null
            }
        }.getOrNull()
    }

    private fun selectProxyViaController(groupName: String, proxyName: String, restPort: Int, restSecret: String): Boolean {
        val encGroup = URLEncoder.encode(groupName, "UTF-8").replace("+", "%20")
        val payload = JSONObject().put("name", proxyName).toString()
        val req = Request.Builder()
            .url("http://127.0.0.1:$restPort/proxies/$encGroup")
            .header("Authorization", "Bearer $restSecret")
            .put(payload.toRequestBody("application/json; charset=utf-8".toMediaType()))
            .build()
        return httpClient.newCall(req).execute().use { resp -> resp.isSuccessful }
    }

    private fun probeTcpConnectRtt(host: String, port: Int, timeoutMs: Int = PING_TIMEOUT_MS): Int? {
        if (host.isBlank() || port !in 1..65535) return null
        val startNs = System.nanoTime()
        return runCatching {
            Socket().use { sock ->
                sock.connect(InetSocketAddress(host, port), timeoutMs.coerceIn(200, 30_000))
            }
            ((System.nanoTime() - startNs) / 1_000_000L).toInt().coerceAtLeast(1)
        }.getOrNull()
    }

    private fun measureDownloadMbps(client: OkHttpClient): Double? {
        val req = Request.Builder()
            .url("$DOWNLOAD_TEST_URL?bytes=$MAX_DOWNLOAD_BYTES")
            .header("Connection", "close")
            .get()
            .build()
        val call = client.newCall(req)
        activeCall.set(call)
        try {
            call.execute().use { resp ->
                if (!resp.isSuccessful) return null
                val stream = resp.body?.byteStream() ?: return null
                val buf = ByteArray(16 * 1024)
                var totalBytes = 0L
                val startNs = System.nanoTime()
                while (!cancelled.get()) {
                    val n = stream.read(buf)
                    if (n < 0) break
                    totalBytes += n
                    val elapsedMs = (System.nanoTime() - startNs) / 1_000_000L
                    if (totalBytes >= MAX_DOWNLOAD_BYTES) break
                    if (totalBytes >= EARLY_STOP_BYTES && elapsedMs >= EARLY_STOP_MS) break
                }
                val elapsedSec = ((System.nanoTime() - startNs) / 1_000_000_000.0).coerceAtLeast(0.05)
                if (totalBytes < 16 * 1024) return null
                return (totalBytes * 8.0) / (elapsedSec * 1_000_000.0)
            }
        } finally {
            activeCall.compareAndSet(call, null)
        }
    }

    private fun measureUploadMbps(client: OkHttpClient): Double? {
        var startNs = System.nanoTime()
        var sentBytes = 0L
        val body = object : RequestBody() {
            override fun contentType() = "application/octet-stream".toMediaType()
            // Chunked transfer encoding prevents ProtocolException when slow-link early stop triggers
            override fun contentLength(): Long = -1L
            override fun writeTo(sink: BufferedSink) {
                startNs = System.nanoTime()
                val chunk = ByteArray(16 * 1024)
                var remaining = MAX_UPLOAD_BYTES
                while (remaining > 0 && !cancelled.get()) {
                    val toWrite = minOf(chunk.size, remaining)
                    sink.write(chunk, 0, toWrite)
                    sink.flush()
                    sentBytes += toWrite
                    remaining -= toWrite
                    val elapsedMs = (System.nanoTime() - startNs) / 1_000_000L
                    if (sentBytes >= EARLY_STOP_BYTES && elapsedMs >= EARLY_STOP_MS) break
                }
            }
        }
        val req = Request.Builder()
            .url(UPLOAD_TEST_URL)
            .header("Connection", "close")
            .post(body)
            .build()
        val call = client.newCall(req)
        activeCall.set(call)
        try {
            call.execute().use { resp ->
                if (!resp.isSuccessful) return null
                val elapsedSec = ((System.nanoTime() - startNs) / 1_000_000_000.0).coerceAtLeast(0.05)
                if (sentBytes < 16 * 1024) return null
                return (sentBytes * 8.0) / (elapsedSec * 1_000_000.0)
            }
        } finally {
            activeCall.compareAndSet(call, null)
        }
    }

    companion object {
        const val MAX_PING_CONCURRENCY = 6
        const val PING_TIMEOUT_MS = 3500
        const val MAX_DOWNLOAD_BYTES = 2 * 1024 * 1024 // 2 MiB
        const val MAX_UPLOAD_BYTES = 1 * 1024 * 1024 // 1 MiB
        const val EARLY_STOP_BYTES = 512 * 1024 // 512 KiB slow-link early stop
        const val EARLY_STOP_MS = 3500L
        const val LATENCY_PROBE_URL = "https://cp.cloudflare.com/generate_204"
        const val DOWNLOAD_TEST_URL = "https://speed.cloudflare.com/__down"
        const val UPLOAD_TEST_URL = "https://speed.cloudflare.com/__up"
    }
}
