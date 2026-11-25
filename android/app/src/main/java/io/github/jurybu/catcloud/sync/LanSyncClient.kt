package io.github.jurybu.catcloud.sync

import io.github.jurybu.catcloud.data.ShareBundleCodec
import io.github.jurybu.catcloud.data.ShareBundlePreview
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.io.IOException
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Hardened OkHttp [Dns] rejecting any hostname that resolves to even one private, loopback,
 * link-local, metadata, NAT64, or reserved IP address (prevents DNS rebinding SSRF).
 */
class PublicOnlyDns(
    private val resolver: (String) -> List<InetAddress> = { host ->
        InetAddress.getAllByName(host).toList()
    },
) : Dns {
    override fun lookup(hostname: String): List<InetAddress> {
        val addresses = try {
            resolver(hostname)
        } catch (uhe: UnknownHostException) {
            throw uhe
        } catch (t: Throwable) {
            throw UnknownHostException("DNS lookup failed for $hostname: ${t.message}").apply { initCause(t) }
        }
        if (addresses.isEmpty()) {
            throw UnknownHostException("Empty DNS response for $hostname")
        }
        for (addr in addresses) {
            if (SyncCrypto.isSpecialOrPrivateIp(addr)) {
                throw IOException("Blocked non-public relay IP: ${addr.hostAddress} ($hostname)")
            }
        }
        return addresses
    }
}

data class SyncPullResult(
    val zipBytes: ByteArray,
    val zipFpHex16: String,
    val preview: ShareBundlePreview,
    val sourceBaseUrl: String,
)

/**
 * Multi-NIC concurrent-race (`1500ms`) LAN/Relay sync client implementing Stage 18 Section 2.3:
 * - QR direct pull (`GET /sync/v1/bundle`)
 * - QR reverse push (`POST /sync/v1/bundle`, hard cap `<= 17 MiB`)
 * - 6-digit PIN `ECDH_P256` handshake (`GET /sync/v1/info` + `POST /sync/v1/pin-exchange`)
 * - Public zero-knowledge HTTPS relay download (`role=relay_url` + SSRF guard)
 * - Offline `.ccsync` + `file_key` decryption
 */
class LanSyncClient(
    private val raceClient: OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(1500, TimeUnit.MILLISECONDS)
        .readTimeout(12_000, TimeUnit.MILLISECONDS)
        .writeTimeout(12_000, TimeUnit.MILLISECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build(),
    private val relayClient: OkHttpClient = buildDefaultRelayClient(),
) {

    suspend fun pullBySyncUri(parsed: ParsedSyncUri): SyncPullResult = withContext(Dispatchers.IO) {
        when (parsed.role) {
            SyncRole.PULL -> {
                val baseUrls = buildCandidateBaseUrls(parsed.customEndpoint, parsed.hosts, parsed.port)
                require(baseUrls.isNotEmpty()) { "同步二维码未提供可用的局域网或自定义地址" }
                val winnerBase = raceWinnerBaseUrlByInfo(
                    baseUrls = baseUrls,
                    expectedSid = parsed.sid,
                    expectedRole = SyncRole.PULL.wireValue,
                )
                val auth = SyncCrypto.computeAuthMac(parsed.keyBytes, "GET", "/sync/v1/bundle", parsed.sid)
                val req = Request.Builder()
                    .url("$winnerBase/sync/v1/bundle")
                    .header("X-CatCloud-Sid", parsed.sid)
                    .header("X-CatCloud-Auth", auth)
                    .get()
                    .build()
                val envelope = executeBounded(raceClient, req)
                val zipBytes = SyncCrypto.openWithRawKey(envelope, parsed.keyBytes, expectedSid = parsed.sid)
                verifyAndBuildPullResult(zipBytes, parsed.fpHex, winnerBase)
            }
            SyncRole.RELAY_URL -> {
                val url = parsed.relayUrl ?: throw IllegalArgumentException("缺少公网中转 URL")
                val (finalUrl, envelope) = executeRelayGetWithRedirects(url)
                val zipBytes = SyncCrypto.openWithRawKey(envelope, parsed.keyBytes, expectedSid = "")
                verifyAndBuildPullResult(zipBytes, parsed.fpHex, finalUrl)
            }
            else -> throw IllegalArgumentException("当前 URI 角色 `${parsed.role.wireValue}` 不支持拉取")
        }
    }

    suspend fun pushBySyncUri(parsed: ParsedSyncUri, zipBytes: ByteArray): String = withContext(Dispatchers.IO) {
        require(parsed.role == SyncRole.PUSH) { "仅支持 role=push 二维码反向推送" }
        val envelope = SyncCrypto.sealWithRawKey(zipBytes, parsed.keyBytes, sid = parsed.sid)
        require(envelope.size <= MAX_TRANSFER_BYTES) {
            "同步密文超过 17 MiB 传输上限 (${envelope.size} bytes)"
        }
        val baseUrls = buildCandidateBaseUrls(parsed.customEndpoint, parsed.hosts, parsed.port)
        require(baseUrls.isNotEmpty()) { "反推二维码未提供可用的接收端地址" }
        // First race read-only GET /sync/v1/info to elect a single winner, preventing duplicate POST delivery
        val winnerBase = raceWinnerBaseUrlByInfo(
            baseUrls = baseUrls,
            expectedSid = parsed.sid,
            expectedRole = SyncRole.PUSH.wireValue,
        )
        val auth = SyncCrypto.computeAuthMac(parsed.keyBytes, "POST", "/sync/v1/bundle", parsed.sid)
        val req = Request.Builder()
            .url("$winnerBase/sync/v1/bundle")
            .header("X-CatCloud-Sid", parsed.sid)
            .header("X-CatCloud-Auth", auth)
            .post(envelope.toRequestBody(OCTET_MEDIA_TYPE))
            .build()
        executeBounded(raceClient, req)
        winnerBase
    }

    suspend fun pullWithPin(hostOrUrl: String, port: Int, pin: String): SyncPullResult = withContext(Dispatchers.IO) {
        val cleanPin = pin.trim()
        require(cleanPin.length >= 6) { "请输入完整的 6 位一次性配对码" }
        val base = normalizeSingleBaseUrl(hostOrUrl, port)
        val infoObj = fetchSyncInfo(base)
        val sid = infoObj.getString("sid")
        val role = infoObj.optString("role", "pull")
        require(role.equals("pull", ignoreCase = true)) { "对端当前会话角色不是发送端 (role=$role)" }

        val challengeB64 = infoObj.getString("challenge_b64")
        val serverPubB64 = infoObj.getString("server_pub_p256_b64")
        val challengeBytes = Base64.getDecoder().decode(challengeB64)
        val serverPubKey = SyncCrypto.decodeP256PublicKeySec1(Base64.getDecoder().decode(serverPubB64))

        val clientKp = SyncCrypto.generateEcdhP256KeyPair()
        val clientPubB64 = Base64.getEncoder().encodeToString(SyncCrypto.encodeP256PublicKeySec1(clientKp.public))
        val proof = SyncCrypto.computePinProof(cleanPin, sid, challengeB64, serverPubB64, clientPubB64)

        val bodyJson = JSONObject().apply {
            put("sid", sid)
            put("client_pub_p256_b64", clientPubB64)
            put("proof", proof)
        }.toString()

        val req = Request.Builder()
            .url("$base/sync/v1/pin-exchange")
            .post(bodyJson.toRequestBody(JSON_MEDIA_TYPE))
            .build()
        val envelope = executeBounded(raceClient, req)

        val shared = SyncCrypto.computeEcdhSharedSecret(clientKp.private, serverPubKey)
        val kEphem = SyncCrypto.derivePinSessionKey(challengeBytes, shared, sid)
        val zipBytes = SyncCrypto.openWithRawKey(envelope, kEphem, expectedSid = sid)
        verifyAndBuildPullResult(zipBytes, expectedFp = null, sourceUrl = base)
    }

    suspend fun pushWithPin(hostOrUrl: String, port: Int, pin: String, zipBytes: ByteArray): String =
        withContext(Dispatchers.IO) {
            val cleanPin = pin.trim()
            require(cleanPin.length >= 6) { "请输入完整的 6 位一次性配对码" }
            val base = normalizeSingleBaseUrl(hostOrUrl, port)
            val infoObj = fetchSyncInfo(base)
            val sid = infoObj.getString("sid")
            val role = infoObj.optString("role", "push")
            require(role.equals("push", ignoreCase = true)) { "对端当前会话角色不是接收端 (role=$role)" }

            val challengeB64 = infoObj.getString("challenge_b64")
            val serverPubB64 = infoObj.getString("server_pub_p256_b64")
            val challengeBytes = Base64.getDecoder().decode(challengeB64)
            val serverPubKey = SyncCrypto.decodeP256PublicKeySec1(Base64.getDecoder().decode(serverPubB64))

            val clientKp = SyncCrypto.generateEcdhP256KeyPair()
            val clientPubB64 = Base64.getEncoder().encodeToString(SyncCrypto.encodeP256PublicKeySec1(clientKp.public))
            val proof = SyncCrypto.computePinProof(cleanPin, sid, challengeB64, serverPubB64, clientPubB64)

            val exchBody = JSONObject().apply {
                put("sid", sid)
                put("client_pub_p256_b64", clientPubB64)
                put("proof", proof)
            }.toString()
            val exchRespBytes = executeBounded(
                raceClient,
                Request.Builder()
                    .url("$base/sync/v1/pin-exchange")
                    .post(exchBody.toRequestBody(JSON_MEDIA_TYPE))
                    .build(),
            )
            val exchResp = JSONObject(exchRespBytes.toString(Charsets.UTF_8))
            require(exchResp.optBoolean("ok", false)) { "对端配对码校验未通过" }
            val sessionToken = exchResp.optString("session_token", "").trim()

            val shared = SyncCrypto.computeEcdhSharedSecret(clientKp.private, serverPubKey)
            val kEphem = SyncCrypto.derivePinSessionKey(challengeBytes, shared, sid)
            val envelope = SyncCrypto.sealWithRawKey(zipBytes, kEphem, sid = sid)
            require(envelope.size <= MAX_TRANSFER_BYTES) { "加密载荷超过 17 MiB 传输上限" }

            val auth = SyncCrypto.computeAuthMac(kEphem, "POST", "/sync/v1/bundle", sid)
            val pushReqBuilder = Request.Builder()
                .url("$base/sync/v1/bundle")
                .header("X-CatCloud-Sid", sid)
                .header("X-CatCloud-Auth", auth)
                .post(envelope.toRequestBody(OCTET_MEDIA_TYPE))
            if (sessionToken.isNotEmpty()) {
                pushReqBuilder.header("X-CatCloud-Session-Token", sessionToken)
            }
            executeBounded(raceClient, pushReqBuilder.build())
            base
        }

    fun decryptOfflineCcsyncFile(
        ccsyncBytes: ByteArray,
        fileKeyUri: ParsedSyncUri? = null,
        password: String? = null,
    ): SyncPullResult {
        val zipBytes = when {
            fileKeyUri != null -> {
                require(fileKeyUri.role == SyncRole.FILE_KEY) { "需要 role=file_key 的密钥二维码" }
                SyncCrypto.openWithRawKey(ccsyncBytes, fileKeyUri.keyBytes, expectedSid = "")
            }
            !password.isNullOrEmpty() -> {
                SyncCrypto.openWithPassword(ccsyncBytes, password, expectedSid = "")
            }
            else -> throw IllegalArgumentException("解密离线 .ccsync 文件需要密钥二维码或口令")
        }
        return verifyAndBuildPullResult(zipBytes, fileKeyUri?.fpHex, "offline:.ccsync")
    }

    private fun fetchSyncInfo(base: String): JSONObject {
        val req = Request.Builder().url("$base/sync/v1/info").get().build()
        val body = executeBounded(raceClient, req)
        return JSONObject(body.toString(Charsets.UTF_8))
    }

    private fun verifyAndBuildPullResult(
        zipBytes: ByteArray,
        expectedFp: String?,
        sourceUrl: String,
    ): SyncPullResult {
        val actualFp = SyncCrypto.bundleFingerprintHex16(zipBytes)
        if (!expectedFp.isNullOrBlank() && !actualFp.equals(expectedFp, ignoreCase = true)) {
            throw SecurityException("同步包完整性指纹校验失败 (expected=$expectedFp, actual=$actualFp)")
        }
        val preview = ShareBundleCodec.previewShareBundleZip(zipBytes)
        return SyncPullResult(
            zipBytes = zipBytes,
            zipFpHex16 = actualFp,
            preview = preview,
            sourceBaseUrl = sourceUrl,
        )
    }

    private fun buildCandidateBaseUrls(
        customEndpoint: String?,
        hosts: List<String>,
        port: Int?,
    ): List<String> {
        val out = LinkedHashSet<String>()
        if (!customEndpoint.isNullOrBlank()) {
            val clean = customEndpoint.trim().trimEnd('/')
            SyncCrypto.validateLanOrHttpsEndpoint(clean)
            out.add(clean)
        }
        if (port != null && port in 1..65535) {
            for (h in hosts) {
                val hostTrim = h.trim()
                if (hostTrim.isEmpty()) continue
                val formatted = if (hostTrim.contains(':') && !hostTrim.startsWith("[")) {
                    "http://[$hostTrim]:$port"
                } else {
                    "http://$hostTrim:$port"
                }
                if (runCatching { SyncCrypto.validateLanOrHttpsEndpoint(formatted) }.isSuccess) {
                    out.add(formatted)
                }
            }
        }
        return out.toList()
    }

    private fun normalizeSingleBaseUrl(hostOrUrl: String, port: Int): String {
        val trimmed = hostOrUrl.trim().trimEnd('/')
        val candidate = if (trimmed.startsWith("http://", true) || trimmed.startsWith("https://", true)) {
            trimmed
        } else {
            val h = if (trimmed.contains(':') && !trimmed.startsWith("[")) "[$trimmed]" else trimmed
            "http://$h:$port"
        }
        SyncCrypto.validateLanOrHttpsEndpoint(candidate)
        return candidate
    }

    /**
     * Execute a public HTTPS relay GET with automatic redirects strictly disabled.
     * Manually follows at most [MAX_RELAY_REDIRECTS] (3) 301/302/303/307/308 redirects,
     * resolving each hop via [URI.resolve] and re-validating via [SyncCrypto.validatePublicHttpsUrl].
     */
    internal fun executeRelayGetWithRedirects(initialUrl: String): Pair<String, ByteArray> {
        val strictClient = relayClient.newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
        var currentUrl = initialUrl.trim()
        var hops = 0
        while (true) {
            SyncCrypto.validatePublicHttpsUrl(currentUrl)
            val req = Request.Builder().url(currentUrl).get().build()
            strictClient.newCall(req).execute().use { resp ->
                if (resp.code in REDIRECT_STATUS_CODES) {
                    if (hops >= MAX_RELAY_REDIRECTS) {
                        throw IOException("公网中转重定向次数超过上限 ($MAX_RELAY_REDIRECTS)")
                    }
                    val location = resp.header("Location")?.trim()
                        ?.takeIf { it.isNotEmpty() }
                        ?: throw IOException("HTTP ${resp.code} 缺少 Location 重定向头")
                    val resolved = runCatching { URI(currentUrl).resolve(location).toString() }.getOrElse {
                        throw SecurityException("无效的重定向目标地址: $location")
                    }
                    SyncCrypto.validatePublicHttpsUrl(resolved)
                    currentUrl = resolved
                    hops++
                } else {
                    if (!resp.isSuccessful) {
                        throw IOException("HTTP ${resp.code}: ${resp.message}")
                    }
                    return currentUrl to readResponseBodyBounded(resp)
                }
            }
        }
    }

    /**
     * Concurrently probe read-only `GET /sync/v1/info` across all candidate NICs/endpoints,
     * verify `sid` (and optional `role`) match, and elect a single winning `baseUrl` before
     * executing any stateful GET/POST `/sync/v1/bundle`.
     */
    private suspend fun raceWinnerBaseUrlByInfo(
        baseUrls: List<String>,
        expectedSid: String,
        expectedRole: String? = null,
    ): String = coroutineScope {
        val activeCalls = ArrayList<Call>(baseUrls.size)
        val channel = Channel<Result<String>>(baseUrls.size)

        for (base in baseUrls) {
            val req = Request.Builder().url("$base/sync/v1/info").get().build()
            val call = raceClient.newCall(req)
            synchronized(activeCalls) { activeCalls.add(call) }
            launch(Dispatchers.IO) {
                val res = runCatching {
                    val body = executeCallBounded(call)
                    val obj = JSONObject(body.toString(Charsets.UTF_8))
                    val actualSid = obj.optString("sid", "").trim()
                    if (expectedSid.isNotEmpty() && actualSid != expectedSid) {
                        throw SecurityException("对端同步会话 sid 不匹配 (expected=$expectedSid, got=$actualSid)")
                    }
                    if (!expectedRole.isNullOrBlank()) {
                        val actualRole = obj.optString("role", "").trim()
                        if (actualRole.isNotEmpty() && !actualRole.equals(expectedRole, ignoreCase = true)) {
                            throw SecurityException("对端同步角色不匹配 (expected=$expectedRole, got=$actualRole)")
                        }
                    }
                    base
                }
                channel.trySend(res)
            }
        }

        var lastError: Throwable? = null
        var winner: String? = null
        for (i in baseUrls.indices) {
            val res = channel.receive()
            if (res.isSuccess) {
                winner = res.getOrThrow()
                break
            } else {
                lastError = res.exceptionOrNull()
            }
        }

        // Deterministically cancel any remaining in-flight sibling probe calls
        synchronized(activeCalls) {
            for (c in activeCalls) {
                if (!c.isCanceled()) c.cancel()
            }
        }
        coroutineContext.cancelChildren()

        winner ?: throw IOException(
            "局域网多地址 /sync/v1/info 探测全部失败（共 ${baseUrls.size} 个候选）：${lastError?.message ?: "超时"}",
            lastError,
        )
    }

    private fun executeBounded(client: OkHttpClient, request: Request): ByteArray =
        executeCallBounded(client.newCall(request))

    private fun executeCallBounded(call: Call): ByteArray {
        call.execute().use { resp ->
            if (!resp.isSuccessful) {
                throw IOException("HTTP ${resp.code}: ${resp.message}")
            }
            return readResponseBodyBounded(resp)
        }
    }

    private fun readResponseBodyBounded(resp: Response): ByteArray {
        val body = resp.body ?: throw IOException("空响应体")
        val source = body.source()
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        source.inputStream().use { ins ->
            while (true) {
                val n = ins.read(buf)
                if (n < 0) break
                total += n
                if (total > MAX_TRANSFER_BYTES) {
                    throw SecurityException("响应体超过 17 MiB 安全上限")
                }
                out.write(buf, 0, n)
            }
        }
        return out.toByteArray()
    }

    companion object {
        const val MAX_TRANSFER_BYTES = 17 * 1024 * 1024
        const val MAX_RELAY_REDIRECTS = 3
        private val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
        private val OCTET_MEDIA_TYPE = "application/octet-stream".toMediaType()

        fun buildDefaultRelayClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(6000, TimeUnit.MILLISECONDS)
            .readTimeout(20_000, TimeUnit.MILLISECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
            .dns(PublicOnlyDns())
            .build()
    }
}
