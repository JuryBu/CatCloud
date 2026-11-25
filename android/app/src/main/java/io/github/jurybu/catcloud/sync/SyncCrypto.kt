package io.github.jurybu.catcloud.sync

import io.github.jurybu.catcloud.data.NodeFingerprint
import java.math.BigInteger
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

enum class SyncRole(val wireValue: String) {
    PULL("pull"),
    PUSH("push"),
    RELAY_URL("relay_url"),
    FILE_KEY("file_key");

    companion object {
        fun fromWire(raw: String): SyncRole? = entries.firstOrNull { it.wireValue.equals(raw.trim(), ignoreCase = true) }
    }
}

data class ParsedSyncUri(
    val role: SyncRole,
    val keyBytes: ByteArray,
    val sid: String = "",
    val hosts: List<String> = emptyList(),
    val port: Int? = null,
    val customEndpoint: String? = null,
    val relayUrl: String? = null,
    val fpHex: String? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ParsedSyncUri) return false
        return role == other.role &&
            keyBytes.contentEquals(other.keyBytes) &&
            sid == other.sid &&
            hosts == other.hosts &&
            port == other.port &&
            customEndpoint == other.customEndpoint &&
            relayUrl == other.relayUrl &&
            fpHex == other.fpHex
    }

    override fun hashCode(): Int {
        var r = role.hashCode()
        r = 31 * r + keyBytes.contentHashCode()
        r = 31 * r + sid.hashCode()
        r = 31 * r + hosts.hashCode()
        r = 31 * r + (port ?: 0)
        r = 31 * r + (customEndpoint?.hashCode() ?: 0)
        r = 31 * r + (relayUrl?.hashCode() ?: 0)
        r = 31 * r + (fpHex?.hashCode() ?: 0)
        return r
    }
}

/**
 * Bit-for-bit implementation of Stage 18 Section 2.2–2.3 `catcloud-sync/v1`:
 * - Self-describing `CCSYNC01` envelope (`AES-256-GCM`, Big-Endian header, full header AAD)
 * - `PBKDF2WithHmacSHA256` (`kdf_mode = 0x02`)
 * - `ECDH secp256r1` 65B uncompressed SEC1 public key + RFC 5869 `HKDF-SHA256`
 * - `catcloud://sync/v1?...#k=...` URI codec with strict `#fragment`-only key rule & SSRF guard
 */
object SyncCrypto {

    val MAGIC: ByteArray = "CCSYNC01".toByteArray(Charsets.US_ASCII)
    const val KDF_MODE_RAW_KEY: Byte = 0x01
    const val KDF_MODE_PBKDF2: Byte = 0x02
    const val DEFAULT_PBKDF2_ITERS: Int = 100_000
    const val KEY_LEN = 32
    const val SALT_LEN = 16
    const val NONCE_LEN = 12
    const val TAG_LEN = 16
    const val MAX_SID_LEN = 64
    private const val FIXED_HEADER_LEN = 30 // 8 magic + 1 mode + 4 iters + 16 salt + 1 sid_len

    private val secureRandom = SecureRandom()

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { secureRandom.nextBytes(it) }

    fun sha256Hex(data: ByteArray): String =
        NodeFingerprint.toHexLower(MessageDigest.getInstance("SHA-256").digest(data))

    fun bundleFingerprintHex16(zipBytes: ByteArray): String = sha256Hex(zipBytes).take(16)

    // ---- CCSYNC01 Envelope ----

    fun sealWithRawKey(
        plaintext: ByteArray,
        key32: ByteArray,
        sid: String = "",
        customNonce: ByteArray? = null,
    ): ByteArray {
        require(key32.size == KEY_LEN) { "AES-256 key must be exactly 32 bytes" }
        val sidBytes = sid.toByteArray(Charsets.UTF_8)
        require(sidBytes.size <= MAX_SID_LEN) { "sid length exceeds 64 bytes" }
        val nonce = customNonce ?: randomBytes(NONCE_LEN)
        require(nonce.size == NONCE_LEN) { "GCM nonce must be 12 bytes" }

        val aad = buildHeaderAad(
            kdfMode = KDF_MODE_RAW_KEY,
            kdfIters = 0,
            salt = ByteArray(SALT_LEN),
            sidBytes = sidBytes,
        )
        return encryptEnvelope(aad, nonce, key32, plaintext)
    }

    fun sealWithPassword(
        plaintext: ByteArray,
        passwordUtf8: String,
        sid: String = "",
        iters: Int = DEFAULT_PBKDF2_ITERS,
        customSalt: ByteArray? = null,
        customNonce: ByteArray? = null,
    ): ByteArray {
        require(passwordUtf8.isNotEmpty()) { "password cannot be empty" }
        require(iters in 1_000..2_000_000) { "PBKDF2 iterations must be in 1000..2000000 (got $iters)" }
        val sidBytes = sid.toByteArray(Charsets.UTF_8)
        require(sidBytes.size <= MAX_SID_LEN) { "sid length exceeds 64 bytes" }
        val salt = customSalt ?: randomBytes(SALT_LEN)
        require(salt.size == SALT_LEN) { "PBKDF2 salt must be 16 bytes" }
        val nonce = customNonce ?: randomBytes(NONCE_LEN)
        require(nonce.size == NONCE_LEN) { "GCM nonce must be 12 bytes" }

        val derivedKey = derivePbkdf2Key(passwordUtf8, salt, iters)
        val aad = buildHeaderAad(
            kdfMode = KDF_MODE_PBKDF2,
            kdfIters = iters,
            salt = salt,
            sidBytes = sidBytes,
        )
        return encryptEnvelope(aad, nonce, derivedKey, plaintext)
    }

    fun openWithRawKey(
        envelope: ByteArray,
        key32: ByteArray,
        expectedSid: String? = null,
    ): ByteArray {
        require(key32.size == KEY_LEN) { "AES-256 key must be exactly 32 bytes" }
        val parsed = parseEnvelopeHeader(envelope)
        require(parsed.kdfMode == KDF_MODE_RAW_KEY) {
            "Unexpected CCSYNC01 kdf_mode=${parsed.kdfMode}; expected raw key mode (0x01)"
        }
        if (expectedSid != null) {
            require(parsed.sid == expectedSid) {
                "CCSYNC01 sid mismatch: expected `$expectedSid`, got `${parsed.sid}`"
            }
        }
        return decryptEnvelope(parsed, key32)
    }

    fun openWithPassword(
        envelope: ByteArray,
        passwordUtf8: String,
        expectedSid: String? = null,
    ): ByteArray {
        val parsed = parseEnvelopeHeader(envelope)
        require(parsed.kdfMode == KDF_MODE_PBKDF2) {
            "Unexpected CCSYNC01 kdf_mode=${parsed.kdfMode}; expected PBKDF2 mode (0x02)"
        }
        require(parsed.kdfIters > 0) { "Invalid PBKDF2 iteration count in envelope" }
        if (expectedSid != null) {
            require(parsed.sid == expectedSid) {
                "CCSYNC01 sid mismatch: expected `$expectedSid`, got `${parsed.sid}`"
            }
        }
        val derivedKey = derivePbkdf2Key(passwordUtf8, parsed.salt, parsed.kdfIters)
        return decryptEnvelope(parsed, derivedKey)
    }

    private data class ParsedEnvelope(
        val kdfMode: Byte,
        val kdfIters: Int,
        val salt: ByteArray,
        val sid: String,
        val aad: ByteArray,
        val nonce: ByteArray,
        val ciphertextAndTag: ByteArray,
    )

    private fun buildHeaderAad(
        kdfMode: Byte,
        kdfIters: Int,
        salt: ByteArray,
        sidBytes: ByteArray,
    ): ByteArray {
        val buf = ByteBuffer.allocate(FIXED_HEADER_LEN + sidBytes.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(MAGIC)
        buf.put(kdfMode)
        buf.putInt(kdfIters)
        buf.put(salt)
        buf.put(sidBytes.size.toByte())
        buf.put(sidBytes)
        return buf.array()
    }

    private fun parseEnvelopeHeader(envelope: ByteArray): ParsedEnvelope {
        require(envelope.size >= FIXED_HEADER_LEN + NONCE_LEN + TAG_LEN) {
            "CCSYNC01 envelope too short (${envelope.size} bytes)"
        }
        for (i in MAGIC.indices) {
            require(envelope[i] == MAGIC[i]) { "Invalid CCSYNC01 magic header" }
        }
        val buf = ByteBuffer.wrap(envelope).order(ByteOrder.BIG_ENDIAN)
        val kdfMode = envelope[8]
        val kdfIters = buf.getInt(9)
        val salt = envelope.copyOfRange(13, 29)
        val sidLen = envelope[29].toInt() and 0xFF
        require(sidLen <= MAX_SID_LEN) { "Invalid CCSYNC01 sid_len=$sidLen" }
        when (kdfMode) {
            KDF_MODE_RAW_KEY -> {
                require(kdfIters == 0 && salt.all { it == 0.toByte() }) {
                    "kdf_mode=0x01 must carry zero kdf_iters and zero salt"
                }
            }
            KDF_MODE_PBKDF2 -> {
                require(kdfIters in 1_000..2_000_000) {
                    "PBKDF2 iteration count out of range: $kdfIters"
                }
            }
            else -> throw IllegalArgumentException("Unsupported CCSYNC01 kdf_mode=$kdfMode")
        }
        val aadLen = FIXED_HEADER_LEN + sidLen
        require(envelope.size >= aadLen + NONCE_LEN + TAG_LEN) {
            "Truncated CCSYNC01 envelope body"
        }
        val sid = String(envelope, FIXED_HEADER_LEN, sidLen, Charsets.UTF_8)
        val aad = envelope.copyOfRange(0, aadLen)
        val nonce = envelope.copyOfRange(aadLen, aadLen + NONCE_LEN)
        val ctAndTag = envelope.copyOfRange(aadLen + NONCE_LEN, envelope.size)
        return ParsedEnvelope(kdfMode, kdfIters, salt, sid, aad, nonce, ctAndTag)
    }

    private fun encryptEnvelope(
        aad: ByteArray,
        nonce: ByteArray,
        key32: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val ctAndTag = cipher.doFinal(plaintext)
        val out = ByteArray(aad.size + nonce.size + ctAndTag.size)
        System.arraycopy(aad, 0, out, 0, aad.size)
        System.arraycopy(nonce, 0, out, aad.size, nonce.size)
        System.arraycopy(ctAndTag, 0, out, aad.size + nonce.size, ctAndTag.size)
        return out
    }

    private fun decryptEnvelope(parsed: ParsedEnvelope, key32: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key32, "AES"), GCMParameterSpec(128, parsed.nonce))
        cipher.updateAAD(parsed.aad)
        return cipher.doFinal(parsed.ciphertextAndTag)
    }

    private fun derivePbkdf2Key(passwordUtf8: String, salt: ByteArray, iters: Int): ByteArray {
        val spec = PBEKeySpec(passwordUtf8.toCharArray(), salt, iters, KEY_LEN * 8)
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    }

    // ---- HMAC, ECDH secp256r1 (65B SEC1 uncompressed), HKDF-SHA256 ----

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun computeAuthMac(key: ByteArray, method: String, path: String, sid: String): String {
        val msg = "$sid:${method.uppercase()}:$path".toByteArray(Charsets.UTF_8)
        return NodeFingerprint.toHexLower(hmacSha256(key, msg))
    }

    fun computePinProof(
        pinUtf8: String,
        sid: String,
        challengeB64: String,
        serverPubB64: String,
        clientPubB64: String,
    ): String {
        val msg = "$sid:$challengeB64:$serverPubB64:$clientPubB64".toByteArray(Charsets.UTF_8)
        return NodeFingerprint.toHexLower(hmacSha256(pinUtf8.toByteArray(Charsets.UTF_8), msg))
    }

    fun generateEcdhP256KeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"), secureRandom)
        return kpg.generateKeyPair()
    }

    /**
     * Encode a NIST P-256 public key into standard 65-byte uncompressed SEC1 format: `0x04 || X(32B) || Y(32B)`.
     */
    fun encodeP256PublicKeySec1(pub: PublicKey): ByteArray {
        val ecPub = pub as? ECPublicKey ?: throw IllegalArgumentException("Expected ECPublicKey")
        val x = bigIntToFixedUnsignedBytes(ecPub.w.affineX, 32)
        val y = bigIntToFixedUnsignedBytes(ecPub.w.affineY, 32)
        val out = ByteArray(65)
        out[0] = 0x04
        System.arraycopy(x, 0, out, 1, 32)
        System.arraycopy(y, 0, out, 33, 32)
        return out
    }

    /**
     * Decode a 65-byte uncompressed SEC1 NIST P-256 public key into an [ECPublicKey].
     */
    fun decodeP256PublicKeySec1(sec1: ByteArray): ECPublicKey {
        require(sec1.size == 65 && sec1[0] == 0x04.toByte()) {
            "Expected 65-byte uncompressed SEC1 P-256 public key"
        }
        val x = BigInteger(1, sec1.copyOfRange(1, 33))
        val y = BigInteger(1, sec1.copyOfRange(33, 65))
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val keySpec = ECPublicKeySpec(ECPoint(x, y), params)
        return KeyFactory.getInstance("EC").generatePublic(keySpec) as ECPublicKey
    }

    fun computeEcdhSharedSecret(privateKey: PrivateKey, peerPublicKey: PublicKey): ByteArray {
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(peerPublicKey, true)
        return ka.generateSecret()
    }

    /**
     * Standard RFC 5869 HKDF-SHA256 (`Extract` + `Expand`).
     */
    fun hkdfSha256(
        salt: ByteArray,
        ikm: ByteArray,
        info: ByteArray,
        length: Int = KEY_LEN,
    ): ByteArray {
        require(length in 1..(255 * 32)) { "Invalid HKDF output length $length" }
        val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
        val prk = hmacSha256(actualSalt, ikm)
        val out = ByteArray(length)
        var offset = 0
        var prevT = ByteArray(0)
        var counter = 1
        while (offset < length) {
            val input = ByteArray(prevT.size + info.size + 1)
            System.arraycopy(prevT, 0, input, 0, prevT.size)
            System.arraycopy(info, 0, input, prevT.size, info.size)
            input[input.size - 1] = counter.toByte()
            prevT = hmacSha256(prk, input)
            val take = minOf(prevT.size, length - offset)
            System.arraycopy(prevT, 0, out, offset, take)
            offset += take
            counter++
        }
        return out
    }

    fun derivePinSessionKey(
        challengeBytes: ByteArray,
        ecdhSharedSecret: ByteArray,
        sid: String,
    ): ByteArray {
        val info = "catcloud-lan-pin-v1:$sid".toByteArray(Charsets.UTF_8)
        return hkdfSha256(salt = challengeBytes, ikm = ecdhSharedSecret, info = info, length = KEY_LEN)
    }

    // ---- Sync URI Codec + SSRF / Public-HTTPS Guard ----

    fun formatSyncUri(
        role: SyncRole,
        keyBytes: ByteArray,
        sid: String = "",
        hosts: List<String> = emptyList(),
        port: Int? = null,
        customEndpoint: String? = null,
        relayUrl: String? = null,
        fpHex: String? = null,
    ): String {
        require(keyBytes.size == KEY_LEN) { "Sync key must be 32 bytes" }
        val qParts = ArrayList<String>()
        qParts.add("role=${role.wireValue}")
        if (!customEndpoint.isNullOrBlank()) {
            qParts.add("ep=${urlEncode(customEndpoint.trim())}")
        }
        if (hosts.isNotEmpty()) {
            qParts.add("hosts=${urlEncode(hosts.joinToString(","))}")
        }
        if (port != null && port in 1..65535) {
            qParts.add("port=$port")
        }
        if (sid.isNotBlank()) {
            qParts.add("sid=${urlEncode(sid.trim())}")
        }
        if (!relayUrl.isNullOrBlank()) {
            validatePublicHttpsUrl(relayUrl.trim())
            qParts.add("url=${urlEncode(relayUrl.trim())}")
        }
        if (!fpHex.isNullOrBlank()) {
            qParts.add("fp=${urlEncode(fpHex.trim().lowercase())}")
        }
        val kB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes)
        return "catcloud://sync/v1?${qParts.joinToString("&")}#k=$kB64"
    }

    fun parseSyncUri(raw: String): ParsedSyncUri {
        val trimmed = raw.trim()
        val u = runCatching { URI(trimmed) }.getOrElse {
            throw IllegalArgumentException("无效的同步 URI: ${it.message}")
        }
        val scheme = u.scheme?.lowercase() ?: ""
        val validRoute = when (scheme) {
            "catcloud" -> u.host == "sync" && u.path == "/v1"
            "catcloud-sync" -> (u.host == "v1" && (u.path.isNullOrEmpty() || u.path == "/")) ||
                (u.host == "sync" && u.path == "/v1")
            else -> false
        }
        require(validRoute) {
            "不支持的同步 URI 路径或前缀: $scheme://${u.host}${u.path}"
        }

        val queryMap = parseKeyValues(u.rawQuery)
        // Security invariant: key MUST NEVER appear in query string
        if (queryMap.containsKey("k")) {
            throw SecurityException("拒绝解析：同步密钥 k 严禁出现在 ?query 中，必须仅位于 #fragment")
        }

        val fragMap = parseKeyValues(u.rawFragment)
        val rawK = fragMap["k"]?.trim()
            ?: throw IllegalArgumentException("同步 URI 缺少 #k= 密钥片段")
        val keyBytes = runCatching { Base64.getUrlDecoder().decode(rawK) }.getOrElse {
            throw IllegalArgumentException("同步密钥 #k= Base64URL 解码失败")
        }
        require(keyBytes.size == KEY_LEN) {
            "同步密钥长度无效 (${keyBytes.size} != $KEY_LEN)"
        }

        val roleStr = queryMap["role"] ?: throw IllegalArgumentException("同步 URI 缺少 role 参数")
        val role = SyncRole.fromWire(roleStr)
            ?: throw IllegalArgumentException("不支持的同步角色: $roleStr")

        val hosts = queryMap["hosts"]
            ?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?: emptyList()
        val port = queryMap["port"]?.toIntOrNull()?.takeIf { it in 1..65535 }
        val sid = queryMap["sid"]?.trim().orEmpty()
        val sidByteLen = sid.toByteArray(Charsets.UTF_8).size
        require(sidByteLen <= MAX_SID_LEN) {
            "同步参数 sid 长度超过 64 字节上限 ($sidByteLen)"
        }
        val ep = queryMap["ep"]?.trim()?.takeIf { it.isNotEmpty() }
        val relayUrl = queryMap["url"]?.trim()?.takeIf { it.isNotEmpty() }
        val rawFp = queryMap["fp"]
        val fpHex = if (rawFp != null) {
            val cleanFp = rawFp.trim().lowercase()
            require(cleanFp.length == 16 && cleanFp.all { it in '0'..'9' || it in 'a'..'f' }) {
                "无效的指纹参数 fp（必须为 16 位十六进制）: $cleanFp"
            }
            cleanFp
        } else {
            null
        }

        if (role == SyncRole.PULL || role == SyncRole.PUSH) {
            require(sid.isNotEmpty()) { "${role.wireValue} 模式缺少必需的 sid 参数" }
            val hasLanTarget = hosts.isNotEmpty() && port != null
            require(ep != null || hasLanTarget) {
                "${role.wireValue} 模式至少需要提供 ep 或 hosts+port 之一"
            }
        }
        if (role == SyncRole.RELAY_URL) {
            val uStr = relayUrl ?: throw IllegalArgumentException("relay_url 模式缺少 url 参数")
            validatePublicHttpsUrl(uStr)
        }
        if (ep != null) {
            validateLanOrHttpsEndpoint(ep)
        }

        return ParsedSyncUri(
            role = role,
            keyBytes = keyBytes,
            sid = sid,
            hosts = hosts,
            port = port,
            customEndpoint = ep,
            relayUrl = relayUrl,
            fpHex = fpHex,
        )
    }

    /**
     * Enforce `https://` and reject loopback, RFC1918, CGNAT, link-local / cloud metadata (`169.254.169.254`),
     * IPv6 ULA/link-local/loopback, and `.local` hostnames to prevent SSRF on `relay_url`.
     */
    fun validatePublicHttpsUrl(rawUrl: String): URI {
        val u = runCatching { URI(rawUrl.trim()) }.getOrElse {
            throw SecurityException("公网中转 URL 格式无效")
        }
        if (!u.scheme.equals("https", ignoreCase = true)) {
            throw SecurityException("公网同步地址必须使用 https://，严禁明文 http://")
        }
        if (!u.rawUserInfo.isNullOrEmpty()) {
            throw SecurityException("公网中转地址禁止内嵌 userinfo 凭据")
        }
        val host = u.host?.trim()?.removePrefix("[")?.removeSuffix("]")?.lowercase()
            ?: throw SecurityException("公网同步地址缺少主机名")
        if (isPrivateOrSpecialHost(host)) {
            throw SecurityException("公网中转地址禁止指向私网/环回/元数据地址: $host")
        }
        return u
    }

    /**
     * Allow `http://` ONLY for private LAN / loopback / CGNAT addresses; require `https://` for any public host.
     */
    fun validateLanOrHttpsEndpoint(rawUrl: String): URI {
        val u = runCatching { URI(rawUrl.trim()) }.getOrElse {
            throw SecurityException("同步端点 URL 格式无效")
        }
        if (!u.rawUserInfo.isNullOrEmpty()) {
            throw SecurityException("同步端点禁止内嵌 userinfo 凭据")
        }
        val scheme = u.scheme?.lowercase() ?: ""
        val host = u.host?.trim()?.removePrefix("[")?.removeSuffix("]")?.lowercase()
            ?: throw SecurityException("同步端点缺少主机名")
        return when (scheme) {
            "https" -> u
            "http" -> {
                if (!isPrivateLanOrLoopbackHost(host)) {
                    throw SecurityException("公网端点 `$host` 强制使用 https://，拒绝明文降级")
                }
                u
            }
            else -> throw SecurityException("不支持的端点协议: $scheme")
        }
    }

    fun isPrivateOrSpecialHost(host: String): Boolean {
        val h = host.trim().removePrefix("[").removeSuffix("]").lowercase().trimEnd('.')
        if (h.isEmpty() || h == "localhost" || h.endsWith(".localhost") || h.endsWith(".local") ||
            h.endsWith(".internal") || h.endsWith(".lan") || h.endsWith(".home.arpa") ||
            h.all { it.isDigit() } || h.startsWith("0x")
        ) {
            return true
        }
        val ip = parseLiteralIpOrNull(h) ?: return false
        return isSpecialOrPrivateIp(ip)
    }

    fun isPrivateLanOrLoopbackHost(host: String): Boolean {
        val h = host.trim().removePrefix("[").removeSuffix("]").lowercase()
        if (h == "localhost" || h.endsWith(".local") || h.endsWith(".lan")) return true
        val ip = parseLiteralIpOrNull(h) ?: return false
        if (ip is Inet4Address) {
            val b = ip.address
            val o0 = b[0].toInt() and 0xFF
            val o1 = b[1].toInt() and 0xFF
            return o0 == 127 ||
                o0 == 10 ||
                (o0 == 172 && o1 in 16..31) ||
                (o0 == 192 && o1 == 168) ||
                (o0 == 100 && o1 in 64..127)
        }
        if (ip is Inet6Address) {
            val b0 = ip.address[0].toInt() and 0xFF
            return ip.isLoopbackAddress || ip.isLinkLocalAddress || (b0 and 0xFE) == 0xFC
        }
        return false
    }

    fun isSpecialOrPrivateIp(ip: InetAddress): Boolean {
        if (ip.isAnyLocalAddress || ip.isLoopbackAddress || ip.isLinkLocalAddress ||
            ip.isSiteLocalAddress || ip.isMulticastAddress
        ) {
            return true
        }
        if (ip is Inet4Address) {
            val b = ip.address
            val o0 = b[0].toInt() and 0xFF
            val o1 = b[1].toInt() and 0xFF
            val o2 = b[2].toInt() and 0xFF
            return o0 == 0 ||
                o0 == 10 ||
                o0 == 127 ||
                (o0 == 100 && o1 in 64..127) ||
                (o0 == 169 && o1 == 254) ||
                (o0 == 172 && o1 in 16..31) ||
                // RFC 6890 IETF protocol assignments & RFC 5737 TEST-NET-1
                (o0 == 192 && o1 == 0 && (o2 == 0 || o2 == 2)) ||
                (o0 == 192 && o1 == 168) ||
                (o0 == 198 && (o1 == 18 || o1 == 19)) ||
                // RFC 5737 TEST-NET-2 & TEST-NET-3
                (o0 == 198 && o1 == 51 && o2 == 100) ||
                (o0 == 203 && o1 == 0 && o2 == 113) ||
                o0 >= 224
        }
        if (ip is Inet6Address) {
            val b = ip.address
            if (b.size != 16) return true
            val b0 = b[0].toInt() and 0xFF
            val b1 = b[1].toInt() and 0xFF
            val b2 = b[2].toInt() and 0xFF
            val b3 = b[3].toInt() and 0xFF
            val b4 = b[4].toInt() and 0xFF
            val b5 = b[5].toInt() and 0xFF
            // fc00::/7 ULA
            if ((b0 and 0xFE) == 0xFC) return true
            // 2001:db8::/32 documentation prefix (RFC 3849)
            if (b0 == 0x20 && b1 == 0x01 && b2 == 0x0D && b3 == 0xB8) return true
            // 64:ff9b::/96 well-known NAT64 (RFC 6052) and 64:ff9b:1::/48 local NAT64 (RFC 8215)
            if (b0 == 0x00 && b1 == 0x64 && b2 == 0xFF && b3 == 0x9B) {
                val isWellKnownNat64 = (4..11).all { b[it] == 0.toByte() }
                val isLocalNat64 = b4 == 0x00 && b5 == 0x01
                if (isWellKnownNat64 || isLocalNat64) return true
            }
            // ::w.x.y.z deprecated IPv4-compatible IPv6 (also encompasses :: and ::1)
            if ((0..11).all { b[it] == 0.toByte() }) return true
            // ::ffff:w.x.y.z IPv4-mapped IPv6
            if ((0..9).all { b[it] == 0.toByte() } &&
                (b[10].toInt() and 0xFF) == 0xFF &&
                (b[11].toInt() and 0xFF) == 0xFF
            ) {
                val mappedV4 = runCatching { InetAddress.getByAddress(b.copyOfRange(12, 16)) }.getOrNull()
                return mappedV4 == null || isSpecialOrPrivateIp(mappedV4)
            }
        }
        return false
    }

    private fun parseLiteralIpOrNull(host: String): InetAddress? {
        val isIpv4 = host.all { it in '0'..'9' || it == '.' } && host.count { it == '.' } == 3
        val isIpv6 = host.contains(':')
        if (!isIpv4 && !isIpv6) return null
        return runCatching { InetAddress.getByName(host) }.getOrNull()
    }

    private fun bigIntToFixedUnsignedBytes(v: BigInteger, length: Int): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(length)
        if (raw.size == length) {
            System.arraycopy(raw, 0, out, 0, length)
        } else if (raw.size == length + 1 && raw[0] == 0.toByte()) {
            System.arraycopy(raw, 1, out, 0, length)
        } else if (raw.size < length) {
            System.arraycopy(raw, 0, out, length - raw.size, raw.size)
        } else {
            throw IllegalArgumentException("Coordinate length exceeds $length bytes")
        }
        return out
    }

    private fun parseKeyValues(raw: String?): Map<String, String> {
        if (raw.isNullOrBlank()) return emptyMap()
        val map = LinkedHashMap<String, String>()
        for (part in raw.split('&')) {
            if (part.isBlank()) continue
            val eq = part.indexOf('=')
            if (eq > 0) {
                val k = urlDecode(part.substring(0, eq)).trim().lowercase()
                val v = urlDecode(part.substring(eq + 1))
                if (k.isNotEmpty()) map[k] = v
            } else if (eq < 0) {
                val k = urlDecode(part).trim().lowercase()
                if (k.isNotEmpty()) map[k] = ""
            }
        }
        return map
    }

    private fun urlEncode(s: String): String = URLEncoder.encode(s, "UTF-8")

    private fun urlDecode(s: String): String =
        runCatching { URLDecoder.decode(s, "UTF-8") }.getOrDefault(s)
}
