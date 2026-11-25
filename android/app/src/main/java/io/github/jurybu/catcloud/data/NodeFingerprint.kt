package io.github.jurybu.catcloud.data

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.TreeMap

/**
 * Byte-for-byte port of desktop `catcloud-core::subscription::parser::node_dedup_fingerprint`
 * (`catcloud-node-fp-v1`) and `preaccel::schema::relay_dedup_fingerprint`.
 */
object NodeFingerprint {

    private sealed class CanonicalVal {
        data object NullVal : CanonicalVal()
        data class BoolVal(val v: Boolean) : CanonicalVal()
        data class NumVal(val text: String) : CanonicalVal()
        data class StrVal(val v: String) : CanonicalVal()
        data class ArrVal(val items: List<CanonicalVal>) : CanonicalVal()
        data class ObjVal(val entries: TreeMap<String, CanonicalVal>) : CanonicalVal()
    }

    fun normalizeProtocol(proto: String): String = when (proto.trim().lowercase()) {
        "hy2", "hysteria2" -> "hysteria2"
        "shadowsocks", "ss" -> "ss"
        "socks", "socks5" -> "socks5"
        else -> proto.trim().lowercase()
    }

    fun normalizeRelayProtocol(proto: String): String = when (proto.trim().lowercase()) {
        "anytls" -> "anytls"
        "trojan" -> "trojan"
        "vless" -> "vless"
        "hy2", "hysteria2" -> "hysteria2"
        "tuic" -> "tuic"
        else -> proto.trim().lowercase()
    }

    /**
     * Relay deduplication key matching Rust `(protocol_lower, server_lower, port)`.
     */
    fun relayDedupFingerprint(relay: PreAccelRelayRecord): Triple<String, String, Int> =
        Triple(
            normalizeRelayProtocol(relay.protocol),
            relay.server.trim().lowercase(),
            relay.port,
        )

    fun relayDedupKeyString(relay: PreAccelRelayRecord): String {
        val (p, s, port) = relayDedupFingerprint(relay)
        return "$p|$s|$port"
    }

    /**
     * Compute 64-char lowercase hex SHA-256 `catcloud-node-fp-v1` fingerprint identical to desktop Rust.
     */
    fun computeNodeFingerprint(node: ProxyNodeRecord): String {
        val rawObj = parseJsonObjectOrNull(node.rawConfigJson)
        return computeNodeFingerprint(
            protocol = node.protocol,
            server = node.server,
            port = node.port,
            rawObj = rawObj,
        )
    }

    fun computeNodeFingerprint(
        protocol: String,
        server: String,
        port: Int,
        rawObj: JSONObject?,
    ): String {
        val rawProto = if (protocol.trim().isNotEmpty()) {
            protocol
        } else {
            optNonEmptyStr(rawObj, "type", "protocol") ?: ""
        }
        val normProto = normalizeProtocol(rawProto)

        val rawServer = if (server.trim().isNotEmpty()) {
            server
        } else {
            optNonEmptyStr(rawObj, "server") ?: ""
        }
        val normServer = rawServer.trim().removePrefix("[").removeSuffix("]").lowercase()

        val normPort = if (port > 0) {
            port
        } else {
            optPositivePort(rawObj?.opt("port")) ?: 0
        }

        val coreFields = TreeMap<String, CanonicalVal>()
        if (rawObj != null) {
            optNonEmptyStr(rawObj, "uuid", "id")?.let {
                coreFields["uuid"] = CanonicalVal.StrVal(it.lowercase())
            }
            optNonEmptyStr(rawObj, "password", "auth-str", "auth_str")?.let {
                coreFields["password"] = CanonicalVal.StrVal(it)
            }
            optNonEmptyStr(rawObj, "username")?.let {
                coreFields["username"] = CanonicalVal.StrVal(it)
            }
            optNonEmptyStr(rawObj, "token")?.let {
                coreFields["token"] = CanonicalVal.StrVal(it)
            }
            optNonEmptyStr(rawObj, "cipher", "method", "security")?.let {
                coreFields["cipher"] = CanonicalVal.StrVal(it.lowercase())
            }
            val aid = firstNonNull(rawObj, "alterId", "alter-id", "alter_id")
                ?.let { anyToLong(it) }
                ?.takeIf { it > 0L }
            if (aid != null) {
                coreFields["alter_id"] = CanonicalVal.NumVal(aid.toString())
            }

            val implicitTls = normProto in setOf("trojan", "anytls", "hysteria2", "hysteria", "tuic")
            if (!implicitTls && anyToBool(rawObj.opt("tls")) == true) {
                coreFields["tls"] = CanonicalVal.BoolVal(true)
            }

            optNonEmptyStr(rawObj, "sni", "servername", "server_name")?.let {
                coreFields["sni"] = CanonicalVal.StrVal(it.lowercase())
            }

            optNonEmptyStr(rawObj, "network")?.let {
                val netLower = it.lowercase()
                if (netLower != "tcp") {
                    coreFields["network"] = CanonicalVal.StrVal(netLower)
                }
            }

            rawObj.opt("ws-opts")?.let { canonicalizeWsOpts(it) }?.let {
                coreFields["ws-opts"] = it
            }
            rawObj.opt("grpc-opts")?.let { canonicalizeGrpcOpts(it) }?.let {
                coreFields["grpc-opts"] = it
            }
            rawObj.opt("h2-opts")?.let { canonicalizeJsonValue(it) }?.let {
                coreFields["h2-opts"] = it
            }
            rawObj.opt("http-opts")?.let { canonicalizeJsonValue(it) }?.let {
                coreFields["http-opts"] = it
            }
            rawObj.opt("reality-opts")?.let { canonicalizeRealityOpts(it) }?.let {
                coreFields["reality-opts"] = it
            }
            rawObj.opt("alpn")?.let { canonicalizeAlpn(it) }?.let {
                coreFields["alpn"] = it
            }
            optNonEmptyStr(rawObj, "flow")?.let {
                coreFields["flow"] = CanonicalVal.StrVal(it.lowercase())
            }
            optNonEmptyStr(rawObj, "obfs")?.let {
                coreFields["obfs"] = CanonicalVal.StrVal(it.lowercase())
            }
            optNonEmptyStr(rawObj, "obfs-password", "obfs_password")?.let {
                coreFields["obfs-password"] = CanonicalVal.StrVal(it)
            }
            optNonEmptyStr(rawObj, "plugin")?.let {
                coreFields["plugin"] = CanonicalVal.StrVal(it.lowercase())
            }
            rawObj.opt("plugin-opts")?.let { canonicalizeJsonValue(it) }?.let {
                coreFields["plugin-opts"] = it
            }
            optNonEmptyStr(rawObj, "ports")?.let {
                coreFields["ports"] = CanonicalVal.StrVal(it)
            }
            optNonEmptyStr(rawObj, "congestion-controller", "congestion_control")?.let {
                coreFields["congestion-controller"] = CanonicalVal.StrVal(it.lowercase())
            }
            optNonEmptyStr(rawObj, "udp-relay-mode", "udp_relay_mode")?.let {
                coreFields["udp-relay-mode"] = CanonicalVal.StrVal(it.lowercase())
            }
        }

        val md = MessageDigest.getInstance("SHA-256")
        md.update("catcloud-node-fp-v1\u001f".toByteArray(Charsets.UTF_8))
        md.update(normProto.toByteArray(Charsets.UTF_8))
        md.update(0x1f.toByte())
        md.update(normServer.toByteArray(Charsets.UTF_8))
        md.update(0x1f.toByte())
        md.update(normPort.toString().toByteArray(Charsets.UTF_8))
        for ((k, v) in coreFields) {
            md.update(0x1f.toByte())
            md.update(k.toByteArray(Charsets.UTF_8))
            md.update('='.code.toByte())
            hashCanonicalVal(md, v)
        }
        return toHexLower(md.digest())
    }

    fun detectIs443Native(protocol: String, port: Int, rawObj: JSONObject?): Boolean {
        if (port != 443) return false
        val proto = normalizeProtocol(protocol)
        val hasReality = rawObj != null && rawObj.has("reality-opts") && !rawObj.isNull("reality-opts")
        val tlsFlag = rawObj?.let { anyToBool(it.opt("tls")) }
        return when (proto) {
            "trojan", "anytls", "hysteria2", "tuic", "hysteria" -> true
            "vless" -> if (hasReality) true else (tlsFlag ?: true)
            "vmess", "http", "socks5" -> hasReality || (tlsFlag ?: false)
            "ss" -> {
                if (hasReality || (tlsFlag ?: false)) return true
                val po = rawObj?.optJSONObject("plugin-opts")
                anyToBool(po?.opt("tls")) ?: false
            }
            else -> hasReality || (tlsFlag ?: false)
        }
    }

    fun extractMultiplier(name: String): Double {
        val suffixRe = Regex("(?i)(?:^|[^0-9a-zA-Z.])(\\d+(?:\\.\\d+)?)\\s*(?:x|×|✕|倍(?:率)?)(?:$|[^0-9a-zA-Z])")
        suffixRe.find(name)?.groupValues?.getOrNull(1)?.toDoubleOrNull()?.let { v ->
            if (v.isFinite() && v in 0.0..100.0) return v
        }
        val prefixRe = Regex("(?i)(?:^|[^0-9a-zA-Z.])(?:x|×|✕)\\s*(\\d+(?:\\.\\d+)?)(?:$|[^0-9a-zA-Z])")
        prefixRe.find(name)?.groupValues?.getOrNull(1)?.toDoubleOrNull()?.let { v ->
            if (v.isFinite() && v in 0.0..100.0) return v
        }
        return 1.0
    }

    fun detectRegionCode(name: String): String {
        extractFlagRegionCode(name)?.let { return it }
        val upper = name.uppercase()
        val phraseRules: List<Pair<List<String>, String>> = listOf(
            listOf("台湾", "台灣", "台北", "臺北", "新北", "高雄", "TAIWAN", "TAIPEI") to "TW",
            listOf("香港", "HONG KONG", "HONGKONG") to "HK",
            listOf("澳门", "澳門", "MACAU", "MACAO") to "MO",
            listOf("日本", "东京", "東京", "大阪", "JAPAN", "TOKYO", "OSAKA") to "JP",
            listOf("新加坡", "狮城", "獅城", "SINGAPORE") to "SG",
            listOf("韩国", "韓國", "首尔", "首爾", "KOREA", "SEOUL") to "KR",
            listOf("马来西亚", "馬來西亞", "吉隆坡", "MALAYSIA") to "MY",
            listOf("泰国", "泰國", "曼谷", "THAILAND", "BANGKOK") to "TH",
            listOf("越南", "河内", "胡志明", "VIETNAM") to "VN",
            listOf("菲律宾", "菲律賓", "马尼拉", "PHILIPPINES") to "PH",
            listOf("印度尼西亚", "印尼", "雅加达", "INDONESIA") to "ID",
            listOf("印度", "孟买", "INDIA", "MUMBAI") to "IN",
            listOf("土耳其", "TURKEY", "TURKIYE") to "TR",
            listOf("阿联酋", "迪拜", "DUBAI", "UNITED ARAB EMIRATES") to "AE",
            listOf("英国", "英國", "伦敦", "LONDON", "UNITED KINGDOM") to "UK",
            listOf("德国", "德國", "法兰克福", "GERMANY", "FRANKFURT") to "DE",
            listOf("法国", "法國", "巴黎", "FRANCE", "PARIS") to "FR",
            listOf("荷兰", "荷蘭", "阿姆斯特丹", "NETHERLANDS", "AMSTERDAM") to "NL",
            listOf("瑞士", "苏黎世", "SWITZERLAND", "ZURICH") to "CH",
            listOf("俄罗斯", "俄羅斯", "莫斯科", "RUSSIA", "MOSCOW") to "RU",
            listOf("美国", "美國", "洛杉矶", "圣何塞", "西雅图", "硅谷", "纽约", "达拉斯", "UNITED STATES", "AMERICA", "LOS ANGELES", "SAN JOSE", "SEATTLE", "NEW YORK") to "US",
            listOf("加拿大", "多伦多", "温哥华", "CANADA", "TORONTO", "VANCOUVER") to "CA",
            listOf("澳大利亚", "澳洲", "悉尼", "墨尔本", "AUSTRALIA", "SYDNEY") to "AU",
            listOf("新西兰", "奥克兰", "NEW ZEALAND") to "NZ",
            listOf("巴西", "圣保罗", "BRAZIL") to "BR",
            listOf("阿根廷", "ARGENTINA") to "AR",
        )
        for ((patterns, code) in phraseRules) {
            if (patterns.any { name.contains(it) || upper.contains(it) }) return code
        }
        val tokenRules = listOf(
            "TW" to "TW", "TWN" to "TW", "HK" to "HK", "HKG" to "HK",
            "JP" to "JP", "JPN" to "JP", "SG" to "SG", "SGP" to "SG",
            "KR" to "KR", "KOR" to "KR", "US" to "US", "USA" to "US",
            "UK" to "UK", "GB" to "UK", "DE" to "DE", "FR" to "FR",
            "NL" to "NL", "CA" to "CA", "AU" to "AU", "IN" to "IN",
            "TR" to "TR", "MY" to "MY", "TH" to "TH", "VN" to "VN",
            "RU" to "RU", "BR" to "BR", "CH" to "CH", "SE" to "SE",
            "IT" to "IT", "ES" to "ES", "IE" to "IE", "NZ" to "NZ",
        )
        for ((tok, code) in tokenRules) {
            if (containsAsciiToken(upper, tok)) return code
        }
        return "UNK"
    }

    private fun extractFlagRegionCode(name: String): String? {
        var prev: Int? = null
        var i = 0
        while (i < name.length) {
            val cp = name.codePointAt(i)
            i += Character.charCount(cp)
            if (cp in 0x1F1E6..0x1F1FF) {
                val letter = 'A'.code + (cp - 0x1F1E6)
                if (prev != null) {
                    val code = String(charArrayOf(prev.toChar(), letter.toChar()))
                    return if (code == "GB") "UK" else code
                }
                prev = letter
            } else {
                prev = null
            }
        }
        return null
    }

    private fun containsAsciiToken(upper: String, token: String): Boolean {
        var idx = upper.indexOf(token)
        while (idx >= 0) {
            val beforeOk = idx == 0 || !upper[idx - 1].isAsciiLetter()
            val afterIdx = idx + token.length
            val afterOk = afterIdx >= upper.length || !upper[afterIdx].isAsciiLetter()
            if (beforeOk && afterOk) return true
            idx = upper.indexOf(token, idx + 1)
        }
        return false
    }

    private fun Char.isAsciiLetter(): Boolean = this in 'A'..'Z' || this in 'a'..'z'

    private fun canonicalizeJsonValue(raw: Any?): CanonicalVal? = when (raw) {
        null, JSONObject.NULL -> null
        is Boolean -> CanonicalVal.BoolVal(raw)
        is Int -> CanonicalVal.NumVal(raw.toString())
        is Long -> CanonicalVal.NumVal(raw.toString())
        is Number -> {
            val d = raw.toDouble()
            if (d.isFinite() && d == d.toLong().toDouble() && !raw.toString().contains('.')) {
                CanonicalVal.NumVal(raw.toLong().toString())
            } else {
                CanonicalVal.NumVal(raw.toString())
            }
        }
        is String -> raw.trim().takeIf { it.isNotEmpty() }?.let { CanonicalVal.StrVal(it) }
        is JSONArray -> {
            val out = ArrayList<CanonicalVal>()
            for (i in 0 until raw.length()) {
                canonicalizeJsonValue(raw.opt(i))?.let { out.add(it) }
            }
            if (out.isEmpty()) null else CanonicalVal.ArrVal(out)
        }
        is JSONObject -> {
            val sorted = TreeMap<String, CanonicalVal>()
            val keys = raw.keys()
            while (keys.hasNext()) {
                val k = keys.next().trim()
                if (k.isEmpty()) continue
                canonicalizeJsonValue(raw.opt(k))?.let { sorted[k] = it }
            }
            if (sorted.isEmpty()) null else CanonicalVal.ObjVal(sorted)
        }
        else -> null
    }

    private fun canonicalizeWsOpts(raw: Any?): CanonicalVal? {
        val obj = raw as? JSONObject ?: return null
        val sorted = TreeMap<String, CanonicalVal>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val origKey = keys.next()
            val keyLower = origKey.trim().lowercase()
            if (keyLower.isEmpty()) continue
            val value = obj.opt(origKey)
            if (keyLower == "headers") {
                val hdrs = value as? JSONObject ?: continue
                val normHdrs = TreeMap<String, CanonicalVal>()
                val hKeys = hdrs.keys()
                while (hKeys.hasNext()) {
                    val hOrig = hKeys.next()
                    val hkLower = hOrig.trim().lowercase()
                    if (hkLower.isEmpty()) continue
                    val cv = canonicalizeJsonValue(hdrs.opt(hOrig)) ?: continue
                    val finalCv = if (hkLower == "host" && cv is CanonicalVal.StrVal) {
                        CanonicalVal.StrVal(cv.v.lowercase())
                    } else {
                        cv
                    }
                    normHdrs[hkLower] = finalCv
                }
                if (normHdrs.isNotEmpty()) {
                    sorted["headers"] = CanonicalVal.ObjVal(normHdrs)
                }
            } else {
                canonicalizeJsonValue(value)?.let { sorted[keyLower] = it }
            }
        }
        return if (sorted.isEmpty()) null else CanonicalVal.ObjVal(sorted)
    }

    private fun canonicalizeGrpcOpts(raw: Any?): CanonicalVal? {
        val obj = raw as? JSONObject ?: return null
        val sorted = TreeMap<String, CanonicalVal>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val origKey = keys.next()
            val normKey = when (origKey.trim().lowercase()) {
                "grpc-service-name", "service-name", "service_name" -> "grpc-service-name"
                "" -> continue
                else -> origKey.trim().lowercase()
            }
            canonicalizeJsonValue(obj.opt(origKey))?.let { sorted[normKey] = it }
        }
        return if (sorted.isEmpty()) null else CanonicalVal.ObjVal(sorted)
    }

    private fun canonicalizeRealityOpts(raw: Any?): CanonicalVal? {
        val obj = raw as? JSONObject ?: return null
        val sorted = TreeMap<String, CanonicalVal>()
        val keys = obj.keys()
        while (keys.hasNext()) {
            val origKey = keys.next()
            val normKey = when (origKey.trim().lowercase()) {
                "public-key", "public_key" -> "public-key"
                "short-id", "short_id" -> "short-id"
                "spider-x", "spider_x" -> "spider-x"
                "" -> continue
                else -> origKey.trim().lowercase()
            }
            canonicalizeJsonValue(obj.opt(origKey))?.let { sorted[normKey] = it }
        }
        return if (sorted.isEmpty()) null else CanonicalVal.ObjVal(sorted)
    }

    private fun canonicalizeAlpn(raw: Any?): CanonicalVal? {
        val items = ArrayList<CanonicalVal>()
        when (raw) {
            is JSONArray -> {
                for (i in 0 until raw.length()) {
                    val s = raw.opt(i) as? String ?: continue
                    val t = s.trim().lowercase()
                    if (t.isNotEmpty()) items.add(CanonicalVal.StrVal(t))
                }
            }
            is String -> {
                for (part in raw.split(',')) {
                    val t = part.trim().lowercase()
                    if (t.isNotEmpty()) items.add(CanonicalVal.StrVal(t))
                }
            }
        }
        return if (items.isEmpty()) null else CanonicalVal.ArrVal(items)
    }

    private fun hashCanonicalVal(md: MessageDigest, value: CanonicalVal) {
        when (value) {
            CanonicalVal.NullVal -> md.update("null".toByteArray(Charsets.US_ASCII))
            is CanonicalVal.BoolVal -> md.update((if (value.v) "true" else "false").toByteArray(Charsets.US_ASCII))
            is CanonicalVal.NumVal -> md.update(value.text.toByteArray(Charsets.US_ASCII))
            is CanonicalVal.StrVal -> {
                val bytes = value.v.toByteArray(Charsets.UTF_8)
                md.update("s:".toByteArray(Charsets.US_ASCII))
                md.update(u64LeBytes(bytes.size.toLong()))
                md.update(':'.code.toByte())
                md.update(bytes)
            }
            is CanonicalVal.ArrVal -> {
                md.update('['.code.toByte())
                value.items.forEachIndexed { idx, item ->
                    if (idx > 0) md.update(','.code.toByte())
                    hashCanonicalVal(md, item)
                }
                md.update(']'.code.toByte())
            }
            is CanonicalVal.ObjVal -> {
                md.update('{'.code.toByte())
                var idx = 0
                for ((k, v) in value.entries) {
                    if (idx > 0) md.update(','.code.toByte())
                    val kBytes = k.toByteArray(Charsets.UTF_8)
                    md.update(u64LeBytes(kBytes.size.toLong()))
                    md.update(':'.code.toByte())
                    md.update(kBytes)
                    md.update('='.code.toByte())
                    hashCanonicalVal(md, v)
                    idx++
                }
                md.update('}'.code.toByte())
            }
        }
    }

    private fun u64LeBytes(v: Long): ByteArray =
        ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(v).array()

    private fun parseJsonObjectOrNull(raw: String): JSONObject? {
        val t = raw.trim()
        if (t.isEmpty() || !t.startsWith("{")) return null
        return runCatching { JSONObject(t) }.getOrNull()
    }

    private fun firstNonNull(obj: JSONObject, vararg keys: String): Any? {
        for (k in keys) {
            if (obj.has(k) && !obj.isNull(k)) {
                return obj.opt(k)
            }
        }
        return null
    }

    private fun optNonEmptyStr(obj: JSONObject?, vararg keys: String): String? {
        if (obj == null) return null
        for (k in keys) {
            val v = obj.opt(k)
            if (v is String) {
                val t = v.trim()
                if (t.isNotEmpty()) return t
            }
        }
        return null
    }

    private fun optPositivePort(v: Any?): Int? {
        val n = anyToLong(v) ?: return null
        return if (n in 1L..65535L) n.toInt() else null
    }

    private fun anyToLong(v: Any?): Long? = when (v) {
        is Int -> v.toLong()
        is Long -> v
        is Number -> v.toLong()
        is String -> v.trim().toLongOrNull()
        else -> null
    }

    private fun anyToBool(v: Any?): Boolean? = when (v) {
        is Boolean -> v
        is Number -> v.toInt() != 0
        is String -> when (v.trim().lowercase()) {
            "true", "1", "yes" -> true
            "false", "0", "no" -> false
            else -> null
        }
        else -> null
    }

    fun toHexLower(bytes: ByteArray): String {
        val hex = "0123456789abcdef"
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xFF
            out[i * 2] = hex[b ushr 4]
            out[i * 2 + 1] = hex[b and 0x0F]
        }
        return String(out)
    }
}
