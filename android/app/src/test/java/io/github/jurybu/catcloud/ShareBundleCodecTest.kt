package io.github.jurybu.catcloud

import io.github.jurybu.catcloud.data.MultiGroupRecord
import io.github.jurybu.catcloud.data.NodeFingerprint
import io.github.jurybu.catcloud.data.PreAccelRelayRecord
import io.github.jurybu.catcloud.data.ProxyNodeRecord
import io.github.jurybu.catcloud.data.ShareBundleCodec
import io.github.jurybu.catcloud.data.ShareGroupRecord
import io.github.jurybu.catcloud.data.ShareGroupsDocument
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ShareBundleCodecTest {

    private fun demoNode(id: String, name: String, ip: String, uuid: String): ProxyNodeRecord {
        val raw = JSONObject().apply {
            put("name", name)
            put("type", "vless")
            put("server", ip)
            put("port", 443)
            put("uuid", uuid)
            put("tls", true)
            put("servername", "demo.example.invalid")
            put("dialer-proxy", "⚡ 国内预加速入口")
        }
        val fp = NodeFingerprint.computeNodeFingerprint("vless", ip, 443, raw)
        return ProxyNodeRecord(
            id = id,
            name = name,
            protocol = "vless",
            server = ip,
            port = 443,
            rawConfigJson = raw.toString(),
            regionCode = NodeFingerprint.detectRegionCode(name),
            fingerprint = fp,
        )
    }

    private fun demoRelay(): PreAccelRelayRecord = PreAccelRelayRecord(
        id = "relay-demo-1",
        name = "Demo-CN-443",
        provider = "demo",
        region = "CN-EAST",
        server = "198.51.100.10",
        port = 443,
        protocol = "anytls",
        password = "demo-relay-password",
        sni = null,
        skipCertVerify = true,
        priority = 10,
        enabled = true,
    )

    @Test
    fun shareBundleRoundtripStripsDialerProxyAndPreservesGroupsAndRelays() {
        val n1 = demoNode("n1", "🇯🇵 东京 0.5x", "203.0.113.10", "00000000-0000-4000-8000-000000000001")
        val n2 = demoNode("n2", "🇸🇬 新加坡 1x", "203.0.113.11", "00000000-0000-4000-8000-000000000002")
        val relay = demoRelay()
        val gBackup = MultiGroupRecord(
            id = "g-backup",
            name = "BackupPool",
            memberNodeIds = listOf(n2.id),
            activeNodeId = n2.id,
        )
        val gMain = MultiGroupRecord(
            id = "g-main",
            name = "AI-Smart",
            matchRules = listOf("@ai_domains"),
            memberNodeIds = listOf(n1.id, n2.id),
            fallbackPoolId = gBackup.id,
            activeNodeId = n1.id,
        )

        val (zipBytes, manifest) = ShareBundleCodec.exportShareBundleZip(
            name = "Demo Starter Pack",
            nodes = listOf(n1, n2),
            relays = listOf(relay),
            groups = listOf(gMain, gBackup),
            activeGroupName = "AI-Smart",
            routeMode = "group",
        )
        assertEquals(ShareBundleCodec.SHARE_BUNDLE_SCHEMA, manifest.schema)
        assertEquals(2, manifest.nodeCount)
        assertEquals(1, manifest.relayCount)

        val preview = ShareBundleCodec.previewShareBundleZip(zipBytes)
        assertTrue(preview.hasReadme)
        assertEquals(2, preview.nodes.size)
        assertFalse(preview.nodes[0].rawConfigJson.contains("dialer-proxy"))
        assertEquals(1, preview.relays.size)
        assertEquals("198.51.100.10", preview.relays[0].server)
        assertNotNull(preview.groupsDoc)
        assertEquals(2, preview.groupsDoc!!.groups.size)
        assertEquals("BackupPool", preview.groupsDoc!!.groups[0].fallbackPoolName)
    }

    @Test
    fun groupsJsonSameNameUnionMergePreservesLocalActiveNodeAndResolvesFallbackPool() {
        val n1 = demoNode("local-n1", "JP-1", "203.0.113.10", "00000000-0000-4000-8000-000000000001")
        val n2 = demoNode("local-n2", "SG-2", "203.0.113.11", "00000000-0000-4000-8000-000000000002")
        val n3 = demoNode("local-n3", "US-3", "203.0.113.12", "00000000-0000-4000-8000-000000000003")
        val fpMap = mapOf(
            n1.fingerprint to n1.id,
            n2.fingerprint to n2.id,
            n3.fingerprint to n3.id,
        )

        val existing = listOf(
            MultiGroupRecord(
                id = "existing-ai",
                name = "AI-Smart",
                memberNodeIds = listOf(n1.id),
                activeNodeId = n1.id,
                cooldownSec = 95L,
            )
        )

        val importedDoc = ShareGroupsDocument(
            groups = listOf(
                ShareGroupRecord(
                    name = "AI-Smart",
                    memberFingerprints = listOf(n2.fingerprint, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                    activeNodeFingerprint = n2.fingerprint,
                ),
                ShareGroupRecord(
                    name = "BackupPool",
                    memberFingerprints = listOf(n3.fingerprint),
                    fallbackPoolName = "AI-Smart",
                ),
                ShareGroupRecord(
                    name = "GhostEmptyGroup",
                    memberFingerprints = listOf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                ),
            )
        )

        val res = ShareBundleCodec.mergeImportedGroups(existing, importedDoc, fpMap)
        assertEquals(1, res.mergedCount)
        assertEquals(1, res.importedCount)
        assertEquals(1, res.warnings.size) // GhostEmptyGroup skipped with warning

        val ai = res.mergedGroups.first { it.name == "AI-Smart" }
        assertEquals(listOf("local-n1", "local-n2"), ai.memberNodeIds)
        assertEquals("local-n1", ai.activeNodeId) // Preserved local active selection
        assertEquals(95L, ai.cooldownSec) // Preserved local setting

        val backup = res.mergedGroups.first { it.name == "BackupPool" }
        assertEquals("existing-ai", backup.fallbackPoolId)

        // Unmatched fallback_pool_name resolves to null
        val orphanRes = ShareBundleCodec.mergeImportedGroups(
            existingGroups = emptyList(),
            importedDoc = ShareGroupsDocument(
                groups = listOf(
                    ShareGroupRecord(
                        name = "Solo",
                        memberFingerprints = listOf(n1.fingerprint),
                        fallbackPoolName = "NonExistentPool",
                    )
                )
            ),
            fingerprintToNodeId = fpMap,
        )
        assertNull(orphanRes.mergedGroups.first().fallbackPoolId)
    }

    @Test
    fun previewRejectsZipSlipBackslashesDuplicateGroupsAndUnixSymlink() {
        val evilPaths = listOf("../escape.yaml", "a/../../escape.yaml", "/etc/passwd", "C:/evil.yaml", "sub\\evil.yaml")
        for (evil in evilPaths) {
            val z = buildSingleEntryZip(evil, "x".toByteArray())
            assertThrowsSecurity("Zip Slip must be rejected for $evil") {
                ShareBundleCodec.previewShareBundleZip(z)
            }
        }

        // Duplicate groups.json entry must be rejected
        val dupZip = ByteArrayOutputStream().apply {
            ZipOutputStream(this).use { zos ->
                zos.putNextEntry(ZipEntry("manifest.json"))
                zos.write("""{"schema":"catcloud-share/v1","name":"dup","created_at":"","node_count":0,"relay_count":0}""".toByteArray())
                zos.closeEntry()
                zos.putNextEntry(ZipEntry("groups.json"))
                zos.write("""{"schema":"catcloud-groups/v1","groups":[]}""".toByteArray())
                zos.closeEntry()
                zos.putNextEntry(ZipEntry("wrapper/groups.json"))
                zos.write("""{"schema":"catcloud-groups/v1","groups":[]}""".toByteArray())
                zos.closeEntry()
            }
        }.toByteArray()
        assertThrowsSecurity("Duplicate groups.json must be rejected") {
            ShareBundleCodec.previewShareBundleZip(dupZip)
        }

        // Crafted ZIP central directory with Unix symlink mode (0120777 -> 0xA1FF in high 16 bits of external attr)
        val symlinkZip = buildSingleEntryZip("manifest.json", "{}".toByteArray())
        val patched = patchCentralDirectoryUnixMode(symlinkZip, 0xA1FF)
        assertThrowsSecurity("Unix symlink entry must be rejected") {
            ShareBundleCodec.previewShareBundleZip(patched)
        }
    }

    @Test
    fun mmrelayUriAndDemoProxyUrisParseCleanly() {
        val relay = demoRelay()
        val uri = ShareBundleCodec.encodeMmRelayUri(listOf(relay))
        assertTrue(uri.startsWith("mmrelay://v1/"))
        val decodedRelays = ShareBundleCodec.decodeMmRelayInput(uri)
        assertEquals(1, decodedRelays.size)
        assertEquals("198.51.100.10", decodedRelays[0].server)

        // All test proxy URIs strictly use `00000000` / `demo` / `test` prefixes per public sanitization gate.
        val multiUriText = listOf(
            "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?security=tls&sni=demo.example.invalid#JP-Demo-VLESS",
            "trojan://demo-pass-1234567890@203.0.113.11:443?sni=demo.example.invalid#SG-Demo-Trojan",
            "hy2://test-hy2-pass-12345@203.0.113.12:443?insecure=1#US-Demo-HY2",
            "anytls://demo-anytls-pass-01@203.0.113.13:443?insecure=1#HK-Demo-AnyTLS",
            "ss://demo-aes:test-pass@203.0.113.14:8388#TW-Demo-SS",
        ).joinToString("\n")
        val parsed = ShareBundleCodec.parseTextImport(multiUriText, subId = "test")
        assertEquals(5, parsed.size)
        assertEquals("vless", parsed[0].protocol)
        assertEquals("trojan", parsed[1].protocol)
        assertEquals("hysteria2", parsed[2].protocol)
        assertEquals("anytls", parsed[3].protocol)
        assertEquals("ss", parsed[4].protocol)
    }

    private fun buildSingleEntryZip(name: String, body: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            ZipOutputStream(this).use { zos ->
                zos.putNextEntry(ZipEntry(name))
                zos.write(body)
                zos.closeEntry()
            }
        }.toByteArray()

    private fun patchCentralDirectoryUnixMode(zipBytes: ByteArray, unixMode: Int): ByteArray {
        val copy = zipBytes.copyOf()
        val buf = ByteBuffer.wrap(copy).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until copy.size - 46) {
            if (buf.getInt(i) == 0x02014b50) {
                buf.putShort(i + 4, ((3 shl 8) or 20).toShort()) // versionMadeBy = Unix (3)
                buf.putInt(i + 38, unixMode shl 16)
                break
            }
        }
        return copy
    }

    @Test
    fun previewRejectsMalformedOrTruncatedCentralDirectoryZip() {
        // 1. Non-ZIP / missing EOCD must throw IllegalArgumentException (never silently skip security scan)
        val noEocd = "PK\u0003\u0004not-a-valid-zip-archive-without-eocd".toByteArray(Charsets.UTF_8)
        assertThrowsIllegalArg("Missing EOCD must be rejected") {
            ShareBundleCodec.previewShareBundleZip(noEocd)
        }

        // 2. Truncated valid ZIP missing EOCD tail must throw IllegalArgumentException
        val validZip = buildSingleEntryZip(
            "manifest.json",
            """{"schema":"catcloud-share/v1","name":"t","created_at":"","node_count":0,"relay_count":0}""".toByteArray(),
        )
        val truncatedNoEocd = validZip.copyOf(validZip.size - 20)
        assertThrowsIllegalArg("Truncated ZIP missing EOCD must be rejected") {
            ShareBundleCodec.previewShareBundleZip(truncatedNoEocd)
        }

        // 3. Corrupted EOCD central directory offset out of bounds must throw IllegalArgumentException
        val badOffsetZip = validZip.copyOf()
        val bufOffset = ByteBuffer.wrap(badOffsetZip).order(ByteOrder.LITTLE_ENDIAN)
        val eocdPos = findEocdOffset(badOffsetZip)
        assertTrue(eocdPos >= 0)
        bufOffset.putInt(eocdPos + 16, badOffsetZip.size + 100)
        assertThrowsIllegalArg("Out-of-bounds central directory offset must be rejected") {
            ShareBundleCodec.previewShareBundleZip(badOffsetZip)
        }

        // 4. Corrupted central directory header signature must throw IllegalArgumentException
        val badCdSigZip = validZip.copyOf()
        val bufSig = ByteBuffer.wrap(badCdSigZip).order(ByteOrder.LITTLE_ENDIAN)
        val cdOff = bufSig.getInt(eocdPos + 16)
        bufSig.putInt(cdOff, 0x11223344)
        assertThrowsIllegalArg("Corrupted central directory signature must be rejected") {
            ShareBundleCodec.previewShareBundleZip(badCdSigZip)
        }
    }

    @Test
    fun mergeImportedGroupsStripsSelfReferenceAndDanglingFallbackPool() {
        val n1 = demoNode("local-n1", "JP-1", "203.0.113.10", "00000000-0000-4000-8000-000000000001")
        val fpMap = mapOf(n1.fingerprint to n1.id)

        val existing = listOf(
            MultiGroupRecord(
                id = "grp-self-existing",
                name = "SelfExisting",
                memberNodeIds = listOf(n1.id),
                fallbackPoolId = "grp-self-existing", // self-reference
            ),
            MultiGroupRecord(
                id = "grp-dangling-existing",
                name = "DanglingExisting",
                memberNodeIds = listOf(n1.id),
                fallbackPoolId = "grp-does-not-exist", // dangling reference
            ),
        )
        val importedDoc = ShareGroupsDocument(
            groups = listOf(
                ShareGroupRecord(
                    name = "SelfImported",
                    memberFingerprints = listOf(n1.fingerprint),
                    fallbackPoolName = "SelfImported", // self-reference by name
                )
            )
        )

        val merged = ShareBundleCodec.mergeImportedGroups(existing, importedDoc, fpMap)
        assertNull(merged.mergedGroups.first { it.name == "SelfExisting" }.fallbackPoolId)
        assertNull(merged.mergedGroups.first { it.name == "DanglingExisting" }.fallbackPoolId)
        assertNull(merged.mergedGroups.first { it.name == "SelfImported" }.fallbackPoolId)
    }

    private fun findEocdOffset(zipBytes: ByteArray): Int {
        for (i in (zipBytes.size - 22) downTo maxOf(0, zipBytes.size - 65557)) {
            if (zipBytes[i] == 0x50.toByte() &&
                zipBytes[i + 1] == 0x4b.toByte() &&
                zipBytes[i + 2] == 0x05.toByte() &&
                zipBytes[i + 3] == 0x06.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    private fun assertThrowsIllegalArg(msg: String, block: () -> Unit) {
        try {
            block()
            fail(msg)
        } catch (_: IllegalArgumentException) {
            // Expected
        }
    }

    private fun assertThrowsSecurity(msg: String, block: () -> Unit) {
        try {
            block()
            fail(msg)
        } catch (_: SecurityException) {
            // Expected
        }
    }
}
