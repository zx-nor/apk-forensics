package forensics.metadata

import forensics.archive.ZipDirectory
import forensics.archive.ZipDirectoryReader
import forensics.archive.ZipEntryReader
import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import forensics.common.u32
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Android package information: manifest identity, SDK levels, permissions, components, signer
 * certificates, and structure counts.
 *
 * Certificates are parsed from META-INF signature blocks. Their cryptographic signatures are NOT
 * verified, and the v2/v3 signing block is only detected, not parsed. Permission lists are reported
 * as declared; they are not used to classify an app as benign or malicious.
 */
object ApkMetadataExtractor {
    const val NAME = "apk-manifest"
    const val VERSION = "1.0.0"
    private const val SIG_BLOCK_MAGIC = "APK Sig Block 42"
    private val COMPONENTS = setOf("activity", "activity-alias", "service", "receiver", "provider")

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            val dir = ZipDirectoryReader.read(src, limits)
            if (dir.entries.any { it.flags and 1 != 0 }) sink.note("Package contains encrypted entries; those parts were not read.")
            val manifestBytes = ZipEntryReader.read(src, dir, "AndroidManifest.xml", limits.maxMetadataSegmentBytes * 16)
                ?: throw FormatException("AndroidManifest.xml missing")
            parseManifest(manifestBytes, sink, limits)
            signers(src, dir, sink, limits)
            structure(src, dir, sink)
        }
    }

    private fun parseManifest(bytes: ByteArray, sink: MetadataSink, limits: AnalysisLimits) {
        val events = Axml.parse(bytes)
        val stack = ArrayList<String>()
        var pkg = ""
        var currentComponent: Pair<String, MutableMap<String, Any>>? = null
        var inIntentFilter = false
        for (ev in events) {
            when (ev) {
                is Axml.Event.Start -> {
                    val a = ev.attrs
                    val parent = stack.lastOrNull()
                    stack += ev.name
                    when (ev.name) {
                        "manifest" -> {
                            pkg = a["package"] ?: ""
                            sink.add("APK.manifest", "Package", cleanText(pkg, 256))
                            a["android:versionCode"]?.let { sink.add("APK.manifest", "VersionCode", it) }
                            a["android:versionName"]?.let { sink.add("APK.manifest", "VersionName", cleanText(it, limits.maxStringValueLength)) }
                            a["android:sharedUserId"]?.let { sink.add("APK.manifest", "SharedUserId", cleanText(it, 256)) }
                        }
                        "uses-sdk" -> {
                            a["android:minSdkVersion"]?.let { sink.add("APK.sdk", "MinSdkVersion", it) }
                            a["android:targetSdkVersion"]?.let { sink.add("APK.sdk", "TargetSdkVersion", it) }
                            a["android:maxSdkVersion"]?.let { sink.add("APK.sdk", "MaxSdkVersion", it) }
                        }
                        "uses-permission", "uses-permission-sdk-23" -> {
                            val n = a["android:name"] ?: "(unnamed)"
                            val max = a["android:maxSdkVersion"]?.let { " maxSdk=$it" } ?: ""
                            sink.add("APK.permission", "uses-permission", cleanText(n, 256) + max)
                        }
                        "uses-feature" -> sink.add("APK.feature", a["android:name"] ?: "(unnamed)",
                            "required=${a["android:required"] ?: "true"}")
                        "application" -> {
                            a["android:name"]?.let { sink.add("APK.application", "ApplicationClass", expand(it, pkg)) }
                            a["android:label"]?.let { sink.add("APK.application", "Label", cleanText(it, 256)) }
                            a["android:debuggable"]?.let { sink.add("APK.application", "Debuggable", it) }
                            a["android:allowBackup"]?.let { sink.add("APK.application", "AllowBackup", it) }
                            a["android:usesCleartextTraffic"]?.let { sink.add("APK.application", "UsesCleartextTraffic", it) }
                        }
                        "intent-filter" -> if (currentComponent != null) inIntentFilter = true
                        "action", "category" -> if (inIntentFilter && currentComponent != null) {
                            @Suppress("UNCHECKED_CAST") val list = currentComponent.second.getOrPut(ev.name + "s") { mutableListOf<String>() } as MutableList<String>
                            list += a["android:name"] ?: ""
                        }
                        else -> if (ev.name in COMPONENTS && parent == "application") {
                            val name = expand(a["android:name"] ?: "(unnamed)", pkg)
                            val info = mutableMapOf<String, Any>(
                                "name" to name,
                                "exported" to (a["android:exported"] ?: "unset"),
                                "permission" to (a["android:permission"] ?: ""),
                            )
                            currentComponent = ev.name to info
                        }
                    }
                }
                is Axml.Event.End -> {
                    if (ev.name == "intent-filter") inIntentFilter = false
                    if (ev.name in COMPONENTS && currentComponent != null) {
                        val (type, info) = currentComponent
                        val actions = (info["actions"] as? List<*>)?.joinToString(",") ?: ""
                        val cats = (info["categorys"] as? List<*>)?.joinToString(",") ?: ""
                        val launcher = cats.contains("android.intent.category.LAUNCHER")
                        val text = "${info["name"]} exported=${info["exported"]}" +
                            (if (info["permission"] != "") " permission=${info["permission"]}" else "") +
                            (if (actions.isNotEmpty()) " actions=[$actions]" else "") +
                            (if (launcher) " launcher=yes" else "")
                        sink.add("APK.component", type, cleanText(text, limits.maxStringValueLength))
                        currentComponent = null
                    }
                    if (stack.isNotEmpty()) stack.removeAt(stack.size - 1)
                }
            }
        }
        if (pkg.isEmpty()) sink.note("Manifest does not declare a package attribute.")
    }

    /** Relative component names (".Main") are expanded with the package; other names are shown as declared. */
    private fun expand(name: String, pkg: String): String =
        if (name.startsWith(".") && pkg.isNotEmpty()) pkg + name else name

    private fun signers(src: BoundedFile, dir: ZipDirectory, sink: MetadataSink, limits: AnalysisLimits) {
        val cf = CertificateFactory.getInstance("X.509")
        val certEntries = dir.entries.filter {
            it.name.startsWith("META-INF/") && (it.name.endsWith(".RSA") || it.name.endsWith(".DSA") || it.name.endsWith(".EC"))
        }
        if (certEntries.isEmpty()) sink.note("No signature block found in META-INF (package may be unsigned or signed with v2/v3 only).")
        for (e in certEntries) {
            try {
                val bytes = ZipEntryReader.read(src, dir, e.name, limits.maxMetadataSegmentBytes) ?: continue
                val certs = cf.generateCertificates(ByteArrayInputStream(bytes))
                for (c in certs) {
                    if (c is X509Certificate) certFields(c, sink)
                }
            } catch (ex: FormatException) {
                sink.error("${e.name}: ${ex.message}")
            } catch (ex: java.security.cert.CertificateException) {
                sink.error("${e.name}: certificate block could not be parsed")
            }
        }
        if (certEntries.isNotEmpty()) sink.note("Signer certificates were parsed; cryptographic verification of signatures was NOT performed.")
    }

    private fun certFields(c: X509Certificate, sink: MetadataSink) {
        val fmt = DateTimeFormatter.ISO_INSTANT
        sink.add("APK.signer", "Subject", c.subjectX500Principal.name)
        sink.add("APK.signer", "Issuer", c.issuerX500Principal.name)
        sink.add("APK.signer", "SerialNumber", c.serialNumber.toString(16))
        sink.add("APK.signer", "NotBefore", fmt.format(c.notBefore.toInstant().atOffset(ZoneOffset.UTC).toInstant()))
        sink.add("APK.signer", "NotAfter", fmt.format(c.notAfter.toInstant().atOffset(ZoneOffset.UTC).toInstant()))
        val fp = MessageDigest.getInstance("SHA-256").digest(c.encoded).joinToString(":") { "%02X".format(it) }
        sink.add("APK.signer", "SHA256Fingerprint", fp)
    }

    private fun structure(src: BoundedFile, dir: ZipDirectory, sink: MetadataSink) {
        val dex = dir.entries.count { it.name.matches(Regex("classes\\d*\\.dex")) }
        sink.add("structure", "DexFileCount", dex.toString())
        val libs = dir.entries.map { it.name }.filter { it.startsWith("lib/") && it.endsWith(".so") }
        if (libs.isNotEmpty()) {
            val abis = libs.map { it.split('/').getOrNull(1) ?: "" }.distinct().sorted()
            sink.add("structure", "NativeLibraryAbis", abis.joinToString(", "))
            sink.add("structure", "NativeLibraryCount", libs.size.toString())
        }
        val cdStart = dir.centralDirectoryStart
        val magicAt = cdStart - 16
        val hasBlock = magicAt >= 0 && runCatching {
            String(src.read(magicAt, 16), Charsets.ISO_8859_1) == SIG_BLOCK_MAGIC
        }.getOrDefault(false)
        sink.add("structure", "SigningBlockV2V3Present", if (hasBlock) "yes (located, not verified)" else "no")
    }
}
