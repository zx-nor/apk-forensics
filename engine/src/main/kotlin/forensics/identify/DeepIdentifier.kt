package forensics.identify

import forensics.archive.PackageKind
import forensics.archive.ZipAnalysis
import forensics.archive.ZipAnalyzer
import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.EngineInfo
import forensics.common.Finding
import forensics.common.FormatException
import forensics.common.Severity
import java.io.File

/** Complete identification of one file: base signature, refined format, structure, and anomalies. */
data class DeepIdentification(
    val engineVersion: String,
    val base: IdentificationResult,
    val refinedFormat: String?,
    val refinedDisplayName: String?,
    val refinedConfidence: Confidence,
    val refinedEvidence: List<String>,
    val extensionMismatch: Boolean,
    val zip: ZipAnalysis?,
    val appended: AppendedData?,
    val embedded: List<EmbeddedHit>,
    val findings: List<Finding>,
)

/**
 * Combines magic-byte identification with structural analysis.
 *
 * The base result comes from [FileIdentifier]. Container formats are then refined from their
 * internal structure: RIFF into WAV/WEBP, ISO base media into MP4/MOV/M4A/HEIC, and ZIP into
 * APK, JAR, DOCX, XLSX, PPTX, or plain ZIP. Extension mismatch is judged against the refined format.
 */
class DeepIdentifier(
    private val limits: AnalysisLimits = AnalysisLimits(),
    private val scratchDir: File = File(System.getProperty("java.io.tmpdir")),
) {
    private val base = FileIdentifier()
    private val zipAnalyzer = ZipAnalyzer(limits, scratchDir)
    private val appendedDetector = AppendedDataDetector(limits)
    private val embeddedScanner = EmbeddedScanner(limits)

    fun identify(file: File): DeepIdentification {
        require(file.isFile) { "not a regular file: $file" }
        val b = try { base.identify(file) } catch (e: FormatException) {
            throw IllegalStateException("base identification failed: ${e.message}", e)
        }
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<String>()
        var refined: String? = b.detectedFormatId
        var refinedName: String? = b.displayName
        var confidence = b.confidence

        var zip: ZipAnalysis? = null
        if (b.detectedFormatId == "zip") {
            zip = zipAnalyzer.analyze(file)
            val kind = zip.classification.kind
            refined = when (kind) {
                PackageKind.APK -> "apk"
                PackageKind.AAB -> "aab"
                PackageKind.JAR -> "jar"
                PackageKind.DOCX -> "docx"
                PackageKind.XLSX -> "xlsx"
                PackageKind.PPTX -> "pptx"
                PackageKind.ODF -> "odf"
                PackageKind.AMBIGUOUS_OFFICE_OR_APK -> "zip"
                PackageKind.NOT_ZIP -> "zip-invalid"
                PackageKind.ZIP -> "zip"
            }
            refinedName = when (refined) {
                "apk" -> "Android package (APK)"
                "aab" -> "Android App Bundle (AAB)"
                "jar" -> "Java archive (JAR)"
                "docx" -> "Word document (OOXML)"
                "xlsx" -> "Excel workbook (OOXML)"
                "pptx" -> "PowerPoint presentation (OOXML)"
                "odf" -> "OpenDocument container"
                "zip-invalid" -> "ZIP signature without valid ZIP structure"
                else -> "ZIP archive"
            }
            confidence = zip.classification.confidence
            evidence += "Structure: ${zip.classification.kind} from markers ${zip.classification.markers}."
            if (kind == PackageKind.AMBIGUOUS_OFFICE_OR_APK) findings += Finding(
                "AMBIGUOUS_CONTAINER", Severity.SUSPICIOUS,
                "Entry names match more than one container type. Classification is not reliable.")
            if (zip.parseError != null) findings += Finding("ZIP_STRUCTURE_INVALID", Severity.ERROR, zip.parseError)
        }

        if (b.detectedFormatId == "wav") {
            val tag = readTag(file, 8)
            when (tag) {
                "WAVE" -> { refined = "wav"; refinedName = "WAV audio (RIFF/WAVE)" }
                "WEBP" -> { refined = "webp"; refinedName = "WebP image" }
                "AVI " -> { refined = "avi"; refinedName = "AVI video (identified only; not analyzed)" }
                else -> { refined = "riff-unknown"; refinedName = "RIFF container (unknown form '$tag')" }
            }
            evidence += "RIFF form type '$tag' at offset 8."
        }

        if (b.detectedFormatId == "mp4") {
            val brand = readTag(file, 8)
            refined = when (brand) {
                "qt  " -> "mov"
                "M4A " -> "m4a"
                "heic", "heix", "mif1", "msf1", "heim", "heis" -> "heic"
                else -> "mp4"
            }
            refinedName = when (refined) {
                "mov" -> "QuickTime movie (MOV)"
                "m4a" -> "MPEG-4 audio (M4A)"
                "heic" -> "HEIF/HEIC image"
                else -> "MPEG-4 video (MP4)"
            }
            evidence += "ftyp major brand '$brand'."
            if (brand.isNotEmpty() && refined == "mp4" && brand !in KNOWN_MP4_BRANDS) {
                findings += Finding("UNRECOGNIZED_BRAND", Severity.NOTE,
                    "Major brand '$brand' is not in the brand table; classified as generic MP4.")
            }
        }

        if (b.detectedFormatId == null && zip == null) {
            // Unknown content; keep base result.
        }

        val appended: AppendedData? = when {
            zip != null -> null
            refined in setOf("png", "jpeg", "pdf", "wav") -> try {
                appendedDetector.detect(file, refined)
            } catch (e: FormatException) {
                findings += Finding("APPENDED_CHECK_FAILED", Severity.ERROR, e.message ?: "structure check failed")
                null
            }
            else -> null
        }
        appended?.findings?.let { findings += it }

        if (zip != null && zip.trailingBytes > 0) {
            findings += Finding("TRAILING_DATA_AFTER_ARCHIVE", Severity.SUSPICIOUS,
                "${zip.trailingBytes} bytes follow the ZIP end record.")
        }

        val embedded = embeddedScanner.scan(file)
        if (embedded.isNotEmpty()) {
            findings += Finding("EMBEDDED_SIGNATURES", Severity.NOTE,
                "${embedded.size} signature(s) found at non-zero offsets; these are leads, not confirmed embedded files.")
        }

        val mismatch = mismatch(file.name.substringAfterLast('.', "").lowercase().ifEmpty { null }, refined)
        if (mismatch) {
            findings += Finding("EXTENSION_MISMATCH", Severity.SUSPICIOUS,
                "File extension does not match the content (detected: ${refined ?: "unknown"}).")
        }
        if (refined == null) evidence += "No documented signature matched."

        return DeepIdentification(
            EngineInfo.VERSION, b, refined, refinedName, confidence, evidence,
            mismatch, zip, appended, embedded, findings + b.uncertainty.map {
                Finding("IDENTIFICATION_UNCERTAINTY", Severity.NOTE, it)
            },
        )
    }

    private fun readTag(file: File, offset: Long): String = BoundedFile(file).use { src ->
        if (src.length < offset + 4) "" else String(src.read(offset, 4), Charsets.ISO_8859_1)
    }

    companion object {
        private val KNOWN_MP4_BRANDS = setOf("isom", "mp41", "mp42", "avc1", "iso2", "iso5", "iso6", "M4V ", "dash", "3gp4", "3gp5")

        /** Extensions that conventionally name each refined format. Unknown extensions are never a mismatch. */
        private val EXPECTED: Map<String, Set<String>> = mapOf(
            "png" to setOf("png"),
            "jpeg" to setOf("jpg", "jpeg", "jpe"),
            "gif" to setOf("gif"),
            "pdf" to setOf("pdf"),
            "zip" to setOf("zip"),
            "zip-invalid" to setOf("zip"),
            "apk" to setOf("apk"),
            "aab" to setOf("aab"),
            "jar" to setOf("jar"),
            "docx" to setOf("docx", "docm", "dotx"),
            "xlsx" to setOf("xlsx", "xlsm", "xltx"),
            "pptx" to setOf("pptx", "pptm", "potx"),
            "odf" to setOf("odt", "ods", "odp", "odg"),
            "gzip" to setOf("gz", "tgz"),
            "7z" to setOf("7z"),
            "rar" to setOf("rar"),
            "wav" to setOf("wav"),
            "webp" to setOf("webp"),
            "avi" to setOf("avi"),
            "riff-unknown" to setOf("wav", "webp", "avi"),
            "mp4" to setOf("mp4", "m4v"),
            "mov" to setOf("mov", "qt"),
            "m4a" to setOf("m4a"),
            "heic" to setOf("heic", "heif"),
            "flac" to setOf("flac"),
            "mp3" to setOf("mp3"),
            "ogg" to setOf("ogg", "oga", "opus"),
            "sqlite3" to setOf("db", "sqlite", "sqlite3"),
            "pcap-le" to setOf("pcap", "cap"),
            "pcap-be" to setOf("pcap", "cap"),
            "pcapng" to setOf("pcapng"),
            "elf" to setOf("so", "elf", "o"),
            "tar-ustar" to setOf("tar"),
            "tiff-le" to setOf("tif", "tiff"),
            "tiff-be" to setOf("tif", "tiff"),
        )

        private val ALL_KNOWN: Set<String> = EXPECTED.values.flatten().toSet()

        /**
         * A mismatch is reported only when the extension names a known format and the detected
         * format is known, and the two differ. Unknown extensions and unidentified content are not mismatches.
         */
        fun mismatch(ext: String?, refined: String?): Boolean {
            if (ext == null || refined == null) return false
            val expected = EXPECTED[refined] ?: return false
            return ext in ALL_KNOWN && ext !in expected
        }
    }
}
