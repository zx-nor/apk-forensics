package forensics.report

import forensics.archive.MeasurementStatus
import forensics.archive.ZipAnalysis
import forensics.binary.StringExtractor
import forensics.common.AnalysisLimits
import forensics.common.EngineInfo
import forensics.common.Finding
import forensics.hash.StreamingHasher
import forensics.identify.DeepIdentification
import forensics.identify.DeepIdentifier
import forensics.metadata.MetadataDispatcher
import forensics.metadata.MetadataResult
import java.io.File

/** Display-ready finding. All values are strings so the UI and any export format share one shape. */
data class FindingLine(val severity: String, val code: String, val message: String, val location: String?)

data class MetadataLine(val group: String, val key: String, val value: String)

data class EntryLine(
    val name: String,
    val method: String,
    val encryption: String?,
    val measurement: String,
    val declaredSize: Long,
    val measuredSize: Long?,
    val crcState: String,
    val nested: String?,
    val findings: List<FindingLine>,
)

/** Complete, display-ready analysis of one evidence file. */
data class AnalysisReport(
    val sourceName: String,
    val sourceBytes: Long,
    val sourceSha256: String,
    val workingCopySha256: String,
    val workingCopyMatchesSource: Boolean,
    val engineVersion: String,
    val javaRuntime: String,
    val refinedFormat: String?,
    val formatName: String?,
    val confidence: String,
    val identificationEvidence: List<String>,
    val extensionMismatch: Boolean,
    val findings: List<FindingLine>,
    val metadataStatus: String,
    val metadata: List<MetadataLine>,
    val metadataNotes: List<String>,
    val metadataErrors: List<String>,
    val zipKind: String?,
    val zipConfidence: String?,
    val zipParseError: String?,
    val zipEntryCount: Int,
    val zipEntries: List<EntryLine>,
    val zipEntriesShown: Int,
    val appendedBytes: Long,
    val appendedIsZeroPadding: Boolean,
    val embeddedHits: List<String>,
    val strings: List<String>,
)

/**
 * Runs the complete analysis on a working copy and returns a display-ready report.
 *
 * The working copy is the only file read by the engine. Its SHA-256 is recomputed here and compared
 * with the hash recorded when the copy was made, so a report states whether the analyzed bytes are
 * exactly the acquired bytes. The original evidence is never opened by this function.
 */
object ReportBuilder {
    const val MAX_ENTRIES_SHOWN = 500
    const val MAX_STRINGS = 300

    fun build(
        workingCopy: File,
        sourceName: String,
        sourceSha256: String,
        sourceBytes: Long,
        scratchDir: File,
        limits: AnalysisLimits = AnalysisLimits(),
    ): AnalysisReport {
        require(workingCopy.isFile) { "working copy missing: $workingCopy" }
        val workingHash = StreamingHasher.sha256(workingCopy).sha256Hex
        val d: DeepIdentification = DeepIdentifier(limits, scratchDir).identify(workingCopy)
        val meta: MetadataResult? = MetadataDispatcher.extract(workingCopy, d.refinedFormat, limits)
        val zip: ZipAnalysis? = d.zip

        val findings = mutableListOf<Finding>()
        findings += d.findings
        if (zip != null) {
            findings += zip.archiveFindings
            zip.entries.forEach { findings += it.findings }
        }

        val strings = StringExtractor(minLength = 6, maxResults = MAX_STRINGS)
            .extractAscii(workingCopy)
            .map { "%08X  %s".format(it.offset, it.text.take(200)) }

        val shownEntries = zip?.entries.orEmpty().take(MAX_ENTRIES_SHOWN)

        return AnalysisReport(
            sourceName = sourceName,
            sourceBytes = sourceBytes,
            sourceSha256 = sourceSha256,
            workingCopySha256 = workingHash,
            workingCopyMatchesSource = workingHash.equals(sourceSha256, ignoreCase = true) && workingCopy.length() == sourceBytes,
            engineVersion = EngineInfo.VERSION,
            javaRuntime = EngineInfo.javaRuntime,
            refinedFormat = d.refinedFormat,
            formatName = d.refinedDisplayName ?: d.base.displayName,
            confidence = d.refinedConfidence.name,
            identificationEvidence = d.refinedEvidence,
            extensionMismatch = d.extensionMismatch,
            findings = findings.map { it.toLine() },
            metadataStatus = meta?.status?.name ?: "NOT_APPLICABLE",
            metadata = meta?.fields.orEmpty().map { MetadataLine(it.group, it.key, it.value) },
            metadataNotes = meta?.notes.orEmpty(),
            metadataErrors = meta?.errors.orEmpty(),
            zipKind = zip?.classification?.kind?.name,
            zipConfidence = zip?.classification?.confidence?.name,
            zipParseError = zip?.parseError,
            zipEntryCount = zip?.entries?.size ?: 0,
            zipEntries = shownEntries.map { e ->
                EntryLine(
                    name = e.name,
                    method = e.methodName,
                    encryption = e.encryption?.let { enc ->
                        enc.scheme + (enc.strengthBits?.let { " $it-bit" } ?: "")
                    },
                    measurement = e.measurement.name,
                    declaredSize = e.declaredUncompressedSize,
                    measuredSize = e.measuredUncompressedSize,
                    crcState = when {
                        e.measurement != MeasurementStatus.COMPLETE -> "not verified"
                        e.crc32Computed == e.crc32Declared -> "match"
                        else -> "MISMATCH"
                    },
                    nested = e.nestedKind,
                    findings = e.findings.map { it.toLine() },
                )
            },
            zipEntriesShown = shownEntries.size,
            appendedBytes = d.appended?.trailingBytes ?: 0L,
            appendedIsZeroPadding = d.appended?.zeroPadding ?: false,
            embeddedHits = d.embedded.map { "${it.formatId} at offset ${it.offset} (${it.confidence.name.lowercase()} confidence)" },
            strings = strings,
        )
    }

    private fun Finding.toLine() = FindingLine(severity.name, code, message, location)
}
