package forensics.archive

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.EngineInfo
import forensics.common.Finding
import forensics.common.FormatException
import forensics.common.Severity
import forensics.common.u16
import forensics.common.u32
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.util.zip.CRC32
import java.util.zip.DataFormatException
import java.util.zip.Inflater

enum class MeasurementStatus {
    COMPLETE,
    CAPPED_ENTRY_LIMIT,
    CAPPED_BUDGET,
    NOT_MEASURED_ENCRYPTED,
    NOT_MEASURED_UNSUPPORTED_METHOD,
    DATA_TRUNCATED,
    DECOMPRESSION_ERROR,
}

data class EncryptionInfo(val scheme: String, val strengthBits: Int?, val actualMethod: Int?, val supported: Boolean)

data class ZipEntryReport(
    val index: Int,
    val name: String,
    val isDirectory: Boolean,
    val method: Int,
    val methodName: String,
    val encryption: EncryptionInfo?,
    val compressedSize: Long,
    val declaredUncompressedSize: Long,
    val localHeaderOffset: Long,
    val dataOffset: Long?,
    val measuredUncompressedSize: Long?,
    val measurement: MeasurementStatus,
    val crc32Declared: Long,
    val crc32Computed: Long?,
    val compressionRatio: Double?,
    val isSymlink: Boolean,
    val symlinkTarget: String?,
    val unixMode: Int?,
    val nestedKind: String?,
    val nested: ZipAnalysis?,
    val findings: List<Finding>,
)

data class ZipAnalysis(
    val engineName: String,
    val engineVersion: String,
    val javaRuntime: String,
    val fileLength: Long,
    val depth: Int,
    val classification: Classification,
    val entries: List<ZipEntryReport>,
    val archiveFindings: List<Finding>,
    val declaredEntryCount: Long,
    val zip64: Boolean,
    val prependedBytes: Long,
    val trailingBytes: Long,
    val signingBlockPresent: Boolean,
    val parseError: String?,
)

/** Shared across nested analyses so a crafted archive cannot exhaust the inspection budget by nesting. */
class InspectionBudget(limits: AnalysisLimits) {
    var remainingBytes: Long = limits.maxTotalInspectionBytes
    var nestedArchives: Int = 0
}

/**
 * Analyzes a ZIP-based file: enumerates entries, verifies local headers, checks paths,
 * measures real decompressed sizes and CRCs within limits, and recurses into nested ZIPs.
 *
 * Nothing in the archive is executed. Extracted content exists only as bounded temporary
 * files for nested inspection and is deleted afterwards.
 */
class ZipAnalyzer(
    private val limits: AnalysisLimits = AnalysisLimits(),
    private val scratchDir: File = File(System.getProperty("java.io.tmpdir")),
) {
    init { require(scratchDir.isDirectory) { "scratch directory does not exist: $scratchDir" } }

    fun analyze(file: File): ZipAnalysis = analyzeInternal(file, 0, InspectionBudget(limits))

    internal fun analyzeInternal(file: File, depth: Int, budget: InspectionBudget): ZipAnalysis {
        try {
            return analyzeChecked(file, depth, budget)
        } catch (e: RuntimeException) {
            // A defect must never escape as a crash on evidence; it is recorded as a failed analysis.
            return failure(file.length(), depth, "internal engine error (${e.javaClass.simpleName}): ${e.message ?: "no message"}")
        }
    }

    private fun analyzeChecked(file: File, depth: Int, budget: InspectionBudget): ZipAnalysis {
        BoundedFile(file).use { src ->
            val dir = try {
                ZipDirectoryReader.read(src, limits)
            } catch (e: FormatException) {
                return failure(src.length, depth, e.message ?: "malformed ZIP structure")
            }
            val findings = dir.findings.toMutableList()
            val reports = dir.entries.map { inspectEntry(src, dir, it, depth, budget) }

            val dupes = dir.entries.groupBy { it.name }.filter { it.value.size > 1 }.keys
            for (d in dupes) {
                findings += Finding("DUPLICATE_ENTRY_NAME", Severity.SUSPICIOUS,
                    "Entry name appears more than once in the central directory.", d)
            }

            val eocdEnd = dir.eocdPosition + 22 + dir.eocdCommentLength
            val trailing = src.length - eocdEnd
            if (trailing > 0) {
                findings += Finding("TRAILING_DATA_AFTER_ARCHIVE", Severity.SUSPICIOUS,
                    "$trailing bytes follow the end of the ZIP archive.")
            } else if (trailing < 0) {
                findings += Finding("EOCD_COMMENT_OVERRUNS_FILE", Severity.ERROR,
                    "End-of-central-directory comment length exceeds the file by ${-trailing} bytes.")
            }

            val signingBlock = hasApkSigningBlock(src, dir)
            val classification = ZipClassifier.classify(dir.entries.map { it.name })
            if (classification.kind == PackageKind.APK && signingBlock) {
                findings += Finding("APK_SIGNING_BLOCK_PRESENT", Severity.NOTE,
                    "APK Signature Scheme v2/v3 block is present. The block was located but its signatures were not cryptographically verified.")
            }

            return ZipAnalysis(
                engineName = EngineInfo.NAME, engineVersion = EngineInfo.VERSION, javaRuntime = EngineInfo.javaRuntime,
                fileLength = src.length, depth = depth, classification = classification,
                entries = reports, archiveFindings = findings, declaredEntryCount = dir.declaredEntryCount,
                zip64 = dir.zip64, prependedBytes = dir.prependedBytes, trailingBytes = maxOf(trailing, 0L),
                signingBlockPresent = signingBlock, parseError = dir.parseError,
            )
        }
    }

    private fun failure(len: Long, depth: Int, msg: String) = ZipAnalysis(
        EngineInfo.NAME, EngineInfo.VERSION, EngineInfo.javaRuntime, len, depth,
        Classification(PackageKind.NOT_ZIP, forensics.identify.Confidence.NONE, emptyList(),
            listOf("Structure could not be parsed as ZIP.")),
        emptyList(),
        listOf(Finding("ZIP_STRUCTURE_INVALID", Severity.ERROR, msg)),
        0L, false, 0L, 0L, false, msg,
    )

    private fun hasApkSigningBlock(src: BoundedFile, dir: ZipDirectory): Boolean {
        val magicPos = dir.centralDirectoryStart - 16
        if (magicPos < 0) return false
        return try {
            String(src.read(magicPos, 16), Charsets.ISO_8859_1) == "APK Sig Block 42"
        } catch (_: FormatException) { false }
    }

    private fun inspectEntry(src: BoundedFile, dir: ZipDirectory, e: RawZipEntry, depth: Int, budget: InspectionBudget): ZipEntryReport {
        val findings = mutableListOf<Finding>()
        val isDir = e.name.endsWith("/")
        findings += PathChecks.check(e.name)

        val madeOnUnix = (e.versionMadeBy ushr 8) == 3
        val unixMode = if (madeOnUnix) ((e.externalAttributes ushr 16) and 0xFFFF).toInt() else null
        val isSymlink = unixMode != null && (unixMode and 0xF000) == 0xA000

        val encryption = encryptionOf(e)
        val methodName = MethodNames.of(e.method)

        // Local header verification.
        val localPos = dir.prependedBytes + e.localHeaderOffset
        var dataOffset: Long? = null
        val lh = localHeader(src, localPos, e, findings)
        if (lh != null) dataOffset = lh

        val report: ZipEntryReport = if (dataOffset == null) {
            ZipEntryReport(e.index, e.name, isDir, e.method, methodName, encryption, e.compressedSize,
                e.uncompressedSize, e.localHeaderOffset, null, null, MeasurementStatus.DATA_TRUNCATED,
                e.crc32, null, null, isSymlink, null, unixMode, null, null, findings)
        } else {
            measureEntry(src, e, dataOffset, encryption, methodName, isSymlink, unixMode, isDir, depth, budget, findings)
        }
        return report
    }

    /** Returns the file offset of entry data if the local header is valid and in range; otherwise null. */
    private fun localHeader(src: BoundedFile, pos: Long, e: RawZipEntry, findings: MutableList<Finding>): Long? {
        if (pos < 0 || pos + 30 > src.length) {
            findings += Finding("LOCAL_HEADER_OUT_OF_RANGE", Severity.ERROR,
                "Local header offset $pos lies outside the file.", e.name)
            return null
        }
        val hdr = src.read(pos, 30)
        if (u32(hdr, 0) != 0x04034b50L) {
            findings += Finding("LOCAL_HEADER_INVALID", Severity.ERROR,
                "No local file header signature at offset $pos.", e.name)
            return null
        }
        val lflags = u16(hdr, 6)
        val lmethod = u16(hdr, 8)
        val nlen = u16(hdr, 26)
        val elen = u16(hdr, 28)
        if (pos + 30 + nlen > src.length) {
            findings += Finding("LOCAL_HEADER_OUT_OF_RANGE", Severity.ERROR, "Local name field exceeds file.", e.name)
            return null
        }
        val localName = ZipDirectoryReader.decodeName(src.read(pos + 30, nlen), lflags)
        if (localName != e.name) {
            findings += Finding("LOCAL_NAME_MISMATCH", Severity.SUSPICIOUS,
                "Local header name '$localName' differs from central directory name '${e.name}'.", e.name)
        }
        if ((lflags and 1) != (e.flags and 1)) {
            findings += Finding("ENCRYPTION_FLAG_MISMATCH", Severity.SUSPICIOUS,
                "Encryption flag differs between local and central headers.", e.name)
        }
        if (lmethod != e.method) {
            findings += Finding("METHOD_MISMATCH", Severity.SUSPICIOUS,
                "Compression method differs between local ($lmethod) and central (${e.method}) headers.", e.name)
        }
        val dataStart = pos + 30 + nlen + elen
        if (dataStart + e.compressedSize > src.length) {
            findings += Finding("ENTRY_DATA_TRUNCATED", Severity.ERROR,
                "Declared compressed size (${e.compressedSize}) extends beyond end of file.", e.name)
            return null
        }
        return dataStart
    }

    private fun encryptionOf(e: RawZipEntry): EncryptionInfo? {
        if (e.flags and 1 == 0) return null
        if (e.method == 99) {
            val strength = aesStrength(e.extra)
            val actual = aesActualMethod(e.extra)
            val bits = when (strength) { 1 -> 128; 2 -> 192; 3 -> 256; else -> null }
            return EncryptionInfo("WINZIP_AES", bits, actual, supported = false)
        }
        if (e.flags and 0x40 != 0) {
            return EncryptionInfo("PKWARE_STRONG", null, e.method, supported = false)
        }
        return EncryptionInfo("TRADITIONAL_PKWARE_ZIPCRYPTO", null, e.method, supported = false)
    }

    private fun aesStrength(extra: ByteArray): Int? = findExtra(extra, 0x9901)?.let { d ->
        if (d.size >= 7) d[4].toInt() and 0xFF else null
    }

    /** Extra data layout (7 bytes): vendor version (2), vendor id "AE" (2), strength (1), actual method (2). */
    private fun aesActualMethod(extra: ByteArray): Int? = findExtra(extra, 0x9901)?.let { d ->
        if (d.size >= 7) u16(d, 5) else null
    }

    private fun findExtra(extra: ByteArray, id: Int): ByteArray? {
        var p = 0
        while (p + 4 <= extra.size) {
            val hid = u16(extra, p)
            val size = u16(extra, p + 2)
            if (p + 4 + size > extra.size) return null
            if (hid == id) return extra.copyOfRange(p + 4, p + 4 + size)
            p += 4 + size
        }
        return null
    }

    private fun measureEntry(
        src: BoundedFile, e: RawZipEntry, dataOffset: Long, encryption: EncryptionInfo?, methodName: String,
        isSymlink: Boolean, unixMode: Int?, isDir: Boolean, depth: Int, budget: InspectionBudget,
        findings: MutableList<Finding>,
    ): ZipEntryReport {
        val common = { m: MeasurementStatus, measured: Long?, crc: Long?, ratio: Double?, link: String?, nestedKind: String?, nested: ZipAnalysis? ->
            ZipEntryReport(e.index, e.name, isDir, e.method, methodName, encryption, e.compressedSize,
                e.uncompressedSize, e.localHeaderOffset, dataOffset, measured, m, e.crc32, crc, ratio,
                isSymlink, link, unixMode, nestedKind, nested, findings)
        }

        if (encryption != null) {
            findings += Finding("ENCRYPTED_ENTRY", Severity.NOTE,
                "Entry is encrypted (${encryption.scheme}). Content was not decrypted or measured.", e.name)
            return common(MeasurementStatus.NOT_MEASURED_ENCRYPTED, null, null, null, null, null, null)
        }
        if (e.method != 0 && e.method != 8) {
            findings += Finding("UNSUPPORTED_COMPRESSION_METHOD", Severity.NOTE,
                "Compression method $methodName is not measured by this engine.", e.name)
            return common(MeasurementStatus.NOT_MEASURED_UNSUPPORTED_METHOD, null, null, null, null, null, null)
        }
        if (isDir) {
            return common(MeasurementStatus.COMPLETE, 0L, 0L, null, null, null, null)
        }

        // Pass 1: measure size and CRC, capturing the first 512 bytes for signature checks.
        val head = ByteArrayOutputStream()
        val pass1 = stream(src, dataOffset, e.compressedSize, e.method, budget, null, head)
        val ratio = when {
            pass1.produced == 0L -> 0.0
            e.compressedSize == 0L -> Double.POSITIVE_INFINITY
            else -> pass1.produced.toDouble() / e.compressedSize.toDouble()
        }

        if (isSymlink) {
            val target = String(head.toByteArray(), Charsets.UTF_8).take(4096)
            findings += Finding("SYMLINK_ENTRY", Severity.NOTE, "Symbolic link to '$target'. The link was not followed.", e.name)
            findings += PathChecks.check(target, "symlink target")
        }

        val nestedKind = NestedDetector.kindOf(head.toByteArray())
        if (nestedKind != null) {
            findings += Finding("NESTED_ARCHIVE", Severity.NOTE,
                "Content begins with a $nestedKind signature.", e.name)
        }

        if (pass1.error != null) {
            findings += Finding("DECOMPRESSION_ERROR", Severity.ERROR, pass1.error, e.name)
            return common(MeasurementStatus.DECOMPRESSION_ERROR, pass1.produced, null, ratio, null, nestedKind, null)
        }

        val status = when {
            pass1.complete -> MeasurementStatus.COMPLETE
            pass1.budgetCapped -> MeasurementStatus.CAPPED_BUDGET
            pass1.capped -> MeasurementStatus.CAPPED_ENTRY_LIMIT
            else -> MeasurementStatus.DATA_TRUNCATED
        }

        if (status == MeasurementStatus.DATA_TRUNCATED) {
            findings += Finding("ENTRY_STREAM_ENDED_EARLY", Severity.ERROR,
                "Compressed stream ended before its declared end.", e.name)
        }
        if (status == MeasurementStatus.CAPPED_ENTRY_LIMIT) {
            findings += Finding("ENTRY_INSPECTION_LIMIT", Severity.SUSPICIOUS,
                "Decompressed output exceeded the per-entry inspection limit (${limits.maxEntryInspectionBytes} bytes). Measurement is partial.", e.name)
        }
        if (status == MeasurementStatus.CAPPED_BUDGET) {
            findings += Finding("INSPECTION_BUDGET_EXHAUSTED", Severity.SUSPICIOUS,
                "Total inspection budget was exhausted before this entry finished. Measurement is partial.", e.name)
        }

        if (status == MeasurementStatus.COMPLETE) {
            if (e.uncompressedSize != 0xFFFFFFFFL && e.uncompressedSize != pass1.produced) {
                findings += Finding("DECLARED_SIZE_MISMATCH", Severity.SUSPICIOUS,
                    "Declared uncompressed size ${e.uncompressedSize} differs from measured ${pass1.produced}.", e.name)
            }
            if (pass1.crc != e.crc32) {
                findings += Finding("CRC_MISMATCH", Severity.ERROR,
                    "Computed CRC-32 %08X differs from declared %08X.".format(pass1.crc, e.crc32), e.name)
            }
            if (pass1.produced >= limits.minBombOutputBytes && (ratio > limits.maxCompressionRatio || ratio.isInfinite())) {
                findings += Finding("EXCESSIVE_COMPRESSION_RATIO", Severity.SUSPICIOUS,
                    "Measured expansion ratio is ${if (ratio.isInfinite()) "undefined (zero compressed bytes)" else "%.1f:1".format(ratio)}, " +
                        "above the threshold of ${limits.maxCompressionRatio}:1.", e.name)
            }
        }

        var nested: ZipAnalysis? = null
        if (nestedKind == "ZIP" && status == MeasurementStatus.COMPLETE) {
            if (depth + 1 > limits.maxNestingDepth) {
                findings += Finding("NESTING_LIMIT_REACHED", Severity.SUSPICIOUS,
                    "Nested archive not inspected: depth limit ${limits.maxNestingDepth} reached.", e.name)
            } else if (pass1.produced > limits.maxNestedArchiveBytes) {
                findings += Finding("NESTED_ARCHIVE_TOO_LARGE", Severity.NOTE,
                    "Nested archive (${pass1.produced} bytes) exceeds the nested inspection size limit; not inspected.", e.name)
            } else {
                nested = inspectNested(src, dataOffset, e, depth, budget, findings)
            }
        }

        // A CRC is a checksum of the whole entry. It is reported only when the entry was measured completely.
        val crcForReport = if (status == MeasurementStatus.COMPLETE) pass1.crc else null
        return common(status, pass1.produced, crcForReport, ratio, if (isSymlink) String(head.toByteArray(), Charsets.UTF_8).take(4096) else null, nestedKind, nested)
    }

    private fun inspectNested(src: BoundedFile, dataOffset: Long, e: RawZipEntry, depth: Int, budget: InspectionBudget, findings: MutableList<Finding>): ZipAnalysis? {
        budget.nestedArchives++
        val tmp = File.createTempFile("bbf-nested-", ".zip", scratchDir)
        return try {
            FileOutputStream(tmp).use { out ->
                stream(src, dataOffset, e.compressedSize, e.method, budget, out, null)
            }
            analyzeInternal(tmp, depth + 1, budget)
        } catch (ex: FormatException) {
            findings += Finding("NESTED_ARCHIVE_INVALID", Severity.ERROR, ex.message ?: "nested archive invalid", e.name)
            null
        } finally {
            tmp.delete()
        }
    }

    private class StreamResult(
        val produced: Long, val crc: Long, val complete: Boolean, val capped: Boolean,
        val budgetCapped: Boolean, val error: String?,
    )

    /**
     * Streams one entry's decompressed bytes through CRC and an optional sink.
     * Output is capped by both the per-entry limit and the remaining total budget.
     */
    private fun stream(
        src: BoundedFile, dataOffset: Long, compSize: Long, method: Int, budget: InspectionBudget,
        sink: java.io.OutputStream?, head: ByteArrayOutputStream?,
    ): StreamResult {
        val entryCap = limits.maxEntryInspectionBytes
        val effectiveCap = minOf(entryCap, budget.remainingBytes)
        val budgetLimited = effectiveCap < entryCap
        val crc = CRC32()
        var produced = 0L
        var complete = false
        var capped = false
        var error: String? = null
        val inflater = if (method == 8) Inflater(true) else null
        val inBuf = ByteArray(CHUNK)
        val outBuf = ByteArray(CHUNK)
        var inOffset = 0L
        var inRemaining = compSize

        fun emit(buf: ByteArray, n: Int): Boolean {
            var take = n.toLong()
            var stop = false
            if (produced + take > effectiveCap) {
                take = effectiveCap - produced
                stop = true
            }
            if (take > 0) {
                val t = take.toInt()
                crc.update(buf, 0, t)
                sink?.write(buf, 0, t)
                if (head != null && head.size() < HEAD_BYTES) {
                    head.write(buf, 0, minOf(t, HEAD_BYTES - head.size()))
                }
                produced += take
            }
            return !stop
        }

        try {
            if (inflater == null) {
                // Stored entry: copy bytes through the same accounting path.
                while (inRemaining > 0 && !capped) {
                    val n = minOf(inBuf.size.toLong(), inRemaining).toInt()
                    val chunk = src.read(dataOffset + inOffset, n)
                    inOffset += n
                    inRemaining -= n
                    if (!emit(chunk, n)) capped = true
                }
                complete = !capped && inRemaining == 0L
            } else {
                while (true) {
                    if (inflater.needsInput()) {
                        if (inRemaining == 0L) break
                        val n = minOf(inBuf.size.toLong(), inRemaining).toInt()
                        val chunk = src.read(dataOffset + inOffset, n)
                        inflater.setInput(chunk, 0, n)
                        inOffset += n
                        inRemaining -= n
                    }
                    val n = inflater.inflate(outBuf)
                    if (n > 0 && !emit(outBuf, n)) {
                        capped = true
                        break
                    }
                    if (inflater.finished()) {
                        complete = true
                        break
                    }
                    if (inflater.needsDictionary()) {
                        error = "deflate stream requires a preset dictionary"
                        break
                    }
                    if (n == 0 && inflater.needsInput() && inRemaining == 0L) break
                }
            }
        } catch (ex: DataFormatException) {
            error = "corrupt deflate stream: ${ex.message}"
        } finally {
            inflater?.end()
        }

        budget.remainingBytes -= produced
        val budgetCapped = capped && budgetLimited
        return StreamResult(produced, crc.value, complete && !capped, capped && !budgetCapped, budgetCapped, error)
    }

    companion object {
        private const val CHUNK = 64 * 1024
        private const val HEAD_BYTES = 512
    }
}

/** Human-readable names for ZIP compression method identifiers (APPNOTE 4.4.5). */
object MethodNames {
    fun of(method: Int): String = when (method) {
        0 -> "stored"
        1 -> "shrunk"
        6 -> "imploded"
        8 -> "deflate"
        9 -> "deflate64"
        12 -> "bzip2"
        14 -> "lzma"
        93 -> "zstd"
        95 -> "xz"
        98 -> "ppmd"
        99 -> "winzip-aes"
        else -> "unknown($method)"
    }
}

/** Detects common container signatures at the start of an entry. Used to flag nesting, never to execute. */
object NestedDetector {
    fun kindOf(head: ByteArray): String? = when {
        head.size >= 4 && head[0] == 0x50.toByte() && head[1] == 0x4B.toByte() &&
            (head[2] == 0x03.toByte() || head[2] == 0x05.toByte()) -> "ZIP"
        head.size >= 3 && head[0] == 0x1F.toByte() && head[1] == 0x8B.toByte() -> "GZIP"
        head.size >= 6 && head[0] == 0x37.toByte() && head[1] == 0x7A.toByte() && head[2] == 0xBC.toByte() &&
            head[3] == 0xAF.toByte() && head[4] == 0x27.toByte() && head[5] == 0x1C.toByte() -> "7Z"
        head.size >= 7 && String(head, 0, 7, Charsets.ISO_8859_1) == "Rar!\u001A\u0007\u0000" -> "RAR"
        head.size >= 8 && String(head, 0, 8, Charsets.ISO_8859_1) == "Rar!\u001A\u0007\u0001\u0000" -> "RAR"
        else -> null
    }
}
