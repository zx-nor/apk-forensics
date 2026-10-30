package forensics.identify

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.Finding
import forensics.common.FormatException
import forensics.common.Severity
import forensics.common.u32
import java.io.File

/**
 * Bytes that follow a format's logical end marker.
 *
 * [zeroPadding] is true when all trailing bytes are 0x00, which many writers add for alignment.
 * Such padding is reported but is not treated as hidden content.
 */
data class AppendedData(
    val formatId: String,
    val structureEnd: Long,
    val trailingBytes: Long,
    val zeroPadding: Boolean,
    val method: String,
    val confidence: Confidence,
    val uncertainty: List<String>,
    val findings: List<Finding>,
)

/**
 * Detects data after the structural end of a format: PNG after IEND, JPEG after the last EOI
 * marker, PDF after the last %%EOF, and WAV beyond its RIFF size. Each check is format-specific.
 */
class AppendedDataDetector(private val limits: AnalysisLimits = AnalysisLimits()) {

    fun detect(file: File, formatId: String?): AppendedData? = BoundedFile(file).use { src ->
        when (formatId) {
            "png" -> png(src)
            "jpeg" -> jpeg(src)
            "pdf" -> pdf(src)
            "wav" -> wav(src)
            else -> null
        }
    }

    private fun png(src: BoundedFile): AppendedData? {
        val s = PngChunks.walk(src)
        val iend = s.iendEnd
        if (iend == null) {
            return AppendedData("png", src.length, 0, false, "PNG chunk walk", Confidence.NONE, listOf(s.error ?: "IEND not found"),
                listOf(Finding("PNG_STRUCTURE_INCOMPLETE", Severity.ERROR, s.error ?: "IEND chunk not found")))
        }
        return build("png", iend, src, "PNG IEND chunk", Confidence.HIGH, emptyList())
    }

    private fun jpeg(src: BoundedFile): AppendedData? {
        val lastEoi = lastIndexOfMarker(src, 0xFF.toByte(), 0xD9.toByte()) ?: return AppendedData(
            "jpeg", 0, 0, false, "JPEG EOI scan", Confidence.NONE, listOf("No EOI marker found."),
            listOf(Finding("JPEG_EOI_MISSING", Severity.ERROR, "No end-of-image marker (FF D9) was found; file may be truncated.")))
        return build("jpeg", lastEoi + 2, src, "last JPEG EOI marker", Confidence.MEDIUM,
            listOf("If the appended data itself contains FF D9, the boundary may be placed inside it."))
    }

    private fun pdf(src: BoundedFile): AppendedData? {
        val pat = "%%EOF".toByteArray(Charsets.ISO_8859_1)
        val hits = indicesOf(src, pat)
        if (hits.isEmpty()) return AppendedData("pdf", 0, 0, false, "PDF %%EOF scan", Confidence.NONE,
            listOf("No %%EOF marker found."), listOf(Finding("PDF_EOF_MISSING", Severity.ERROR, "No %%EOF marker found.")))
        val last = hits.last()
        val end = last + pat.size
        val rest = src.length - end
        val tail = if (rest > 0) String(src.read(end, minOf(rest, 4096L).toInt()), Charsets.ISO_8859_1) else ""
        val findings = mutableListOf<Finding>()
        val onlyWhitespace = tail.all { it == '\r' || it == '\n' || it == ' ' || it == '\t' || it == '\u0000' }
        if (hits.size > 1) {
            findings += Finding("PDF_INCREMENTAL_UPDATES", Severity.NOTE,
                "The file contains ${hits.size} %%EOF markers, consistent with incremental updates.")
        }
        if (onlyWhitespace) return build("pdf", end, src, "last %%EOF marker", Confidence.HIGH, emptyList(), findings)
        if (tail.contains("xref") || tail.contains("startxref") || tail.contains(" obj")) {
            findings += Finding("PDF_INCREMENTAL_UPDATE_SECTION", Severity.NOTE,
                "Data after the last %%EOF contains cross-reference or object syntax, consistent with an incremental update.")
            return build("pdf", end, src, "last %%EOF marker", Confidence.MEDIUM,
                listOf("Trailing section looks like an incremental update, not arbitrary appended data."), findings)
        }
        return build("pdf", end, src, "last %%EOF marker", Confidence.HIGH,
            listOf("Trailing bytes contain no PDF object syntax; they may be appended payload."), findings)
    }

    private fun wav(src: BoundedFile): AppendedData? {
        if (src.length < 12) return null
        val hdr = src.read(0, 12)
        if (String(hdr, 0, 4, Charsets.ISO_8859_1) != "RIFF" || String(hdr, 8, 4, Charsets.ISO_8859_1) != "WAVE") return null
        val riff = u32(hdr, 4)
        val expected = riff + 8
        val findings = mutableListOf<Finding>()
        if (expected > src.length) {
            findings += Finding("RIFF_SIZE_EXCEEDS_FILE", Severity.ERROR,
                "RIFF size declares $expected bytes; file has ${src.length}. File is truncated.")
            return AppendedData("wav", src.length, 0, false, "RIFF size field", Confidence.HIGH, emptyList(), findings)
        }
        return build("wav", expected, src, "RIFF size field", Confidence.HIGH, emptyList(), findings)
    }

    private fun build(
        formatId: String, end: Long, src: BoundedFile, method: String, confidence: Confidence,
        uncertainty: List<String>, extra: List<Finding> = emptyList(),
    ): AppendedData {
        val trailing = src.length - end
        if (trailing <= 0) {
            return AppendedData(formatId, end, 0, false, method, confidence, uncertainty, extra)
        }
        val zeros = isAllZero(src, end, trailing)
        val findings = extra.toMutableList()
        if (zeros) {
            findings += Finding("TRAILING_ZERO_PADDING", Severity.INFO,
                "$trailing trailing bytes after $method are all zero (padding).")
        } else {
            findings += Finding("APPENDED_DATA", Severity.SUSPICIOUS,
                "$trailing bytes follow the end of the $formatId structure ($method).")
        }
        return AppendedData(formatId, end, trailing, zeros, method, confidence, uncertainty, findings)
    }

    private fun isAllZero(src: BoundedFile, from: Long, count: Long): Boolean {
        var done = 0L
        while (done < count) {
            val n = minOf(64 * 1024L, count - done).toInt()
            val b = src.read(from + done, n)
            if (b.any { it != 0.toByte() }) return false
            done += n
        }
        return true
    }

    private fun lastIndexOfMarker(src: BoundedFile, a: Byte, b: Byte): Long? {
        var last: Long? = null
        var prev: Byte? = null
        var pos = 0L
        val scanned = minOf(src.length, limits.maxEmbeddedScanBytes)
        while (pos < scanned) {
            val n = minOf(64 * 1024L, scanned - pos).toInt()
            val buf = src.read(pos, n)
            for (i in buf.indices) {
                if (buf[i] == b && (if (i > 0) buf[i - 1] else prev) == a) {
                    last = pos + i - 1
                }
            }
            prev = buf[buf.size - 1]
            pos += n
        }
        return last
    }

    private fun indicesOf(src: BoundedFile, pat: ByteArray): List<Long> {
        val out = mutableListOf<Long>()
        val overlap = pat.size - 1
        var pos = 0L
        var carry = ByteArray(0)
        val scanned = minOf(src.length, limits.maxEmbeddedScanBytes)
        while (pos < scanned) {
            val n = minOf(64 * 1024L, scanned - pos).toInt()
            val buf = carry + src.read(pos, n)
            val base = pos - carry.size
            for (i in 0..buf.size - pat.size) {
                var ok = true
                for (k in pat.indices) if (buf[i + k] != pat[k]) { ok = false; break }
                if (ok) {
                    val abs = base + i
                    if (out.isEmpty() || out.last() != abs) out += abs
                }
            }
            carry = if (buf.size >= overlap) buf.copyOfRange(buf.size - overlap, buf.size) else buf
            pos += n
        }
        return out
    }
}
