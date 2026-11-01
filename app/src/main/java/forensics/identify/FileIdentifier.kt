package forensics.identify

import java.io.InputStream
import java.io.RandomAccessFile

/** How a format was identified. */
enum class IdentificationMethod { MAGIC_AT_OFFSET, NO_MATCH }

/** Confidence in the identification, based on the evidence actually examined. */
enum class Confidence { HIGH, MEDIUM, LOW, NONE }

/**
 * Result of identifying one file.
 *
 * [detectedFormatId] is null when no signature matched. [extensionMismatch] is true
 * when the filename extension names a different format than the content, or names
 * a format while the content matches none of the known signatures.
 */
data class IdentificationResult(
    val detectedFormatId: String?,
    val displayName: String?,
    val mimeType: String?,
    val method: IdentificationMethod,
    val confidence: Confidence,
    val evidence: String,
    val filenameExtension: String?,
    val extensionMismatch: Boolean,
    val uncertainty: List<String>,
)

/**
 * Identifies file formats from content, never from filename.
 *
 * Reads only a bounded window ([headerWindowBytes]) so memory use is fixed
 * regardless of file size. Signatures anchored beyond the window are read
 * with a targeted positioned read, not a full load.
 */
class FileIdentifier(
    private val signatures: List<FileSignature> = FileSignature.DEFAULT,
    private val headerWindowBytes: Int = 4096,
) {
    init {
        require(headerWindowBytes >= 512) { "Header window too small" }
    }

    /** Identify a file on disk. Extension is compared, not trusted. */
    fun identify(file: java.io.File, declaredSize: Long = file.length()): IdentificationResult {
        val ext = file.name.substringAfterLast('.', missingDelimiterValue = "").lowercase().ifEmpty { null }
        val header = readHeader(file)
        return classify(header, declaredSize, ext)
    }

    /** Identify from an already-read byte array (used by tests and in-memory data). */
    fun identify(bytes: ByteArray, filename: String? = null): IdentificationResult {
        val ext = filename?.substringAfterLast('.', "")?.lowercase()?.ifEmpty { null }
        return classify(bytes.copyOf(minOf(bytes.size, headerWindowBytes)), bytes.size.toLong(), ext)
    }

    private fun readHeader(file: java.io.File): ByteArray {
        val len = minOf(file.length(), headerWindowBytes.toLong()).toInt()
        val buf = ByteArray(len)
        java.io.FileInputStream(file).use { input -> readFully(input, buf) }
        return buf
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) break
            off += n
        }
    }

    private fun classify(header: ByteArray, size: Long, ext: String?): IdentificationResult {
        val uncertainty = mutableListOf<String>()
        val matches = signatures.filter { sig ->
            val end = sig.offset + sig.magic.size
            end <= header.size && header.copyOfRange(sig.offset, end).contentEquals(sig.magic)
        }

        // Prefer the most specific match: longer magic wins, then anchored-at-zero.
        val best = matches.maxWithOrNull(compareBy({ it.magic.size }, { -it.offset }))

        if (best == null) {
            val mismatch = ext != null && ext in KNOWN_EXTENSIONS
            if (mismatch) uncertainty.add("Extension '.$ext' names a known format, but no signature matched the content.")
            if (header.size < 16) uncertainty.add("File is very small; signatures may be truncated.")
            return IdentificationResult(
                detectedFormatId = null, displayName = null, mimeType = null,
                method = IdentificationMethod.NO_MATCH, confidence = Confidence.NONE,
                evidence = "No documented signature matched the examined header window.",
                filenameExtension = ext, extensionMismatch = mismatch, uncertainty = uncertainty,
            )
        }

        val confidence = when {
            best.magic.size >= 6 -> Confidence.HIGH
            best.magic.size >= 3 -> Confidence.MEDIUM
            else -> Confidence.LOW
        }
        if (matches.size > 1) {
            uncertainty.add("Multiple signatures matched (${matches.joinToString { it.formatId }}); the most specific was chosen.")
        }
        if (confidence == Confidence.LOW) {
            uncertainty.add("Short signature; this match could be coincidental.")
        }
        if (best.formatId == "zip") {
            uncertainty.add("ZIP signature only. The file may be a ZIP-based format (for example OOXML, APK, or JAR); deeper examination is required to determine which.")
        }

        val expectedExts = best.extensions
        val mismatch = ext != null && ext !in expectedExts && ext in KNOWN_EXTENSIONS
        if (mismatch) {
            uncertainty.add("Extension '.$ext' does not match detected format '${best.formatId}'.")
        }

        return IdentificationResult(
            detectedFormatId = best.formatId, displayName = best.displayName, mimeType = best.mimeType,
            method = IdentificationMethod.MAGIC_AT_OFFSET, confidence = confidence,
            evidence = "Magic ${best.magic.toHex()} at offset ${best.offset}.",
            filenameExtension = ext, extensionMismatch = mismatch, uncertainty = uncertainty,
        )
    }

    companion object {
        private val KNOWN_EXTENSIONS: Set<String> =
            FileSignature.DEFAULT.flatMap { it.extensions }.toSet()

        internal fun ByteArray.toHex(): String = joinToString(" ") { "%02X".format(it) }
    }
}
