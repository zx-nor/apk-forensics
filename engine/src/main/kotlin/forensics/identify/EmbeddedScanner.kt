package forensics.identify

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import java.io.File

/** A signature found at a non-zero offset inside a file. Hits are leads, not identifications of embedded content. */
data class EmbeddedHit(val offset: Long, val formatId: String, val displayName: String, val confidence: Confidence)

/**
 * Streams a file looking for known signatures after offset 0.
 *
 * Carries an overlap between blocks so a signature split across a block boundary is found once.
 * Short signatures produce LOW confidence because they occur by chance in compressed data.
 */
class EmbeddedScanner(private val limits: AnalysisLimits = AnalysisLimits()) {

    private data class Pattern(val formatId: String, val name: String, val bytes: ByteArray)

    fun scan(file: File): List<EmbeddedHit> = BoundedFile(file).use { src -> scan(src) }

    fun scan(src: BoundedFile): List<EmbeddedHit> {
        val patterns = PATTERNS
        val maxLen = patterns.maxOf { it.bytes.size }
        val hits = mutableListOf<EmbeddedHit>()
        var carry = ByteArray(0)
        var pos = 0L
        val scanned = minOf(src.length, limits.maxEmbeddedScanBytes)
        while (pos < scanned && hits.size < limits.maxEmbeddedHits) {
            val n = minOf(BLOCK.toLong(), scanned - pos).toInt()
            val buf = carry + src.read(pos, n)
            val base = pos - carry.size
            for (p in patterns) {
                var i = 0
                while (i + p.bytes.size <= buf.size) {
                    if (matchesAt(buf, i, p.bytes)) {
                        val abs = base + i
                        // Matches wholly inside the carried overlap were already reported in the previous block.
                        if (i + p.bytes.size > carry.size && abs > 0) {
                            hits += EmbeddedHit(abs, p.formatId, p.name, confidenceFor(p.bytes.size))
                            if (hits.size >= limits.maxEmbeddedHits) break
                        }
                    }
                    i++
                }
                if (hits.size >= limits.maxEmbeddedHits) break
            }
            val keep = minOf(maxLen - 1, buf.size)
            carry = buf.copyOfRange(buf.size - keep, buf.size)
            pos += n
        }
        return hits.sortedBy { it.offset }
    }

    private fun matchesAt(buf: ByteArray, at: Int, pat: ByteArray): Boolean {
        for (k in pat.indices) if (buf[at + k] != pat[k]) return false
        return true
    }

    private fun confidenceFor(len: Int) = when {
        len >= 8 -> Confidence.HIGH
        len >= 4 -> Confidence.MEDIUM
        else -> Confidence.LOW
    }

    companion object {
        private const val BLOCK = 256 * 1024

        private fun p(id: String, name: String, vararg b: Int) = Pattern(id, name, ByteArray(b.size) { b[it].toByte() })
        private fun s(id: String, name: String, text: String) = Pattern(id, name, text.toByteArray(Charsets.ISO_8859_1))

        private val PATTERNS: List<Pattern> = listOf(
            p("png", "PNG image", 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A),
            p("zip", "ZIP local file header", 0x50, 0x4B, 0x03, 0x04),
            p("zip", "ZIP end-of-central-directory", 0x50, 0x4B, 0x05, 0x06),
            p("7z", "7-Zip archive", 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C),
            s("rar", "RAR archive", "Rar!\u001A\u0007"),
            s("pdf", "PDF document", "%PDF-"),
            s("gif", "GIF image", "GIF89a"),
            s("gif", "GIF image", "GIF87a"),
            p("elf", "ELF object", 0x7F, 0x45, 0x4C, 0x46),
            s("sqlite3", "SQLite 3 database", "SQLite format 3\u0000"),
            p("jpeg", "JPEG image", 0xFF, 0xD8, 0xFF),
            p("gzip", "GZIP stream", 0x1F, 0x8B, 0x08),
        )
    }
}
