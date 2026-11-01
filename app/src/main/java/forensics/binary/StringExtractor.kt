package forensics.binary

import java.io.File
import java.io.RandomAccessFile

/** A run of printable text found in binary data. */
data class FoundString(val offset: Long, val text: String, val encoding: Encoding)

enum class Encoding { ASCII, UTF16LE }

/**
 * Extracts printable strings, in the spirit of the standard `strings` utility.
 *
 * Streams the file in chunks. A run that straddles a chunk boundary is carried
 * over, so results do not depend on the chunk size. Output is capped by
 * [maxResults] so a pathological file cannot exhaust memory.
 */
class StringExtractor(
    private val minLength: Int = 4,
    private val maxResults: Int = 100_000,
    private val chunkSize: Int = 64 * 1024,
) {
    init {
        require(minLength >= 1)
        require(maxResults >= 1)
        require(chunkSize >= 1024)
    }

    fun extractAscii(bytes: ByteArray): List<FoundString> = scanAscii(bytes, 0L)

    fun extractAscii(file: File): List<FoundString> {
        val out = ArrayList<FoundString>()
        RandomAccessFile(file, "r").use { raf ->
            var run = StringBuilder()
            var runStart = -1L
            var pos = 0L
            val buf = ByteArray(chunkSize)
            while (pos < raf.length() && out.size < maxResults) {
                raf.seek(pos)
                val n = raf.read(buf)
                if (n <= 0) break
                for (i in 0 until n) {
                    val b = buf[i].toInt() and 0xFF
                    if (b in 0x20..0x7E || b == 0x09) {
                        if (run.isEmpty()) runStart = pos + i
                        run.append(b.toChar())
                    } else {
                        flush(run, runStart, out, Encoding.ASCII)
                        run = StringBuilder()
                        if (out.size >= maxResults) break
                    }
                }
                pos += n
            }
            if (out.size < maxResults) flush(run, runStart, out, Encoding.ASCII)
        }
        return out
    }

    private fun flush(run: StringBuilder, start: Long, out: MutableList<FoundString>, enc: Encoding) {
        if (run.length >= minLength && out.size < maxResults) {
            out.add(FoundString(start, run.toString(), enc))
        }
    }

    /** In-memory ASCII scan. Used by tests; for large files use the File overload. */
    fun scanAscii(bytes: ByteArray, baseOffset: Long): List<FoundString> {
        val out = ArrayList<FoundString>()
        var run = StringBuilder()
        var start = -1L
        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 0x20..0x7E || b == 0x09) {
                if (run.isEmpty()) start = baseOffset + i
                run.append(b.toChar())
            } else {
                flush(run, start, out, Encoding.ASCII)
                run = StringBuilder()
                if (out.size >= maxResults) break
            }
        }
        if (out.size < maxResults) flush(run, start, out, Encoding.ASCII)
        return out
    }

    /**
     * UTF-16LE scan for characters in the basic printable ASCII range (the common
     * Windows and Android-resource layout). Non-ASCII UTF-16 is not decoded.
     */
    fun scanUtf16LeAscii(bytes: ByteArray, baseOffset: Long): List<FoundString> {
        val out = ArrayList<FoundString>()
        var run = StringBuilder()
        var start = -1L
        var i = 0
        while (i + 1 < bytes.size) {
            val lo = bytes[i].toInt() and 0xFF
            val hi = bytes[i + 1].toInt() and 0xFF
            if (hi == 0 && (lo in 0x20..0x7E || lo == 0x09)) {
                if (run.isEmpty()) start = baseOffset + i
                run.append(lo.toChar())
                i += 2
            } else {
                flush(run, start, out, Encoding.UTF16LE)
                run = StringBuilder()
                if (out.size >= maxResults) break
                i += 1 // resync: advance one byte to find alignment
            }
        }
        if (out.size < maxResults) flush(run, start, out, Encoding.UTF16LE)
        return out
    }
}
