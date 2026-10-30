package forensics.common

import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile

/** Engine identity recorded with every analysis result. */
object EngineInfo {
    const val NAME = "BLACKBOX FORENSICS engine"
    const val VERSION = "0.2.0"
    val javaRuntime: String
        get() = System.getProperty("java.vendor", "unknown") + " " + System.getProperty("java.version", "unknown")
}

enum class Severity { INFO, NOTE, SUSPICIOUS, ERROR }

/**
 * A structural or security observation.
 * Findings describe what was observed; they are not conclusions about intent.
 */
data class Finding(val code: String, val severity: Severity, val message: String, val location: String? = null)

/** Thrown when bytes do not form the structure a parser expects (malformed or truncated). */
class FormatException(message: String) : Exception(message)

/**
 * Resource limits applied to every analysis. All defaults are conservative; tests override them.
 */
data class AnalysisLimits(
    val maxZipEntries: Int = 50_000,
    val maxCentralDirectoryBytes: Long = 16L shl 20,
    val maxEntryInspectionBytes: Long = 64L shl 20,
    val maxTotalInspectionBytes: Long = 512L shl 20,
    val maxCompressionRatio: Double = 100.0,
    val minBombOutputBytes: Long = 1L shl 20,
    val maxNestingDepth: Int = 3,
    val maxNestedArchiveBytes: Long = 64L shl 20,
    val maxMetadataSegmentBytes: Int = 1 shl 20,
    val maxMetadataTotalBytes: Long = 16L shl 20,
    val maxEmbeddedScanBytes: Long = 256L shl 20,
    val maxEmbeddedHits: Int = 1000,
    val maxStringValueLength: Int = 4096,
) {
    init {
        require(maxZipEntries > 0)
        require(maxCentralDirectoryBytes > 0)
        require(maxEntryInspectionBytes > 0)
        // A total budget smaller than one entry's cap is legitimate; the effective cap is the smaller of the two.
        require(maxCompressionRatio > 1.0)
        require(maxNestingDepth >= 0)
        require(maxMetadataSegmentBytes > 0)
        require(maxEmbeddedScanBytes > 0)
        require(maxStringValueLength > 0)
    }
}

/**
 * Random-access reader over an evidence file. Opened read-only; never writes.
 * Every read is bounds-checked and capped, so a corrupt length field cannot
 * trigger an oversized allocation.
 */
/** Random-access bytes with a known size. Implemented by files and in-memory buffers. */
interface ByteSource {
    val size: Long
    fun read(offset: Long, count: Int): ByteArray
}

/** In-memory [ByteSource]; used for segments already extracted from a larger file. */
class ArraySource(private val bytes: ByteArray) : ByteSource {
    override val size: Long get() = bytes.size.toLong()
    override fun read(offset: Long, count: Int): ByteArray {
        if (offset < 0 || count < 0 || offset + count > bytes.size) throw FormatException("read past end of segment")
        return bytes.copyOfRange(offset.toInt(), offset.toInt() + count)
    }
}

class BoundedFile(file: File) : Closeable, ByteSource {
    private val raf = RandomAccessFile(file, "r")
    val length: Long = raf.length()
    override val size: Long get() = length

    override fun read(offset: Long, count: Int): ByteArray {
        if (offset < 0 || count < 0) throw FormatException("negative read offset=$offset count=$count")
        if (count > MAX_SINGLE_READ) throw FormatException("read of $count bytes exceeds single-read cap")
        if (offset + count > length) {
            throw FormatException("read past end of file: offset=$offset count=$count size=$length")
        }
        val buf = ByteArray(count)
        synchronized(raf) {
            raf.seek(offset)
            raf.readFully(buf)
        }
        return buf
    }

    /** Reads up to [count] bytes, returning fewer only at end of file. */
    fun readAvailable(offset: Long, count: Int): ByteArray {
        if (offset >= length) return ByteArray(0)
        return read(offset, minOf(count.toLong(), length - offset).toInt())
    }

    override fun close() = raf.close()

    companion object {
        const val MAX_SINGLE_READ = 16 shl 20
    }
}

// ---- Little/big-endian primitives with bounds checks ----

private fun check(b: ByteArray, off: Int, n: Int) {
    if (off < 0 || n < 0 || off > b.size - n) throw FormatException("field at $off (+$n) exceeds ${b.size} bytes")
}

fun u8(b: ByteArray, o: Int): Int { check(b, o, 1); return b[o].toInt() and 0xFF }
fun u16(b: ByteArray, o: Int, le: Boolean = true): Int {
    check(b, o, 2)
    val x = b[o].toInt() and 0xFF
    val y = b[o + 1].toInt() and 0xFF
    return if (le) (y shl 8) or x else (x shl 8) or y
}
fun u32(b: ByteArray, o: Int, le: Boolean = true): Long {
    check(b, o, 4)
    var v = 0L
    for (i in 0 until 4) {
        val idx = if (le) o + 3 - i else o + i
        v = (v shl 8) or (b[idx].toLong() and 0xFF)
    }
    return v
}
/** Returns -1 for values that overflow a signed Long; callers treat negatives as invalid. */
fun u64(b: ByteArray, o: Int, le: Boolean = true): Long {
    check(b, o, 8)
    var v = 0L
    for (i in 0 until 8) {
        val idx = if (le) o + 7 - i else o + i
        v = (v shl 8) or (b[idx].toLong() and 0xFF)
    }
    return v
}

/** Latin-1 decode that never throws; used for ASCII-compatible metadata fields. */
fun ascii(b: ByteArray, off: Int, len: Int): String {
    check(b, off, len)
    return String(b, off, len, Charsets.ISO_8859_1)
}

/** Trims NULs and whitespace that padded fixed-width text fields contain. */
fun cleanText(s: String, max: Int): String {
    val t = s.trim { it == '\u0000' || it.isWhitespace() }
    return if (t.length > max) t.substring(0, max) + "…" else t
}

fun File.isRegularReadable(): Boolean = isFile && canRead()
