package forensics.binary

import java.io.File
import java.io.InputStream
import kotlin.math.ln

/**
 * Shannon entropy in bits per byte, range 0.0 .. 8.0.
 *
 * Entropy measures how uniformly byte values are distributed. High entropy is
 * consistent with compressed or encrypted data but is NOT proof of encryption:
 * compressed media, random test data, and some formats score high too.
 */
data class EntropyResult(
    val bitsPerByte: Double,
    val byteCount: Long,
    val histogram: LongArray,
) {
    init { require(histogram.size == 256) }

    /** True when the value is consistent with high-randomness data. Not proof. */
    fun isHighlyRandom(threshold: Double = 7.5): Boolean = byteCount > 0 && bitsPerByte >= threshold
}

object Entropy {
    /** Computes entropy by streaming. Histogram is fixed at 256 entries. */
    fun of(file: File, chunkSize: Int = 64 * 1024): EntropyResult =
        file.inputStream().use { of(it, chunkSize) }

    fun of(input: InputStream, chunkSize: Int = 64 * 1024): EntropyResult {
        require(chunkSize > 0)
        val hist = LongArray(256)
        val buf = ByteArray(chunkSize)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            for (i in 0 until n) hist[buf[i].toInt() and 0xFF]++
            total += n
        }
        return EntropyResult(shannon(hist, total), total, hist)
    }

    /** Shannon entropy from a byte histogram. Returns 0.0 for empty input. */
    fun shannon(histogram: LongArray, total: Long): Double {
        require(histogram.size == 256)
        if (total <= 0L) return 0.0
        var h = 0.0
        for (count in histogram) {
            if (count == 0L) continue
            val p = count.toDouble() / total.toDouble()
            h -= p * (ln(p) / ln(2.0))
        }
        // Clamp floating-point noise at the boundaries.
        return h.coerceIn(0.0, 8.0)
    }
}
