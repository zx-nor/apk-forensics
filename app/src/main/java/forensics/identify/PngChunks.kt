package forensics.identify

import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.u32
import java.util.zip.CRC32

/** One PNG chunk located in the file. [dataOffset] is absolute; the body is never loaded here. */
data class PngChunk(val offset: Long, val length: Long, val type: String, val dataOffset: Long, val crcStored: Long, val crcComputed: Long) {
    val end: Long get() = dataOffset + length + 4
    val crcValid: Boolean get() = crcStored == crcComputed
}

/** Result of walking a PNG's chunk sequence. */
data class PngStructure(val chunks: List<PngChunk>, val iendEnd: Long?, val error: String?)

/**
 * Walks PNG chunks by length, verifying CRC-32 in bounded streaming reads.
 * Chunk bodies are never held in memory in full.
 */
object PngChunks {
    private val SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    private const val BLOCK = 64 * 1024

    fun walk(src: BoundedFile, maxChunks: Int = 100_000): PngStructure {
        if (src.length < 8 || !src.read(0, 8).contentEquals(SIGNATURE)) {
            return PngStructure(emptyList(), null, "PNG signature missing")
        }
        val chunks = mutableListOf<PngChunk>()
        var pos = 8L
        while (true) {
            if (chunks.size >= maxChunks) return PngStructure(chunks, null, "chunk limit reached")
            if (pos + 12 > src.length) return PngStructure(chunks, null, "file ends inside chunk header at $pos")
            val hdr = src.read(pos, 8)
            val len = u32(hdr, 0, le = false)
            val type = String(hdr, 4, 4, Charsets.ISO_8859_1)
            if (len > Int.MAX_VALUE) return PngStructure(chunks, null, "chunk length $len at $pos is out of range")
            val end = pos + 12 + len
            if (end > src.length) return PngStructure(chunks, null, "chunk $type at $pos extends beyond end of file")
            val crcStored = u32(src.read(pos + 8 + len, 4), 0, le = false)
            val crc = crcOf(src, pos + 4, 4 + len)
            chunks += PngChunk(pos, len, type, pos + 8, crcStored, crc)
            if (type == "IEND") return PngStructure(chunks, end, null)
            pos = end
        }
    }

    /** CRC-32 over [count] bytes starting at [offset], streamed in blocks. */
    fun crcOf(src: BoundedFile, offset: Long, count: Long): Long {
        val crc = CRC32()
        var done = 0L
        while (done < count) {
            val n = minOf(BLOCK.toLong(), count - done).toInt()
            crc.update(src.read(offset + done, n))
            done += n
        }
        return crc.value
    }
}
