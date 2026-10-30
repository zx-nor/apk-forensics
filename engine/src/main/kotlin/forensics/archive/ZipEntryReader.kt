package forensics.archive

import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.u16
import forensics.common.u32
import java.util.zip.CRC32
import java.util.zip.Inflater

/**
 * Reads the bytes of one named entry (stored or deflate) without extracting the archive.
 * Size is capped by [maxBytes]; CRC is verified and a mismatch is reported as an error.
 */
object ZipEntryReader {
    fun read(src: BoundedFile, dir: ZipDirectory, name: String, maxBytes: Int): ByteArray? {
        val e = dir.entries.firstOrNull { it.name == name } ?: return null
        if (e.flags and 1 != 0) throw FormatException("entry '$name' is encrypted; content not read")
        if (e.uncompressedSize > maxBytes) throw FormatException("entry '$name' (${e.uncompressedSize} bytes) exceeds the read limit")
        val pos = dir.prependedBytes + e.localHeaderOffset
        val hdr = src.read(pos, 30)
        if (u32(hdr, 0) != 0x04034b50L) throw FormatException("local header missing for '$name'")
        val dataStart = pos + 30 + u16(hdr, 26) + u16(hdr, 28)
        if (dataStart + e.compressedSize > src.length) throw FormatException("entry '$name' data extends beyond end of file")
        val raw = src.read(dataStart, e.compressedSize.toInt())
        val out = when (e.method) {
            0 -> raw
            8 -> inflate(raw, maxBytes, name)
            else -> throw FormatException("compression method ${MethodNames.of(e.method)} not supported for '$name'")
        }
        val crc = CRC32().apply { update(out) }.value
        if (crc != e.crc32) throw FormatException("CRC mismatch reading '$name'")
        return out
    }

    private fun inflate(raw: ByteArray, cap: Int, name: String): ByteArray {
        val inf = Inflater(true)
        try {
            inf.setInput(raw)
            val out = java.io.ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) throw FormatException("truncated deflate data in '$name'")
                out.write(buf, 0, n)
                if (out.size() > cap) throw FormatException("decompressed '$name' exceeds the read limit")
            }
            return out.toByteArray()
        } catch (e: java.util.zip.DataFormatException) {
            throw FormatException("corrupt deflate data in '$name': ${e.message}")
        } finally {
            inf.end()
        }
    }
}
