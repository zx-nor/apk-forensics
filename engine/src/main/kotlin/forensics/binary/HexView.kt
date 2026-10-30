package forensics.binary

import java.io.RandomAccessFile

/**
 * Hexadecimal and ASCII view of a file region.
 *
 * Reads only the requested window using a positioned read, so offset navigation
 * on large evidence never loads the full file.
 */
object HexView {
    const val BYTES_PER_ROW = 16
    const val MAX_WINDOW = 64 * 1024

    data class Row(val offset: Long, val hex: String, val ascii: String)

    fun render(file: java.io.File, offset: Long, length: Int): List<Row> {
        require(offset >= 0) { "offset must be non-negative" }
        require(length in 1..MAX_WINDOW) { "length must be in 1..$MAX_WINDOW" }
        RandomAccessFile(file, "r").use { raf ->
            if (offset >= raf.length()) return emptyList()
            val available = minOf(length.toLong(), raf.length() - offset).toInt()
            val buf = ByteArray(available)
            raf.seek(offset)
            raf.readFully(buf)
            return formatRows(buf, offset)
        }
    }

    /** Format a byte array as hex+ASCII rows. Pure function, used by tests. */
    fun formatRows(bytes: ByteArray, baseOffset: Long = 0L): List<Row> {
        val rows = ArrayList<Row>()
        var i = 0
        while (i < bytes.size) {
            val end = minOf(i + BYTES_PER_ROW, bytes.size)
            val hex = StringBuilder()
            val ascii = StringBuilder()
            for (j in i until i + BYTES_PER_ROW) {
                if (j < end) {
                    val b = bytes[j].toInt() and 0xFF
                    hex.append("%02X ".format(b))
                    ascii.append(if (b in 0x20..0x7E) b.toChar() else '.')
                } else {
                    hex.append("   ")
                }
                if (j - i == 7) hex.append(' ')
            }
            rows.add(Row(baseOffset + i, hex.toString().trimEnd(), ascii.toString()))
            i = end
        }
        return rows
    }
}
