package forensics.metadata

import forensics.common.ByteSource
import forensics.common.FormatException
import forensics.common.cleanText
import forensics.common.u16
import forensics.common.u32

/**
 * TIFF/EXIF directory parser. Reads IFDs through a [ByteSource], so large TIFF files are never loaded whole.
 * Offsets inside the TIFF structure are relative to the start of the TIFF header.
 */
object Exif {
    const val VERSION = "1.0.0"
    private const val MAX_ENTRIES = 1000
    private const val MAX_IFDS = 16
    private const val MAX_VALUE_BYTES = 64 * 1024

    private val IFD0_TAGS = mapOf(
        0x0100 to "ImageWidth", 0x0101 to "ImageLength", 0x010E to "ImageDescription", 0x010F to "Make",
        0x0110 to "Model", 0x0112 to "Orientation", 0x0131 to "Software", 0x0132 to "DateTime",
        0x013B to "Artist", 0x8298 to "Copyright",
    )
    private val EXIF_TAGS = mapOf(
        0x829A to "ExposureTime", 0x829D to "FNumber", 0x8827 to "ISOSpeedRatings",
        0x9003 to "DateTimeOriginal", 0x9004 to "DateTimeDigitized", 0x9010 to "OffsetTime",
        0x9011 to "OffsetTimeOriginal", 0x9012 to "OffsetTimeDigitized", 0x920A to "FocalLength",
        0xA433 to "LensMake", 0xA434 to "LensModel", 0x9286 to "UserComment",
    )
    private val GPS_TAGS = mapOf(
        0x0001 to "GPSLatitudeRef", 0x0003 to "GPSLongitudeRef", 0x0005 to "GPSAltitudeRef",
        0x0006 to "GPSAltitude", 0x0007 to "GPSTimeStamp", 0x001D to "GPSDateStamp",
    )

    private class Entry(val tag: Int, val type: Int, val count: Long, val raw: ByteArray)

    /**
     * Parses a TIFF header at offset 0 of [src] and writes fields into [sink].
     * Group names: IFD0 tags use [group]; Exif sub-IFD uses "$group.Exif"; GPS uses "$group.GPS".
     */
    fun parse(src: ByteSource, group: String, sink: MetadataSink, maxStringLength: Int) {
        if (src.size < 8) throw FormatException("TIFF header shorter than 8 bytes")
        val h = src.read(0, 8)
        val le = when {
            h[0] == 'I'.code.toByte() && h[1] == 'I'.code.toByte() -> true
            h[0] == 'M'.code.toByte() && h[1] == 'M'.code.toByte() -> false
            else -> throw FormatException("TIFF byte-order mark missing")
        }
        if (u16(h, 2, le) != 42) throw FormatException("TIFF magic number 42 missing")
        val visited = mutableSetOf<Long>()
        val ifd0 = u32(h, 4, le)
        ifd(src, ifd0, le, group, IFD0_TAGS, sink, maxStringLength, visited, 0)
    }

    private fun ifd(
        src: ByteSource, offset: Long, le: Boolean, group: String, tags: Map<Int, String>,
        sink: MetadataSink, maxStr: Int, visited: MutableSet<Long>, depth: Int,
    ) {
        if (offset == 0L) return
        if (depth > 2 || visited.size >= MAX_IFDS) { sink.note("EXIF sub-directory limit reached; not followed."); return }
        if (!visited.add(offset)) { sink.note("EXIF directory loop detected at offset $offset; not followed."); return }
        if (offset + 2 > src.size) throw FormatException("IFD offset $offset lies beyond end of data")
        val count = u16(src.read(offset, 2), 0, le)
        if (count > MAX_ENTRIES) throw FormatException("IFD entry count $count exceeds limit")
        val table = src.read(offset + 2, count * 12)
        val entries = (0 until count).map { i ->
            val o = i * 12
            Entry(u16(table, o, le), u16(table, o + 2, le), u32(table, o + 4, le), table.copyOfRange(o + 8, o + 12))
        }
        var exifPtr = 0L
        var gpsPtr = 0L
        for (e in entries) {
            try {
                when (e.tag) {
                    0x8769 -> exifPtr = u32(e.raw, 0, le)
                    0x8825 -> gpsPtr = u32(e.raw, 0, le)
                    else -> {
                        val name = tags[e.tag] ?: if (group.endsWith("GPS")) GPS_TAGS[e.tag] else null
                        if (name != null) {
                            val text = valueText(src, e, le, maxStr, sink)
                            if (text != null) sink.add(group, name, text)
                        }
                    }
                }
            } catch (ex: FormatException) {
                sink.note("EXIF tag 0x%04X in $group could not be read: ${ex.message}".format(e.tag))
            }
        }
        if (exifPtr != 0L) ifd(src, exifPtr, le, "$group.Exif", EXIF_TAGS, sink, maxStr, visited, depth + 1)
        if (gpsPtr != 0L) {
            ifd(src, gpsPtr, le, "$group.GPS", GPS_TAGS, sink, maxStr, visited, depth + 1)
            gpsDecimal(src, gpsPtr, le, group, sink, visited)
        }
    }

    /** Converts GPS latitude/longitude degree-minute-second triples into signed decimal degrees. */
    private fun gpsDecimal(src: ByteSource, gpsOffset: Long, le: Boolean, group: String, sink: MetadataSink, visited: MutableSet<Long>) {
        val count = u16(src.read(gpsOffset, 2), 0, le)
        val table = src.read(gpsOffset + 2, count * 12)
        val byTag = (0 until count).associate { i ->
            val o = i * 12
            u16(table, o, le) to Entry(u16(table, o, le), u16(table, o + 2, le), u32(table, o + 4, le), table.copyOfRange(o + 8, o + 12))
        }
        fun dms(tag: Int): Double? {
            val e = byTag[tag] ?: return null
            if (e.type != 5 || e.count != 3L) return null
            val parts = rationals(src, e, le, 3) ?: return null
            return parts[0] + parts[1] / 60.0 + parts[2] / 3600.0
        }
        val latRef = byTag[0x0001]?.let { textOf(src, it, le) }
        val lonRef = byTag[0x0003]?.let { textOf(src, it, le) }
        val lat = dms(0x0002)
        val lon = dms(0x0004)
        if (lat != null && latRef != null) {
            val signed = if (latRef.startsWith("S")) -lat else lat
            sink.add("$group.GPS", "GPSLatitudeDecimal", "%.6f".format(signed))
        }
        if (lon != null && lonRef != null) {
            val signed = if (lonRef.startsWith("W")) -lon else lon
            sink.add("$group.GPS", "GPSLongitudeDecimal", "%.6f".format(signed))
        }
    }

    private fun textOf(src: ByteSource, e: Entry, le: Boolean): String? =
        if (e.type == 2) valueText(src, e, le, 64, null) else null

    private fun typeSize(type: Int): Int = when (type) {
        1, 2, 6, 7 -> 1
        3, 8 -> 2
        4, 9, 11 -> 4
        5, 10 -> 8
        12 -> 8
        else -> 0
    }

    private fun bytesOf(src: ByteSource, e: Entry, le: Boolean): ByteArray {
        val size = typeSize(e.type).toLong() * e.count
        if (e.type == 0 || size == 0L) throw FormatException("unsupported value type ${e.type}")
        if (size > MAX_VALUE_BYTES) throw FormatException("value of $size bytes exceeds limit")
        return if (size <= 4) e.raw.copyOf(size.toInt())
        else src.read(u32(e.raw, 0, le), size.toInt())
    }

    private fun rationals(src: ByteSource, e: Entry, le: Boolean, max: Int): List<Double>? {
        if (e.type != 5 && e.type != 10) return null
        val b = bytesOf(src, e, le)
        val n = minOf(max.toLong(), e.count).toInt()
        return (0 until n).map { i ->
            val num = u32(b, i * 8, le).toDouble()
            val den = u32(b, i * 8 + 4, le).toDouble()
            if (den == 0.0) 0.0 else num / den
        }
    }

    private fun valueText(src: ByteSource, e: Entry, le: Boolean, maxStr: Int, sink: MetadataSink?): String? {
        return when (e.type) {
            2 -> {
                val b = bytesOf(src, e, le)
                val end = b.indexOf(0).let { if (it < 0) b.size else it }
                cleanText(String(b, 0, end, Charsets.ISO_8859_1), maxStr)
            }
            3, 8 -> {
                val b = bytesOf(src, e, le)
                (0 until e.count.toInt()).joinToString(", ") { i ->
                    if (e.type == 3) u16(b, i * 2, le).toString() else u16(b, i * 2, le).toShort().toString()
                }
            }
            4, 9 -> {
                val b = bytesOf(src, e, le)
                (0 until e.count.toInt()).joinToString(", ") { i -> u32(b, i * 4, le).toString() }
            }
            5, 10 -> {
                val r = rationals(src, e, le, 8) ?: return null
                val b = bytesOf(src, e, le)
                if (e.count == 1L) {
                    val num = u32(b, 0, le)
                    val den = u32(b, 4, le)
                    if (den == 0L) "$num/0 (invalid denominator)" else "$num/$den"
                } else r.joinToString(", ") { "%.4f".format(it) }
            }
            7 -> {
                // UNDEFINED: UserComment carries an 8-byte character-code prefix.
                val b = bytesOf(src, e, le)
                if (b.size >= 8) {
                    val code = String(b, 0, 8, Charsets.ISO_8859_1).trimEnd('\u0000')
                    val payload = b.copyOfRange(8, b.size)
                    val text = if (code == "UNICODE") String(payload, Charsets.UTF_16LE) else String(payload, Charsets.ISO_8859_1)
                    cleanText(text, maxStr)
                } else null
            }
            else -> null
        }
    }
}
