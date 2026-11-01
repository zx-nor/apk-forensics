package forensics.metadata

import forensics.common.FormatException
import forensics.common.u16
import forensics.common.u32

/**
 * Decoder for Android binary XML (AXML), the compiled form of AndroidManifest.xml.
 *
 * Decodes the string pool, namespace declarations, and element/attribute chunks. Attribute values
 * are returned as text: typed integers in decimal, booleans as true/false, references as @0x...
 * Unknown value types are shown as hexadecimal, never guessed.
 */
internal object Axml {
    const val ANDROID_NS = "http://schemas.android.com/apk/res/android"

    private const val TYPE_STRING_POOL = 0x0001
    private const val TYPE_XML = 0x0003
    private const val TYPE_START_NS = 0x0100
    private const val TYPE_END_NS = 0x0101
    private const val TYPE_START_ELEMENT = 0x0102
    private const val TYPE_END_ELEMENT = 0x0103
    private const val MAX_STRINGS = 200_000

    sealed class Event {
        data class Start(val name: String, val attrs: Map<String, String>) : Event()
        data class End(val name: String) : Event()
    }

    fun parse(b: ByteArray, maxEvents: Int = 500_000): List<Event> {
        if (b.size < 8) throw FormatException("binary XML shorter than its header")
        if (u16(b, 0) != TYPE_XML) throw FormatException("binary XML document chunk missing")
        val total = u32(b, 4).toInt()
        if (total < 8 || total > b.size) throw FormatException("binary XML declares size $total; have ${b.size}")
        var strings: List<String> = emptyList()
        val events = ArrayList<Event>()
        var pos = u16(b, 2)
        while (pos < total) {
            if (pos + 8 > total) throw FormatException("chunk header at $pos exceeds document")
            val type = u16(b, pos)
            val size = u32(b, pos + 4).toInt()
            if (size < 8 || pos + size > total) throw FormatException("chunk at $pos has invalid size $size")
            when (type) {
                TYPE_STRING_POOL -> strings = readPool(b, pos)
                TYPE_START_ELEMENT -> {
                    if (events.size >= maxEvents) throw FormatException("XML event limit exceeded")
                    events += startElement(b, pos, strings)
                }
                TYPE_END_ELEMENT -> {
                    val nameIdx = u32(b, pos + 20).toInt()
                    events += Event.End(str(strings, nameIdx))
                }
                TYPE_START_NS, TYPE_END_NS -> {}
                else -> {} // resource map and unknown chunks are skipped
            }
            pos += size
        }
        return events
    }

    private fun startElement(b: ByteArray, pos: Int, strings: List<String>): Event.Start {
        val name = str(strings, u32(b, pos + 20).toInt())
        val attrStart = u16(b, pos + 24)
        val attrSize = u16(b, pos + 26)
        val attrCount = u16(b, pos + 28)
        if (attrSize < 20) throw FormatException("attribute size $attrSize below minimum 20")
        val base = pos + 16 + attrStart
        val attrs = LinkedHashMap<String, String>()
        for (i in 0 until attrCount) {
            val a = base + i * attrSize
            val nsIdx = u32(b, a)
            val nameIdx = u32(b, a + 4).toInt()
            val raw = u32(b, a + 8)
            val dataType = u8(b, a + 15)
            val data = u32(b, a + 16)
            val nsUri = if (nsIdx == 0xFFFFFFFFL) null else str(strings, nsIdx.toInt())
            val key = if (nsUri == ANDROID_NS) "android:" + str(strings, nameIdx) else str(strings, nameIdx)
            val value = if (raw != 0xFFFFFFFFL) str(strings, raw.toInt()) else typed(dataType, data, strings)
            attrs[key] = value
        }
        return Event.Start(name, attrs)
    }

    private fun typed(dataType: Int, data: Long, strings: List<String>): String = when (dataType) {
        0x03 -> str(strings, data.toInt())
        0x10 -> data.toInt().toString()
        0x11 -> "0x%08X".format(data)
        0x12 -> if (data != 0L) "true" else "false"
        0x01 -> "@0x%08X".format(data)
        else -> "0x%08X".format(data)
    }

    private fun u8(b: ByteArray, o: Int): Int = forensics.common.u8(b, o)

    private fun str(strings: List<String>, i: Int): String {
        if (i < 0 || i >= strings.size) return ""
        return strings[i]
    }

    private fun readPool(b: ByteArray, pos: Int): List<String> {
        val count = u32(b, pos + 8).toInt()
        val flags = u32(b, pos + 16)
        val strStart = u32(b, pos + 20).toInt()
        val headerSize = u16(b, pos + 2)
        if (count < 0 || count > MAX_STRINGS) throw FormatException("string pool count $count out of range")
        val utf8 = flags and 0x100L != 0L
        val offsets = IntArray(count) { u32(b, pos + headerSize + it * 4).toInt() }
        return List(count) { i ->
            var off = pos + strStart + offsets[i]
            if (utf8) {
                val (_, n1) = varint8(b, off)
                off += n1
                val (byteLen, n2) = varint8(b, off)
                off += n2
                if (off + byteLen > b.size) throw FormatException("string $i overruns the document")
                String(b, off, byteLen, Charsets.UTF_8)
            } else {
                var len = u16(b, off)
                off += 2
                if (len and 0x8000 != 0) {
                    len = ((len and 0x7FFF) shl 16) or u16(b, off)
                    off += 2
                }
                if (off + len * 2 > b.size) throw FormatException("string $i overruns the document")
                String(b, off, len * 2, Charsets.UTF_16LE)
            }
        }
    }

    private fun varint8(b: ByteArray, o: Int): Pair<Int, Int> {
        val first = u8(b, o)
        return if (first and 0x80 != 0) {
            (((first and 0x7F) shl 8) or u8(b, o + 1)) to 2
        } else first to 1
    }
}
