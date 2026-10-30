package forensics.metadata

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import forensics.common.u16
import forensics.common.u32
import java.io.File

/** MP3: ID3v2 text/comment/picture frames, ID3v1 trailer, and first-frame MPEG header. */
object Mp3MetadataExtractor {
    const val NAME = "mp3-id3"
    const val VERSION = "1.0.0"

    private val TEXT_FRAMES = mapOf(
        "TIT2" to "Title", "TPE1" to "Artist", "TALB" to "Album", "TPE2" to "AlbumArtist",
        "TCOM" to "Composer", "TCON" to "Genre", "TYER" to "Year", "TDRC" to "RecordingTime",
        "TRCK" to "Track", "TPOS" to "DiscNumber", "TENC" to "EncodedBy", "TSSE" to "Encoder",
        "TCOP" to "Copyright", "TDEN" to "EncodingTime", "TDTG" to "TaggingTime",
    )

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            var audioStart = 0L
            if (src.length >= 10 && String(src.read(0, 3), Charsets.ISO_8859_1) == "ID3") {
                audioStart = readId3v2(src, limits, sink)
            } else {
                sink.note("No ID3v2 tag at offset 0.")
            }
            readId3v1(src, sink, limits)
            findFrame(src, audioStart, sink)
        }
    }

    private fun readId3v2(src: BoundedFile, limits: AnalysisLimits, sink: MetadataSink): Long {
        val h = src.read(0, 10)
        val major = h[3].toInt() and 0xFF
        val flags = h[5].toInt() and 0xFF
        if (major !in 2..4) throw FormatException("unsupported ID3v2 major version $major")
        val tagSize = syncsafe(h, 6)
        sink.add("structure", "ID3v2Version", "2.$major.${h[4].toInt() and 0xFF}")
        val end = 10 + tagSize
        if (end > src.length) throw FormatException("ID3v2 tag size $tagSize exceeds file")
        if (tagSize > limits.maxMetadataTotalBytes) throw FormatException("ID3v2 tag exceeds the metadata size limit")
        var raw = src.read(10, tagSize)
        if (flags and 0x80 != 0 && major < 4) raw = unsynchronize(raw)
        var pos = 0
        if (flags and 0x40 != 0 && major >= 3) {
            if (raw.size < 4) throw FormatException("truncated ID3 extended header")
            pos = if (major == 4) syncsafe(raw, 0) else (u32(raw, 0, le = false).toInt() + 4)
        }
        while (pos + 10 <= raw.size) {
            if (raw[pos] == 0.toByte()) break
            val id = String(raw, pos, 4, Charsets.ISO_8859_1)
            val size = if (major == 4) syncsafe(raw, pos + 4) else u32(raw, pos + 4, le = false).toInt()
            val fflags = u16(raw, pos + 8, le = false)
            if (size < 0 || pos + 10 + size > raw.size) { sink.error("ID3 frame $id at tag offset $pos overruns the tag"); break }
            var body = raw.copyOfRange(pos + 10, pos + 10 + size)
            if (major == 4 && fflags and 0x0002 != 0) body = unsynchronize(body)
            frame(id, body, sink, limits)
            pos += 10 + size
        }
        return end.toLong()
    }

    private fun frame(id: String, body: ByteArray, sink: MetadataSink, limits: AnalysisLimits) {
        when {
            id in TEXT_FRAMES -> {
                if (body.isEmpty()) return
                val text = decodeFrameText(body[0].toInt(), body, 1, multi = true)
                sink.add("ID3", TEXT_FRAMES.getValue(id), cleanText(text, limits.maxStringValueLength))
            }
            id == "TXXX" -> {
                if (body.isEmpty()) return
                val enc = body[0].toInt()
                val (desc, rest) = splitTerminated(body, 1, enc)
                val value = decodeFrameText(enc, body, rest, multi = false)
                sink.add("ID3.TXXX", cleanText(desc, 256), cleanText(value, limits.maxStringValueLength))
            }
            id == "COMM" -> {
                if (body.size < 5) return
                val enc = body[0].toInt()
                val lang = String(body, 1, 3, Charsets.ISO_8859_1)
                val (_, rest) = splitTerminated(body, 4, enc)
                sink.add("ID3.COMM", "Comment[$lang]", cleanText(decodeFrameText(enc, body, rest, multi = false), limits.maxStringValueLength))
            }
            id == "APIC" -> {
                if (body.isEmpty()) return
                val enc = body[0].toInt()
                val mimeEnd = body.indexOf(0, 1).let { if (it < 0) body.size else it }
                val mime = String(body, 1, mimeEnd - 1, Charsets.ISO_8859_1)
                val picType = if (mimeEnd + 1 < body.size) body[mimeEnd + 1].toInt() and 0xFF else -1
                val (_, dataStart) = splitTerminated(body, mimeEnd + 2, enc)
                val pictureBytes = body.size - minOf(dataStart, body.size)
                sink.add("ID3.APIC", "Picture", "type=$picType mime=$mime bytes=$pictureBytes")
            }
        }
    }

    /** Decodes ID3 text. Encodings: 0 Latin-1, 1 UTF-16 with BOM, 2 UTF-16BE, 3 UTF-8. */
    private fun decodeFrameText(enc: Int, body: ByteArray, from: Int, multi: Boolean): String {
        if (from > body.size) return ""
        val slice = body.copyOfRange(from, body.size)
        val text = when (enc) {
            0 -> String(slice, Charsets.ISO_8859_1)
            1 -> {
                val bom = slice.size >= 2 && slice[0] == 0xFF.toByte() && slice[1] == 0xFE.toByte()
                val be = slice.size >= 2 && slice[0] == 0xFE.toByte() && slice[1] == 0xFF.toByte()
                val payload = if (bom || be) slice.copyOfRange(2, slice.size) else slice
                String(payload, if (be) Charsets.UTF_16BE else Charsets.UTF_16LE)
            }
            2 -> String(slice, Charsets.UTF_16BE)
            3 -> String(slice, Charsets.UTF_8)
            else -> throw FormatException("unknown ID3 text encoding $enc")
        }
        val parts = text.split('\u0000').map { it.trim() }.filter { it.isNotEmpty() }
        return if (multi) parts.joinToString("; ") else parts.joinToString(" ")
    }

    /** Splits a terminated string at the encoding's terminator; returns the string and the index after it. */
    private fun splitTerminated(body: ByteArray, from: Int, enc: Int): Pair<String, Int> {
        val wide = enc == 1 || enc == 2
        var i = from
        if (wide) {
            while (i + 1 < body.size && !(body[i] == 0.toByte() && body[i + 1] == 0.toByte())) i += 2
            val s = String(body, from, minOf(i, body.size) - from, if (enc == 2) Charsets.UTF_16BE else Charsets.UTF_16LE)
            return s to minOf(i + 2, body.size)
        }
        while (i < body.size && body[i] != 0.toByte()) i++
        val cs = if (enc == 3) Charsets.UTF_8 else Charsets.ISO_8859_1
        return String(body, from, i - from, cs) to minOf(i + 1, body.size)
    }

    private fun readId3v1(src: BoundedFile, sink: MetadataSink, limits: AnalysisLimits) {
        if (src.length < 128) return
        val t = src.read(src.length - 128, 128)
        if (String(t, 0, 3, Charsets.ISO_8859_1) != "TAG") return
        sink.add("ID3v1", "Title", cleanText(String(t, 3, 30, Charsets.ISO_8859_1), limits.maxStringValueLength))
        sink.add("ID3v1", "Artist", cleanText(String(t, 33, 30, Charsets.ISO_8859_1), limits.maxStringValueLength))
        sink.add("ID3v1", "Album", cleanText(String(t, 63, 30, Charsets.ISO_8859_1), limits.maxStringValueLength))
        sink.add("ID3v1", "Year", cleanText(String(t, 93, 4, Charsets.ISO_8859_1), 4))
        val commentLimit = if (t[125] == 0.toByte() && t[126] != 0.toByte()) 28 else 30
        sink.add("ID3v1", "Comment", cleanText(String(t, 97, commentLimit, Charsets.ISO_8859_1), limits.maxStringValueLength))
        if (commentLimit == 28) sink.add("ID3v1", "Track", (t[126].toInt() and 0xFF).toString())
        sink.add("ID3v1", "Genre", (t[127].toInt() and 0xFF).toString())
    }

    /** Finds the first MPEG Layer III frame header after the ID3v2 tag and reports its parameters. */
    private fun findFrame(src: BoundedFile, from: Long, sink: MetadataSink) {
        val window = src.readAvailable(from, 64 * 1024)
        var i = 0
        while (i + 4 <= window.size) {
            val b1 = window[i + 1].toInt() and 0xFF
            val b0 = window[i].toInt() and 0xFF
            if (b0 == 0xFF && (b1 and 0xE0) == 0xE0) {
                val version = (b1 shr 3) and 3
                val layer = (b1 shr 1) and 3
                val b2 = window[i + 2].toInt() and 0xFF
                val b3 = window[i + 3].toInt() and 0xFF
                if (version != 1 && layer != 0) {
                    val ver = when (version) { 3 -> "MPEG-1"; 2 -> "MPEG-2"; else -> "MPEG-2.5" }
                    val lay = when (layer) { 3 -> "Layer I"; 2 -> "Layer II"; 1 -> "Layer III"; else -> "" }
                    val br = bitrate(version, layer, b2 shr 4)
                    val sr = sampleRate(version, (b2 shr 2) and 3)
                    val mode = when (b3 shr 6) { 0 -> "stereo"; 1 -> "joint stereo"; 2 -> "dual channel"; else -> "mono" }
                    sink.add("structure", "MPEGVersion", ver)
                    sink.add("structure", "Layer", lay)
                    if (br != null) sink.add("structure", "BitrateKbpsFirstFrame", br.toString())
                    if (sr != null) sink.add("structure", "SampleRateHz", sr.toString())
                    sink.add("structure", "ChannelMode", mode)
                    sink.note("Bitrate reflects the first frame only; variable-bitrate files may differ.")
                    return
                }
            }
            i++
        }
        sink.note("No MPEG frame header found in the first 64 KiB of audio.")
    }

    private fun bitrate(version: Int, layer: Int, idx: Int): Int? {
        if (idx == 0 || idx == 15 || layer != 1) return null
        val mpeg1L3 = intArrayOf(0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0)
        val mpeg2L3 = intArrayOf(0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0)
        return if (version == 3) mpeg1L3[idx] else mpeg2L3[idx]
    }

    private fun sampleRate(version: Int, idx: Int): Int? {
        if (idx == 3) return null
        val table = when (version) {
            3 -> intArrayOf(44100, 48000, 32000)
            2 -> intArrayOf(22050, 24000, 16000)
            else -> intArrayOf(11025, 12000, 8000)
        }
        return table[idx]
    }

    private fun syncsafe(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0x7F) shl 21) or ((b[o + 1].toInt() and 0x7F) shl 14) or
            ((b[o + 2].toInt() and 0x7F) shl 7) or (b[o + 3].toInt() and 0x7F)

    private fun unsynchronize(b: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(b.size)
        var i = 0
        while (i < b.size) {
            out.write(b[i].toInt())
            if (b[i] == 0xFF.toByte() && i + 1 < b.size && b[i + 1] == 0.toByte()) i++
            i++
        }
        return out.toByteArray()
    }

    private fun ByteArray.indexOf(v: Int, from: Int): Int {
        for (k in from until size) if (this[k] == v.toByte()) return k
        return -1
    }
}

/** FLAC: STREAMINFO, VORBIS_COMMENT, and PICTURE metadata blocks. */
object FlacMetadataExtractor {
    const val NAME = "flac-blocks"
    const val VERSION = "1.0.0"

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            if (src.length < 8 || String(src.read(0, 4), Charsets.ISO_8859_1) != "fLaC") throw FormatException("fLaC marker missing")
            var pos = 4L
            var total = 0L
            var last = false
            while (!last) {
                if (pos + 4 > src.length) throw FormatException("file ends inside metadata block header at $pos")
                val h = src.read(pos, 4)
                last = (h[0].toInt() and 0x80) != 0
                val type = h[0].toInt() and 0x7F
                val len = ((h[1].toInt() and 0xFF) shl 16) or ((h[2].toInt() and 0xFF) shl 8) or (h[3].toInt() and 0xFF)
                if (pos + 4 + len > src.length) throw FormatException("metadata block type $type at $pos overruns file")
                total += len
                if (total > limits.maxMetadataTotalBytes) throw FormatException("metadata exceeds the total size limit")
                if (len <= limits.maxMetadataSegmentBytes) {
                    val body = src.read(pos + 4, len)
                    block(type, body, sink, limits)
                } else sink.note("Metadata block type $type ($len bytes) exceeds the segment limit; skipped.")
                pos += 4 + len
            }
            sink.add("structure", "AudioDataOffset", pos.toString())
        }
    }

    private fun block(type: Int, b: ByteArray, sink: MetadataSink, limits: AnalysisLimits) {
        when (type) {
            0 -> {
                if (b.size < 34) throw FormatException("STREAMINFO shorter than 34 bytes")
                val rate = ((b[10].toInt() and 0xFF) shl 12) or ((b[11].toInt() and 0xFF) shl 4) or ((b[12].toInt() and 0xFF) shr 4)
                val channels = ((b[12].toInt() shr 1) and 7) + 1
                val bps = (((b[12].toInt() and 1) shl 4) or ((b[13].toInt() and 0xFF) shr 4)) + 1
                val samples = ((b[13].toLong() and 0x0F) shl 32) or u32(b, 14, le = false)
                val md5 = b.copyOfRange(18, 34).joinToString("") { "%02x".format(it) }
                sink.add("structure", "SampleRateHz", rate.toString())
                sink.add("structure", "Channels", channels.toString())
                sink.add("structure", "BitsPerSample", bps.toString())
                sink.add("structure", "TotalSamples", samples.toString())
                if (rate > 0 && samples > 0) sink.add("structure", "DurationSeconds", "%.3f".format(samples.toDouble() / rate))
                if (md5 != "0".repeat(32)) sink.add("structure", "StreamMD5", md5)
                else sink.note("STREAMINFO MD5 is zero; the encoder did not record a signature of the audio.")
            }
            4 -> {
                val vendorLen = u32(b, 0).toInt()
                if (vendorLen < 0 || 4 + vendorLen + 4 > b.size) throw FormatException("VORBIS_COMMENT vendor string overruns block")
                sink.add("FLAC.Vendor", "VendorString", cleanText(String(b, 4, vendorLen, Charsets.UTF_8), limits.maxStringValueLength))
                var p = 4 + vendorLen
                val count = u32(b, p).toInt()
                p += 4
                for (i in 0 until minOf(count, 10_000)) {
                    if (p + 4 > b.size) throw FormatException("VORBIS_COMMENT entry $i overruns block")
                    val n = u32(b, p).toInt()
                    p += 4
                    if (n < 0 || p + n > b.size) throw FormatException("VORBIS_COMMENT entry $i overruns block")
                    val kv = String(b, p, n, Charsets.UTF_8)
                    p += n
                    val eq = kv.indexOf('=')
                    if (eq > 0) sink.add("FLAC.Vorbis", kv.substring(0, eq).uppercase(), cleanText(kv.substring(eq + 1), limits.maxStringValueLength))
                }
            }
            6 -> {
                val picType = u32(b, 0, le = false)
                val mimeLen = u32(b, 4, le = false).toInt()
                if (mimeLen < 0 || 8 + mimeLen + 4 > b.size) throw FormatException("PICTURE block overruns")
                val mime = String(b, 8, mimeLen, Charsets.ISO_8859_1)
                val descLenAt = 8 + mimeLen
                if (descLenAt + 4 > b.size) throw FormatException("PICTURE description length missing")
                val descLen = u32(b, descLenAt, le = false).toInt()
                val geometryAt = descLenAt + 4 + descLen
                val dataLenAt = geometryAt + 16
                if (descLen < 0 || dataLenAt + 4 > b.size) throw FormatException("PICTURE block overruns")
                val dataLen = u32(b, dataLenAt, le = false).toInt()
                sink.add("FLAC.Picture", "Picture", "type=$picType mime=$mime bytes=$dataLen")
            }
            else -> {}
        }
    }
}

/** WAV: fmt and data chunks, LIST/INFO text, bext, and RIFF size consistency. */
object WavMetadataExtractor {
    const val NAME = "wav-riff"
    const val VERSION = "1.0.0"

    private val INFO = mapOf(
        "INAM" to "Title", "IART" to "Artist", "IPRD" to "Product", "ICRD" to "CreationDate",
        "ICMT" to "Comment", "ISFT" to "Software", "IENG" to "Engineer", "ICOP" to "Copyright",
        "IGNR" to "Genre", "ITRK" to "Track", "ISBJ" to "Subject", "IKEY" to "Keywords",
    )

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            val h = src.read(0, 12)
            if (String(h, 0, 4, Charsets.ISO_8859_1) != "RIFF" || String(h, 8, 4, Charsets.ISO_8859_1) != "WAVE") {
                throw FormatException("RIFF/WAVE header missing")
            }
            val riff = u32(h, 4)
            if (riff + 8 > src.length) sink.error("RIFF size declares ${riff + 8} bytes; file has ${src.length} (truncated)")
            else if (riff + 8 < src.length) sink.note("${src.length - riff - 8} bytes follow the RIFF container.")
            val end = minOf(src.length, riff + 8)
            var pos = 12L
            var byteRate = 0L
            var dataBytes: Long? = null
            while (pos + 8 <= end) {
                val ch = src.read(pos, 8)
                val id = String(ch, 0, 4, Charsets.ISO_8859_1)
                val size = u32(ch, 4)
                val body = pos + 8
                if (body + size > src.length) { sink.error("chunk '$id' at $pos overruns the file"); break }
                val n = size.toInt()
                when (id) {
                    "fmt " -> {
                        val f = src.read(body, minOf(n, 16))
                        if (f.size < 16) throw FormatException("fmt chunk shorter than 16 bytes")
                        val tag = u16(f, 0, le = true)
                        val channels = u16(f, 2)
                        val rate = u32(f, 4)
                        byteRate = u32(f, 8)
                        val bits = u16(f, 14)
                        sink.add("structure", "AudioFormatTag", if (tag == 1) "PCM" else "0x%04X".format(tag))
                        sink.add("structure", "Channels", channels.toString())
                        sink.add("structure", "SampleRateHz", rate.toString())
                        sink.add("structure", "BitsPerSample", bits.toString())
                    }
                    "data" -> dataBytes = size
                    "LIST" -> if (n >= 4 && n <= limits.maxMetadataSegmentBytes && String(src.read(body, 4), Charsets.ISO_8859_1) == "INFO") {
                        listInfo(src, body + 4, body + n, sink, limits)
                    }
                    "bext" -> if (n >= 256 && n <= limits.maxMetadataSegmentBytes) {
                        val b = src.read(body, n)
                        sink.add("WAV.bext", "Description", cleanText(String(b, 0, 256, Charsets.ISO_8859_1), limits.maxStringValueLength))
                        sink.add("WAV.bext", "Originator", cleanText(String(b, 256, 32, Charsets.ISO_8859_1), 256))
                        sink.add("WAV.bext", "OriginationDate", cleanText(String(b, 320, 10, Charsets.ISO_8859_1), 10))
                        sink.add("WAV.bext", "OriginationTime", cleanText(String(b, 330, 8, Charsets.ISO_8859_1), 8))
                    }
                    "id3 ", "ID3 " -> sink.note("Embedded ID3 chunk present; not parsed by the WAV extractor.")
                }
                pos = body + size + (size and 1L)
            }
            if (dataBytes != null) {
                sink.add("structure", "DataBytes", dataBytes.toString())
                if (byteRate > 0) sink.add("structure", "DurationSeconds", "%.3f".format(dataBytes.toDouble() / byteRate))
            }
        }
    }

    private fun listInfo(src: BoundedFile, from: Long, to: Long, sink: MetadataSink, limits: AnalysisLimits) {
        var p = from
        while (p + 8 <= to) {
            val h = src.read(p, 8)
            val id = String(h, 0, 4, Charsets.ISO_8859_1)
            val size = u32(h, 4).toInt()
            if (size < 0 || p + 8 + size > to) break
            val raw = src.read(p + 8, size)
            val text = String(raw, Charsets.ISO_8859_1).substringBefore('\u0000')
            INFO[id]?.let { sink.add("WAV.INFO", it, cleanText(text, limits.maxStringValueLength)) }
            p += 8 + size + (size and 1)
        }
    }
}
