package forensics.metadata

import forensics.common.AnalysisLimits
import forensics.common.ArraySource
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import forensics.common.u16
import forensics.common.u32
import forensics.identify.PngChunks
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.Inflater

/** Shared XMP subset reader. Recognizes common simple properties in attribute and element form. */
internal object XmpSubset {
    private val patterns = listOf(
        "xmp:CreatorTool", "xmp:CreateDate", "xmp:ModifyDate", "xmp:MetadataDate", "dc:format",
    )

    fun read(text: String, sink: MetadataSink, max: Int) {
        for (p in patterns) {
            val attr = Regex("$p\\s*=\\s*\"([^\"]*)\"").find(text)?.groupValues?.get(1)
            val elem = Regex("<$p>([^<]*)</$p>").find(text)?.groupValues?.get(1)
            val v = attr ?: elem
            if (v != null) sink.add("XMP", p.substringAfter(':'), cleanText(v, max))
        }
        for (p in listOf("dc:title", "dc:creator")) {
            Regex("<$p>\\s*<rdf:(?:Alt|Seq|Bag)>\\s*<rdf:li[^>]*>([^<]*)</rdf:li>").find(text)?.let {
                sink.add("XMP", p.substringAfter(':'), cleanText(it.groupValues[1], max))
            }
        }
    }
}

/** JPEG: JFIF, Exif (TIFF), XMP, COM, and frame dimensions. Stops at start-of-scan. */
object JpegMetadataExtractor {
    const val NAME = "jpeg-segments"
    const val VERSION = "1.0.0"

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            if (src.length < 4 || u16(src.read(0, 2), 0, le = false) != 0xFFD8) throw FormatException("JPEG SOI marker missing")
            var pos = 2L
            var sawFrame = false
            while (true) {
                if (pos + 4 > src.length) { sink.note("JPEG segment stream ended before start-of-scan."); break }
                // Skip fill bytes before a marker.
                var b = src.read(pos, 1)[0].toInt() and 0xFF
                if (b != 0xFF) throw FormatException("expected marker at offset $pos, found 0x%02X".format(b))
                var mp = pos + 1
                var m = src.read(mp, 1)[0].toInt() and 0xFF
                while (m == 0xFF) { mp++; if (mp >= src.length) throw FormatException("file ends inside marker fill"); m = src.read(mp, 1)[0].toInt() and 0xFF }
                if (m == 0xD9 || m == 0xDA) break
                if (m == 0x01 || (m in 0xD0..0xD7)) { pos = mp + 1; continue }
                val lenBytes = src.read(mp + 1, 2)
                val segLen = u16(lenBytes, 0, le = false)
                if (segLen < 2) throw FormatException("invalid segment length $segLen at offset $mp")
                if (segLen - 2 > limits.maxMetadataSegmentBytes) {
                    sink.note("Segment 0x%02X at offset $mp (%d bytes) exceeds the segment limit; skipped.".format(m, segLen))
                    pos = mp + 1 + segLen
                    continue
                }
                val body = src.read(mp + 3, segLen - 2)
                handleSegment(m, body, sink, limits)
                if (m in frameMarkers()) sawFrame = true
                pos = mp + 1 + segLen
            }
            if (!sawFrame) sink.note("No frame header (SOF) found before end of segments.")
        }
    }

    private fun frameMarkers(): Set<Int> = setOf(0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF)

    private fun handleSegment(m: Int, body: ByteArray, sink: MetadataSink, limits: AnalysisLimits) {
        when {
            m == 0xE0 && body.size >= 5 && String(body, 0, 5, Charsets.ISO_8859_1) == "JFIF\u0000" && body.size >= 9 -> {
                sink.add("structure", "JFIFVersion", "${body[5].toInt()}.${"%02d".format(body[6].toInt())}")
            }
            m == 0xE1 && body.size >= 6 && String(body, 0, 6, Charsets.ISO_8859_1) == "Exif\u0000\u0000" -> {
                Exif.parse(ArraySource(body.copyOfRange(6, body.size)), "EXIF", sink, limits.maxStringValueLength)
            }
            m == 0xE1 && body.startsWith("http://ns.adobe.com/xap/1.0/") -> {
                val off = "http://ns.adobe.com/xap/1.0/".length + 1
                XmpSubset.read(String(body, off, body.size - off, Charsets.UTF_8), sink, limits.maxStringValueLength)
            }
            m == 0xFE -> sink.add("JPEG", "Comment", cleanText(String(body, Charsets.ISO_8859_1), limits.maxStringValueLength))
            m == 0xED -> sink.note("Photoshop/IPTC resource block present (APP13); not parsed.")
            m in setOf(0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF) && body.size >= 6 -> {
                sink.add("structure", "BitsPerSample", (body[0].toInt() and 0xFF).toString())
                sink.add("structure", "ImageHeight", u16(body, 1, le = false).toString())
                sink.add("structure", "ImageWidth", u16(body, 3, le = false).toString())
                sink.add("structure", "ComponentCount", (body[5].toInt() and 0xFF).toString())
            }
        }
    }

    private fun ByteArray.startsWith(s: String): Boolean =
        size >= s.length && String(this, 0, s.length, Charsets.ISO_8859_1) == s
}

/** PNG: IHDR, text chunks (tEXt, zTXt, iTXt), eXIf, tIME, pHYs, with CRC verification. */
object PngMetadataExtractor {
    const val NAME = "png-chunks"
    const val VERSION = "1.0.0"

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            val s = PngChunks.walk(src)
            for (c in s.chunks) {
                if (!c.crcValid) sink.error("CRC mismatch in chunk ${c.type} at offset ${c.offset}")
            }
            if (s.error != null) sink.error(s.error)
            for (c in s.chunks) {
                if (c.length > limits.maxMetadataSegmentBytes && c.type != "IDAT") {
                    sink.note("Chunk ${c.type} at ${c.offset} (${c.length} bytes) exceeds the segment limit; skipped.")
                    continue
                }
                when (c.type) {
                    "IHDR" -> {
                        val d = src.read(c.dataOffset, 13)
                        sink.add("structure", "ImageWidth", u32(d, 0, le = false).toString())
                        sink.add("structure", "ImageHeight", u32(d, 4, le = false).toString())
                        sink.add("structure", "BitDepth", (d[8].toInt() and 0xFF).toString())
                        sink.add("structure", "ColorType", (d[9].toInt() and 0xFF).toString())
                        sink.add("structure", "Interlace", (d[12].toInt() and 0xFF).toString())
                    }
                    "tEXt" -> {
                        val d = src.read(c.dataOffset, c.length.toInt())
                        val sep = d.indexOf(0)
                        if (sep > 0) {
                            val k = String(d, 0, sep, Charsets.ISO_8859_1)
                            val v = String(d, sep + 1, d.size - sep - 1, Charsets.ISO_8859_1)
                            addText(sink, "PNG.tEXt", k, v, limits)
                        } else sink.note("tEXt chunk at ${c.offset} has no keyword separator.")
                    }
                    "zTXt" -> {
                        val d = src.read(c.dataOffset, c.length.toInt())
                        val sep = d.indexOf(0)
                        if (sep > 0 && sep + 2 <= d.size) {
                            val k = String(d, 0, sep, Charsets.ISO_8859_1)
                            val text = inflate(d, sep + 2, d.size, limits.maxMetadataSegmentBytes)
                            addText(sink, "PNG.zTXt", k, String(text, Charsets.ISO_8859_1), limits)
                        } else sink.note("zTXt chunk at ${c.offset} is malformed.")
                    }
                    "iTXt" -> {
                        val d = src.read(c.dataOffset, c.length.toInt())
                        val kEnd = d.indexOf(0)
                        if (kEnd > 0 && kEnd + 3 <= d.size) {
                            val k = String(d, 0, kEnd, Charsets.UTF_8)
                            val compressed = d[kEnd + 1].toInt() == 1
                            var p = kEnd + 3
                            val langEnd = zeroFrom(d, p)
                            p = langEnd + 1
                            val tEnd = zeroFrom(d, minOf(p, d.size))
                            p = tEnd + 1
                            val payload = if (p <= d.size) d.copyOfRange(p, d.size) else ByteArray(0)
                            val text = if (compressed) inflate(payload, 0, payload.size, limits.maxMetadataSegmentBytes) else payload
                            addText(sink, "PNG.iTXt", k, String(text, Charsets.UTF_8), limits)
                        } else sink.note("iTXt chunk at ${c.offset} is malformed.")
                    }
                    "eXIf" -> {
                        val d = src.read(c.dataOffset, c.length.toInt())
                        Exif.parse(ArraySource(d), "EXIF", sink, limits.maxStringValueLength)
                    }
                    "tIME" -> {
                        val d = src.read(c.dataOffset, 7)
                        val y = u16(d, 0, le = false)
                        sink.add("PNG.tIME", "ModificationTime", "%04d-%02d-%02dT%02d:%02d:%02d (UTC per PNG specification)"
                            .format(y, d[2].toInt(), d[3].toInt(), d[4].toInt(), d[5].toInt(), d[6].toInt()))
                    }
                    "pHYs" -> {
                        val d = src.read(c.dataOffset, 9)
                        val unit = d[8].toInt() and 0xFF
                        sink.add("structure", "PixelsPerUnitX", u32(d, 0, le = false).toString())
                        sink.add("structure", "PixelsPerUnitY", u32(d, 4, le = false).toString())
                        sink.add("structure", "PixelUnit", if (unit == 1) "meter" else "unknown")
                    }
                }
            }
            if (s.iendEnd == null && s.error == null) sink.error("IEND chunk not found")
        }
    }

    private fun addText(sink: MetadataSink, group: String, key: String, value: String, limits: AnalysisLimits) {
        if (key == "XML:com.adobe.xmp") {
            XmpSubset.read(value, sink, limits.maxStringValueLength)
        } else {
            sink.add(group, cleanText(key, 256), cleanText(value, limits.maxStringValueLength))
        }
    }

    /** Index of the next NUL at or after [from], or the array length when there is none. */
    private fun zeroFrom(d: ByteArray, from: Int): Int {
        for (i in from until d.size) if (d[i] == 0.toByte()) return i
        return d.size
    }

    private fun inflate(data: ByteArray, from: Int, to: Int, cap: Int): ByteArray {
        val inf = Inflater()
        return try {
            inf.setInput(data, from, to - from)
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break
                out.write(buf, 0, n)
                if (out.size() > cap) throw FormatException("compressed text exceeds the segment limit")
            }
            out.toByteArray()
        } catch (e: java.util.zip.DataFormatException) {
            throw FormatException("compressed text is corrupt: ${e.message}")
        } finally {
            inf.end()
        }
    }
}

/** WebP: RIFF chunks VP8X/VP8/VP8L for dimensions, EXIF and XMP chunks for metadata. */
object WebpMetadataExtractor {
    const val NAME = "webp-riff"
    const val VERSION = "1.0.0"

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            val h = src.read(0, 12)
            if (String(h, 0, 4, Charsets.ISO_8859_1) != "RIFF" || String(h, 8, 4, Charsets.ISO_8859_1) != "WEBP") {
                throw FormatException("RIFF/WEBP header missing")
            }
            val riffSize = u32(h, 4)
            val end = minOf(src.length, riffSize + 8)
            var pos = 12L
            while (pos + 8 <= end) {
                val ch = src.read(pos, 8)
                val fourcc = String(ch, 0, 4, Charsets.ISO_8859_1)
                val size = u32(ch, 4)
                val body = pos + 8
                if (body + size > src.length) { sink.error("chunk $fourcc at $pos extends beyond end of file"); break }
                val payloadLen = size.toInt()
                when (fourcc) {
                    "VP8X" -> {
                        val d = src.read(body, minOf(payloadLen, 10))
                        sink.add("structure", "ImageWidth", (1 + littleInt(d, 4, 3)).toString())
                        sink.add("structure", "ImageHeight", (1 + littleInt(d, 7, 3)).toString())
                        val flags = d[0].toInt() and 0xFF
                        sink.add("structure", "HasExifChunk", if (flags and 0x08 != 0) "yes" else "no")
                        sink.add("structure", "HasXmpChunk", if (flags and 0x04 != 0) "yes" else "no")
                    }
                    "VP8 " -> {
                        val d = src.read(body, 10)
                        if (!(d[3] == 0x9D.toByte() && d[4] == 0x01.toByte() && d[5] == 0x2A.toByte())) throw FormatException("VP8 start code missing")
                        sink.add("structure", "ImageWidth", (littleInt(d, 6, 2) and 0x3FFF).toString())
                        sink.add("structure", "ImageHeight", (littleInt(d, 8, 2) and 0x3FFF).toString())
                        sink.add("structure", "Codec", "VP8 lossy")
                    }
                    "VP8L" -> {
                        val d = src.read(body, 5)
                        if (d[0] != 0x2F.toByte()) throw FormatException("VP8L signature byte missing")
                        val bits = littleInt(d, 1, 4)
                        sink.add("structure", "ImageWidth", ((bits and 0x3FFF) + 1).toString())
                        sink.add("structure", "ImageHeight", (((bits shr 14) and 0x3FFF) + 1).toString())
                        sink.add("structure", "Codec", "VP8L lossless")
                    }
                    "EXIF" -> {
                        if (payloadLen > limits.maxMetadataSegmentBytes) sink.note("EXIF chunk exceeds the segment limit; skipped.")
                        else {
                            var d = src.read(body, payloadLen)
                            if (d.size >= 6 && String(d, 0, 6, Charsets.ISO_8859_1) == "Exif\u0000\u0000") d = d.copyOfRange(6, d.size)
                            Exif.parse(ArraySource(d), "EXIF", sink, limits.maxStringValueLength)
                        }
                    }
                    "XMP " -> {
                        if (payloadLen > limits.maxMetadataSegmentBytes) sink.note("XMP chunk exceeds the segment limit; skipped.")
                        else XmpSubset.read(String(src.read(body, payloadLen), Charsets.UTF_8), sink, limits.maxStringValueLength)
                    }
                    else -> sink.note("Unhandled chunk '$fourcc' at offset $pos.")
                }
                pos = body + size + (size and 1L)
            }
        }
    }

    private fun littleInt(b: ByteArray, off: Int, n: Int): Int {
        var v = 0
        for (i in n - 1 downTo 0) v = (v shl 8) or (b[off + i].toInt() and 0xFF)
        return v
    }
}

/** TIFF files: IFD0 and sub-directories read directly from the file. */
object TiffMetadataExtractor {
    const val NAME = "tiff-ifd"
    const val VERSION = "1.0.0"

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src -> Exif.parse(src, "TIFF", sink, limits.maxStringValueLength) }
    }
}
