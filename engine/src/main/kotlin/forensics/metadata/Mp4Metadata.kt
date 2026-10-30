package forensics.metadata

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import forensics.common.u16
import forensics.common.u32
import forensics.common.u64
import java.io.File
import java.time.Instant

/**
 * MP4 / MOV / M4A: ftyp brands, movie header times, track geometry and codec, and iTunes/QuickTime
 * metadata items. Box sizes are validated against their containers; an overrunning box stops the walk.
 *
 * Creation times are seconds since 1904-01-01 UTC. A zero value means "not set" and is reported as
 * a note, not as a date.
 */
object Mp4MetadataExtractor {
    const val NAME = "iso-bmff"
    const val VERSION = "1.0.0"
    private val EPOCH_1904: Instant = Instant.parse("1904-01-01T00:00:00Z")
    private val CONTAINERS = setOf("moov", "trak", "mdia", "minf", "stbl", "edts")
    private val ITEM_NAMES = mapOf(
        "\u00A9nam" to "Title", "\u00A9ART" to "Artist", "\u00A9alb" to "Album", "\u00A9day" to "Date",
        "\u00A9too" to "Encoder", "\u00A9gen" to "Genre", "\u00A9cmt" to "Comment", "\u00A9wrt" to "Composer",
        "aART" to "AlbumArtist", "desc" to "Description", "\u00A9grp" to "Grouping", "cprt" to "Copyright",
    )

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            val trackCounter = intArrayOf(0)
            walk(src, 0L, src.length, 0, sink, limits, trackCounter, null)
        }
    }

    private data class Box(val type: String, val start: Long, val headerSize: Int, val size: Long) {
        val bodyStart: Long get() = start + headerSize
        val end: Long get() = start + size
    }

    private fun readBox(src: BoundedFile, pos: Long, containerEnd: Long): Box {
        if (pos + 8 > containerEnd) throw FormatException("box header at $pos exceeds its container")
        val h = src.read(pos, 8)
        var size = u32(h, 0, le = false)
        val type = String(h, 4, 4, Charsets.ISO_8859_1)
        var header = 8
        if (size == 1L) {
            if (pos + 16 > containerEnd) throw FormatException("64-bit box header at $pos exceeds its container")
            size = u64(src.read(pos + 8, 8), 0, le = false)
            header = 16
        } else if (size == 0L) {
            size = containerEnd - pos
        }
        if (size < header || pos + size > containerEnd) throw FormatException("box '$type' at $pos (size $size) overruns its container")
        return Box(type, pos, header, size)
    }

    private fun walk(
        src: BoundedFile, start: Long, end: Long, depth: Int, sink: MetadataSink, limits: AnalysisLimits,
        trackCounter: IntArray, trackCtx: TrackCtx?,
    ) {
        if (depth > 8) { sink.note("Box nesting limit reached; deeper boxes not parsed."); return }
        var pos = start
        while (pos < end) {
            val box = readBox(src, pos, end)
            when {
                box.type == "ftyp" -> ftyp(src, box, sink)
                box.type == "mvhd" -> mvhd(src, box, sink)
                box.type == "trak" -> {
                    val n = ++trackCounter[0]
                    val ctx = TrackCtx(n)
                    walk(src, box.bodyStart, box.end, depth + 1, sink, limits, trackCounter, ctx)
                    ctx.emit(sink)
                }
                box.type == "tkhd" && trackCtx != null -> tkhd(src, box, trackCtx)
                box.type == "mdhd" && trackCtx != null -> mdhd(src, box, trackCtx)
                box.type == "hdlr" && trackCtx != null -> hdlr(src, box, trackCtx)
                box.type == "stsd" && trackCtx != null -> stsd(src, box, trackCtx)
                box.type == "udta" -> udta(src, box, sink, limits)
                box.type == "meta" -> meta(src, box, sink, limits)
                box.type == "mdat" -> sink.note("Media data box (mdat) of ${box.size} bytes; not parsed.")
                box.type in CONTAINERS -> walk(src, box.bodyStart, box.end, depth + 1, sink, limits, trackCounter,
                    if (box.type == "trak") trackCtx else trackCtx)
            }
            pos = box.end
        }
    }

    private fun ftyp(src: BoundedFile, box: Box, sink: MetadataSink) {
        val body = src.read(box.bodyStart, (box.end - box.bodyStart).toInt())
        if (body.size < 8) throw FormatException("ftyp shorter than 8 bytes")
        sink.add("structure", "MajorBrand", String(body, 0, 4, Charsets.ISO_8859_1))
        val compat = (8 until body.size - 3 step 4).map { String(body, it, 4, Charsets.ISO_8859_1) }.filter { it.isNotBlank() }
        if (compat.isNotEmpty()) sink.add("structure", "CompatibleBrands", compat.joinToString(", "))
    }

    private fun mvhd(src: BoundedFile, box: Box, sink: MetadataSink) {
        val b = src.read(box.bodyStart, (box.end - box.bodyStart).toInt())
        val v = b[0].toInt() and 0xFF
        val (created, modified, timescale, duration) = if (v == 1) {
            listOf(u64(b, 4, le = false), u64(b, 12, le = false), u32(b, 20, le = false), u64(b, 24, le = false))
        } else {
            listOf(u32(b, 4, le = false), u32(b, 8, le = false), u32(b, 12, le = false), u32(b, 16, le = false))
        }
        addTime(sink, "MovieHeader", "CreationTime", created)
        addTime(sink, "MovieHeader", "ModificationTime", modified)
        if (timescale > 0) {
            sink.add("structure", "MovieTimescale", timescale.toString())
            sink.add("structure", "DurationSeconds", "%.3f".format(duration.toDouble() / timescale))
        }
    }

    private fun addTime(sink: MetadataSink, group: String, key: String, secs1904: Long) {
        if (secs1904 == 0L) {
            sink.note("$group.$key is zero (not set by the writer); no date reported.")
        } else if (secs1904 < 0) {
            sink.note("$group.$key is out of range.")
        } else {
            sink.add(group, key, EPOCH_1904.plusSeconds(secs1904).toString() + " (UTC, as recorded by writer)")
        }
    }

    private class TrackCtx(val n: Int) {
        var handler: String? = null
        var codec: String? = null
        var width: Double? = null
        var height: Double? = null
        var timescale: Long? = null
        var duration: Long? = null
        var language: String? = null
        fun emit(sink: MetadataSink) {
            val g = "MP4.track$n"
            handler?.let { sink.add(g, "HandlerType", it) }
            codec?.let { sink.add(g, "Codec", it) }
            width?.let { if (it > 0) sink.add(g, "Width", "%.0f".format(it)) }
            height?.let { if (it > 0) sink.add(g, "Height", "%.0f".format(it)) }
            language?.let { sink.add(g, "Language", it) }
            val ts = timescale; val d = duration
            if (ts != null && d != null && ts > 0) sink.add(g, "DurationSeconds", "%.3f".format(d.toDouble() / ts))
        }
    }

    private fun tkhd(src: BoundedFile, box: Box, ctx: TrackCtx) {
        val b = src.read(box.bodyStart, (box.end - box.bodyStart).toInt())
        val v = b[0].toInt() and 0xFF
        val wOff = if (v == 1) 88 else 76
        if (b.size < wOff + 8) throw FormatException("tkhd shorter than expected")
        ctx.width = u32(b, wOff, le = false) / 65536.0
        ctx.height = u32(b, wOff + 4, le = false) / 65536.0
    }

    private fun mdhd(src: BoundedFile, box: Box, ctx: TrackCtx) {
        val b = src.read(box.bodyStart, (box.end - box.bodyStart).toInt())
        val v = b[0].toInt() and 0xFF
        if (v == 1) {
            ctx.timescale = u32(b, 20, le = false)
            ctx.duration = u64(b, 24, le = false)
            ctx.language = packedLanguage(u16(b, 32, le = false))
        } else {
            ctx.timescale = u32(b, 12, le = false)
            ctx.duration = u32(b, 16, le = false)
            ctx.language = packedLanguage(u16(b, 20, le = false))
        }
    }

    private fun packedLanguage(v: Int): String? {
        if (v == 0 || v == 0x7FFF) return null
        return String(charArrayOf(((v shr 10) and 0x1F).plus(0x60).toChar(), ((v shr 5) and 0x1F).plus(0x60).toChar(), (v and 0x1F).plus(0x60).toChar()))
    }

    private fun hdlr(src: BoundedFile, box: Box, ctx: TrackCtx) {
        val b = src.read(box.bodyStart, (box.end - box.bodyStart).toInt())
        if (b.size >= 12) ctx.handler = String(b, 8, 4, Charsets.ISO_8859_1)
    }

    private fun stsd(src: BoundedFile, box: Box, ctx: TrackCtx) {
        val b = src.read(box.bodyStart, minOf(box.end - box.bodyStart, 64L).toInt())
        if (b.size >= 16) ctx.codec = String(b, 12, 4, Charsets.ISO_8859_1).trimEnd()
    }

    private fun udta(src: BoundedFile, box: Box, sink: MetadataSink, limits: AnalysisLimits) {
        var pos = box.bodyStart
        while (pos < box.end) {
            val c = readBox(src, pos, box.end)
            if (c.type == "meta") meta(src, c, sink, limits)
            else if (c.type.startsWith("\u00A9") || c.type == "loci") quickTimeText(src, c, sink, limits)
            pos = c.end
        }
    }

    /** QuickTime text items: uint16 length, uint16 language, text. */
    private fun quickTimeText(src: BoundedFile, c: Box, sink: MetadataSink, limits: AnalysisLimits) {
        val body = src.read(c.bodyStart, (c.end - c.bodyStart).toInt())
        if (body.size < 4) return
        val len = u16(body, 0, le = false)
        if (4 + len > body.size) throw FormatException("QuickTime text item '${c.type}' overruns its box")
        val text = String(body, 4, len, Charsets.UTF_8)
        val key = if (c.type == "loci" || c.type.endsWith("xyz")) "Location" else ITEM_NAMES[c.type] ?: c.type
        sink.add("MP4.udta", key, cleanText(text, limits.maxStringValueLength))
    }

    /** ISO meta is a full box (version/flags precede children); QuickTime meta has no such prefix. */
    private fun meta(src: BoundedFile, box: Box, sink: MetadataSink, limits: AnalysisLimits) {
        // A QuickTime meta box has its first child (type at offset 4) directly; an ISO meta box
        // starts with version/flags, so its first child's type sits at offset 8.
        val probe = src.readAvailable(box.bodyStart + 4, 4)
        val quickTime = probe.size == 4 && String(probe, Charsets.ISO_8859_1) == "hdlr"
        val start = if (quickTime) box.bodyStart else box.bodyStart + 4
        var pos = start
        while (pos < box.end) {
            val c = readBox(src, pos, box.end)
            if (c.type == "ilst") ilst(src, c, sink, limits)
            pos = c.end
        }
    }

    private fun ilst(src: BoundedFile, box: Box, sink: MetadataSink, limits: AnalysisLimits) {
        var pos = box.bodyStart
        while (pos < box.end) {
            val item = readBox(src, pos, box.end)
            val name = ITEM_NAMES[item.type] ?: item.type.trimEnd()
            var p = item.bodyStart
            while (p < item.end) {
                val d = readBox(src, p, item.end)
                if (d.type == "data") {
                    val body = src.read(d.bodyStart, (d.end - d.bodyStart).toInt())
                    if (body.size >= 8) {
                        val kind = u32(body, 0, le = false)
                        val payload = body.copyOfRange(8, body.size)
                        when (kind) {
                            1L -> sink.add("MP4.ilst", name, cleanText(String(payload, Charsets.UTF_8), limits.maxStringValueLength))
                            13L, 14L -> sink.add("MP4.ilst", name, "image (${if (kind == 13L) "JPEG" else "PNG"}, ${payload.size} bytes)")
                            21L -> if (payload.isNotEmpty()) sink.add("MP4.ilst", name, when (payload.size) {
                                1 -> (payload[0].toInt() and 0xFF).toString()
                                2 -> u16(payload, 0, le = false).toString()
                                4 -> u32(payload, 0, le = false).toString()
                                else -> "integer(${payload.size} bytes)"
                            })
                            else -> sink.add("MP4.ilst", name, "binary data (type $kind, ${payload.size} bytes)")
                        }
                    }
                }
                p = d.end
            }
            pos = item.end
        }
    }
}
