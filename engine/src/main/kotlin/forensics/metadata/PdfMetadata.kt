package forensics.metadata

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import java.io.ByteArrayOutputStream
import java.io.File

/**
 * PDF document information.
 *
 * Locates the trailer (classic xref or xref stream), reads /Info and /Encrypt, then parses the
 * Info dictionary from its top-level object. Info dictionaries stored inside object streams are
 * reported as not located rather than guessed at. Encrypted documents are NOT_SUPPORTED: their
 * strings are ciphertext and no decryption is attempted.
 */
object PdfMetadataExtractor {
    const val NAME = "pdf-info"
    const val VERSION = "1.0.0"

    private val INFO_KEYS = listOf("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate", "Trapped")

    fun extract(file: File, limits: AnalysisLimits): MetadataResult {
        val notSupportedResult = BoundedFile(file).use { src -> analyze(src, limits) }
        return notSupportedResult
    }

    private fun analyze(src: BoundedFile, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        val head = src.read(0, minOf(src.length, 1024L).toInt())
        val hdr = String(head, Charsets.ISO_8859_1)
        if (!hdr.startsWith("%PDF-")) throw FormatException("%PDF- header missing")
        sink.add("structure", "PDFVersion", hdr.substring(5, minOf(8, hdr.length)).trim())

        val trailer = findTrailer(src, sink) ?: throw FormatException("trailer dictionary not found")
        if (trailer.containsKey("Encrypt")) {
            // Encrypted: strings are ciphertext. Report the state, not partial values.
            sink.unsupported("Document is encrypted (/Encrypt present). Metadata strings were not decrypted; no values reported.")
            return@runExtractor
        }
        val infoRef = trailer["Info"] as? PdfRef
        if (infoRef == null) {
            sink.note("Trailer has no /Info entry; document information is absent.")
            return@runExtractor
        }
        val objBytes = findObjectDictionary(src, infoRef, limits)
        if (objBytes == null) {
            sink.note("Info dictionary ${infoRef.num} ${infoRef.gen} R was not found as a top-level object (it may reside in an object stream). Not extracted.")
            return@runExtractor
        }
        for (k in INFO_KEYS) {
            val v = objBytes[k] ?: continue
            val text = when (v) {
                is PdfString -> decodeText(v.bytes)
                is PdfName -> v.value
                else -> continue
            }
            if (k.endsWith("Date")) {
                sink.add("PDF.Info", k, formatPdfDate(text))
            } else {
                sink.add("PDF.Info", k, cleanText(text, limits.maxStringValueLength))
            }
        }
    }

    /** Finds the trailer dictionary in the last 64 KiB (classic xref) or from startxref (xref stream). */
    private fun findTrailer(src: BoundedFile, sink: MetadataSink): Map<String, Any>? {
        val tailStart = maxOf(0L, src.length - 65536)
        val tail = String(src.read(tailStart, (src.length - tailStart).toInt()), Charsets.ISO_8859_1)
        val t = tail.lastIndexOf("trailer")
        if (t >= 0) {
            val p = PdfParser(src.read(tailStart + t + 7, minOf(4096L, src.length - tailStart - t - 7).toInt()))
            val v = p.parseValue()
            if (v is PdfDict) return v.map
        }
        val sx = tail.lastIndexOf("startxref")
        if (sx >= 0) {
            val after = tail.substring(sx + 9).trim().takeWhile { it.isDigit() }
            val off = after.toLongOrNull() ?: return null
            if (off < 0 || off >= src.length) throw FormatException("startxref offset out of range")
            val chunk = src.read(off, minOf(65536L, src.length - off).toInt())
            val p = PdfParser(chunk)
            p.parseIndirectHeader()
            val v = p.parseValue()
            if (v is PdfDict) {
                sink.note("Trailer taken from cross-reference stream at offset $off.")
                return v.map
            }
        }
        return null
    }

    /** Locates the last top-level "num gen obj" for [ref] and parses its dictionary. */
    private fun findObjectDictionary(src: BoundedFile, ref: PdfRef, limits: AnalysisLimits): Map<String, Any>? {
        val needle = "${ref.num} ${ref.gen} obj".toByteArray(Charsets.ISO_8859_1)
        var found = -1L
        var carry = ByteArray(0)
        var pos = 0L
        val scanned = minOf(src.length, limits.maxEmbeddedScanBytes)
        while (pos < scanned) {
            val n = minOf(64 * 1024L, scanned - pos).toInt()
            val buf = carry + src.read(pos, n)
            val base = pos - carry.size
            var i = 0
            while (i + needle.size <= buf.size) {
                var ok = true
                for (k in needle.indices) if (buf[i + k] != needle[k]) { ok = false; break }
                if (ok) {
                    val abs = base + i
                    val prevDigit = if (i > 0) buf[i - 1].toInt().toChar().isDigit() else false
                    if (!prevDigit) found = abs
                }
                i++
            }
            carry = if (buf.size >= needle.size - 1) buf.copyOfRange(buf.size - (needle.size - 1), buf.size) else buf
            pos += n
        }
        if (found < 0) return null
        val body = src.read(found, minOf(65536L, src.length - found).toInt())
        val p = PdfParser(body)
        p.parseIndirectHeader()
        val v = p.parseValue()
        return (v as? PdfDict)?.map
    }

    /** PDF text strings: UTF-16BE with BOM, UTF-8 with BOM, otherwise PDFDocEncoding approximated as Latin-1. */
    fun decodeText(b: ByteArray): String = when {
        b.size >= 2 && b[0] == 0xFE.toByte() && b[1] == 0xFF.toByte() -> String(b, 2, b.size - 2, Charsets.UTF_16BE)
        b.size >= 3 && b[0] == 0xEF.toByte() && b[1] == 0xBB.toByte() && b[2] == 0xBF.toByte() -> String(b, 3, b.size - 3, Charsets.UTF_8)
        else -> String(b, Charsets.ISO_8859_1)
    }

    /** D:YYYYMMDDHHmmSSOHH'mm' is kept as written and annotated with its offset when present. */
    fun formatPdfDate(raw: String): String {
        val m = Regex("^D:(\\d{4})(\\d{2})?(\\d{2})?(\\d{2})?(\\d{2})?(\\d{2})?([Zz+-])?(\\d{2})?'?(\\d{2})?'?").find(raw.trim())
            ?: return raw
        val g = m.groupValues
        val base = "${g[1]}-${g[2].ifEmpty { "01" }}-${g[3].ifEmpty { "01" }}T${g[4].ifEmpty { "00" }}:${g[5].ifEmpty { "00" }}:${g[6].ifEmpty { "00" }}"
        val zone = when (g[7]) {
            "" -> " (no time zone recorded)"
            "Z", "z" -> " (UTC)"
            else -> " (UTC${g[7]}${g[8].ifEmpty { "00" }}:${g[9].ifEmpty { "00" }})"
        }
        return base + zone
    }
}

data class PdfRef(val num: Int, val gen: Int)
data class PdfName(val value: String)
data class PdfString(val bytes: ByteArray)
data class PdfDict(val map: Map<String, Any>)

/** Minimal PDF object parser for dictionaries, names, strings, numbers, arrays, and references. */
internal class PdfParser(private val b: ByteArray) {
    private var p = 0
    private var depth = 0

    fun parseIndirectHeader() {
        skipWs()
        val n = readInt() ?: throw FormatException("object number missing")
        skipWs(); readInt() ?: throw FormatException("generation number missing")
        skipWs()
        if (!matchWord("obj")) throw FormatException("'obj' keyword missing")
        if (n < 0) throw FormatException("negative object number")
    }

    fun parseValue(): Any? {
        if (++depth > 64) throw FormatException("PDF object nesting too deep")
        try {
            skipWs()
            if (p >= b.size) throw FormatException("unexpected end of PDF object data")
            val c = b[p].toInt().toChar()
            return when {
                c == '<' && p + 1 < b.size && b[p + 1] == '<'.code.toByte() -> parseDict()
                c == '<' -> parseHex()
                c == '(' -> parseLiteral()
                c == '[' -> parseArray()
                c == '/' -> parseName()
                c == '-' || c == '+' || c == '.' || c.isDigit() -> parseNumberOrRef()
                matchWord("true") -> true
                matchWord("false") -> false
                matchWord("null") -> null
                else -> throw FormatException("unexpected character '$c' at PDF offset $p")
            }
        } finally { depth-- }
    }

    private fun parseDict(): PdfDict {
        p += 2
        val map = LinkedHashMap<String, Any>()
        while (true) {
            skipWs()
            if (p + 1 < b.size && b[p] == '>'.code.toByte() && b[p + 1] == '>'.code.toByte()) { p += 2; break }
            if (p >= b.size) throw FormatException("dictionary not terminated")
            val key = parseName().value
            val v = parseValue()
            if (v != null) map[key] = v
        }
        return PdfDict(map)
    }

    private fun parseArray(): List<Any?> {
        p++
        val out = mutableListOf<Any?>()
        while (true) {
            skipWs()
            if (p >= b.size) throw FormatException("array not terminated")
            if (b[p] == ']'.code.toByte()) { p++; break }
            out += parseValue()
        }
        return out
    }

    private fun parseName(): PdfName {
        skipWs()
        if (p >= b.size || b[p] != '/'.code.toByte()) throw FormatException("name expected at PDF offset $p")
        p++
        val sb = StringBuilder()
        while (p < b.size && !isDelimiter(b[p]) && !isWhite(b[p])) {
            if (b[p] == '#'.code.toByte() && p + 2 < b.size) {
                sb.append(hexByte(b[p + 1], b[p + 2]).toInt().toChar())
                p += 3
            } else { sb.append(b[p].toInt().toChar()); p++ }
        }
        return PdfName(sb.toString())
    }

    private fun parseLiteral(): PdfString {
        p++
        val out = ByteArrayOutputStream()
        var nest = 1
        while (p < b.size) {
            val c = b[p].toInt() and 0xFF
            p++
            when (c) {
                '('.code -> { nest++; out.write(c) }
                ')'.code -> { nest--; if (nest == 0) return PdfString(out.toByteArray()); out.write(c) }
                '\\'.code -> {
                    if (p >= b.size) break
                    val e = b[p].toInt() and 0xFF
                    p++
                    when (e) {
                        'n'.code -> out.write(10)
                        'r'.code -> out.write(13)
                        't'.code -> out.write(9)
                        'b'.code -> out.write(8)
                        'f'.code -> out.write(12)
                        '('.code, ')'.code, '\\'.code -> out.write(e)
                        in '0'.code..'7'.code -> {
                            var v = e - '0'.code
                            var k = 0
                            while (k < 2 && p < b.size && b[p] in '0'.code.toByte()..'7'.code.toByte()) {
                                v = v * 8 + (b[p] - '0'.code.toByte()); p++; k++
                            }
                            out.write(v and 0xFF)
                        }
                        '\r'.code -> if (p < b.size && b[p] == '\n'.code.toByte()) p++
                        '\n'.code -> {}
                        else -> out.write(e)
                    }
                }
                else -> out.write(c)
            }
            if (out.size() > MAX_STRING) throw FormatException("string exceeds limit")
        }
        throw FormatException("literal string not terminated")
    }

    private fun parseHex(): PdfString {
        p++
        val out = ByteArrayOutputStream()
        var hi = -1
        while (p < b.size && b[p] != '>'.code.toByte()) {
            val c = b[p].toInt().toChar()
            p++
            if (isWhite(b[p - 1])) continue
            val v = Character.digit(c, 16)
            if (v < 0) throw FormatException("invalid hex digit in PDF string")
            if (hi < 0) hi = v else { out.write(hi * 16 + v); hi = -1 }
        }
        if (p >= b.size) throw FormatException("hex string not terminated")
        p++
        if (hi >= 0) out.write(hi * 16)
        return PdfString(out.toByteArray())
    }

    private fun parseNumberOrRef(): Any {
        val start = p
        val first = readNumberToken() ?: throw FormatException("number expected")
        val save = p
        skipWs()
        if (first is Int && p < b.size && b[p].toInt().toChar().isDigit()) {
            val g = readInt()
            skipWs()
            if (g != null && p < b.size && b[p] == 'R'.code.toByte()) {
                p++
                return PdfRef(first, g)
            }
        }
        p = save
        if (p == start) throw FormatException("number parse stalled")
        return first
    }

    private fun readNumberToken(): Number? {
        val s = p
        if (p < b.size && (b[p] == '-'.code.toByte() || b[p] == '+'.code.toByte())) p++
        while (p < b.size && (b[p].toInt().toChar().isDigit() || b[p] == '.'.code.toByte())) p++
        val t = String(b, s, p - s, Charsets.ISO_8859_1)
        return t.toIntOrNull() ?: t.toDoubleOrNull()
    }

    private fun readInt(): Int? {
        val s = p
        while (p < b.size && b[p].toInt().toChar().isDigit()) p++
        return if (p == s) null else String(b, s, p - s, Charsets.ISO_8859_1).toIntOrNull()
    }

    private fun matchWord(w: String): Boolean {
        if (p + w.length > b.size) return false
        for (i in w.indices) if (b[p + i] != w[i].code.toByte()) return false
        val end = p + w.length
        if (end < b.size && !isDelimiter(b[end]) && !isWhite(b[end])) return false
        p = end
        return true
    }

    private fun skipWs() {
        while (p < b.size) {
            val c = b[p]
            if (isWhite(c)) { p++; continue }
            if (c == '%'.code.toByte()) {
                while (p < b.size && b[p] != '\n'.code.toByte() && b[p] != '\r'.code.toByte()) p++
                continue
            }
            break
        }
    }

    private fun isWhite(c: Byte) = c == 0.toByte() || c == 9.toByte() || c == 10.toByte() || c == 12.toByte() || c == 13.toByte() || c == 32.toByte()
    private fun isDelimiter(c: Byte) = "()<>[]{}/%".indexOf(c.toInt().toChar()) >= 0
    private fun hexByte(a: Byte, b2: Byte): Byte = (Character.digit(a.toInt().toChar(), 16) * 16 + Character.digit(b2.toInt().toChar(), 16)).toByte()

    companion object { private const val MAX_STRING = 1 shl 20 }
}
