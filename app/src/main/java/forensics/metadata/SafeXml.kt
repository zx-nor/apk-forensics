package forensics.metadata

import forensics.common.FormatException

/**
 * Minimal, non-validating XML reader for OOXML property parts.
 *
 * Written in plain Kotlin so it runs on Android (which has no javax.xml.stream) as well as on the JVM.
 * Deliberately limited: it resolves only the five predefined entities and numeric character references.
 * Any other entity reference (including external entities in a DOCTYPE) is a FormatException, and a
 * DOCTYPE is reported as an event so the caller can record it. Nothing is ever fetched or expanded.
 */
object SafeXml {
    sealed class Event {
        data class Start(val localName: String, val attributes: Map<String, String>) : Event()
        data class Text(val text: String) : Event()
        data class End(val localName: String) : Event()
        object Doctype : Event()
    }

    private const val MAX_DEPTH = 64

    fun parse(bytes: ByteArray): List<Event> {
        val s = String(bytes, Charsets.UTF_8)
        val out = ArrayList<Event>()
        val open = ArrayList<String>()
        var i = 0
        fun fail(msg: String): Nothing = throw FormatException("XML: $msg at character $i")
        while (i < s.length) {
            val c = s[i]
            if (c != '<') {
                val end = s.indexOf('<', i).let { if (it < 0) s.length else it }
                val raw = s.substring(i, end)
                if (open.isNotEmpty()) out += Event.Text(decode(raw) { fail(it) })
                i = end
                continue
            }
            when {
                s.startsWith("<?", i) -> {
                    val e = s.indexOf("?>", i)
                    if (e < 0) fail("unterminated processing instruction")
                    i = e + 2
                }
                s.startsWith("<!--", i) -> {
                    val e = s.indexOf("-->", i + 4)
                    if (e < 0) fail("unterminated comment")
                    i = e + 3
                }
                s.startsWith("<![CDATA[", i) -> {
                    val e = s.indexOf("]]>", i + 9)
                    if (e < 0) fail("unterminated CDATA section")
                    if (open.isNotEmpty()) out += Event.Text(s.substring(i + 9, e))
                    i = e + 3
                }
                s.startsWith("<!DOCTYPE", i) -> {
                    out += Event.Doctype
                    i = skipDoctype(s, i) { fail(it) }
                }
                s.startsWith("</", i) -> {
                    val e = s.indexOf('>', i)
                    if (e < 0) fail("unterminated end tag")
                    val name = localNameOf(s.substring(i + 2, e).trim())
                    if (open.isEmpty() || open.last() != name) fail("mismatched end tag </$name>")
                    open.removeAt(open.size - 1)
                    out += Event.End(name)
                    i = e + 1
                }
                else -> {
                    val (name, attrs, selfClosing, next) = readStartTag(s, i) { fail(it) }
                    if (open.size >= MAX_DEPTH) fail("nesting deeper than $MAX_DEPTH")
                    out += Event.Start(localNameOf(name), attrs.mapKeys { localNameOf(it.key) })
                    if (selfClosing) out += Event.End(localNameOf(name)) else open += localNameOf(name)
                    i = next
                }
            }
        }
        if (open.isNotEmpty()) throw FormatException("XML: element <${open.last()}> is never closed")
        return out
    }

    private data class StartTag(val name: String, val attrs: Map<String, String>, val selfClosing: Boolean, val next: Int)

    private inline fun readStartTag(s: String, start: Int, fail: (String) -> Nothing): StartTag {
        var i = start + 1
        val nameStart = i
        while (i < s.length && !s[i].isWhitespace() && s[i] != '>' && s[i] != '/') i++
        val name = s.substring(nameStart, i)
        if (name.isEmpty()) fail("empty tag name")
        val attrs = LinkedHashMap<String, String>()
        while (true) {
            while (i < s.length && s[i].isWhitespace()) i++
            if (i >= s.length) fail("unterminated start tag <$name>")
            if (s[i] == '>') return StartTag(name, attrs, false, i + 1)
            if (s[i] == '/' && i + 1 < s.length && s[i + 1] == '>') return StartTag(name, attrs, true, i + 2)
            val an = i
            while (i < s.length && s[i] != '=' && !s[i].isWhitespace()) i++
            val aname = s.substring(an, i)
            while (i < s.length && s[i].isWhitespace()) i++
            if (i >= s.length || s[i] != '=') fail("attribute '$aname' has no value")
            i++
            while (i < s.length && s[i].isWhitespace()) i++
            if (i >= s.length || (s[i] != '"' && s[i] != '\'')) fail("attribute '$aname' is not quoted")
            val q = s[i]
            val vEnd = s.indexOf(q, i + 1)
            if (vEnd < 0) fail("attribute '$aname' is not terminated")
            attrs[aname] = decode(s.substring(i + 1, vEnd)) { fail(it) }
            i = vEnd + 1
        }
    }

    /** Skips a DOCTYPE including an internal subset in brackets; its contents are never interpreted. */
    private inline fun skipDoctype(s: String, start: Int, fail: (String) -> Nothing): Int {
        var i = start + 9
        var depth = 0
        while (i < s.length) {
            when (s[i]) {
                '[' -> depth++
                ']' -> depth--
                '>' -> if (depth <= 0) return i + 1
            }
            i++
        }
        fail("unterminated DOCTYPE")
    }

    private inline fun decode(raw: String, fail: (String) -> Nothing): String {
        if (raw.indexOf('&') < 0) return raw
        val sb = StringBuilder(raw.length)
        var i = 0
        while (i < raw.length) {
            val c = raw[i]
            if (c != '&') { sb.append(c); i++; continue }
            val semi = raw.indexOf(';', i)
            if (semi < 0 || semi - i > 12) fail("malformed character reference")
            val ref = raw.substring(i + 1, semi)
            when {
                ref == "lt" -> sb.append('<')
                ref == "gt" -> sb.append('>')
                ref == "amp" -> sb.append('&')
                ref == "quot" -> sb.append('"')
                ref == "apos" -> sb.append('\'')
                ref.startsWith("#x") -> sb.appendCodePoint(ref.substring(2).toIntOrNull(16) ?: fail("bad reference &$ref;"))
                ref.startsWith("#") -> sb.appendCodePoint(ref.substring(1).toIntOrNull() ?: fail("bad reference &$ref;"))
                else -> fail("entity &$ref; is not permitted")
            }
            i = semi + 1
        }
        return sb.toString()
    }

    private fun localNameOf(qname: String): String = qname.substringAfter(':')
}
