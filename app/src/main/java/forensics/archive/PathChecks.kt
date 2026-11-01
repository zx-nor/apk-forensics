package forensics.archive

import forensics.common.Finding
import forensics.common.Severity

/**
 * Inspects archive entry names for path-traversal and deception patterns.
 * Pure string analysis: nothing is resolved against the filesystem.
 */
object PathChecks {
    private val driveLetter = Regex("^[A-Za-z]:")
    private val executableExtensions = setOf(
        "exe", "dll", "so", "dex", "elf", "sh", "bat", "cmd", "ps1", "msi", "jar", "apk", "bin",
    )
    private val bidiControls = setOf('\u202A', '\u202B', '\u202C', '\u202D', '\u202E', '\u2066', '\u2067', '\u2068', '\u2069')

    fun check(path: String, what: String = "entry name"): List<Finding> {
        val out = mutableListOf<Finding>()
        if (path.isEmpty()) {
            out += Finding("EMPTY_NAME", Severity.SUSPICIOUS, "$what is empty.", path)
            return out
        }
        val segments = path.split('/', '\\')
        if (segments.any { it == ".." }) {
            out += Finding("PATH_TRAVERSAL", Severity.SUSPICIOUS,
                "$what contains a parent-directory segment (..). Extraction would escape its target directory.", path)
        }
        if (path.startsWith('/') || path.startsWith('\\')) {
            out += Finding("ABSOLUTE_PATH", Severity.SUSPICIOUS, "$what is absolute.", path)
        }
        if (driveLetter.containsMatchIn(path)) {
            out += Finding("DRIVE_LETTER_PATH", Severity.SUSPICIOUS, "$what begins with a drive letter.", path)
        }
        if (path.contains('\\')) {
            out += Finding("BACKSLASH_SEPARATOR", Severity.NOTE,
                "$what uses backslash separators, which some extractors interpret differently.", path)
        }
        if (path.any { it.code < 0x20 || it.code == 0x7F }) {
            out += Finding("CONTROL_CHARACTER", Severity.SUSPICIOUS,
                "$what contains control characters.", path.map { if (it.code < 0x20 || it.code == 0x7F) "\\x%02X".format(it.code) else it.toString() }.joinToString(""))
        }
        if (path.any { it in bidiControls }) {
            out += Finding("BIDI_CONTROL_CHARACTER", Severity.SUSPICIOUS,
                "$what contains a bidirectional override or isolate character, which can make a name display differently from its true value.", path)
        }
        if (path.length > 255) {
            out += Finding("LONG_NAME", Severity.NOTE, "$what is ${path.length} characters long.", path.take(64) + "…")
        }
        val ext = path.substringAfterLast('.', "").lowercase()
        if (what == "entry name" && ext in executableExtensions && !path.endsWith("/")) {
            out += Finding("EXECUTABLE_CONTENT_PRESENT", Severity.INFO,
                "Entry has an executable or code extension (.$ext). It was not executed or extracted.", path)
        }
        return out
    }
}
