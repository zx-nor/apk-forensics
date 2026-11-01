package forensics.metadata

import forensics.archive.ZipDirectory
import forensics.archive.ZipDirectoryReader
import forensics.archive.ZipEntryReader
import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import java.io.File

/**
 * DOCX/XLSX/PPTX document properties from docProps/core.xml, docProps/app.xml, and docProps/custom.xml.
 *
 * XML is parsed with external entities and DTDs disabled. A DTD in a package part is reported as a
 * finding; it is never resolved.
 */
object OoxmlMetadataExtractor {
    const val NAME = "ooxml-properties"
    const val VERSION = "1.0.0"

    private val CORE = mapOf(
        "title" to "Title", "subject" to "Subject", "creator" to "Creator", "description" to "Description",
        "keywords" to "Keywords", "category" to "Category", "lastModifiedBy" to "LastModifiedBy",
        "revision" to "Revision", "created" to "Created", "modified" to "Modified", "language" to "Language",
        "contentStatus" to "ContentStatus", "version" to "Version",
    )
    private val APP = mapOf(
        "Application" to "Application", "AppVersion" to "AppVersion", "Company" to "Company",
        "Manager" to "Manager", "Template" to "Template", "TotalTime" to "TotalEditingMinutes",
        "Pages" to "Pages", "Words" to "Words", "Slides" to "Slides", "Notes" to "Notes",
        "Characters" to "Characters", "Lines" to "Lines", "Paragraphs" to "Paragraphs",
    )

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            val dir = ZipDirectoryReader.read(src, limits)
            val names = dir.entries.map { it.name }.toSet()
            if ("[Content_Types].xml" !in names) throw FormatException("[Content_Types].xml missing; not an OOXML package")
            if (dir.entries.any { it.flags and 1 != 0 }) {
                sink.note("Package contains encrypted entries; those parts were not read.")
            }
            val partLimit = minOf(limits.maxMetadataSegmentBytes, 4 shl 20)
            readPart(src, dir, "docProps/core.xml", partLimit, sink) { bytes -> parseFlat(bytes, "OOXML.core", CORE, sink, limits) }
            readPart(src, dir, "docProps/app.xml", partLimit, sink) { bytes -> parseFlat(bytes, "OOXML.app", APP, sink, limits) }
            readPart(src, dir, "docProps/custom.xml", partLimit, sink) { bytes -> parseCustom(bytes, sink, limits) }
            if ("docProps/core.xml" !in names && "docProps/app.xml" !in names) {
                sink.note("No docProps parts are present; document properties are absent.")
            }
        }
    }

    private fun readPart(src: BoundedFile, dir: ZipDirectory, name: String, cap: Int, sink: MetadataSink, parse: (ByteArray) -> Unit) {
        if (dir.entries.none { it.name == name }) return
        try {
            val bytes = ZipEntryReader.read(src, dir, name, cap) ?: return
            parse(bytes)
        } catch (e: FormatException) {
            sink.error("$name: ${e.message}")
        }
    }

    private fun parseFlat(bytes: ByteArray, group: String, keys: Map<String, String>, sink: MetadataSink, limits: AnalysisLimits) {
        var current: String? = null
        val text = StringBuilder()
        for (ev in SafeXml.parse(bytes)) {
            when (ev) {
                SafeXml.Event.Doctype -> sink.note("$group: document type declaration present; not resolved.")
                is SafeXml.Event.Start -> {
                    current = if (keys.containsKey(ev.localName)) ev.localName else null
                    text.setLength(0)
                }
                is SafeXml.Event.Text -> if (current != null) text.append(ev.text)
                is SafeXml.Event.End -> {
                    if (current != null && ev.localName == current) {
                        sink.add(group, keys.getValue(current), cleanText(text.toString(), limits.maxStringValueLength))
                    }
                    current = null
                }
            }
        }
    }

    private fun parseCustom(bytes: ByteArray, sink: MetadataSink, limits: AnalysisLimits) {
        var name: String? = null
        var inside = false
        val text = StringBuilder()
        for (ev in SafeXml.parse(bytes)) {
            when (ev) {
                is SafeXml.Event.Start -> if (ev.localName == "property") {
                    name = ev.attributes["name"]
                    inside = true
                    text.setLength(0)
                }
                is SafeXml.Event.Text -> if (inside) text.append(ev.text)
                is SafeXml.Event.End -> if (ev.localName == "property" && inside) {
                    sink.add("OOXML.custom", cleanText(name ?: "(unnamed)", 256),
                        cleanText(text.toString(), limits.maxStringValueLength))
                    inside = false
                }
                SafeXml.Event.Doctype -> sink.note("OOXML.custom: document type declaration present; not resolved.")
            }
        }
    }
}
