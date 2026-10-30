package forensics.metadata

import forensics.archive.ZipDirectory
import forensics.archive.ZipDirectoryReader
import forensics.archive.ZipEntryReader
import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.cleanText
import java.io.ByteArrayInputStream
import java.io.File
import javax.xml.stream.XMLInputFactory
import javax.xml.stream.XMLStreamConstants

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
        } catch (e: javax.xml.stream.XMLStreamException) {
            sink.error("$name: XML is malformed or refers to an entity that is not allowed (${e.message?.lineSequence()?.firstOrNull() ?: "no detail"})")
        }
    }

    private fun factory(): XMLInputFactory = XMLInputFactory.newFactory().apply {
        setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)
        setProperty(XMLInputFactory.SUPPORT_DTD, false)
        setProperty(XMLInputFactory.IS_COALESCING, true)
    }

    private fun parseFlat(bytes: ByteArray, group: String, keys: Map<String, String>, sink: MetadataSink, limits: AnalysisLimits) {
        val r = factory().createXMLStreamReader(ByteArrayInputStream(bytes))
        try {
            var current: String? = null
            val text = StringBuilder()
            while (r.hasNext()) {
                when (r.next()) {
                    XMLStreamConstants.DTD -> sink.note("$group: document type declaration present; not resolved.")
                    XMLStreamConstants.START_ELEMENT -> {
                        val local = r.localName
                        current = if (keys.containsKey(local)) local else null
                        text.setLength(0)
                    }
                    XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA -> if (current != null) text.append(r.text)
                    XMLStreamConstants.END_ELEMENT -> {
                        if (current != null && r.localName == current) {
                            sink.add(group, keys.getValue(current), cleanText(text.toString(), limits.maxStringValueLength))
                        }
                        current = null
                    }
                }
            }
        } finally { r.close() }
    }

    private fun parseCustom(bytes: ByteArray, sink: MetadataSink, limits: AnalysisLimits) {
        val r = factory().createXMLStreamReader(ByteArrayInputStream(bytes))
        try {
            var name: String? = null
            var inside = false
            val text = StringBuilder()
            while (r.hasNext()) {
                when (r.next()) {
                    XMLStreamConstants.START_ELEMENT -> if (r.localName == "property") {
                        name = r.getAttributeValue(null, "name")
                        inside = true
                        text.setLength(0)
                    }
                    XMLStreamConstants.CHARACTERS, XMLStreamConstants.CDATA -> if (inside) text.append(r.text)
                    XMLStreamConstants.END_ELEMENT -> if (r.localName == "property" && inside) {
                        sink.add("OOXML.custom", cleanText(name ?: "(unnamed)", 256),
                            cleanText(text.toString(), limits.maxStringValueLength))
                        inside = false
                    }
                }
            }
        } finally { r.close() }
    }
}
