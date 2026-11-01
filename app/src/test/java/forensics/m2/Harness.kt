package forensics.m2

import forensics.CorpusTestSupport
import forensics.archive.MeasurementStatus
import forensics.archive.ZipAnalysis
import forensics.archive.ZipAnalyzer
import forensics.common.AnalysisLimits
import forensics.common.Finding
import forensics.identify.DeepIdentification
import forensics.identify.DeepIdentifier
import forensics.metadata.MetadataDispatcher
import forensics.metadata.MetadataResult
import java.io.File
import java.nio.file.Files

/** One expectation row: file, key, expected value. */
data class ExpectRow(val file: String, val key: String, val value: String)

object ExpectationTable {
    fun load(): List<ExpectRow> {
        val lines = File(CorpusTestSupport.corpus2Dir, "expected_m2.tsv").readLines().map { it.trimEnd('\r') }
        return lines.drop(1).filter { it.isNotBlank() }.map { line ->
            val parts = line.split("\t", limit = 3)
            require(parts.size == 3) { "malformed expectation row: $line" }
            ExpectRow(parts[0], parts[1], parts[2])
        }
    }
}

/** Runs the full analysis pipeline on one file, with a private scratch directory for nested work. */
class Analysis private constructor(val file: File, private val scratch: File, val limits: AnalysisLimits) {
    val deep: DeepIdentification by lazy { DeepIdentifier(limits, scratch).identify(file) }
    val meta: MetadataResult? by lazy { MetadataDispatcher.extract(file, deep.refinedFormat, limits) }
    /** Zip analysis for the file. Falls back to direct analysis for archives whose leading bytes are not a ZIP signature. */
    val zip: ZipAnalysis? by lazy { deep.zip ?: ZipAnalyzer(limits, scratch).analyze(file) }

    val allFindings: List<Finding> by lazy {
        val out = mutableListOf<Finding>()
        out += deep.findings
        zip?.let { out += collect(it) }
        out
    }

    private fun collect(z: ZipAnalysis): List<Finding> =
        z.archiveFindings + z.entries.flatMap { e -> e.findings + (e.nested?.let { collect(it) } ?: emptyList()) }

    fun fieldsWithKey(group: String, key: String) = meta?.fields.orEmpty().filter { it.group == group && it.key == key }

    fun entry(name: String) = zip?.entries?.firstOrNull { it.name == name }
        ?: error("no zip entry '$name' in ${file.name}")

    companion object {
        fun of(name: String, limits: AnalysisLimits = AnalysisLimits()): Analysis {
            val scratch = Files.createTempDirectory("bbf-m2-").toFile().also { it.deleteOnExit() }
            return Analysis(CorpusTestSupport.file2(name), scratch, limits)
        }
    }
}

/** Evaluates one expectation row against an analysis. Returns null on success or a failure description. */
fun evaluate(a: Analysis, row: ExpectRow): String? {
    val k = row.key
    val v = row.value
    fun fail(msg: String) = "${row.file} [$k] expected '$v': $msg"
    return when {
        k == "refined" -> {
            val actual = a.deep.refinedFormat ?: "<none>"
            if (actual == v) null else fail("was '$actual'")
        }
        k == "mismatch" -> {
            val actual = a.deep.extensionMismatch.toString()
            if (actual == v) null else fail("was $actual")
        }
        k == "zipkind" -> {
            val actual = (a.deep.zip ?: a.zip)?.classification?.kind?.name ?: "<none>"
            if (actual == v) null else fail("was '$actual'")
        }
        k == "appended.bytes" -> {
            val actual = (a.deep.appended?.trailingBytes ?: 0L).toString()
            if (actual == v) null else fail("was $actual")
        }
        k == "appended.zero" -> {
            val actual = (a.deep.appended?.zeroPadding ?: false).toString()
            if (actual == v) null else fail("was $actual")
        }
        k == "meta.status" -> {
            val actual = a.meta?.status?.name ?: "NONE"
            if (actual == v) null else fail("was '$actual' (errors=${a.meta?.errors}, notes=${a.meta?.notes})")
        }
        k.startsWith("field:") -> {
            val spec = k.removePrefix("field:")
            val (group, key) = spec.split("|", limit = 2)
            val values = a.fieldsWithKey(group, key).map { it.value }
            if (v in values) null else fail("field $group|$key values were $values")
        }
        k.startsWith("absent:") && k.contains("|") -> {
            val (group, key) = k.removePrefix("absent:").split("|", limit = 2)
            if (a.fieldsWithKey(group, key).isEmpty()) null else fail("field $group|$key should be absent")
        }
        k.startsWith("absent:") -> {
            val code = k.removePrefix("absent:")
            if (a.allFindings.none { it.code == code }) null else fail("finding $code should be absent")
        }
        k.startsWith("finding:") -> {
            val code = k.removePrefix("finding:")
            if (a.allFindings.any { it.code == code }) null else fail("finding $code not reported; had ${a.allFindings.map { it.code }.distinct()}")
        }
        k.startsWith("note:") -> {
            val text = k.removePrefix("note:")
            val texts = (a.meta?.notes.orEmpty() + a.meta?.errors.orEmpty() + a.allFindings.map { it.message })
            if (texts.any { it.contains(text) }) null else fail("no note containing '$text'")
        }
        k.startsWith("error:") -> {
            val text = k.removePrefix("error:")
            if (a.meta?.errors.orEmpty().any { it.contains(text) }) null else fail("errors were ${a.meta?.errors}")
        }
        k == "parseerror" -> {
            val msg = (a.deep.zip ?: a.zip)?.parseError.orEmpty()
            if (msg.contains(v)) null else fail("parse error was '$msg'")
        }
        k == "entries" -> {
            val actual = (a.zip?.entries?.size ?: -1).toString()
            if (actual == v) null else fail("entry count was $actual")
        }
        k.startsWith("zip.enc:") -> {
            val e = a.entry(k.removePrefix("zip.enc:"))
            val actual = e.encryption?.scheme ?: "<none>"
            if (actual == v) null else fail("encryption was '$actual'")
        }
        k.startsWith("zip.enc.bits:") -> {
            val e = a.entry(k.removePrefix("zip.enc.bits:"))
            val actual = e.encryption?.strengthBits?.toString() ?: "<none>"
            if (actual == v) null else fail("strength bits were '$actual'")
        }
        k.startsWith("zip.enc.actual:") -> {
            val e = a.entry(k.removePrefix("zip.enc.actual:"))
            val actual = e.encryption?.actualMethod?.toString() ?: "<none>"
            if (actual == v) null else fail("actual method was '$actual'")
        }
        k == "zip.trailing" -> {
            val actual = (a.zip?.trailingBytes ?: -1).toString()
            if (actual == v) null else fail("trailing bytes were $actual")
        }
        k == "zip.prepended" -> {
            val actual = (a.zip?.prependedBytes ?: -1).toString()
            if (actual == v) null else fail("prepended bytes were $actual")
        }
        k.startsWith("entry:") && k.endsWith("|measured") -> {
            val e = a.entry(k.removePrefix("entry:").removeSuffix("|measured"))
            val actual = e.measuredUncompressedSize?.toString() ?: "<not measured: ${e.measurement}>"
            if (actual == v) null else fail("measured was '$actual'")
        }
        k.startsWith("entry:") && k.endsWith("|crc") -> {
            val e = a.entry(k.removePrefix("entry:").removeSuffix("|crc"))
            val actual = when {
                e.crc32Computed == null -> "not computed"
                e.crc32Computed == e.crc32Declared -> "ok"
                else -> "bad"
            }
            if (actual == v) null else fail("crc state was '$actual'")
        }
        k.startsWith("nested:") -> {
            val e = a.entry(k.removePrefix("nested:"))
            val actual = e.nestedKind ?: "<none>"
            if (actual == v) null else fail("nested kind was '$actual'")
        }
        k.startsWith("nested.entry:") -> {
            val (outer, inner) = k.removePrefix("nested.entry:").split("|", limit = 2)
            val nested = a.entry(outer).nested
            if (nested != null && nested.entries.any { it.name == inner }) null
            else fail("nested archive does not contain '$inner'")
        }
        k.startsWith("embedded:") -> {
            val spec = k.removePrefix("embedded:")
            val (kind, off) = spec.split("@", limit = 2)
            val hit = a.deep.embedded.any { it.formatId == kind && (off.isEmpty() || it.offset == off.toLong()) }
            if (hit) null else fail("no embedded $kind at offset '$off'; hits=${a.deep.embedded.map { it.formatId + "@" + it.offset }}")
        }
        else -> fail("unknown expectation key")
    }
}

/** Convenience for tests: whether a measurement status is the given one for the named entry. */
fun Analysis.measurementOf(name: String): MeasurementStatus = entry(name).measurement
