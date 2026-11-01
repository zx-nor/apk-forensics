package forensics.metadata

import forensics.common.EngineInfo
import forensics.common.FormatException

/**
 * Outcome of one extraction.
 *
 * EXTRACTED: descriptive fields were found.
 * NO_METADATA_PRESENT: the structure parsed correctly and contains no descriptive metadata.
 * EXTRACTION_FAILED: the structure was malformed or unreadable. [MetadataResult.errors] says why.
 * NOT_SUPPORTED: the format is recognized but the content cannot be read (for example, encrypted).
 */
enum class MetadataStatus { EXTRACTED, NO_METADATA_PRESENT, EXTRACTION_FAILED, NOT_SUPPORTED }

/** One name/value pair. [group] names the source block (for example "EXIF", "PNG.tEXt", "structure"). */
data class MetadataField(val group: String, val key: String, val value: String)

data class MetadataResult(
    val extractor: String,
    val extractorVersion: String,
    val engineVersion: String,
    val javaRuntime: String,
    val status: MetadataStatus,
    val fields: List<MetadataField>,
    val notes: List<String>,
    val errors: List<String>,
)

/** Collects fields and notes while an extractor runs. */
class MetadataSink {
    val fields = mutableListOf<MetadataField>()
    val notes = mutableListOf<String>()
    val errors = mutableListOf<String>()
    /** Set when the content is recognized but cannot be read (for example, encrypted). */
    var unsupportedReason: String? = null

    fun unsupported(reason: String) { unsupportedReason = reason }

    fun add(group: String, key: String, value: String) {
        if (value.isNotEmpty()) fields += MetadataField(group, key, value)
    }
    fun note(text: String) { notes += text }
    fun error(text: String) { errors += text }
}

/**
 * Runs one extractor and converts every failure into a result instead of an exception.
 * A FormatException is a malformed input (EXTRACTION_FAILED). Any other exception is a
 * defect in the engine; it is recorded as such and never reported as a clean result.
 */
internal inline fun runExtractor(name: String, version: String, body: (MetadataSink) -> Unit): MetadataResult {
    val sink = MetadataSink()
    var failed = false
    try {
        body(sink)
    } catch (e: FormatException) {
        failed = true
        sink.error(e.message ?: "malformed structure")
    } catch (e: RuntimeException) {
        failed = true
        sink.error("internal engine error (${e.javaClass.simpleName}): ${e.message ?: "no message"}")
    }
    // Any integrity error (bad CRC, truncated chunk, malformed part) means the result is not clean,
    // even when some fields were recovered. Partial fields are kept and the errors explain the rest.
    if (sink.errors.isNotEmpty()) failed = true
    val descriptive = sink.fields.any { it.group != "structure" }
    val status = when {
        failed -> MetadataStatus.EXTRACTION_FAILED
        sink.unsupportedReason != null -> MetadataStatus.NOT_SUPPORTED
        descriptive -> MetadataStatus.EXTRACTED
        else -> MetadataStatus.NO_METADATA_PRESENT
    }
    if (sink.unsupportedReason != null) sink.notes.add(sink.unsupportedReason!!)
    return MetadataResult(name, version, EngineInfo.VERSION, EngineInfo.javaRuntime, status,
        sink.fields.toList(), sink.notes.toList(), sink.errors.toList())
}

internal fun notSupported(name: String, version: String, reason: String) = MetadataResult(
    name, version, EngineInfo.VERSION, EngineInfo.javaRuntime, MetadataStatus.NOT_SUPPORTED,
    emptyList(), listOf(reason), emptyList(),
)
