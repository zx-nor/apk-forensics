package forensics.archive

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.Finding
import forensics.common.FormatException
import forensics.common.Severity
import forensics.common.u16
import forensics.common.u32
import forensics.common.u64
import java.nio.charset.Charset

/** One central-directory record, before any content inspection. Offsets are file-absolute after [ZipDirectory.prependedBytes]. */
data class RawZipEntry(
    val index: Int,
    val name: String,
    val flags: Int,
    val versionMadeBy: Int,
    val method: Int,
    val crc32: Long,
    val compressedSize: Long,
    val uncompressedSize: Long,
    val localHeaderOffset: Long,
    val externalAttributes: Long,
    val extra: ByteArray,
)

data class ZipDirectory(
    val fileLength: Long,
    val eocdPosition: Long,
    val eocdCommentLength: Int,
    val zip64: Boolean,
    val declaredEntryCount: Long,
    val centralDirectoryStart: Long,
    val centralDirectorySize: Long,
    val prependedBytes: Long,
    val entries: List<RawZipEntry>,
    val findings: List<Finding>,
    val parseError: String?,
)

/**
 * Reads the End-of-Central-Directory record and central directory of a ZIP file.
 *
 * The directory is read as one bounded block (at most [AnalysisLimits.maxCentralDirectoryBytes]),
 * then parsed in memory. File content is never loaded here.
 */
object ZipDirectoryReader {
    private const val EOCD_SIG = 0x06054b50L
    private const val ZIP64_LOCATOR_SIG = 0x07064b50L
    private const val ZIP64_EOCD_SIG = 0x06064b50L
    private const val CD_SIG = 0x02014b50L
    private const val EOCD_MIN = 22
    private const val MAX_COMMENT = 65535

    fun read(src: BoundedFile, limits: AnalysisLimits): ZipDirectory {
        val len = src.length
        if (len < EOCD_MIN) throw FormatException("file too small (${len} bytes) to be a ZIP archive")

        val tailStart = maxOf(0L, len - EOCD_MIN - MAX_COMMENT)
        val tail = src.read(tailStart, (len - tailStart).toInt())

        val candidates = ArrayList<Int>()
        var i = tail.size - EOCD_MIN
        while (i >= 0) {
            if (u32(tail, i) == EOCD_SIG) candidates.add(i)
            i--
        }
        if (candidates.isEmpty()) throw FormatException("no end-of-central-directory signature found")

        val findings = mutableListOf<Finding>()
        val strict = candidates.firstOrNull { c -> c + EOCD_MIN + u16(tail, c + 20) == tail.size }

        // A comment can contain bytes that look like an end record. Prefer a candidate whose
        // directory really starts where it claims (strength 2), then a non-empty strict match,
        // then any strict match, and only then the last candidate found.
        fun strength(c: Int): Int {
            val pos = tailStart + c
            val cdSizeC = u32(tail, c + 12)
            if (cdSizeC == 0L) return if (c == strict) 1 else 0
            val start = pos - cdSizeC
            if (start < 0) return 0
            return try {
                if (u32(src.read(start, 4), 0) == CD_SIG) 2 else 0
            } catch (_: FormatException) { 0 }
        }
        val chosen = candidates.firstOrNull { strength(it) == 2 }
            ?: strict?.takeIf { strength(it) >= 1 }
            ?: strict
            ?: candidates.first()
        if (candidates.size > 1) {
            val severity = if (chosen != candidates.first()) Severity.SUSPICIOUS else Severity.NOTE
            findings += Finding(
                "MULTIPLE_EOCD_SIGNATURES", severity,
                "${candidates.size} end-of-central-directory signatures found. The record at file offset ${tailStart + chosen} was used" +
                    (if (chosen != candidates.first()) "; the last signature in the file was not consistent with a directory." else "."),
            )
        }
        val eo = chosen
        val chosenIsStrict = eo + EOCD_MIN + u16(tail, eo + 20) == tail.size
        if (!chosenIsStrict) {
            findings += Finding(
                "EOCD_COMMENT_LENGTH_INCONSISTENT", Severity.SUSPICIOUS,
                "End-of-central-directory comment length does not reach end of file; trailing or appended data is likely.",
            )
        }
        val eocdPos = tailStart + eo
        val commentLen = u16(tail, eo + 20)
        val totalEntries16 = u16(tail, eo + 10).toLong()
        val cdSize32 = u32(tail, eo + 12)
        val cdOffset32 = u32(tail, eo + 16)

        val zip64 = totalEntries16 == 0xFFFFL || cdSize32 == 0xFFFFFFFFL || cdOffset32 == 0xFFFFFFFFL
        var entryCount = totalEntries16
        var cdSize = cdSize32
        var cdOffset = cdOffset32
        var cdEnd = eocdPos

        if (zip64) {
            val locPos = eocdPos - 20
            if (locPos < 0) throw FormatException("ZIP64 fields present but no room for ZIP64 locator")
            val loc = src.read(locPos, 20)
            if (u32(loc, 0) != ZIP64_LOCATOR_SIG) throw FormatException("ZIP64 locator signature missing")
            val rec64Pos = u64(loc, 8)
            if (rec64Pos < 0 || rec64Pos + 56 > len) throw FormatException("ZIP64 record offset out of range")
            val rec = src.read(rec64Pos, 56)
            if (u32(rec, 0) != ZIP64_EOCD_SIG) throw FormatException("ZIP64 end-of-central-directory signature missing")
            entryCount = u64(rec, 32)
            cdSize = u64(rec, 40)
            cdOffset = u64(rec, 48)
            cdEnd = rec64Pos
        }

        if (entryCount < 0 || cdSize < 0 || cdOffset < 0) throw FormatException("directory size fields out of range")
        val actualCdStart = cdEnd - cdSize
        if (actualCdStart < 0) throw FormatException("central directory size ($cdSize) exceeds the bytes before the end record")
        val prepended = actualCdStart - cdOffset
        if (prepended < 0) throw FormatException("central directory offset lies beyond its actual position")
        if (prepended > 0) {
            findings += Finding(
                "PREPENDED_DATA", Severity.NOTE,
                "$prepended bytes precede the archive. Offsets are relative to the archive start (self-extracting or concatenated archive).",
            )
        }

        if (cdSize > limits.maxCentralDirectoryBytes) {
            findings += Finding(
                "CENTRAL_DIRECTORY_TOO_LARGE", Severity.ERROR,
                "Central directory is $cdSize bytes, above the inspection limit of ${limits.maxCentralDirectoryBytes}. No entries were enumerated.",
            )
            return ZipDirectory(len, eocdPos, commentLen, zip64, entryCount, actualCdStart, cdSize, prepended,
                emptyList(), findings, "central directory exceeds inspection limit")
        }

        val cd = src.read(actualCdStart, cdSize.toInt())
        val entries = ArrayList<RawZipEntry>()
        var p = 0
        var parseError: String? = null
        var encryptedCdFlag = false
        while (p < cd.size) {
            if (entries.size >= limits.maxZipEntries) {
                findings += Finding(
                    "ENTRY_LIMIT_REACHED", Severity.ERROR,
                    "Enumeration stopped after ${limits.maxZipEntries} entries (inspection limit).",
                )
                break
            }
            if (cd.size - p < 46) { parseError = "truncated central directory record at directory offset $p"; break }
            if (u32(cd, p) != CD_SIG) { parseError = "invalid central directory signature at directory offset $p"; break }

            val madeBy = u16(cd, p + 4)
            val flags = u16(cd, p + 8)
            val method = u16(cd, p + 10)
            val crc = u32(cd, p + 16)
            var csize = u32(cd, p + 20)
            var usize = u32(cd, p + 24)
            val nlen = u16(cd, p + 28)
            val elen = u16(cd, p + 30)
            val clen = u16(cd, p + 32)
            val ext = u32(cd, p + 38)
            var loc = u32(cd, p + 42)
            val recEnd = p + 46 + nlen + elen + clen
            if (recEnd > cd.size) { parseError = "central directory record at $p overruns the directory"; break }

            val nameBytes = cd.copyOfRange(p + 46, p + 46 + nlen)
            val extra = cd.copyOfRange(p + 46 + nlen, p + 46 + nlen + elen)
            val name = decodeName(nameBytes, flags)

            if (usize == 0xFFFFFFFFL || csize == 0xFFFFFFFFL || loc == 0xFFFFFFFFL) {
                val z = applyZip64Extra(extra, usize == 0xFFFFFFFFL, csize == 0xFFFFFFFFL, loc == 0xFFFFFFFFL)
                usize = z[0]; csize = z[1]; loc = z[2]
            }
            if (flags and 0x2000 != 0) encryptedCdFlag = true

            entries += RawZipEntry(entries.size, name, flags, madeBy, method, crc, csize, usize, loc, ext, extra)
            p = recEnd
        }

        if (encryptedCdFlag) {
            findings += Finding(
                "CENTRAL_DIRECTORY_ENCRYPTION_FLAG", Severity.NOTE,
                "General-purpose flag bit 13 is set on at least one entry; directory listing may be unreliable.",
            )
        }
        if (parseError != null) {
            findings += Finding("CENTRAL_DIRECTORY_CORRUPT", Severity.ERROR, parseError)
        }
        if (entries.size.toLong() != entryCount && parseError == null && entries.size < limits.maxZipEntries) {
            findings += Finding(
                "ENTRY_COUNT_MISMATCH", Severity.SUSPICIOUS,
                "End record declares $entryCount entries; ${entries.size} were enumerated.",
            )
        }

        return ZipDirectory(len, eocdPos, commentLen, zip64, entryCount, actualCdStart, cdSize, prepended,
            entries, findings, parseError)
    }

    /** UTF-8 when general-purpose bit 11 is set, otherwise the legacy IBM PC code page 437. */
    fun decodeName(bytes: ByteArray, flags: Int): String {
        val cs = if (flags and 0x800 != 0) Charsets.UTF_8 else cp437
        return String(bytes, cs)
    }

    private val cp437: Charset by lazy {
        try { Charset.forName("IBM437") } catch (_: Exception) { Charsets.ISO_8859_1 }
    }

    /** Returns [usize, csize, loc] with values from the ZIP64 extra field where the record requires them. */
    private fun applyZip64Extra(extra: ByteArray, needU: Boolean, needC: Boolean, needL: Boolean): LongArray {
        var u = 0L; var c = 0L; var l = 0L
        var p = 0
        while (p + 4 <= extra.size) {
            val id = u16(extra, p)
            val size = u16(extra, p + 2)
            val dataStart = p + 4
            if (dataStart + size > extra.size) break
            if (id == 0x0001) {
                var q = dataStart
                val end = dataStart + size
                if (needU && q + 8 <= end) { u = u64(extra, q); q += 8 }
                if (needC && q + 8 <= end) { c = u64(extra, q); q += 8 }
                if (needL && q + 8 <= end) { l = u64(extra, q); q += 8 }
                break
            }
            p = dataStart + size
        }
        return longArrayOf(u, c, l)
    }
}
