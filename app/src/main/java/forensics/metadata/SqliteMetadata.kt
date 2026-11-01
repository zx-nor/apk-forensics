package forensics.metadata

import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.u16
import forensics.common.u32
import java.io.File

/**
 * SQLite 3 database header fields (first 100 bytes). These describe the file, not its tables;
 * schema and row examination belong to the database laboratory.
 */
object SqliteMetadataExtractor {
    const val NAME = "sqlite-header"
    const val VERSION = "1.0.0"

    fun extract(file: File, limits: AnalysisLimits): MetadataResult = runExtractor(NAME, VERSION) { sink ->
        BoundedFile(file).use { src ->
            if (src.length < 100) throw FormatException("file shorter than the 100-byte SQLite header")
            val h = src.read(0, 100)
            if (String(h, 0, 16, Charsets.ISO_8859_1) != "SQLite format 3\u0000") throw FormatException("SQLite magic string missing")
            val rawPage = u16(h, 16, le = false)
            val pageSize = if (rawPage == 1) 65536 else rawPage
            sink.add("structure", "PageSize", pageSize.toString())
            sink.add("structure", "WriteVersion", (h[18].toInt() and 0xFF).toString())
            sink.add("structure", "ReadVersion", (h[19].toInt() and 0xFF).toString())
            sink.add("structure", "DatabasePages", u32(h, 28, le = false).toString())
            sink.add("structure", "FileChangeCounter", u32(h, 24, le = false).toString())
            sink.add("structure", "SchemaCookie", u32(h, 40, le = false).toString())
            sink.add("structure", "SchemaFormat", u32(h, 44, le = false).toString())
            val enc = u32(h, 56, le = false)
            sink.add("structure", "TextEncoding", when (enc) {
                1L -> "UTF-8"; 2L -> "UTF-16LE"; 3L -> "UTF-16BE"; else -> "unknown($enc)"
            })
            sink.add("DB.Header", "UserVersion", u32(h, 60, le = false).toString())
            sink.add("DB.Header", "ApplicationId", "0x%08X".format(u32(h, 68, le = false)))
            sink.add("DB.Header", "SQLiteVersionNumber", u32(h, 96, le = false).toString())
            val expectedFileSize = u32(h, 28, le = false) * pageSize
            if (expectedFileSize > src.length) sink.error("header declares $expectedFileSize bytes; file has ${src.length} (truncated)")
            if (expectedFileSize < src.length) sink.note("File is ${src.length - expectedFileSize} bytes longer than the header's page count implies (may include journal or free data).")
        }
    }
}
