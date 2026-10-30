package forensics.metadata

import forensics.common.AnalysisLimits
import java.io.File

/**
 * Routes a refined format identifier to its extractor. Formats without an extractor return
 * NOT_SUPPORTED with the reason, so the report never implies metadata was checked when it was not.
 */
object MetadataDispatcher {

    fun extract(file: File, refinedFormat: String?, limits: AnalysisLimits = AnalysisLimits()): MetadataResult? = when (refinedFormat) {
        null -> null
        "jpeg" -> JpegMetadataExtractor.extract(file, limits)
        "png" -> PngMetadataExtractor.extract(file, limits)
        "webp" -> WebpMetadataExtractor.extract(file, limits)
        "tiff-le", "tiff-be" -> TiffMetadataExtractor.extract(file, limits)
        "pdf" -> PdfMetadataExtractor.extract(file, limits)
        "docx", "xlsx", "pptx" -> OoxmlMetadataExtractor.extract(file, limits)
        "mp3-id3" -> Mp3MetadataExtractor.extract(file, limits)
        "flac" -> FlacMetadataExtractor.extract(file, limits)
        "wav" -> WavMetadataExtractor.extract(file, limits)
        "mp4", "mov", "m4a" -> Mp4MetadataExtractor.extract(file, limits)
        "apk" -> ApkMetadataExtractor.extract(file, limits)
        "sqlite3" -> SqliteMetadataExtractor.extract(file, limits)
        "heic" -> notSupported("heif-items", "n/a", "HEIF item metadata (EXIF inside meta items) is not parsed by this engine version.")
        "aab" -> notSupported("aab", "n/a", "App Bundle metadata extraction is not implemented; identification only.")
        "jar", "zip", "zip-invalid", "odf" -> notSupported("zip", "n/a", "No format-specific descriptive metadata extractor for $refinedFormat; see archive analysis.")
        "gif", "gzip", "7z", "rar", "avi", "ogg", "elf", "pcap-le", "pcap-be", "pcapng", "tar-ustar", "riff-unknown", "m4a-unused" ->
            notSupported("unsupported", "n/a", "Metadata extraction for $refinedFormat is not implemented in this engine version.")
        else -> notSupported("unsupported", "n/a", "No metadata extractor is registered for '$refinedFormat'.")
    }
}
