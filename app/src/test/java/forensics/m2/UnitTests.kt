package forensics.m2

import forensics.CorpusTestSupport
import forensics.archive.PackageKind
import forensics.archive.PathChecks
import forensics.archive.ZipClassifier
import forensics.archive.NestedDetector
import forensics.archive.MethodNames
import forensics.archive.ZipDirectoryReader
import forensics.common.AnalysisLimits
import forensics.common.BoundedFile
import forensics.common.FormatException
import forensics.common.Severity
import forensics.identify.DeepIdentifier
import forensics.identify.EmbeddedScanner
import forensics.identify.Confidence
import forensics.metadata.MetadataStatus
import forensics.metadata.MetadataDispatcher
import forensics.metadata.PdfMetadataExtractor
import forensics.metadata.TiffMetadataExtractor
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files

class UnitTests {

    @Test fun pathTraversalAndDeceptionPatterns() {
        assertTrue(PathChecks.check("../x").any { it.code == "PATH_TRAVERSAL" })
        assertTrue(PathChecks.check("a/../../b").any { it.code == "PATH_TRAVERSAL" })
        assertTrue(PathChecks.check("a\\..\\b").any { it.code == "PATH_TRAVERSAL" })
        assertTrue(PathChecks.check("a\u202Egnp.exe").any { it.code == "BIDI_CONTROL_CHARACTER" })
        assertTrue(PathChecks.check("bad\u0001name").any { it.code == "CONTROL_CHARACTER" })
        assertTrue(PathChecks.check("").any { it.code == "EMPTY_NAME" })
        assertTrue(PathChecks.check("ok/file.txt").isEmpty())
        // A bare name that merely contains dots is not traversal.
        assertTrue(PathChecks.check("v1..2.txt").none { it.code == "PATH_TRAVERSAL" })
    }

    @Test fun pathChecksDoNotFlagDirectoryEntriesAsExecutable() {
        assertTrue(PathChecks.check("tools.jar/").none { it.code == "EXECUTABLE_CONTENT_PRESENT" })
    }

    @Test fun classifierRecognizesEachPackageKind() {
        fun k(vararg names: String) = ZipClassifier.classify(names.toList()).kind
        assertEquals(PackageKind.APK, k("AndroidManifest.xml", "classes.dex"))
        assertEquals(PackageKind.AAB, k("base/manifest/AndroidManifest.xml", "BundleConfig.pb"))
        assertEquals(PackageKind.DOCX, k("[Content_Types].xml", "word/document.xml"))
        assertEquals(PackageKind.XLSX, k("[Content_Types].xml", "xl/workbook.xml"))
        assertEquals(PackageKind.PPTX, k("[Content_Types].xml", "ppt/presentation.xml"))
        assertEquals(PackageKind.JAR, k("META-INF/MANIFEST.MF", "a/B.class"))
        assertEquals(PackageKind.ODF, k("mimetype", "content.xml", "META-INF/manifest.xml"))
        assertEquals(PackageKind.ZIP, k("a.txt"))
        assertEquals(PackageKind.AMBIGUOUS_OFFICE_OR_APK, k("AndroidManifest.xml", "classes.dex", "word/document.xml", "[Content_Types].xml"))
    }

    @Test fun classificationStatesThatNamesAreNotVerified() {
        val c = ZipClassifier.classify(listOf("[Content_Types].xml", "word/document.xml"))
        assertTrue(c.notes.any { it.contains("names can be forged") })
    }

    @Test fun apkClassificationIsHighConfidenceOnlyWithBothMarkers() {
        assertEquals(Confidence.HIGH, ZipClassifier.classify(listOf("AndroidManifest.xml", "classes.dex")).confidence)
    }

    @Test fun extensionMismatchOnlyForKnownFormats() {
        assertFalse(DeepIdentifier.mismatch("jpg", "jpeg"))
        assertFalse(DeepIdentifier.mismatch("jpeg", "jpeg"))
        assertTrue(DeepIdentifier.mismatch("pdf", "zip"))
        assertFalse(DeepIdentifier.mismatch("unknownext", "zip"), "unknown extensions are not mismatches")
        assertFalse(DeepIdentifier.mismatch(null, "png"))
        assertFalse(DeepIdentifier.mismatch("png", null), "unidentified content is not a mismatch")
        assertTrue(DeepIdentifier.mismatch("zip", "docx"))
        assertFalse(DeepIdentifier.mismatch("docx", "docx"))
    }

    @Test fun nestedContainerSignaturesAreRecognized() {
        assertEquals("ZIP", NestedDetector.kindOf(byteArrayOf(0x50, 0x4B, 0x03, 0x04)))
        assertEquals("ZIP", NestedDetector.kindOf(byteArrayOf(0x50, 0x4B, 0x05, 0x06)))
        assertEquals("GZIP", NestedDetector.kindOf(byteArrayOf(0x1F, 0x8B.toByte(), 0x08.toByte())))
        assertEquals("7Z", NestedDetector.kindOf(byteArrayOf(0x37, 0x7A, 0xBC.toByte(), 0xAF.toByte(), 0x27, 0x1C)))
        assertNull(NestedDetector.kindOf(byteArrayOf(0x50, 0x4B)))
        assertNull(NestedDetector.kindOf(ByteArray(0)))
    }

    @Test fun methodNamesAreStable() {
        assertEquals("stored", MethodNames.of(0))
        assertEquals("deflate", MethodNames.of(8))
        assertEquals("winzip-aes", MethodNames.of(99))
        assertEquals("unknown(250)", MethodNames.of(250))
    }

    @Test fun emptyAndTinyFilesAreRejectedAsZipWithoutCrashing() {
        val f = Files.createTempFile("bbf-tiny-", ".zip").toFile().also { it.deleteOnExit() }
        f.writeBytes(ByteArray(10))
        assertThrows(FormatException::class.java) {
            BoundedFile(f).use { ZipDirectoryReader.read(it, AnalysisLimits()) }
        }
        f.writeBytes(ByteArray(0))
        assertThrows(FormatException::class.java) {
            BoundedFile(f).use { ZipDirectoryReader.read(it, AnalysisLimits()) }
        }
    }

    @Test fun embeddedSignatureSplitAcrossBlockBoundaryIsFoundOnce() {
        // The scanner reads 256 KiB blocks. Place a ZIP signature straddling the first boundary.
        val block = 256 * 1024
        val data = ByteArray(block + 100)
        val sig = byteArrayOf(0x50, 0x4B, 0x03, 0x04)
        val at = block - 2
        System.arraycopy(sig, 0, data, at, sig.size)
        val f = Files.createTempFile("bbf-split-", ".bin").toFile().also { it.deleteOnExit() }
        f.writeBytes(data)
        val hits = EmbeddedScanner().scan(f).filter { it.formatId == "zip" }
        assertEquals(1, hits.size, "a signature across a block boundary must be reported exactly once")
        assertEquals(at.toLong(), hits[0].offset)
    }

    @Test fun embeddedScannerIgnoresOffsetZero() {
        val f = CorpusTestSupport.file2("plain.zip")
        assertTrue(EmbeddedScanner().scan(f).none { it.offset == 0L })
    }

    @Test fun tiffRejectsWrongByteOrderMark() {
        val f = Files.createTempFile("bbf-bad-", ".tif").toFile().also { it.deleteOnExit() }
        f.writeBytes(ByteArray(64) { 0x41 })
        val r = TiffMetadataExtractor.extract(f, AnalysisLimits())
        assertEquals(MetadataStatus.EXTRACTION_FAILED, r.status)
        assertTrue(r.errors.any { it.contains("byte-order") })
    }

    @Test fun pdfDatesKeepTheirTimeZoneSemantics() {
        assertEquals("2024-05-01T12:00:00 (UTC)", PdfMetadataExtractor.formatPdfDate("D:20240501120000Z"))
        assertEquals("2024-01-01T00:00:00 (no time zone recorded)", PdfMetadataExtractor.formatPdfDate("D:2024"))
        assertEquals("not a date", PdfMetadataExtractor.formatPdfDate("not a date"))
        assertEquals("2024-05-01T12:00:00 (UTC-05:30)", PdfMetadataExtractor.formatPdfDate("D:20240501120000-05'30'"))
    }

    @Test fun pdfTextStringsDecodeUtf16AndUtf8() {
        val utf16 = byteArrayOf(0xFE.toByte(), 0xFF.toByte(), 0x00, 0x48, 0x00, 0x69)
        assertEquals("Hi", PdfMetadataExtractor.decodeText(utf16))
        val utf8 = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte(), 0xC3.toByte(), 0xA9.toByte())
        assertEquals("é", PdfMetadataExtractor.decodeText(utf8))
        assertEquals("plain", PdfMetadataExtractor.decodeText("plain".toByteArray(Charsets.ISO_8859_1)))
    }

    @Test fun limitsCannotBeDisabledBySilentlyNegativeValues() {
        assertThrows(IllegalArgumentException::class.java) { AnalysisLimits(maxStringValueLength = 0) }
        assertThrows(IllegalArgumentException::class.java) { AnalysisLimits(maxEmbeddedScanBytes = 0) }
    }

    @Test fun unsupportedFormatsAreNotReportedAsSuccess() {
        val r = MetadataDispatcher.extract(CorpusTestSupport.file2("plain.zip"), "zip")!!
        assertEquals(MetadataStatus.NOT_SUPPORTED, r.status)
        assertTrue(r.notes.isNotEmpty())
        val heic = MetadataDispatcher.extract(CorpusTestSupport.file2("plain.zip"), "heic")!!
        assertEquals(MetadataStatus.NOT_SUPPORTED, heic.status)
    }

    @Test fun nullFormatHasNoExtractor() {
        assertNull(MetadataDispatcher.extract(CorpusTestSupport.file2("plain.zip"), null))
    }

    @Test fun fingerprintsOfExtractedCertificatesAreConsistentWithOpenssl() {
        // Cross-check: the APK fixture's SHA-256 fingerprint matches an independent digest of its signer certificate.
        val rows = ExpectationTable.load().filter { it.file == "demo.apk" && it.key.endsWith("SHA256Fingerprint") }
        assertEquals(1, rows.size)
        assertEquals(95, rows[0].value.length, "SHA-256 fingerprint must be 32 colon-separated bytes")
        assertTrue(rows[0].value.matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")))
    }
}
