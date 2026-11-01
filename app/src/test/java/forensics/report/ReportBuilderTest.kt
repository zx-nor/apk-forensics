package forensics.report

import forensics.CorpusTestSupport
import forensics.common.AnalysisLimits
import forensics.hash.StreamingHasher
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.nio.file.Files

class ReportBuilderTest {
    private fun report(name: String, fromCorpus1: Boolean = false): AnalysisReport {
        val src = if (fromCorpus1) CorpusTestSupport.file(name) else CorpusTestSupport.file2(name)
        val hash = StreamingHasher.sha256(src)
        val scratch = Files.createTempDirectory("bbf-report-").toFile().also { it.deleteOnExit() }
        return ReportBuilder.build(src, name, hash.sha256Hex, hash.byteCount, scratch, AnalysisLimits())
    }

    @Test fun docxReportCarriesFormatMetadataAndIntegrity() {
        val r = report("report.docx")
        assertEquals("docx", r.refinedFormat)
        assertEquals("EXTRACTED", r.metadataStatus)
        assertTrue(r.metadata.any { it.group == "OOXML.core" && it.key == "Title" && it.value == "Quarterly Report" })
        assertTrue(r.workingCopyMatchesSource, "analyzed bytes must equal the acquired bytes")
        assertEquals("DOCX", r.zipKind)
    }

    @Test fun apkReportCarriesManifestAndSignerFields() {
        val r = report("demo.apk")
        assertEquals("apk", r.refinedFormat)
        assertTrue(r.metadata.any { it.key == "Package" && it.value == "com.example.demo" })
        assertTrue(r.metadata.any { it.group == "APK.signer" && it.key == "Subject" })
        assertTrue(r.zipEntries.any { it.name == "AndroidManifest.xml" })
    }

    @Test fun unidentifiedContentIsReportedAsNotApplicable() {
        val r = report("empty.bin")
        assertNull(r.refinedFormat)
        assertEquals("NOT_APPLICABLE", r.metadataStatus)
        assertTrue(r.metadata.isEmpty())
    }

    @Test fun stringsAreExtractedWithOffsets() {
        val r = report("strings_mixed.bin", fromCorpus1 = true)
        assertTrue(r.strings.any { it.endsWith("HelloWorldString") })
    }

    @Test fun encryptedEntriesAreDescribedNotDecrypted() {
        val r = report("encrypted_zipcrypto.zip")
        val e = r.zipEntries.single()
        assertEquals("TRADITIONAL_PKWARE_ZIPCRYPTO", e.encryption)
        assertEquals("NOT_MEASURED_ENCRYPTED", e.measurement)
        assertEquals("not verified", e.crcState)
    }

    @Test fun extensionMismatchAppearsAsFinding() {
        val r = report("archive_disguised.pdf")
        assertTrue(r.extensionMismatch)
        assertTrue(r.findings.any { it.code == "EXTENSION_MISMATCH" && it.severity == "SUSPICIOUS" })
    }
}
