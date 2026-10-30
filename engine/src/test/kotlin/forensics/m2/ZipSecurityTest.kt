package forensics.m2

import forensics.CorpusTestSupport
import forensics.archive.MeasurementStatus
import forensics.archive.ZipAnalyzer
import forensics.common.AnalysisLimits
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ZipSecurityTest {

    /** Builds a deflated ZIP at runtime using the JDK writer, independent of the engine. */
    private fun zipOf(vararg entries: Pair<String, ByteArray>): File {
        val f = Files.createTempFile("bbf-zip-", ".zip").toFile().also { it.deleteOnExit() }
        ZipOutputStream(f.outputStream()).use { z ->
            for ((name, data) in entries) {
                z.putNextEntry(ZipEntry(name))
                z.write(data)
                z.closeEntry()
            }
        }
        return f
    }

    private fun scratch(): File = Files.createTempDirectory("bbf-scratch-").toFile().also { it.deleteOnExit() }

    @Test fun entryLimitStopsEnumerationAndSaysSo() {
        val a = ZipAnalyzer(AnalysisLimits(maxZipEntries = 100)).analyze(CorpusTestSupport.file2("many_entries.zip"))
        assertEquals(100, a.entries.size)
        assertTrue(a.archiveFindings.any { it.code == "ENTRY_LIMIT_REACHED" })
    }

    @Test fun perEntryInspectionCapMakesMeasurementPartial() {
        val limits = AnalysisLimits(maxEntryInspectionBytes = 1L shl 20, maxTotalInspectionBytes = 1L shl 20)
        val e = ZipAnalyzer(limits).analyze(CorpusTestSupport.file2("bomb.zip")).entries.single()
        assertEquals(MeasurementStatus.CAPPED_ENTRY_LIMIT, e.measurement)
        assertEquals(1L shl 20, e.measuredUncompressedSize)
        assertTrue(e.findings.any { it.code == "ENTRY_INSPECTION_LIMIT" })
        // A capped entry has not been fully measured, so it must not be reported as a confirmed bomb.
        assertFalse(e.findings.any { it.code == "EXCESSIVE_COMPRESSION_RATIO" })
        assertNull(e.crc32Computed)
    }

    @Test fun totalBudgetExhaustionIsReportedPerEntry() {
        val big = ByteArray(2 shl 20)
        val f = zipOf("first.bin" to big, "second.bin" to big)
        val limits = AnalysisLimits(maxEntryInspectionBytes = 4L shl 20, maxTotalInspectionBytes = 3L shl 20)
        val a = ZipAnalyzer(limits, scratch()).analyze(f)
        val first = a.entries[0]
        val second = a.entries[1]
        assertEquals(MeasurementStatus.COMPLETE, first.measurement)
        assertEquals(MeasurementStatus.CAPPED_BUDGET, second.measurement)
        assertTrue(second.findings.any { it.code == "INSPECTION_BUDGET_EXHAUSTED" })
    }

    @Test fun compressionRatioThresholdIsConfigurable() {
        val strict = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("bomb.zip")).entries.single()
        assertTrue(strict.findings.any { it.code == "EXCESSIVE_COMPRESSION_RATIO" })
        val lenient = ZipAnalyzer(AnalysisLimits(maxCompressionRatio = 100_000.0)).analyze(CorpusTestSupport.file2("bomb.zip")).entries.single()
        assertFalse(lenient.findings.any { it.code == "EXCESSIVE_COMPRESSION_RATIO" })
        assertEquals(MeasurementStatus.COMPLETE, lenient.measurement)
    }

    @Test fun nestedInspectionLeavesNoTemporaryFiles() {
        val dir = scratch()
        ZipAnalyzer(AnalysisLimits(), dir).analyze(CorpusTestSupport.file2("deep_nested.zip"))
        ZipAnalyzer(AnalysisLimits(), dir).analyze(CorpusTestSupport.file2("nested.zip"))
        assertEquals(emptyList<String>(), dir.list()?.toList().orEmpty(), "nested extraction must not leave files behind")
    }

    @Test fun nestedArchiveIsInspectedAndItsEntriesAreVisible() {
        val a = ZipAnalyzer(AnalysisLimits(), scratch()).analyze(CorpusTestSupport.file2("nested.zip"))
        val inner = a.entries.single { it.name == "inner.zip" }
        assertNotNull(inner.nested, "inner archive must be analyzed")
        assertEquals(listOf("secret.txt"), inner.nested!!.entries.map { it.name })
        assertEquals(1, inner.nested!!.depth)
    }

    @Test fun nestingDepthLimitIsEnforced() {
        val a = ZipAnalyzer(AnalysisLimits(maxNestingDepth = 1), scratch()).analyze(CorpusTestSupport.file2("deep_nested.zip"))
        val reached = mutableListOf<String>()
        fun walk(z: forensics.archive.ZipAnalysis) {
            z.entries.forEach { e ->
                if (e.findings.any { it.code == "NESTING_LIMIT_REACHED" }) reached += e.name
                e.nested?.let { walk(it) }
            }
        }
        walk(a)
        assertTrue(reached.isNotEmpty(), "depth limit of 1 must stop deeper inspection")
        assertTrue(a.entries.single().nested?.entries?.single()?.nested == null, "no archive below depth 1 may be inspected")
    }

    @Test fun symlinkIsDescribedButNeverFollowed() {
        val scratchDir = scratch()
        val e = ZipAnalyzer(AnalysisLimits(), scratchDir).analyze(CorpusTestSupport.file2("symlink.zip")).entries.single()
        assertTrue(e.isSymlink)
        assertEquals("/etc/passwd", e.symlinkTarget)
        assertEquals(emptyList<String>(), scratchDir.list()?.toList().orEmpty())
    }

    @Test fun everyEncryptedEntryIsReportedAsUnsupportedNotDecrypted() {
        for (name in listOf("encrypted_zipcrypto.zip", "aes_synthetic.zip")) {
            val a = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2(name))
            val enc = a.entries.filter { it.encryption != null }
            assertTrue(enc.isNotEmpty(), "$name must contain an encrypted entry")
            for (e in enc) {
                assertFalse(e.encryption!!.supported, "encryption must not be claimed as supported")
                assertEquals(MeasurementStatus.NOT_MEASURED_ENCRYPTED, e.measurement)
                assertNull(e.measuredUncompressedSize)
            }
        }
    }

    @Test fun crcMismatchIsDetectedAndMeasurementIsStillComplete() {
        val e = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("crc_bad.zip")).entries.single()
        assertEquals(MeasurementStatus.COMPLETE, e.measurement)
        assertNotEquals(e.crc32Declared, e.crc32Computed)
        assertTrue(e.findings.any { it.code == "CRC_MISMATCH" })
    }

    @Test fun declaredSizeInCentralDirectoryIsCrossChecked() {
        val e = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("size_lie.zip")).entries.single()
        assertEquals(9L, e.declaredUncompressedSize)
        assertEquals(5L, e.measuredUncompressedSize)
        assertTrue(e.findings.any { it.code == "DECLARED_SIZE_MISMATCH" })
    }

    @Test fun truncatedArchiveIsAFailureNotACrash() {
        val a = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("truncated.zip"))
        assertNotNull(a.parseError)
        assertEquals(0, a.entries.size)
    }

    @Test fun prependedArchiveOffsetsAreResolved() {
        val a = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("prepended.zip"))
        assertEquals(10L, a.prependedBytes)
        assertEquals(2, a.entries.size)
        assertTrue(a.entries.all { it.measurement == MeasurementStatus.COMPLETE })
    }

    @Test fun zip64EntriesAreReadCorrectly() {
        val e = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("zip64_entries.zip")).entries.single()
        assertEquals(70_000L, e.measuredUncompressedSize)
        assertEquals(e.crc32Declared, e.crc32Computed)
    }

    @Test fun cumulativeNestingDoesNotEscapeTheBudget() {
        // The shared budget means nested archives cannot multiply the inspection allowance.
        val inner = zipOf("x.bin" to ByteArray(1 shl 20))
        val outer = zipOf("inner.zip" to inner.readBytes(), "copy.zip" to inner.readBytes())
        val limits = AnalysisLimits(maxTotalInspectionBytes = 2L shl 20, maxEntryInspectionBytes = 2L shl 20)
        val a = ZipAnalyzer(limits, scratch()).analyze(outer)
        val measured = a.entries.sumOf { it.measuredUncompressedSize ?: 0L }
        val nestedMeasured = a.entries.sumOf { e -> e.nested?.entries?.sumOf { it.measuredUncompressedSize ?: 0L } ?: 0L }
        assertTrue(measured + nestedMeasured <= (2L shl 20) + (1L shl 20), "measured $measured + $nestedMeasured exceeds budget")
    }

    @Test fun ordinaryArchiveHasNoSecurityFindings() {
        val a = ZipAnalyzer(AnalysisLimits()).analyze(CorpusTestSupport.file2("plain.zip"))
        val securityCodes = setOf("PATH_TRAVERSAL", "ABSOLUTE_PATH", "CRC_MISMATCH", "EXCESSIVE_COMPRESSION_RATIO", "DECLARED_SIZE_MISMATCH")
        assertTrue(a.entries.flatMap { it.findings }.none { it.code in securityCodes })
        assertTrue(a.archiveFindings.none { it.severity == forensics.common.Severity.SUSPICIOUS })
    }

    @Test fun invalidLimitsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) { AnalysisLimits(maxCompressionRatio = 0.5) }
        // A total budget below one entry's cap is accepted; the smaller value governs.
        assertEquals(5L, AnalysisLimits(maxEntryInspectionBytes = 10, maxTotalInspectionBytes = 5).maxTotalInspectionBytes)
        assertThrows(IllegalArgumentException::class.java) { AnalysisLimits(maxZipEntries = 0) }
    }
}

class BudgetCapTest {
    /** The total budget is larger than the per-entry cap, so only the per-entry cap may limit the entry. */
    @Test fun perEntryCapHoldsEvenWhenTotalBudgetIsLarger() {
        val f = Files.createTempFile("bbf-cap-", ".zip").toFile().also { it.deleteOnExit() }
        ZipOutputStream(f.outputStream()).use { z ->
            z.putNextEntry(ZipEntry("big.bin")); z.write(ByteArray(8 shl 20)); z.closeEntry()
        }
        val limits = AnalysisLimits(maxEntryInspectionBytes = 1L shl 20, maxTotalInspectionBytes = 64L shl 20)
        val e = ZipAnalyzer(limits, Files.createTempDirectory("bbf-capdir-").toFile()).analyze(f).entries.single()
        assertEquals(MeasurementStatus.CAPPED_ENTRY_LIMIT, e.measurement)
        assertEquals(1L shl 20, e.measuredUncompressedSize)
        assertFalse(e.findings.any { it.code == "INSPECTION_BUDGET_EXHAUSTED" })
    }
}
