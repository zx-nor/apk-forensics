package forensics

import forensics.identify.Confidence
import forensics.identify.FileIdentifier
import forensics.identify.IdentificationMethod
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class FileIdentifierTest {
    private val id = FileIdentifier()

    @Test fun identifiesGenuinePng() {
        val r = id.identify(CorpusTestSupport.file("genuine.png"))
        assertEquals("png", r.detectedFormatId)
        assertEquals(Confidence.HIGH, r.confidence)
        assertEquals(IdentificationMethod.MAGIC_AT_OFFSET, r.method)
        assertFalse(r.extensionMismatch)
    }

    @Test fun identifiesGenuineJpeg() {
        val r = id.identify(CorpusTestSupport.file("genuine.jpg"))
        assertEquals("jpeg", r.detectedFormatId)
        assertFalse(r.extensionMismatch)
    }

    @Test fun detectsPngHiddenAsJpg() {
        val r = id.identify(CorpusTestSupport.file("actually_png.jpg"))
        assertEquals("png", r.detectedFormatId, "content must win over the .jpg extension")
        assertTrue(r.extensionMismatch, "extension .jpg must be flagged as a mismatch")
        assertTrue(r.uncertainty.any { it.contains("does not match") })
    }

    @Test fun identifiesPdf() {
        assertEquals("pdf", id.identify(CorpusTestSupport.file("document.pdf")).detectedFormatId)
    }

    @Test fun zipIsReportedWithOoxmlCaveat() {
        val r = id.identify(CorpusTestSupport.file("archive.zip"))
        assertEquals("zip", r.detectedFormatId)
        assertTrue(r.uncertainty.any { it.contains("ZIP-based") }, "must not claim it is a plain zip only")
    }

    @Test fun findsTarMagicAtOffset257() {
        val r = id.identify(CorpusTestSupport.file("archive.tar"))
        assertEquals("tar-ustar", r.detectedFormatId)
        assertTrue(r.evidence.contains("offset 257"))
    }

    @Test fun identifiesSqlite() {
        assertEquals("sqlite3", id.identify(CorpusTestSupport.file("database.sqlite")).detectedFormatId)
    }

    @Test fun pngWithAppendedZipIsPngNotZip() {
        val r = id.identify(CorpusTestSupport.file("png_with_appended_zip.png"))
        assertEquals("png", r.detectedFormatId, "appended payload must not change the leading format")
    }

    @Test fun unknownDataReturnsNoMatchNotAGuess() {
        val r = id.identify(CorpusTestSupport.file("unknown.bin"))
        assertNull(r.detectedFormatId)
        assertEquals(Confidence.NONE, r.confidence)
        assertEquals(IdentificationMethod.NO_MATCH, r.method)
    }

    @Test fun truncatedSignatureIsLowConfidence() {
        val r = id.identify(CorpusTestSupport.file("truncated.png"))
        assertNull(r.detectedFormatId, "3 bytes cannot satisfy the 8-byte PNG signature")
    }

    @Test fun inMemoryIdentificationMatchesFileIdentification() {
        val bytes = CorpusTestSupport.file("genuine.png").readBytes()
        assertEquals("png", id.identify(bytes, "x.png").detectedFormatId)
    }

    @Test fun extensionWithoutAnyKnownFormatIsNotFlagged() {
        // A .txt file with no signature is not a mismatch; .txt is not a known binary format.
        val r = id.identify("hello world, plain text".toByteArray(), "notes.txt")
        assertNull(r.detectedFormatId)
        assertFalse(r.extensionMismatch)
    }
}
