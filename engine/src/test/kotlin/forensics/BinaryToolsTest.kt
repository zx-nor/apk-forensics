package forensics

import forensics.binary.HexView
import forensics.binary.StringExtractor
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File

class BinaryToolsTest {

    @Test fun hexRowFormatsKnownBytes() {
        val rows = HexView.formatRows("ABC\u0000\u007F".toByteArray(Charsets.ISO_8859_1))
        assertEquals(1, rows.size)
        assertEquals(0L, rows[0].offset)
        // 'A'=41 'B'=42 'C'=43 NUL=00 DEL=7F. Non-printable shown as '.'.
        assertEquals("41 42 43 00 7F", rows[0].hex.trim().replace(Regex(" +"), " ").take(14))
        assertEquals("ABC..", rows[0].ascii)
    }

    @Test fun hexViewBaseOffsetAndRowCount() {
        val data = ByteArray(40) { it.toByte() }
        val rows = HexView.formatRows(data, baseOffset = 0x1000L)
        assertEquals(3, rows.size)
        assertEquals(0x1000L, rows[0].offset)
        assertEquals(0x1010L, rows[1].offset)
        assertEquals(0x1020L, rows[2].offset)
    }

    @Test fun hexWindowReadsOnlyRequestedRegion() {
        val f = CorpusTestSupport.file("uniform_256.bin")
        val rows = HexView.render(f, offset = 16, length = 16)
        assertEquals(1, rows.size)
        assertEquals(16L, rows[0].offset)
        assertEquals(16, rows[0].ascii.length)
    }

    @Test fun hexRenderBeyondEndReturnsEmpty() {
        assertTrue(HexView.render(CorpusTestSupport.file("genuine.png"), 10_000, 16).isEmpty())
    }

    @Test fun hexRejectsOversizedWindow() {
        assertThrows(IllegalArgumentException::class.java) {
            HexView.render(CorpusTestSupport.file("genuine.png"), 0, HexView.MAX_WINDOW + 1)
        }
    }

    @Test fun asciiStringsFoundWithOffsets() {
        val data = "\u0000\u0001HelloWorldString\u0000xy\u0000Second!".toByteArray(Charsets.ISO_8859_1)
        val found = StringExtractor(minLength = 4).scanAscii(data, 0L)
        assertEquals(listOf("HelloWorldString", "Second!"), found.map { it.text })
        assertEquals(2L, found[0].offset)
    }

    @Test fun shortRunsBelowMinimumAreDropped() {
        val found = StringExtractor(minLength = 4).scanAscii("ab\u0000cd\u0000efgh".toByteArray(Charsets.ISO_8859_1), 0L)
        assertEquals(listOf("efgh"), found.map { it.text })
    }

    @Test fun mixedFileAsciiAndUtf16LeStringsFromCorpus() {
        val bytes = CorpusTestSupport.file("strings_mixed.bin").readBytes()
        val ascii = StringExtractor(minLength = 4).scanAscii(bytes, 0L).map { it.text }
        assertTrue(ascii.contains("HelloWorldString"), "ASCII run must be found: $ascii")
        val wide = StringExtractor(minLength = 4).scanUtf16LeAscii(bytes, 0L).map { it.text }
        assertTrue(wide.contains("Wide Text Here"), "UTF-16LE run must be found: $wide")
    }

    @Test fun fileExtractionMatchesInMemoryExtraction() {
        val f = CorpusTestSupport.file("strings_mixed.bin")
        val fromFile = StringExtractor(minLength = 4, chunkSize = 1024).extractAscii(f).map { it.text to it.offset }
        val inMemory = StringExtractor(minLength = 4).scanAscii(f.readBytes(), 0L).map { it.text to it.offset }
        assertEquals(inMemory, fromFile)
    }

    @Test fun runCrossingChunkBoundaryIsNotSplit() {
        // A 1,100-byte printable run must come out whole even though chunk size is 1024.
        val payload = "X".repeat(1100)
        val tmp = File.createTempFile("bbf-run", ".bin").apply { deleteOnExit() }
        tmp.writeBytes(byteArrayOf(0) + payload.toByteArray() + byteArrayOf(0))
        val found = StringExtractor(minLength = 4, chunkSize = 1024).extractAscii(tmp)
        assertEquals(1, found.size)
        assertEquals(1100, found[0].text.length)
    }

    @Test fun resultCapPreventsUnboundedOutput() {
        val data = ("abcd\u0000".repeat(1000)).toByteArray(Charsets.ISO_8859_1)
        val found = StringExtractor(minLength = 4, maxResults = 10).scanAscii(data, 0L)
        assertEquals(10, found.size)
    }
}
