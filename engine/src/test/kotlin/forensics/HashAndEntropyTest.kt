package forensics

import forensics.binary.Entropy
import forensics.hash.StreamingHasher
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.io.ByteArrayInputStream

class HashAndEntropyTest {

    /** Every corpus file's SHA-256 must match the Python hashlib value. */
    @Test fun sha256MatchesIndependentReferenceForEveryFile() {
        val expected = CorpusTestSupport.expected()
        assertTrue(expected.size >= 15, "corpus unexpectedly small")
        for (e in expected) {
            val d = StreamingHasher.sha256(CorpusTestSupport.file(e.name))
            assertEquals(e.sha256, d.sha256Hex, "SHA-256 mismatch for ${e.name}")
            assertEquals(e.size, d.byteCount, "byte count mismatch for ${e.name}")
        }
    }

    /** Result must be independent of chunk size: streaming must not change the digest. */
    @ParameterizedTest
    @ValueSource(ints = [1, 7, 64, 4096, 65536])
    fun sha256IsIndependentOfChunkSize(chunk: Int) {
        val f = CorpusTestSupport.file("random_4096.bin")
        val expected = CorpusTestSupport.expected().single { it.name == "random_4096.bin" }.sha256
        assertEquals(expected, StreamingHasher.sha256(f, chunk).sha256Hex)
    }

    @Test fun sha256OfEmptyInputIsKnownConstant() {
        val d = StreamingHasher.sha256(ByteArrayInputStream(ByteArray(0)))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", d.sha256Hex)
        assertEquals(0L, d.byteCount)
    }

    @Test fun rejectsNonPositiveChunkSize() {
        assertThrows(IllegalArgumentException::class.java) {
            StreamingHasher.sha256(ByteArrayInputStream(ByteArray(4)), 0)
        }
    }

    /** Entropy must match the independent Python computation for every corpus file. */
    @Test fun entropyMatchesIndependentReferenceForEveryFile() {
        for (e in CorpusTestSupport.expected()) {
            val r = Entropy.of(CorpusTestSupport.file(e.name))
            assertEquals(e.entropy, r.bitsPerByte, 1e-5, "entropy mismatch for ${e.name}")
        }
    }

    @Test fun uniformDistributionIsExactlyEightBits() {
        val r = Entropy.of(CorpusTestSupport.file("uniform_256.bin"))
        assertEquals(8.0, r.bitsPerByte, 1e-12)
        assertTrue(r.isHighlyRandom())
    }

    @Test fun constantDataIsExactlyZeroBits() {
        assertEquals(0.0, Entropy.of(CorpusTestSupport.file("zeros_1024.bin")).bitsPerByte, 1e-12)
    }

    @Test fun twoEqualSymbolsIsExactlyOneBit() {
        assertEquals(1.0, Entropy.of(CorpusTestSupport.file("two_symbols.bin")).bitsPerByte, 1e-12)
    }

    @Test fun emptyInputHasZeroEntropyAndNoRandomnessClaim() {
        val r = Entropy.of(ByteArrayInputStream(ByteArray(0)))
        assertEquals(0.0, r.bitsPerByte)
        assertFalse(r.isHighlyRandom(), "empty input must never be reported as random")
    }

    /** Documents the limitation: high entropy is not proof of encryption. */
    @Test fun highEntropyIsNotTreatedAsEncryptionProof() {
        val r = Entropy.of(CorpusTestSupport.file("random_4096.bin"))
        assertTrue(r.bitsPerByte > 7.5, "random data should score high")
        // The API exposes only a randomness indicator, never an encryption verdict.
        assertFalse(r.javaClass.methods.any { it.name.contains("encrypt", ignoreCase = true) })
    }

    @Test fun histogramCountsEveryByte() {
        val r = Entropy.of(CorpusTestSupport.file("two_symbols.bin"))
        assertEquals(1024L, r.histogram.sum())
        assertEquals(512L, r.histogram['A'.code])
        assertEquals(512L, r.histogram['B'.code])
    }
}
