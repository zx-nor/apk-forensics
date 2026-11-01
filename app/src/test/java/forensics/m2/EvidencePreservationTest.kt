package forensics.m2

import forensics.CorpusTestSupport
import forensics.common.AnalysisLimits
import forensics.hash.StreamingHasher
import forensics.identify.DeepIdentifier
import forensics.metadata.MetadataDispatcher
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.File
import java.nio.file.Files
import java.util.Random

class EvidencePreservationTest {

    private fun snapshot(dir: File): Map<String, String> =
        dir.listFiles().orEmpty().filter { it.isFile }.associate { it.name to StreamingHasher.sha256(it).sha256Hex }

    @Test fun analysisNeverModifiesOrAddsEvidence() {
        val before = snapshot(CorpusTestSupport.corpus2Dir)
        assertTrue(before.size > 50)
        val limits = AnalysisLimits()
        for (name in before.keys) {
            val f = CorpusTestSupport.file2(name)
            val scratch = Files.createTempDirectory("bbf-pres-").toFile().also { it.deleteOnExit() }
            DeepIdentifier(limits, scratch).identify(f)
            MetadataDispatcher.extract(f, DeepIdentifier(limits, scratch).identify(f).refinedFormat, limits)
        }
        assertEquals(before, snapshot(CorpusTestSupport.corpus2Dir), "analysis must leave every evidence file byte-identical")
    }

    @Test fun xmlExternalEntityIsNeverResolved() {
        val f = CorpusTestSupport.file2("xxe.docx")
        val r = MetadataDispatcher.extract(f, "docx", AnalysisLimits())!!
        val values = r.fields.map { it.value }
        assertTrue(values.none { it.contains("root:") }, "the file:///etc/passwd entity must not be expanded: $values")
        assertTrue(r.fields.none { it.key == "Title" }, "the title that depends on the entity must be absent")
    }

    /**
     * Adversarial inputs: deterministic random mutations of real files. Every mutation must produce a
     * result. Any exception escaping the engine is a defect, not an expected outcome.
     */
    @Test fun mutatedInputsNeverEscapeAsExceptions() {
        val seeds = listOf("plain.zip", "report.docx", "demo.apk", "plain.png", "exif_photo.jpg", "tagged.mp3",
            "tagged.flac", "clip.mp4", "info.pdf", "sample.tif", "tagged.wav", "sample.db")
        val rnd = Random(0xB1AC)
        val work = Files.createTempDirectory("bbf-fuzz-").toFile().also { it.deleteOnExit() }
        val limits = AnalysisLimits(maxCentralDirectoryBytes = 1L shl 20, maxEntryInspectionBytes = 1L shl 20,
            maxTotalInspectionBytes = 4L shl 20)
        val failures = mutableListOf<String>()
        var runs = 0
        for (seed in seeds) {
            val original = CorpusTestSupport.file2(seed).readBytes()
            repeat(12) { round ->
                val mutated = mutate(original, rnd)
                val f = File(work, "m-${seed}-$round")
                f.writeBytes(mutated)
                runs++
                try {
                    val scratch = Files.createTempDirectory(work.toPath(), "s").toFile()
                    val d = DeepIdentifier(limits, scratch).identify(f)
                    MetadataDispatcher.extract(f, d.refinedFormat, limits)
                    assertTrue(scratch.list().isNullOrEmpty(), "temporary files left behind for $seed round $round")
                } catch (t: Throwable) {
                    failures += "$seed round $round: ${t.javaClass.simpleName}: ${t.message}"
                }
                f.delete()
            }
        }
        assertTrue(failures.isEmpty(), "$runs mutated inputs; ${failures.size} escaped as exceptions:\n" + failures.joinToString("\n"))
    }

    private fun mutate(src: ByteArray, rnd: Random): ByteArray {
        val out = src.copyOf()
        return when (rnd.nextInt(5)) {
            0 -> { // flip bytes
                repeat(1 + rnd.nextInt(8)) { out[rnd.nextInt(out.size)] = rnd.nextInt(256).toByte() }
                out
            }
            1 -> src.copyOf(rnd.nextInt(src.size + 1)) // truncate anywhere, including zero length
            2 -> { // overwrite a 4-byte field with 0xFF (size or count fields)
                val at = rnd.nextInt(maxOf(1, out.size - 4))
                for (i in 0 until minOf(4, out.size - at)) out[at + i] = 0xFF.toByte()
                out
            }
            3 -> { // insert random bytes in the middle
                val at = rnd.nextInt(out.size + 1)
                val junk = ByteArray(1 + rnd.nextInt(64)).also { rnd.nextBytes(it) }
                out.copyOfRange(0, at) + junk + out.copyOfRange(at, out.size)
            }
            else -> { // zero a region
                val from = rnd.nextInt(out.size)
                val len = minOf(out.size - from, 1 + rnd.nextInt(256))
                for (i in from until from + len) out[i] = 0
                out
            }
        }
    }
}
