package forensics

import java.io.File

/** Locates the synthetic corpus shipped as test resources. */
object CorpusTestSupport {
    private val dir: File by lazy {
        val candidates = listOf(
            File("src/test/resources/corpus"),
            File("engine/src/test/resources/corpus"),
        )
        candidates.firstOrNull { File(it, "expected.tsv").exists() }
            ?: error("Corpus not found. Run from project root or engine/. Checked: $candidates")
    }

    /** Milestone 2 corpus, with independently generated expectations in expected_m2.tsv. */
    val corpus2Dir: File by lazy {
        listOf(File("src/test/resources/corpus2"), File("engine/src/test/resources/corpus2"))
            .firstOrNull { File(it, "expected_m2.tsv").exists() }
            ?: error("corpus2 not found")
    }

    fun file2(name: String): File = File(corpus2Dir, name).also { check(it.exists()) { "Missing: $name" } }

    fun file(name: String): File = File(dir, name).also {
        check(it.exists()) { "Missing corpus file: $name" }
    }

    /** Expected values computed independently by Python (hashlib + separate entropy code). */
    data class Expected(val name: String, val size: Long, val sha256: String, val entropy: Double)

    fun expected(): List<Expected> {
        val lines = File(dir, "expected.tsv").readLines().map { it.trimEnd('\r') }
        return lines.drop(1).filter { it.isNotBlank() }.map { line ->
            val c = line.split("\t")
            Expected(c[0], c[1].toLong(), c[2], c[3].toDouble())
        }
    }
}
