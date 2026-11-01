package forensics.m2

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Checks every independently generated expectation (see tools/make_fixtures_m2.py).
 * All failures are collected and reported together, so one run shows the full picture.
 */
class ExpectationTableTest {

    @Test fun everyExpectationHolds() {
        val rows = ExpectationTable.load()
        assertTrue(rows.size >= 200, "expectation table unexpectedly small: ${rows.size}")
        val analyses = HashMap<String, Analysis>()
        val failures = mutableListOf<String>()
        for (row in rows) {
            val problem = try {
                evaluate(analyses.getOrPut(row.file) { Analysis.of(row.file) }, row)
            } catch (e: Exception) {
                "${row.file} [${row.key}] threw ${e.javaClass.simpleName}: ${e.message}"
            }
            if (problem != null) failures += problem
        }
        assertTrue(failures.isEmpty(), "${failures.size} of ${rows.size} expectations failed:\n" + failures.joinToString("\n"))
    }
}
