package forensics.archive

import forensics.identify.Confidence

enum class PackageKind { ZIP, JAR, APK, AAB, DOCX, XLSX, PPTX, ODF, AMBIGUOUS_OFFICE_OR_APK, NOT_ZIP }

/**
 * Structural classification of a ZIP-based container.
 *
 * Classification uses conventional entry names. Names are easy to forge, so every result
 * carries a note stating that content was not validated beyond names.
 */
data class Classification(
    val kind: PackageKind,
    val confidence: Confidence,
    val markers: List<String>,
    val notes: List<String>,
)

object ZipClassifier {
    private const val NOTE = "Classification uses conventional entry names only; names can be forged. Content validation was not performed."

    fun classify(names: Collection<String>): Classification {
        val s = names.toSet()
        val markers = mutableListOf<String>()

        val apkMarkers = listOf("AndroidManifest.xml", "classes.dex", "resources.arsc").filter { it in s }
        val aabMarkers = listOf("BundleConfig.pb", "base/manifest/AndroidManifest.xml").filter { it in s }
        val hasAabDex = s.any { it.startsWith("base/dex/") }

        val ooxml = mutableListOf<PackageKind>()
        if ("[Content_Types].xml" in s) {
            if ("word/document.xml" in s) ooxml += PackageKind.DOCX
            if ("xl/workbook.xml" in s) ooxml += PackageKind.XLSX
            if ("ppt/presentation.xml" in s) ooxml += PackageKind.PPTX
        }
        val odf = "mimetype" in s && "content.xml" in s && "META-INF/manifest.xml" in s

        if (aabMarkers.isNotEmpty() || hasAabDex) {
            markers += aabMarkers + (if (hasAabDex) listOf("base/dex/*") else emptyList())
            return Classification(
                PackageKind.AAB,
                if (aabMarkers.size == 2 || (aabMarkers.isNotEmpty() && hasAabDex)) Confidence.HIGH else Confidence.MEDIUM,
                markers, listOf(NOTE),
            )
        }

        if (apkMarkers.isNotEmpty() && ooxml.isNotEmpty()) {
            markers += apkMarkers
            return Classification(PackageKind.AMBIGUOUS_OFFICE_OR_APK, Confidence.LOW,
                markers + ooxml.map { it.name }, listOf("Both APK and OOXML markers are present.", NOTE))
        }
        if (ooxml.size > 1) {
            return Classification(PackageKind.AMBIGUOUS_OFFICE_OR_APK, Confidence.LOW,
                ooxml.map { it.name }, listOf("Several OOXML markers are present.", NOTE))
        }
        if (ooxml.size == 1) {
            val k = ooxml[0]
            val m = when (k) {
                PackageKind.DOCX -> listOf("[Content_Types].xml", "word/document.xml")
                PackageKind.XLSX -> listOf("[Content_Types].xml", "xl/workbook.xml")
                else -> listOf("[Content_Types].xml", "ppt/presentation.xml")
            }
            return Classification(k, Confidence.HIGH, m, listOf(NOTE))
        }

        if ("AndroidManifest.xml" in s && ("classes.dex" in s || "resources.arsc" in s)) {
            markers += apkMarkers
            return Classification(PackageKind.APK, Confidence.HIGH, markers, listOf(NOTE))
        }
        if (odf) {
            return Classification(PackageKind.ODF, Confidence.MEDIUM, listOf("mimetype", "content.xml", "META-INF/manifest.xml"), listOf(NOTE))
        }
        if ("META-INF/MANIFEST.MF" in s) {
            return Classification(PackageKind.JAR, Confidence.MEDIUM, listOf("META-INF/MANIFEST.MF"),
                listOf("JAR and APK archives may both contain META-INF/MANIFEST.MF.", NOTE))
        }
        return Classification(PackageKind.ZIP, Confidence.HIGH, emptyList(),
            listOf("No format-specific entry names found. ZIP structure is valid.", NOTE))
    }
}
