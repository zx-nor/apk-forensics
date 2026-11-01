package com.blackbox.forensics

import android.content.ContentResolver
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.io.IOException
import java.security.MessageDigest

/**
 * Copies a document chosen through the Storage Access Framework into app-private storage.
 *
 * The original is only read. The copy is made read-only and hashed while it is written, so the
 * hash describes exactly the bytes that the engine will analyze. Previous working copies are removed
 * first, so at most one evidence copy exists at a time.
 */
class EvidenceCopier(private val resolver: ContentResolver, private val root: File) {

    data class Copied(val workingFile: File, val displayName: String, val sizeBytes: Long, val sha256: String)

    fun copy(uri: Uri): Copied {
        val name = displayName(uri)
        if (root.exists()) root.deleteRecursively()
        root.mkdirs()
        val dest = File(root, sanitize(name))
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        val input = resolver.openInputStream(uri) ?: throw IOException("Android did not open the selected document.")
        input.use { src ->
            dest.outputStream().use { out ->
                val buf = ByteArray(64 * 1024)
                while (true) {
                    val n = src.read(buf)
                    if (n < 0) break
                    digest.update(buf, 0, n)
                    out.write(buf, 0, n)
                    total += n
                }
            }
        }
        dest.setReadOnly()
        val hex = digest.digest().joinToString("") { "%02x".format(it) }
        return Copied(dest, name, total, hex)
    }

    private fun displayName(uri: Uri): String {
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val i = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (i >= 0) c.getString(i)?.let { if (it.isNotBlank()) return it }
            }
        }
        return "evidence.bin"
    }

    /** Keeps the extension, which the engine uses for mismatch checks, while removing path characters. */
    internal fun sanitize(name: String): String =
        name.replace(Regex("[^A-Za-z0-9._ -]"), "_").replace("..", "_").take(120).ifBlank { "evidence.bin" }
}
