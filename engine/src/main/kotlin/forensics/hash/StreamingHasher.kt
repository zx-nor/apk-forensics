package forensics.hash

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/** Digest of a file computed in fixed-size chunks. Memory use is bounded by [chunkSize]. */
data class FileDigest(val sha256Hex: String, val byteCount: Long)

/**
 * Computes SHA-256 by streaming. Never loads the whole file.
 * Non-destructive: opens the file read-only.
 */
object StreamingHasher {
    const val DEFAULT_CHUNK = 64 * 1024

    fun sha256(file: File, chunkSize: Int = DEFAULT_CHUNK): FileDigest =
        file.inputStream().use { sha256(it, chunkSize) }

    fun sha256(input: InputStream, chunkSize: Int = DEFAULT_CHUNK): FileDigest {
        require(chunkSize > 0) { "chunkSize must be positive" }
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(chunkSize)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
            total += n
        }
        return FileDigest(md.digest().joinToString("") { "%02x".format(it) }, total)
    }
}
