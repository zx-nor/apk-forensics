package forensics.identify

/**
 * A single documented magic-byte signature.
 *
 * [offset] is the byte offset at which [magic] must appear. Most formats use 0;
 * some (e.g. TAR "ustar") are anchored elsewhere. [extensions] are the
 * conventional filename extensions, used only for mismatch detection and
 * never as proof of format.
 */
data class FileSignature(
    val formatId: String,
    val displayName: String,
    val mimeType: String,
    val offset: Int,
    val magic: ByteArray,
    val extensions: Set<String>,
) {
    init {
        require(magic.isNotEmpty()) { "Signature $formatId has empty magic" }
        require(offset >= 0) { "Signature $formatId has negative offset" }
    }

    override fun equals(other: Any?): Boolean =
        other is FileSignature && formatId == other.formatId && offset == other.offset &&
            magic.contentEquals(other.magic)

    override fun hashCode(): Int = formatId.hashCode() * 31 + offset

    companion object {
        private fun b(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
        private fun s(text: String) = text.toByteArray(Charsets.US_ASCII)

        /**
         * Signatures taken from the published format specifications:
         * JPEG (ITU-T T.81 / JFIF), PNG (ISO/IEC 15948), GIF87a/89a, PDF (ISO 32000),
         * ZIP (PKWARE APPNOTE), GZIP (RFC 1952), 7z, RAR4/RAR5, WAV/RIFF, MP3 (ID3 tag),
         * FLAC, OGG, SQLite 3, PCAP, PCAPNG, ELF, and TAR (ustar).
         *
         * OpenPGP is deliberately absent: its binary framing begins with a single
         * packet-tag byte that matches too much unrelated data to be reported
         * reliably. Without a structural parser it is not identified.
         */
        val DEFAULT: List<FileSignature> = listOf(
            FileSignature("jpeg", "JPEG image", "image/jpeg", 0, b(0xFF, 0xD8, 0xFF), setOf("jpg", "jpeg", "jpe")),
            FileSignature("png", "PNG image", "image/png", 0,
                b(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A), setOf("png")),
            FileSignature("gif87a", "GIF image (87a)", "image/gif", 0, s("GIF87a"), setOf("gif")),
            FileSignature("gif89a", "GIF image (89a)", "image/gif", 0, s("GIF89a"), setOf("gif")),
            FileSignature("pdf", "PDF document", "application/pdf", 0, s("%PDF-"), setOf("pdf")),
            FileSignature("zip", "ZIP archive", "application/zip", 0,
                b(0x50, 0x4B, 0x03, 0x04), setOf("zip", "docx", "xlsx", "pptx", "apk", "jar", "odt")),
            FileSignature("gzip", "GZIP compressed", "application/gzip", 0, b(0x1F, 0x8B, 0x08), setOf("gz", "tgz")),
            FileSignature("7z", "7-Zip archive", "application/x-7z-compressed", 0,
                b(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C), setOf("7z")),
            FileSignature("rar4", "RAR archive (v1.5-4.x)", "application/x-rar-compressed", 0,
                b(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00), setOf("rar")),
            FileSignature("rar5", "RAR archive (v5)", "application/x-rar-compressed", 0,
                b(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00), setOf("rar")),
            FileSignature("wav", "WAV audio (RIFF/WAVE)", "audio/wav", 0, s("RIFF"), setOf("wav")),
            FileSignature("mp3-id3", "MP3 audio (ID3 tag)", "audio/mpeg", 0, s("ID3"), setOf("mp3")),
            FileSignature("flac", "FLAC audio", "audio/flac", 0, s("fLaC"), setOf("flac")),
            FileSignature("ogg", "OGG container", "application/ogg", 0, s("OggS"), setOf("ogg", "oga", "opus")),
            FileSignature("sqlite3", "SQLite 3 database", "application/vnd.sqlite3", 0,
                s("SQLite format 3\u0000"), setOf("db", "sqlite", "sqlite3")),
            FileSignature("pcap-le", "PCAP capture (little-endian)", "application/vnd.tcpdump.pcap", 0,
                b(0xD4, 0xC3, 0xB2, 0xA1), setOf("pcap", "cap")),
            FileSignature("pcap-be", "PCAP capture (big-endian)", "application/vnd.tcpdump.pcap", 0,
                b(0xA1, 0xB2, 0xC3, 0xD4), setOf("pcap", "cap")),
            FileSignature("pcapng", "PCAPNG capture", "application/x-pcapng", 0,
                b(0x0A, 0x0D, 0x0D, 0x0A), setOf("pcapng")),
            FileSignature("elf", "ELF executable/object", "application/x-elf", 0,
                b(0x7F, 0x45, 0x4C, 0x46), setOf("so", "elf", "o")),
            FileSignature("tar-ustar", "TAR archive (ustar)", "application/x-tar", 257,
                s("ustar"), setOf("tar")),
        )
    }
}
