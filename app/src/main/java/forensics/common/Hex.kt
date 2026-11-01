package forensics.common

fun ByteArray.toHexString(): String = joinToString(" ") { "%02X".format(it) }
