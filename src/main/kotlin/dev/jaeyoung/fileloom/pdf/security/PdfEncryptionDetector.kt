package dev.jaeyoung.fileloom.pdf.security

/**
 * Lightweight encryption detector for routing PDFs into password handling.
 *
 * This is intentionally conservative: it only scans the trailer section for
 * a PDF `/Encrypt` entry. Full security dictionary parsing is implemented in
 * later stages of the decryptor.
 */
public object PdfEncryptionDetector {
    private val encryptNamePattern = Regex("(?<![A-Za-z0-9_#])/Encrypt(?![A-Za-z0-9_])")

    public fun bytesLookEncrypted(bytes: ByteArray): Boolean {
        val text = bytes.toString(Charsets.ISO_8859_1)
        val trailerIndex = text.lastIndexOf("trailer")
        if (trailerIndex < 0) return false
        return encryptNamePattern.containsMatchIn(text.substring(trailerIndex))
    }
}
