package dev.jaeyoung.fileloom.pdf.security

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PdfEncryptionDetectorTest {
    @Test
    fun detectsTrailerEncryptEntry() {
        val pdf = minimalPdf(trailerExtra = "/Encrypt 5 0 R")

        assertTrue(PdfEncryptionDetector.bytesLookEncrypted(pdf))
    }

    @Test
    fun doesNotTreatNormalPdfAsEncrypted() {
        val pdf = minimalPdf()

        assertFalse(PdfEncryptionDetector.bytesLookEncrypted(pdf))
    }

    @Test
    fun ignoresEncryptTextOutsideTrailer() {
        val pdf = minimalPdf(
            objectExtra = "4 0 obj\n<< /Length 24 >>\nstream\n/Encrypt mentioned here\nendstream\nendobj\n"
        )

        assertFalse(PdfEncryptionDetector.bytesLookEncrypted(pdf))
    }

    private fun minimalPdf(
        trailerExtra: String = "",
        objectExtra: String = ""
    ): ByteArray {
        val body = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
            append("2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n")
            append(objectExtra)
            append("xref\n0 3\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n")
            append("trailer\n<< /Size 3 /Root 1 0 R")
            if (trailerExtra.isNotBlank()) append(' ').append(trailerExtra)
            append(" >>\nstartxref\n120\n%%EOF\n")
        }
        return body.toByteArray(Charsets.ISO_8859_1)
    }
}
