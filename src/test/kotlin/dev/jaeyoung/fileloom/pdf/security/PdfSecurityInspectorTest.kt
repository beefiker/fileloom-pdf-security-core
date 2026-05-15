package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class PdfSecurityInspectorTest {
    @Test
    fun inspectReportsNotEncryptedForNormalPdf() {
        val file = writePdf(
            1 to "<< /Type /Catalog /Pages 2 0 R >>",
            2 to "<< /Type /Pages /Count 0 >>"
        )

        val inspection = FileloomPdfDecryptor.inspect(PdfSecurityInput.FileInput(file))

        assertEquals(PdfSecurityInspection.NotEncrypted, inspection)
    }

    @Test
    fun inspectParsesStandardSecurityDictionary() {
        val ownerEntry = "00".repeat(32)
        val userEntry = "11".repeat(32)
        val file = writePdf(
            1 to "<< /Type /Catalog /Pages 2 0 R >>",
            2 to "<< /Type /Pages /Count 0 >>",
            5 to "<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 /O <$ownerEntry> /U <$userEntry> /EncryptMetadata false >>",
            trailerExtra = "/Encrypt 5 0 R"
        )

        val inspection = FileloomPdfDecryptor.inspect(PdfSecurityInput.FileInput(file))

        val encrypted = assertIs<PdfSecurityInspection.Encrypted>(inspection)
        assertEquals("Standard", encrypted.handler)
        assertEquals(4, encrypted.version)
        assertEquals(4, encrypted.revision)
        assertEquals(128, encrypted.keyLengthBits)
        assertEquals(PdfEncryptionAlgorithm.Standard128Bit, encrypted.algorithm)
        assertEquals(-4, encrypted.permissions)
    }

    private fun writePdf(
        vararg objects: Pair<Int, String>,
        trailerExtra: String = ""
    ): File {
        val file = File.createTempFile("fileloom-security-inspect", ".pdf")
        file.deleteOnExit()

        val sortedObjects = objects.sortedBy { it.first }
        val maxObjectId = sortedObjects.maxOf { it.first }
        val offsets = IntArray(maxObjectId + 1)
        val content = StringBuilder()
        content.append("%PDF-1.4\n")
        sortedObjects.forEach { (objectId, body) ->
            offsets[objectId] = content.length
            content.append(objectId).append(" 0 obj\n")
            content.append(body).append('\n')
            content.append("endobj\n")
        }
        val startXref = content.length
        content.append("xref\n")
        content.append("0 ").append(maxObjectId + 1).append('\n')
        content.append("0000000000 65535 f \n")
        for (objectId in 1..maxObjectId) {
            content.append(offsets[objectId].toString().padStart(10, '0')).append(" 00000 n \n")
        }
        content.append("trailer\n")
        content.append("<< /Size ").append(maxObjectId + 1).append(" /Root 1 0 R")
        if (trailerExtra.isNotBlank()) content.append(' ').append(trailerExtra)
        content.append(" >>\n")
        content.append("startxref\n")
        content.append(startXref).append('\n')
        content.append("%%EOF\n")

        file.writeText(content.toString(), Charsets.ISO_8859_1)
        return file
    }
}
