package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class FileloomPdfStreamingMemoryTest {
    @Test
    fun decryptsSixtyFourMiBAesStreamWithinSmallHeap() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(
            streamPlaintextBytes = 64L * 1024L * 1024L,
        )
        val output = File.createTempFile("fileloom-streaming-output", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        val success = assertIs<PdfDecryptResult.Success>(result, result.toString())
        assertEquals(output, success.outputFile)
        assertEquals(
            PdfSecurityInspection.NotEncrypted,
            FileloomPdfDecryptor.inspect(PdfSecurityInput.FileInput(output)),
        )
        assertEquals(fixture.expectedPlaintextBytes, findFirstStreamLength(output))
        assertEquals(fixture.expectedPlaintextSha256, sha256OfFirstStream(output))
    }
}
