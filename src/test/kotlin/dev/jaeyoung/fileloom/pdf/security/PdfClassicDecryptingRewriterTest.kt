package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class PdfClassicDecryptingRewriterTest {
    @Test
    fun byteSourceDecryptionUsesBoundedReadRequests() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(2L * 1024L * 1024L)
        val source = TrackingSecurityByteSource(fixture.encryptedFile.readBytes())
        val output = File.createTempFile("fileloom-byte-source-streaming", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.ByteSourceInput(source),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        assertTrue(source.maxRequestedBytes.get() <= 64 * 1024)
        assertEquals(fixture.expectedPlaintextSha256, sha256OfFirstStream(output))
    }

    private class TrackingSecurityByteSource(
        private val bytes: ByteArray,
    ) : PdfSecurityByteSource {
        override val length: Long = bytes.size.toLong()
        val maxRequestedBytes = AtomicInteger()

        override fun read(
            position: Long,
            sink: ByteArray,
            offset: Int,
            byteCount: Int,
        ): Int {
            maxRequestedBytes.accumulateAndGet(byteCount, ::maxOf)
            if (position >= bytes.size) return -1
            val count = minOf(byteCount, bytes.size - position.toInt())
            bytes.copyInto(
                destination = sink,
                destinationOffset = offset,
                startIndex = position.toInt(),
                endIndex = position.toInt() + count,
            )
            return count
        }
    }
}
