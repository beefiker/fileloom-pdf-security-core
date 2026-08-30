package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
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

    @Test
    fun sizePreflightPreservesExistingOutputWhenOverwriteIsEnabled() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(1024)
        val output = File.createTempFile("fileloom-existing-output", ".pdf").apply {
            writeText("existing output")
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(
                overwriteOutput = true,
                maxInputBytes = fixture.encryptedFile.length() - 1L,
            ),
        )

        assertIs<PdfDecryptResult.UnsupportedEncryption>(result)
        assertEquals("existing output", output.readText())
    }

    @Test
    fun oversizedByteSourceIsClosedBeforeReturning() {
        val source = TrackingSecurityByteSource(ByteArray(16))
        val output = File.createTempFile("fileloom-oversized-source", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.ByteSourceInput(source),
            password = "unused".toCharArray(),
            output = output,
            options = PdfDecryptOptions(maxInputBytes = 15L),
        )

        assertIs<PdfDecryptResult.UnsupportedEncryption>(result)
        assertTrue(source.closed.get())
    }

    @Test
    fun fileGrowthAfterLengthCheckCannotBypassMaxInputBytes() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(1024)
        val acceptedLength = fixture.encryptedFile.length()
        val growingInput = object : File(fixture.encryptedFile.absolutePath) {
            private var grew = false

            override fun length(): Long {
                val currentLength = super.length()
                if (!grew) {
                    grew = true
                    RandomAccessFile(this, "rw").use { file ->
                        file.setLength(currentLength + 1024L)
                    }
                    return currentLength
                }
                return super.length()
            }
        }
        val output = File.createTempFile("fileloom-growing-input", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(growingInput),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true, maxInputBytes = acceptedLength),
        )

        assertIs<PdfDecryptResult.UnsupportedEncryption>(result)
        assertFalse(output.exists())
    }

    @Test
    fun inflatedTrailerSizeDoesNotDriveDenseXrefAllocationOrOutput() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(1024)
        val original = fixture.encryptedFile.readText(Charsets.ISO_8859_1)
        fixture.encryptedFile.writeText(
            original.replace("/Size 6 ", "/Size 100000 "),
            Charsets.ISO_8859_1,
        )
        val output = File.createTempFile("fileloom-sparse-xref", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        assertTrue(output.length() < 256L * 1024L, "unexpected dense xref output: ${output.length()}")
        assertTrue(output.readText(Charsets.ISO_8859_1).contains("/Size 5"))
    }

    @Test
    fun invalidAesPaddingIsReportedAsMalformedPdf() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(1024)
        corruptLastByteOfFirstStream(fixture.encryptedFile)
        val output = File.createTempFile("fileloom-corrupt-aes", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        assertIs<PdfDecryptResult.MalformedPdf>(result, result.toString())
        assertFalse(output.exists())
    }

    @Test
    fun trailerRealValuesAreSerializedWithoutExponentNotation() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(
            streamPlaintextBytes = 1024,
            trailerExtra = "/Scale 0.0000001",
        )
        val output = File.createTempFile("fileloom-real-trailer", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        val outputText = output.readText(Charsets.ISO_8859_1)
        assertTrue(outputText.contains("/Scale 0.0000001"), outputText)
        assertFalse(outputText.contains("E-7"), outputText)
    }

    @Test
    fun decryptsStreamWhoseKeywordFollowsLongCommentsAndWhitespace() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(
            streamPlaintextBytes = 1024,
            streamPrelude = "% delayed stream keyword\n${" ".repeat(300)}",
        )
        val output = File.createTempFile("fileloom-delayed-stream", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        assertEquals(fixture.expectedPlaintextSha256, sha256OfFirstStream(output))
    }

    @Test
    fun decryptsLargeStreamWhoseHeaderExceedsLegacyProbeWindow() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(
            streamPlaintextBytes = 9L * 1024L * 1024L,
            streamPrelude = "% large delayed stream keyword\n${" ".repeat(70 * 1024)}",
        )
        val output = File.createTempFile("fileloom-large-delayed-stream", ".pdf").apply {
            delete()
            deleteOnExit()
        }

        val result = FileloomPdfDecryptor.decryptToFile(
            input = PdfSecurityInput.FileInput(fixture.encryptedFile),
            password = fixture.password.toCharArray(),
            output = output,
            options = PdfDecryptOptions(overwriteOutput = true),
        )

        assertIs<PdfDecryptResult.Success>(result, result.toString())
        assertEquals(fixture.expectedPlaintextSha256, sha256OfFirstStream(output))
    }

    @Test
    fun classicXrefOffsetsRejectValuesWiderThanTenDigits() {
        val error = assertFailsWith<PdfStreamingRewriteException> {
            formatClassicXrefOffset(10_000_000_000L)
        }

        assertEquals("classic-xref-offset-unsupported", error.code)
        assertEquals(PdfStreamingRewriteFailureKind.Unsupported, error.kind)
    }

    private class TrackingSecurityByteSource(
        private val bytes: ByteArray,
    ) : PdfSecurityByteSource {
        override val length: Long = bytes.size.toLong()
        val maxRequestedBytes = AtomicInteger()
        val closed = AtomicBoolean(false)

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

        override fun close() {
            closed.set(true)
        }
    }
}
