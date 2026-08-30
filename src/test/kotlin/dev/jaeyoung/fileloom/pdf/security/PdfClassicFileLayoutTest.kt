package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import java.io.FileOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PdfClassicFileLayoutTest {
    @Test
    fun returnsSortedInUseObjectRangesEndingAtStartXref() {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(1024)

        val layout = PdfClassicFileLayoutReader.read(fixture.encryptedFile)

        assertTrue(layout.objects.zipWithNext().all { (left, right) ->
            left.sourceOffset < left.sourceEndExclusive &&
                left.sourceEndExclusive <= right.sourceOffset
        })
        assertEquals(layout.startXref, layout.objects.last().sourceEndExclusive)
        assertEquals(listOf(1, 2, 4, 5), layout.objects.map { it.objectNumber })
    }

    @Test
    fun rejectsIncrementalPrevChainsBeforeWritingOutput() {
        val file = classicEncryptedFixtureWithPrevTrailer()

        val error = assertFailsWith<PdfStreamingRewriteException> {
            PdfClassicFileLayoutReader.read(file)
        }

        assertEquals("incremental-xref-unsupported", error.code)
    }

    @Test
    fun rejectsXrefStreamsBeforeObjectParsing() {
        val file = xrefStreamStub()

        val error = assertFailsWith<PdfStreamingRewriteException> {
            PdfClassicFileLayoutReader.read(file)
        }

        assertEquals("xref-stream-unsupported", error.code)
    }

    private fun classicEncryptedFixtureWithPrevTrailer(): File {
        val fixture = StreamingEncryptedPdfFixture.writeAesV2(1024)
        val original = fixture.encryptedFile.readBytes()
        val originalText = original.toString(Charsets.ISO_8859_1)
        val previousXref = Regex("startxref\\s+(\\d+)")
            .findAll(originalText)
            .last()
            .groupValues[1]
            .toLong()
        val file = File.createTempFile("fileloom-incremental-xref", ".pdf").apply {
            deleteOnExit()
        }
        FileOutputStream(file).use { output ->
            output.write(original)
            val currentXref = original.size.toLong()
            output.write(
                (
                    "xref\n0 1\n0000000000 65535 f \n" +
                        "trailer\n<< /Size 6 /Root 1 0 R /Prev $previousXref >>\n" +
                        "startxref\n$currentXref\n%%EOF\n"
                    ).toByteArray(Charsets.ISO_8859_1)
            )
        }
        return file
    }

    private fun xrefStreamStub(): File {
        val file = File.createTempFile("fileloom-xref-stream", ".pdf").apply {
            deleteOnExit()
        }
        val prefix = "%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        val xrefOffset = prefix.toByteArray(Charsets.ISO_8859_1).size
        file.writeText(
            prefix +
                "2 0 obj\n<< /Type /XRef /Size 3 /W [1 1 1] /Length 0 >>\n" +
                "stream\n\nendstream\nendobj\n" +
                "startxref\n$xrefOffset\n%%EOF\n",
            Charsets.ISO_8859_1,
        )
        return file
    }
}
