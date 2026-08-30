package dev.jaeyoung.fileloom.pdf.security

import dev.jaeyoung.fileloom.pdf.document.PdfDocumentReader
import dev.jaeyoung.fileloom.pdf.document.PdfXrefEntry
import dev.jaeyoung.fileloom.pdf.source.PdfByteSource
import dev.jaeyoung.fileloom.pdf.syntax.PdfObject
import java.io.File
import java.io.FileInputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel

internal data class PdfClassicObjectLocation(
    val objectNumber: Int,
    val generation: Int,
    val sourceOffset: Long,
    val sourceEndExclusive: Long,
)

internal data class PdfClassicFileLayout(
    val version: String,
    val startXref: Long,
    val trailer: PdfObject.Dictionary,
    val objects: List<PdfClassicObjectLocation>,
)

internal class PdfStreamingRewriteException(
    val code: String,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    val kind: PdfStreamingRewriteFailureKind = if (code in UNSUPPORTED_CODES) {
        PdfStreamingRewriteFailureKind.Unsupported
    } else {
        PdfStreamingRewriteFailureKind.Malformed
    }

    private companion object {
        val UNSUPPORTED_CODES = setOf(
            "incremental-xref-unsupported",
            "xref-stream-unsupported",
            "object-cipher-unsupported",
            "non-stream-object-too-large",
            "stream-tail-too-large",
            "indirect-stream-length-unsupported",
            "classic-xref-offset-unsupported",
        )
    }
}

internal enum class PdfStreamingRewriteFailureKind {
    Unsupported,
    Malformed,
}

internal object PdfClassicFileLayoutReader {
    fun appendCanonicalStartXrefTail(input: File) {
        val offset = findStartXref(input)
        RandomAccessFile(input, "rw").use { file ->
            file.seek(file.length())
            file.write("\nstartxref\n$offset\n%%EOF\n".toByteArray(Charsets.ISO_8859_1))
        }
    }

    fun read(input: File): PdfClassicFileLayout {
        val fileLength = input.length()
        val startXref = findStartXref(input)
        if (startXref !in 0 until fileLength) {
            throw PdfStreamingRewriteException(
                code = "startxref-out-of-range",
                message = "startxref is outside the input file",
            )
        }
        val xrefKind = RandomAccessFile(input, "r").use { file ->
            file.seek(startXref)
            file.read()
        }
        if (xrefKind != 'x'.code) {
            throw PdfStreamingRewriteException(
                code = "xref-stream-unsupported",
                message = "Only classic xref tables are supported",
            )
        }

        return try {
            FileInputStream(input).channel.use { channel ->
                val document = PdfDocumentReader.open(LayoutFileChannelPdfByteSource(channel))
                document.use {
                    if (it.trailer.entries.containsKey("Prev")) {
                        throw PdfStreamingRewriteException(
                            code = "incremental-xref-unsupported",
                            message = "Incremental xref chains are not supported",
                        )
                    }
                    if (it.trailer.entries.containsKey("XRefStm")) {
                        throw PdfStreamingRewriteException(
                            code = "xref-stream-unsupported",
                            message = "Hybrid xref streams are not supported",
                        )
                    }
                    val sortedEntries = it.xrefEntries.entries
                        .mapNotNull { (id, entry) ->
                            (entry as? PdfXrefEntry.InUse)?.let {
                                Triple(id.objectNumber, id.generationNumber, it.offset)
                            }
                        }
                        .sortedBy { (_, _, offset) -> offset }
                    if (sortedEntries.isEmpty()) {
                        throw PdfStreamingRewriteException(
                            code = "xref-has-no-objects",
                            message = "Classic xref has no in-use objects",
                        )
                    }
                    sortedEntries.forEach { (objectNumber, generation, _) ->
                        if (objectNumber <= 0) {
                            throw PdfStreamingRewriteException(
                                code = "invalid-object-number",
                                message = "Classic xref in-use object numbers must be positive",
                            )
                        }
                        if (generation !in 0..65_535) {
                            throw PdfStreamingRewriteException(
                                code = "invalid-object-generation",
                                message = "Classic xref generations must fit the five-digit field",
                            )
                        }
                    }
                    if (sortedEntries.groupingBy { it.first }.eachCount().any { it.value > 1 }) {
                        throw PdfStreamingRewriteException(
                            code = "duplicate-object-number",
                            message = "Classic xref contains multiple in-use generations for one object",
                        )
                    }
                    sortedEntries.zipWithNext().forEach { (left, right) ->
                        if (left.third == right.third) {
                            throw PdfStreamingRewriteException(
                                code = "duplicate-object-offset",
                                message = "Multiple objects share one xref offset",
                            )
                        }
                    }
                    val locations = sortedEntries.mapIndexed { index, (objectNumber, generation, offset) ->
                        val endExclusive = sortedEntries.getOrNull(index + 1)?.third ?: startXref
                        if (offset < 0L || offset >= endExclusive || endExclusive > startXref) {
                            throw PdfStreamingRewriteException(
                                code = "invalid-object-range",
                                message = "Invalid classic xref object range",
                            )
                        }
                        PdfClassicObjectLocation(
                            objectNumber = objectNumber,
                            generation = generation,
                            sourceOffset = offset,
                            sourceEndExclusive = endExclusive,
                        )
                    }
                    PdfClassicFileLayout(
                        version = it.version,
                        startXref = startXref,
                        trailer = it.trailer,
                        objects = locations,
                    )
                }
            }
        } catch (error: PdfStreamingRewriteException) {
            throw error
        } catch (error: Throwable) {
            throw PdfStreamingRewriteException(
                code = "classic-xref-invalid",
                message = error.message ?: error.javaClass.simpleName,
                cause = error,
            )
        }
    }

    private fun findStartXref(input: File): Long {
        RandomAccessFile(input, "r").use { file ->
            val tailLength = minOf(file.length(), STARTXREF_TAIL_BYTES.toLong()).toInt()
            val tailStart = file.length() - tailLength
            val tail = ByteArray(tailLength)
            file.seek(tailStart)
            file.readFully(tail)
            val text = tail.toString(Charsets.ISO_8859_1)
            val lines = text.lineSequence().toList()
            for (lineIndex in lines.indices.reversed()) {
                if (lines[lineIndex].trim() != STARTXREF_MARKER) continue
                val offset = lines
                    .drop(lineIndex + 1)
                    .firstOrNull { it.isNotBlank() }
                    ?.trim()
                    ?.takeIf { value -> value.isNotEmpty() && value.all(Char::isDigit) }
                    ?.toLongOrNull()
                if (offset != null) return offset
            }
            throw PdfStreamingRewriteException(
                code = "startxref-missing",
                message = "Missing valid startxref marker",
            )
        }
    }

    private const val STARTXREF_TAIL_BYTES = 4 * 1024
    private const val STARTXREF_MARKER = "startxref"
}

private class LayoutFileChannelPdfByteSource(
    private val channel: FileChannel,
) : PdfByteSource {
    override val length: Long = channel.size()

    override fun read(position: Long, sink: ByteArray, offset: Int, byteCount: Int): Int {
        require(position >= 0L)
        require(offset >= 0)
        require(byteCount >= 0)
        require(offset <= sink.size)
        require(byteCount <= sink.size - offset)
        if (byteCount == 0) return 0
        if (position >= length) return -1
        return channel.read(ByteBuffer.wrap(sink, offset, byteCount), position)
    }

    override fun close() {
        channel.close()
    }
}
