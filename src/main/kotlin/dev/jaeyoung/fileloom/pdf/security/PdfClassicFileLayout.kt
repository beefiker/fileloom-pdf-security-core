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
) : Exception(message, cause)

internal object PdfClassicFileLayoutReader {
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
            val markerIndex = text.lastIndexOf(STARTXREF_MARKER)
            if (markerIndex < 0) {
                throw PdfStreamingRewriteException(
                    code = "startxref-missing",
                    message = "Missing startxref marker",
                )
            }
            var cursor = markerIndex + STARTXREF_MARKER.length
            while (cursor < text.length && text[cursor].isWhitespace()) cursor += 1
            val numberStart = cursor
            while (cursor < text.length && text[cursor].isDigit()) cursor += 1
            return text.substring(numberStart, cursor).toLongOrNull()
                ?: throw PdfStreamingRewriteException(
                    code = "startxref-invalid",
                    message = "Invalid startxref offset",
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
