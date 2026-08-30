package dev.jaeyoung.fileloom.pdf.security

import dev.jaeyoung.fileloom.pdf.source.ByteArrayPdfByteSource
import dev.jaeyoung.fileloom.pdf.syntax.PdfLexer
import dev.jaeyoung.fileloom.pdf.syntax.PdfObject
import dev.jaeyoung.fileloom.pdf.syntax.PdfObjectParser
import dev.jaeyoung.fileloom.pdf.syntax.PdfToken
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.math.BigDecimal
import java.security.MessageDigest
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class PdfClassicDecryptingRewriter(
    private val input: File,
    private val output: File,
    private val layout: PdfClassicFileLayout,
    private val fileKey: ByteArray,
    private val cipherMethod: PdfObjectCipherMethod,
    private val encryptObjectNumber: Int?,
    private val encryptMetadata: Boolean = true,
) {
    fun rewrite(): Int {
        val retainedObjects = layout.objects.filterNot { it.objectNumber == encryptObjectNumber }
        if (retainedObjects.isEmpty()) {
            throw PdfStreamingRewriteException(
                code = "no-decryptable-objects",
                message = "PDF contains no decryptable indirect objects",
            )
        }
        output.parentFile?.mkdirs()

        RandomAccessFile(input, "r").use { source ->
            CountingOutputStream(BufferedOutputStream(FileOutputStream(output))).use { target ->
                target.writeLatin1("%PDF-${layout.version}\n")
                val objectOffsets = linkedMapOf<Int, RewrittenXrefEntry>()
                retainedObjects.forEach { location ->
                    objectOffsets[location.objectNumber] = RewrittenXrefEntry(
                        offset = target.byteCount,
                        generation = location.generation,
                    )
                    writeObject(source, target, location)
                }
                val startXref = target.byteCount
                writeSparseXref(target, objectOffsets)
                val xrefSize = (objectOffsets.keys.maxOrNull()?.toLong() ?: 0L) + 1L
                target.writeLatin1("trailer\n")
                target.writeLatin1(serializeTrailer(xrefSize))
                target.writeLatin1("\nstartxref\n$startXref\n%%EOF\n")
            }
        }
        return retainedObjects.size
    }

    private fun writeSparseXref(
        target: CountingOutputStream,
        entries: Map<Int, RewrittenXrefEntry>,
    ) {
        target.writeLatin1("xref\n0 1\n0000000000 65535 f \n")
        val sorted = entries.entries.sortedBy(Map.Entry<Int, RewrittenXrefEntry>::key)
        var index = 0
        while (index < sorted.size) {
            val section = mutableListOf(sorted[index])
            index += 1
            while (
                index < sorted.size &&
                sorted[index].key == section.last().key + 1
            ) {
                section += sorted[index]
                index += 1
            }
            target.writeLatin1("${section.first().key} ${section.size}\n")
            section.forEach { (_, entry) ->
                target.writeLatin1(
                    formatClassicXrefOffset(entry.offset) + " " +
                        entry.generation.toString().padStart(5, '0') + " n \n"
                )
            }
        }
    }

    private fun writeObject(
        source: RandomAccessFile,
        target: CountingOutputStream,
        location: PdfClassicObjectLocation,
    ) {
        val rangeLength = location.sourceEndExclusive - location.sourceOffset
        if (rangeLength <= 0L) {
            throw PdfStreamingRewriteException("invalid-object-range", "Object range is empty")
        }
        if (rangeLength <= MAX_NON_STREAM_OBJECT_BYTES) {
            val objectBytes = readRange(source, location.sourceOffset, rangeLength.toInt())
            val stream = parseStreamEnvelope(objectBytes, location)
            if (stream == null) {
                val objectEnd = locateNonStreamObjectEnd(objectBytes)
                    ?: throw PdfStreamingRewriteException(
                        code = "object-syntax-truncated",
                        message = "Object has no lexical endobj terminator",
                    )
                val objectText = objectBytes.copyOfRange(0, objectEnd).toString(Charsets.ISO_8859_1)
                target.writeLatin1(
                    decryptObjectSyntax(
                        text = objectText,
                        objectKey = pdfObjectKey(
                            fileKey,
                            location.objectNumber,
                            location.generation,
                            cipherMethod,
                        ),
                        cipherMethod = cipherMethod,
                    )
                )
                return
            }
            writeStreamObject(source, target, location, objectBytes, stream)
            return
        }

        val prefixLength = minOf(rangeLength, MAX_NON_STREAM_OBJECT_BYTES).toInt()
        val prefix = readRange(source, location.sourceOffset, prefixLength)
        val stream = parseStreamEnvelope(prefix, location)
        if (stream == null) {
            val objectEnd = locateNonStreamObjectEnd(prefix)
                ?: throw PdfStreamingRewriteException(
                code = "non-stream-object-too-large",
                    message = "Non-stream object syntax exceeds the bounded probe",
                )
            val objectText = prefix.copyOfRange(0, objectEnd).toString(Charsets.ISO_8859_1)
            target.writeLatin1(
                decryptObjectSyntax(
                    text = objectText,
                    objectKey = pdfObjectKey(
                        fileKey,
                        location.objectNumber,
                        location.generation,
                        cipherMethod,
                    ),
                    cipherMethod = cipherMethod,
                )
            )
            return
        }
        writeStreamObject(source, target, location, prefix, stream)
    }

    private fun writeStreamObject(
        source: RandomAccessFile,
        target: CountingOutputStream,
        location: PdfClassicObjectLocation,
        prefix: ByteArray,
        stream: StreamEnvelope,
    ) {
        val relativePayloadOffset = stream.payloadOffset.toLong()
        if (location.sourceOffset > Long.MAX_VALUE - relativePayloadOffset) {
            throw PdfStreamingRewriteException(
                code = "stream-payload-out-of-range",
                message = "Stream payload offset exceeds its object range",
            )
        }
        val payloadOffset = location.sourceOffset + relativePayloadOffset
        val availablePayloadBytes = location.sourceEndExclusive - payloadOffset
        if (
            payloadOffset < location.sourceOffset ||
            availablePayloadBytes < 0L ||
            stream.encryptedLength > availablePayloadBytes
        ) {
            throw PdfStreamingRewriteException(
                code = "stream-payload-out-of-range",
                message = "Direct stream length exceeds its object range",
            )
        }
        val payloadEnd = payloadOffset + stream.encryptedLength
        val tail = readValidatedStreamTail(
            source = source,
            payloadEnd = payloadEnd,
            objectEndExclusive = location.sourceEndExclusive,
        )
        val objectKey = pdfObjectKey(
            fileKey,
            location.objectNumber,
            location.generation,
            cipherMethod,
        )
        val transformedTail = decryptObjectSyntax(
            text = tail.toString(Charsets.ISO_8859_1),
            objectKey = objectKey,
            cipherMethod = cipherMethod,
        )

        if (!encryptMetadata && stream.isMetadata) {
            val header = decryptObjectSyntax(
                stream.headerText,
                objectKey,
                cipherMethod,
            )
            target.writeLatin1(header)
            source.seek(payloadOffset)
            val copied = RandomAccessSliceInputStream(source, stream.encryptedLength)
                .copyTo(target, STREAM_BUFFER_BYTES)
            if (copied != stream.encryptedLength) {
                throw PdfStreamingRewriteException(
                    code = "stream-payload-truncated",
                    message = "Unexpected EOF in plaintext metadata stream",
                )
            }
            target.writeLatin1(transformedTail)
            return
        }

        when (cipherMethod) {
            PdfObjectCipherMethod.Rc4 -> {
                val header = decryptObjectSyntax(
                    stream.headerText,
                    objectKey,
                    cipherMethod,
                )
                target.writeLatin1(header)
                source.seek(payloadOffset)
                streamingCipher(cipherMethod, objectKey).decrypt(
                    input = RandomAccessSliceInputStream(source, stream.encryptedLength),
                    encryptedLength = stream.encryptedLength,
                    output = target,
                )
                target.writeLatin1(transformedTail)
            }
            PdfObjectCipherMethod.AesV2 -> {
                val spool = File.createTempFile("pdf-object-", ".spool", output.parentFile)
                try {
                    val plainLength = FileOutputStream(spool).buffered().use { spoolOutput ->
                        source.seek(payloadOffset)
                        streamingCipher(cipherMethod, objectKey).decrypt(
                            input = RandomAccessSliceInputStream(source, stream.encryptedLength),
                            encryptedLength = stream.encryptedLength,
                            output = spoolOutput,
                        )
                    }
                    val header = decryptObjectSyntax(
                        updateDirectStreamLength(
                            header = stream.headerText,
                            lengthTokenStart = stream.lengthTokenStart,
                            lengthTokenEndExclusive = stream.lengthTokenEndExclusive,
                            plainLength = plainLength,
                        ),
                        objectKey,
                        cipherMethod,
                    )
                    target.writeLatin1(header)
                    spool.inputStream().buffered().use { spoolInput ->
                        spoolInput.copyTo(target, STREAM_BUFFER_BYTES)
                    }
                    target.writeLatin1(transformedTail)
                } finally {
                    spool.delete()
                }
            }
            PdfObjectCipherMethod.Unsupported -> throw PdfStreamingRewriteException(
                code = "object-cipher-unsupported",
                message = "Unsupported PDF object cipher",
            )
        }
    }

    private fun parseStreamEnvelope(
        objectBytes: ByteArray,
        location: PdfClassicObjectLocation,
    ): StreamEnvelope? {
        val source = ByteArrayPdfByteSource(objectBytes)
        val lexer = PdfLexer(source)
        val objectNumber = (lexer.nextToken() as? PdfToken.IntegerNumber)?.value
        val generation = (lexer.nextToken() as? PdfToken.IntegerNumber)?.value
        val objectKeyword = (lexer.nextToken() as? PdfToken.Keyword)?.value
        if (
            objectNumber != location.objectNumber.toLong() ||
            generation != location.generation.toLong() ||
            objectKeyword != "obj"
        ) {
            throw PdfStreamingRewriteException(
                code = "object-header-mismatch",
                message = "Object header does not match its xref entry",
            )
        }
        val dictionaryStart = lexer.nextToken() as? PdfToken.StartDictionary ?: return null
        val dictionary = runCatching {
            PdfObjectParser(
                PdfLexer(ByteArrayPdfByteSource(objectBytes), startPosition = dictionaryStart.offset)
            ).parseObject() as? PdfObject.Dictionary
        }.getOrNull() ?: throw PdfStreamingRewriteException(
            code = "stream-dictionary-invalid",
            message = "Unable to parse stream dictionary",
        )
        val dictionaryEnd = locateDictionaryEnd(objectBytes, dictionaryStart.offset.toInt())
        val streamKeyword = locateStreamKeyword(objectBytes, dictionaryEnd) ?: return null
        val length = (dictionary.entries["Length"] as? PdfObject.IntegerValue)?.value
            ?: throw PdfStreamingRewriteException(
                code = "indirect-stream-length-unsupported",
                message = "Only direct stream lengths are supported",
            )
        if (length < 0L) {
            throw PdfStreamingRewriteException(
                code = "stream-length-invalid",
                message = "Stream length must be non-negative",
            )
        }
        val lengthToken = locateTopLevelLengthToken(objectBytes, dictionaryStart.offset.toInt())
        val payloadOffset = skipStreamLineEnding(objectBytes, streamKeyword + STREAM_KEYWORD.size)
        return StreamEnvelope(
            headerText = objectBytes.copyOfRange(0, payloadOffset).toString(Charsets.ISO_8859_1),
            payloadOffset = payloadOffset,
            encryptedLength = length,
            lengthTokenStart = lengthToken.offset.toInt(),
            lengthTokenEndExclusive = lengthToken.offset.toInt() + lengthToken.raw.length,
            isMetadata = (dictionary.entries["Type"] as? PdfObject.Name)?.value == "Metadata",
        )
    }

    private fun locateDictionaryEnd(bytes: ByteArray, start: Int): Int {
        val lexer = PdfLexer(ByteArrayPdfByteSource(bytes), startPosition = start.toLong())
        var depth = 0
        while (true) {
            val token = lexer.nextToken() ?: throw PdfStreamingRewriteException(
                code = "stream-dictionary-truncated",
                message = "Unexpected EOF in stream dictionary",
            )
            when (token) {
                is PdfToken.StartDictionary -> depth += 1
                is PdfToken.EndDictionary -> {
                    depth -= 1
                    if (depth == 0) return token.offset.toInt() + 2
                }
                else -> Unit
            }
        }
    }

    private fun locateStreamKeyword(bytes: ByteArray, start: Int): Int? {
        val token = PdfLexer(
            ByteArrayPdfByteSource(bytes),
            startPosition = start.toLong(),
        ).nextToken() as? PdfToken.Keyword ?: return null
        return token.offset.toInt().takeIf { token.value == "stream" }
    }

    private fun locateTopLevelLengthToken(
        bytes: ByteArray,
        dictionaryStart: Int,
    ): PdfToken.IntegerNumber {
        val cursor = RewriteTokenCursor(
            PdfLexer(ByteArrayPdfByteSource(bytes), startPosition = dictionaryStart.toLong())
        )
        if (cursor.next() !is PdfToken.StartDictionary) {
            throw PdfStreamingRewriteException(
                code = "stream-dictionary-invalid",
                message = "Stream dictionary has no opening token",
            )
        }
        var lengthToken: PdfToken.IntegerNumber? = null
        while (true) {
            when (val key = cursor.next()) {
                is PdfToken.EndDictionary -> return lengthToken
                    ?: throw PdfStreamingRewriteException(
                        code = "direct-stream-length-missing",
                        message = "Stream dictionary has no direct length token",
                    )
                is PdfToken.Name -> {
                    val value = cursor.next() ?: throw PdfStreamingRewriteException(
                        code = "stream-dictionary-truncated",
                        message = "Stream dictionary ends before ${key.value}",
                    )
                    if (key.value == "Length") {
                        lengthToken = value as? PdfToken.IntegerNumber
                            ?: throw PdfStreamingRewriteException(
                                code = "indirect-stream-length-unsupported",
                                message = "Only direct stream lengths are supported",
                            )
                    }
                    skipObjectValue(value, cursor)
                }
                else -> throw PdfStreamingRewriteException(
                    code = "stream-dictionary-invalid",
                    message = "Stream dictionary contains an invalid key",
                )
            }
        }
    }

    private fun skipObjectValue(first: PdfToken, cursor: RewriteTokenCursor) {
        when (first) {
            is PdfToken.StartArray -> {
                while (true) {
                    val token = cursor.next() ?: throw PdfStreamingRewriteException(
                        code = "stream-dictionary-truncated",
                        message = "Unexpected EOF in array value",
                    )
                    if (token is PdfToken.EndArray) return
                    skipObjectValue(token, cursor)
                }
            }
            is PdfToken.StartDictionary -> {
                while (true) {
                    when (val key = cursor.next()) {
                        is PdfToken.EndDictionary -> return
                        is PdfToken.Name -> {
                            val value = cursor.next() ?: throw PdfStreamingRewriteException(
                                code = "stream-dictionary-truncated",
                                message = "Unexpected EOF in dictionary value",
                            )
                            skipObjectValue(value, cursor)
                        }
                        else -> throw PdfStreamingRewriteException(
                            code = "stream-dictionary-invalid",
                            message = "Nested dictionary contains an invalid key",
                        )
                    }
                }
            }
            is PdfToken.IntegerNumber -> {
                val second = cursor.next()
                if (second is PdfToken.IntegerNumber) {
                    val third = cursor.next()
                    if (third is PdfToken.Keyword && third.value == "R") return
                    cursor.pushBack(third)
                    cursor.pushBack(second)
                } else {
                    cursor.pushBack(second)
                }
            }
            is PdfToken.EndArray,
            is PdfToken.EndDictionary,
            -> throw PdfStreamingRewriteException(
                code = "stream-dictionary-invalid",
                message = "Unexpected closing token in dictionary value",
            )
            else -> Unit
        }
    }

    private fun locateNonStreamObjectEnd(bytes: ByteArray): Int? {
        val lexer = PdfLexer(ByteArrayPdfByteSource(bytes))
        while (true) {
            val token = lexer.nextToken() ?: return null
            if (token is PdfToken.Keyword && token.value == "endobj") {
                return includeOneLineEnding(bytes, token.offset.toInt() + "endobj".length)
            }
        }
    }

    private fun readValidatedStreamTail(
        source: RandomAccessFile,
        payloadEnd: Long,
        objectEndExclusive: Long,
    ): ByteArray {
        val available = objectEndExclusive - payloadEnd
        if (available <= 0L) {
            throw PdfStreamingRewriteException(
                code = "stream-terminator-invalid",
                message = "Stream payload has no terminator",
            )
        }
        val probeLength = minOf(available, MAX_NON_STREAM_OBJECT_BYTES).toInt()
        val probe = readRange(source, payloadEnd, probeLength)
        val lexer = PdfLexer(ByteArrayPdfByteSource(probe))
        val endStream = lexer.nextToken() as? PdfToken.Keyword
        val endObject = lexer.nextToken() as? PdfToken.Keyword
        if (endStream?.value != "endstream" || endObject?.value != "endobj") {
            throw PdfStreamingRewriteException(
                code = "stream-terminator-invalid",
                message = "Declared stream boundary is not followed by endstream and endobj",
            )
        }
        val tailEnd = includeOneLineEnding(probe, endObject.offset.toInt() + "endobj".length)
        return probe.copyOfRange(0, tailEnd)
    }

    private fun includeOneLineEnding(bytes: ByteArray, start: Int): Int {
        if (start >= bytes.size) return start
        return when (bytes[start]) {
            '\r'.code.toByte() -> if (start + 1 < bytes.size && bytes[start + 1] == '\n'.code.toByte()) {
                start + 2
            } else {
                start + 1
            }
            '\n'.code.toByte(), ' '.code.toByte(), '\t'.code.toByte() -> start + 1
            else -> start
        }
    }

    private fun skipStreamLineEnding(bytes: ByteArray, start: Int): Int {
        var cursor = start
        if (cursor < bytes.size && bytes[cursor] == '\r'.code.toByte()) cursor += 1
        if (cursor < bytes.size && bytes[cursor] == '\n'.code.toByte()) cursor += 1
        if (cursor == start) {
            throw PdfStreamingRewriteException(
                code = "stream-line-ending-invalid",
                message = "stream keyword must be followed by a line ending",
            )
        }
        return cursor
    }

    private fun readRange(source: RandomAccessFile, start: Long, byteCount: Int): ByteArray {
        val result = ByteArray(byteCount)
        source.seek(start)
        source.readFully(result)
        return result
    }

    private fun updateDirectStreamLength(
        header: String,
        lengthTokenStart: Int,
        lengthTokenEndExclusive: Int,
        plainLength: Long,
    ): String = header.replaceRange(lengthTokenStart, lengthTokenEndExclusive, plainLength.toString())

    private fun serializeTrailer(xrefSize: Long): String {
        val entries = layout.trailer.entries
            .filterKeys { key -> key !in REMOVED_TRAILER_KEYS }
            .toMutableMap()
        entries["Size"] = PdfObject.IntegerValue(xrefSize)
        return serializePdfObject(PdfObject.Dictionary(entries))
    }

    private data class RewrittenXrefEntry(
        val offset: Long,
        val generation: Int,
    )

    private data class StreamEnvelope(
        val headerText: String,
        val payloadOffset: Int,
        val encryptedLength: Long,
        val lengthTokenStart: Int,
        val lengthTokenEndExclusive: Int,
        val isMetadata: Boolean,
    )

    private companion object {
        const val MAX_NON_STREAM_OBJECT_BYTES = 8L * 1024L * 1024L
        val STREAM_KEYWORD = "stream".toByteArray(Charsets.US_ASCII)
        val REMOVED_TRAILER_KEYS = setOf("Size", "Encrypt", "Prev", "XRefStm")
    }
}

private class RewriteTokenCursor(
    private val lexer: PdfLexer,
) {
    private val pushedBack = ArrayDeque<PdfToken>()

    fun next(): PdfToken? = if (pushedBack.isEmpty()) lexer.nextToken() else pushedBack.removeLast()

    fun pushBack(token: PdfToken?) {
        if (token != null) pushedBack.addLast(token)
    }
}

internal fun formatClassicXrefOffset(offset: Long): String {
    if (offset !in 0L..9_999_999_999L) {
        throw PdfStreamingRewriteException(
            code = "classic-xref-offset-unsupported",
            message = "Classic xref offsets are limited to ten decimal digits",
        )
    }
    return offset.toString().padStart(10, '0')
}

private fun pdfObjectKey(
    fileKey: ByteArray,
    objectNumber: Int,
    generation: Int,
    cipherMethod: PdfObjectCipherMethod,
): ByteArray {
    val digest = MessageDigest.getInstance("MD5")
    digest.update(fileKey)
    digest.update(
        byteArrayOf(
            objectNumber.toByte(),
            (objectNumber ushr 8).toByte(),
            (objectNumber ushr 16).toByte(),
            generation.toByte(),
            (generation ushr 8).toByte(),
        )
    )
    if (cipherMethod == PdfObjectCipherMethod.AesV2) {
        digest.update(byteArrayOf('s'.code.toByte(), 'A'.code.toByte(), 'l'.code.toByte(), 'T'.code.toByte()))
    }
    return digest.digest().copyOf((fileKey.size + 5).coerceAtMost(16))
}

private fun decryptObjectSyntax(
    text: String,
    objectKey: ByteArray,
    cipherMethod: PdfObjectCipherMethod,
): String {
    val output = StringBuilder(text.length)
    var index = 0
    while (index < text.length) {
        when {
            text[index] == '%' -> {
                val endExclusive = text.indexOfAny(charArrayOf('\r', '\n'), startIndex = index)
                    .takeIf { it >= 0 }
                    ?: text.length
                output.append(text, index, endExclusive)
                index = endExclusive
            }
            text[index] == '(' -> {
                val parsed = parsePdfLiteralString(text, index)
                if (parsed == null || !canDecryptObjectString(parsed.bytes, cipherMethod)) {
                    if (parsed == null) {
                        output.append(text[index++])
                    } else {
                        output.append(text, index, parsed.endExclusive)
                        index = parsed.endExclusive
                    }
                } else {
                    output.append(decryptObjectBytes(objectKey, parsed.bytes, cipherMethod).toPdfLiteralString())
                    index = parsed.endExclusive
                }
            }
            text[index] == '<' && index + 1 < text.length && text[index + 1] == '<' -> {
                output.append("<<")
                index += 2
            }
            text[index] == '<' -> {
                val parsed = parsePdfHexString(text, index)
                if (parsed == null || !canDecryptObjectString(parsed.bytes, cipherMethod)) {
                    if (parsed == null) {
                        output.append(text[index++])
                    } else {
                        output.append(text, index, parsed.endExclusive)
                        index = parsed.endExclusive
                    }
                } else {
                    output.append(decryptObjectBytes(objectKey, parsed.bytes, cipherMethod).toPdfLiteralString())
                    index = parsed.endExclusive
                }
            }
            else -> output.append(text[index++])
        }
    }
    return output.toString()
}

private fun parsePdfLiteralString(text: String, start: Int): ParsedLiteralString? {
    if (start >= text.length || text[start] != '(') return null
    val bytes = ByteArray(text.length - start)
    var byteCount = 0
    var index = start + 1
    var depth = 1
    while (index < text.length) {
        when (val char = text[index]) {
            '(' -> {
                depth += 1
                bytes[byteCount++] = (char.code and 0xFF).toByte()
                index += 1
            }
            ')' -> {
                depth -= 1
                if (depth == 0) {
                    return ParsedLiteralString(
                        bytes = bytes.copyOf(byteCount),
                        endExclusive = index + 1,
                    )
                }
                bytes[byteCount++] = (char.code and 0xFF).toByte()
                index += 1
            }
            '\\' -> {
                if (index + 1 >= text.length) return null
                val next = text[index + 1]
                when (next) {
                    'n' -> { bytes[byteCount++] = '\n'.code.toByte(); index += 2 }
                    'r' -> { bytes[byteCount++] = '\r'.code.toByte(); index += 2 }
                    't' -> { bytes[byteCount++] = '\t'.code.toByte(); index += 2 }
                    'b' -> { bytes[byteCount++] = 0x08; index += 2 }
                    'f' -> { bytes[byteCount++] = 0x0C; index += 2 }
                    '(', ')', '\\' -> { bytes[byteCount++] = (next.code and 0xFF).toByte(); index += 2 }
                    '\r' -> index += if (index + 2 < text.length && text[index + 2] == '\n') 3 else 2
                    '\n' -> index += 2
                    in '0'..'7' -> {
                        var end = index + 1
                        while (end < text.length && end < index + 4 && text[end] in '0'..'7') end += 1
                        bytes[byteCount++] = (text.substring(index + 1, end).toInt(8) and 0xFF).toByte()
                        index = end
                    }
                    else -> { bytes[byteCount++] = (next.code and 0xFF).toByte(); index += 2 }
                }
            }
            else -> {
                bytes[byteCount++] = (char.code and 0xFF).toByte()
                index += 1
            }
        }
    }
    return null
}

private fun parsePdfHexString(text: String, start: Int): ParsedHexString? {
    if (start >= text.length || text[start] != '<') return null
    val bytes = ByteArray((text.length - start + 1) / 2)
    var byteCount = 0
    var highNibble = -1
    var index = start + 1
    while (index < text.length) {
        val char = text[index]
        if (char == '>') {
            if (highNibble >= 0) {
                bytes[byteCount++] = (highNibble shl 4).toByte()
            }
            return ParsedHexString(
                bytes = bytes.copyOf(byteCount),
                endExclusive = index + 1,
            )
        }
        if (!char.isWhitespace()) {
            val value = char.digitToIntOrNull(16) ?: return null
            if (highNibble < 0) {
                highNibble = value
            } else {
                bytes[byteCount++] = ((highNibble shl 4) or value).toByte()
                highNibble = -1
            }
        }
        index += 1
    }
    return null
}

private fun canDecryptObjectString(
    bytes: ByteArray,
    cipherMethod: PdfObjectCipherMethod,
): Boolean = when (cipherMethod) {
    PdfObjectCipherMethod.Rc4 -> true
    PdfObjectCipherMethod.AesV2 -> bytes.size > 16 && (bytes.size - 16) % 16 == 0
    PdfObjectCipherMethod.Unsupported -> false
}

private fun decryptObjectBytes(
    objectKey: ByteArray,
    cipherText: ByteArray,
    cipherMethod: PdfObjectCipherMethod,
): ByteArray = when (cipherMethod) {
    PdfObjectCipherMethod.Rc4 -> rc4(objectKey, cipherText)
    PdfObjectCipherMethod.AesV2 -> {
        require(cipherText.size >= 16)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(objectKey, "AES"),
            IvParameterSpec(cipherText.copyOfRange(0, 16)),
        )
        try {
            cipher.doFinal(cipherText, 16, cipherText.size - 16)
        } catch (error: BadPaddingException) {
            throw PdfStreamingRewriteException(
                code = "aesv2-string-invalid",
                message = error.message ?: "Invalid AESV2 string payload",
                cause = error,
            )
        } catch (error: IllegalBlockSizeException) {
            throw PdfStreamingRewriteException(
                code = "aesv2-string-invalid",
                message = error.message ?: "Invalid AESV2 string payload",
                cause = error,
            )
        }
    }
    PdfObjectCipherMethod.Unsupported -> error("Unsupported object cipher")
}

private fun rc4(key: ByteArray, input: ByteArray): ByteArray {
    val state = IntArray(256) { it }
    var j = 0
    for (i in state.indices) {
        j = (j + state[i] + (key[i % key.size].toInt() and 0xFF)) and 0xFF
        val tmp = state[i]
        state[i] = state[j]
        state[j] = tmp
    }
    val output = ByteArray(input.size)
    var i = 0
    j = 0
    input.indices.forEach { index ->
        i = (i + 1) and 0xFF
        j = (j + state[i]) and 0xFF
        val tmp = state[i]
        state[i] = state[j]
        state[j] = tmp
        output[index] = (input[index].toInt() xor state[(state[i] + state[j]) and 0xFF]).toByte()
    }
    return output
}

private fun serializePdfObject(value: PdfObject): String = when (value) {
    PdfObject.Null -> "null"
    is PdfObject.BooleanValue -> value.value.toString()
    is PdfObject.IntegerValue -> value.value.toString()
    is PdfObject.RealValue -> BigDecimal.valueOf(value.value).stripTrailingZeros().toPlainString()
    is PdfObject.Name -> "/${escapePdfName(value.value)}"
    is PdfObject.StringValue -> value.bytes.joinToString(prefix = "<", postfix = ">", separator = "") {
        "%02X".format(it.toInt() and 0xFF)
    }
    is PdfObject.ArrayValue -> value.items.joinToString(prefix = "[", postfix = "]", separator = " ") {
        serializePdfObject(it)
    }
    is PdfObject.Dictionary -> value.entries.entries.joinToString(prefix = "<<", postfix = ">>", separator = " ") {
        "/${escapePdfName(it.key)} ${serializePdfObject(it.value)}"
    }
    is PdfObject.Reference -> "${value.objectNumber} ${value.generationNumber} R"
}

private fun escapePdfName(value: String): String = buildString(value.length) {
    value.forEach { char ->
        if (char.code in 33..126 && char !in "#/%()<>[]{}") {
            append(char)
        } else {
            append('#')
            append(char.code.toString(16).uppercase().padStart(2, '0'))
        }
    }
}

private fun ByteArray.toPdfLiteralString(): String = buildString(size + 2) {
    append('(')
    this@toPdfLiteralString.forEach { byte ->
        when (val value = byte.toInt() and 0xFF) {
            '('.code, ')'.code, '\\'.code -> append('\\').append(value.toChar())
            '\n'.code -> append("\\n")
            '\r'.code -> append("\\r")
            '\t'.code -> append("\\t")
            else -> append(value.toChar())
        }
    }
    append(')')
}

private data class ParsedLiteralString(
    val bytes: ByteArray,
    val endExclusive: Int,
)

private data class ParsedHexString(
    val bytes: ByteArray,
    val endExclusive: Int,
)

private class RandomAccessSliceInputStream(
    private val input: RandomAccessFile,
    private var remaining: Long,
) : InputStream() {
    override fun read(): Int {
        if (remaining <= 0L) return -1
        val value = input.read()
        if (value >= 0) remaining -= 1
        return value
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (remaining <= 0L) return -1
        val read = input.read(buffer, offset, minOf(remaining, length.toLong()).toInt())
        if (read > 0) remaining -= read
        return read
    }
}

private class CountingOutputStream(output: OutputStream) : FilterOutputStream(output) {
    var byteCount: Long = 0L
        private set

    override fun write(value: Int) {
        out.write(value)
        byteCount += 1L
    }

    override fun write(buffer: ByteArray, offset: Int, length: Int) {
        out.write(buffer, offset, length)
        byteCount += length
    }
}

private fun CountingOutputStream.writeLatin1(value: String) {
    write(value.toByteArray(Charsets.ISO_8859_1))
}
