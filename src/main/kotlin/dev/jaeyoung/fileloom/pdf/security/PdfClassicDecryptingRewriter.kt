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
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal class PdfClassicDecryptingRewriter(
    private val input: File,
    private val output: File,
    private val layout: PdfClassicFileLayout,
    private val fileKey: ByteArray,
    private val cipherMethod: PdfObjectCipherMethod,
    private val encryptObjectNumber: Int?,
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
                        updateDirectStreamLength(stream.headerText, plainLength),
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
        val payloadOffset = skipStreamLineEnding(objectBytes, streamKeyword + STREAM_KEYWORD.size)
        return StreamEnvelope(
            headerText = objectBytes.copyOfRange(0, payloadOffset).toString(Charsets.ISO_8859_1),
            payloadOffset = payloadOffset,
            encryptedLength = length,
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

    private fun updateDirectStreamLength(header: String, plainLength: Long): String {
        val match = DIRECT_LENGTH_REGEX.findAll(header).lastOrNull()
            ?: throw PdfStreamingRewriteException(
                code = "direct-stream-length-missing",
                message = "Stream dictionary has no direct length token",
            )
        val prefix = match.groups[1]?.value ?: "/Length "
        return header.replaceRange(match.range, "$prefix$plainLength")
    }

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
    )

    private companion object {
        const val MAX_NON_STREAM_OBJECT_BYTES = 8L * 1024L * 1024L
        val STREAM_KEYWORD = "stream".toByteArray(Charsets.US_ASCII)
        val DIRECT_LENGTH_REGEX = Regex("(/Length\\s+)\\d+")
        val REMOVED_TRAILER_KEYS = setOf("Size", "Encrypt", "Prev", "XRefStm")
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
    val literalDecrypted = decryptLiteralStrings(text, objectKey, cipherMethod)
    return HEX_STRING_REGEX.replace(literalDecrypted) { match ->
        val cipherText = match.groupValues[1].filterNot(Char::isWhitespace).hexToBytes()
        if (!canDecryptObjectString(cipherText, cipherMethod)) return@replace match.value
        decryptObjectBytes(objectKey, cipherText, cipherMethod).toPdfLiteralString()
    }
}

private fun decryptLiteralStrings(
    text: String,
    objectKey: ByteArray,
    cipherMethod: PdfObjectCipherMethod,
): String {
    val output = StringBuilder(text.length)
    var index = 0
    while (index < text.length) {
        if (text[index] != '(') {
            output.append(text[index++])
            continue
        }
        val parsed = parsePdfLiteralString(text, index)
        if (parsed == null || !canDecryptObjectString(parsed.bytes, cipherMethod)) {
            if (parsed == null) {
                output.append(text[index++])
            } else {
                output.append(text, index, parsed.endExclusive)
                index = parsed.endExclusive
            }
            continue
        }
        output.append(decryptObjectBytes(objectKey, parsed.bytes, cipherMethod).toPdfLiteralString())
        index = parsed.endExclusive
    }
    return output.toString()
}

private fun parsePdfLiteralString(text: String, start: Int): ParsedLiteralString? {
    if (start >= text.length || text[start] != '(') return null
    val bytes = mutableListOf<Int>()
    var index = start + 1
    var depth = 1
    while (index < text.length) {
        when (val char = text[index]) {
            '(' -> {
                depth += 1
                bytes += char.code and 0xFF
                index += 1
            }
            ')' -> {
                depth -= 1
                if (depth == 0) {
                    return ParsedLiteralString(
                        bytes = ByteArray(bytes.size) { bytes[it].toByte() },
                        endExclusive = index + 1,
                    )
                }
                bytes += char.code and 0xFF
                index += 1
            }
            '\\' -> {
                if (index + 1 >= text.length) return null
                val next = text[index + 1]
                when (next) {
                    'n' -> { bytes += '\n'.code; index += 2 }
                    'r' -> { bytes += '\r'.code; index += 2 }
                    't' -> { bytes += '\t'.code; index += 2 }
                    'b' -> { bytes += 0x08; index += 2 }
                    'f' -> { bytes += 0x0C; index += 2 }
                    '(', ')', '\\' -> { bytes += next.code and 0xFF; index += 2 }
                    '\r' -> index += if (index + 2 < text.length && text[index + 2] == '\n') 3 else 2
                    '\n' -> index += 2
                    in '0'..'7' -> {
                        var end = index + 1
                        while (end < text.length && end < index + 4 && text[end] in '0'..'7') end += 1
                        bytes += text.substring(index + 1, end).toInt(8) and 0xFF
                        index = end
                    }
                    else -> { bytes += next.code and 0xFF; index += 2 }
                }
            }
            else -> {
                bytes += char.code and 0xFF
                index += 1
            }
        }
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
        cipher.doFinal(cipherText, 16, cipherText.size - 16)
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

private fun String.hexToBytes(): ByteArray {
    val normalized = if (length % 2 == 0) this else this + "0"
    return ByteArray(normalized.length / 2) { index ->
        normalized.substring(index * 2, index * 2 + 2).toInt(16).toByte()
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

private val HEX_STRING_REGEX = Regex("<([0-9A-Fa-f\\s]+)>")

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
