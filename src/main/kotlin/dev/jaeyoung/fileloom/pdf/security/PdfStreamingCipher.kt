package dev.jaeyoung.fileloom.pdf.security

import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

internal interface PdfStreamingCipher {
    fun decrypt(
        input: InputStream,
        encryptedLength: Long,
        output: OutputStream,
    ): Long
}

internal fun streamingCipher(
    method: PdfObjectCipherMethod,
    objectKey: ByteArray,
): PdfStreamingCipher = when (method) {
    PdfObjectCipherMethod.Rc4 -> StreamingRc4Cipher(objectKey)
    PdfObjectCipherMethod.AesV2 -> StreamingAesV2Cipher(objectKey)
    PdfObjectCipherMethod.Unsupported -> throw PdfStreamingRewriteException(
        code = "object-cipher-unsupported",
        message = "Unsupported PDF object cipher",
    )
}

private class StreamingRc4Cipher(key: ByteArray) : PdfStreamingCipher {
    private val state = IntArray(256) { it }
    private var i = 0
    private var j = 0

    init {
        var shuffleIndex = 0
        for (index in state.indices) {
            shuffleIndex = (
                shuffleIndex + state[index] + (key[index % key.size].toInt() and 0xFF)
                ) and 0xFF
            val tmp = state[index]
            state[index] = state[shuffleIndex]
            state[shuffleIndex] = tmp
        }
    }

    override fun decrypt(
        input: InputStream,
        encryptedLength: Long,
        output: OutputStream,
    ): Long {
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        var remaining = encryptedLength
        var written = 0L
        while (remaining > 0L) {
            val read = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
            if (read <= 0) {
                throw PdfStreamingRewriteException(
                    code = "stream-payload-truncated",
                    message = "Unexpected EOF in encrypted RC4 stream",
                )
            }
            for (index in 0 until read) {
                i = (i + 1) and 0xFF
                j = (j + state[i]) and 0xFF
                val tmp = state[i]
                state[i] = state[j]
                state[j] = tmp
                val keyByte = state[(state[i] + state[j]) and 0xFF]
                buffer[index] = (buffer[index].toInt() xor keyByte).toByte()
            }
            output.write(buffer, 0, read)
            remaining -= read
            written += read
        }
        return written
    }
}

private class StreamingAesV2Cipher(
    private val key: ByteArray,
) : PdfStreamingCipher {
    override fun decrypt(
        input: InputStream,
        encryptedLength: Long,
        output: OutputStream,
    ): Long {
        if (encryptedLength <= AES_IV_BYTES || (encryptedLength - AES_IV_BYTES) % AES_BLOCK_BYTES != 0L) {
            throw PdfStreamingRewriteException(
                code = "aesv2-stream-length-invalid",
                message = "AESV2 stream payload has an invalid length",
            )
        }
        val iv = ByteArray(AES_IV_BYTES)
        readFully(input, iv)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            IvParameterSpec(iv),
        )
        val buffer = ByteArray(STREAM_BUFFER_BYTES)
        var remaining = encryptedLength - AES_IV_BYTES
        var written = 0L
        while (remaining > 0L) {
            val read = input.read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
            if (read <= 0) {
                throw PdfStreamingRewriteException(
                    code = "stream-payload-truncated",
                    message = "Unexpected EOF in encrypted AESV2 stream",
                )
            }
            cipher.update(buffer, 0, read)?.let { plain ->
                output.write(plain)
                written += plain.size
            }
            remaining -= read
        }
        val finalBytes = try {
            cipher.doFinal()
        } catch (error: Throwable) {
            throw PdfStreamingRewriteException(
                code = "aesv2-stream-invalid",
                message = error.message ?: "Invalid AESV2 stream payload",
                cause = error,
            )
        }
        output.write(finalBytes)
        return written + finalBytes.size
    }

    private fun readFully(input: InputStream, target: ByteArray) {
        var offset = 0
        while (offset < target.size) {
            val read = input.read(target, offset, target.size - offset)
            if (read <= 0) {
                throw PdfStreamingRewriteException(
                    code = "aesv2-iv-truncated",
                    message = "AESV2 stream is missing its complete IV",
                )
            }
            offset += read
        }
    }
}

internal const val STREAM_BUFFER_BYTES: Int = 64 * 1024
private const val AES_IV_BYTES = 16
private const val AES_BLOCK_BYTES = 16L
