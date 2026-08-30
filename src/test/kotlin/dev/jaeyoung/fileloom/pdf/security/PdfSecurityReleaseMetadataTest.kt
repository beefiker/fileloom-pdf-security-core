package dev.jaeyoung.fileloom.pdf.security

import java.io.File
import kotlin.test.Test
import kotlin.test.assertTrue

class PdfSecurityReleaseMetadataTest {
    @Test
    fun releaseMetadataTargetsReviewHardenedStreamingVersion() {
        val properties = findRepositoryFile("gradle.properties").readText()
        val buildScript = findRepositoryFile("build.gradle.kts").readText()
        val readme = findRepositoryFile("README.md").readText()

        assertTrue(properties.lineSequence().any { it == "version=0.1.5" })
        assertTrue(buildScript.contains("?: \"0.1.5\""))
        assertTrue(readme.contains("fileloom-pdf-security-core:0.1.5"))
        assertTrue(readme.contains("64 KiB streaming decryption"))
        assertTrue(readme.contains("stable bounded input snapshots"))
    }

    private fun findRepositoryFile(relativePath: String): File {
        var current: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (current != null) {
            val file = File(current, relativePath)
            if (file.isFile) return file
            current = current.parentFile
        }
        error("Unable to locate $relativePath")
    }
}
