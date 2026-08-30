plugins {
    kotlin("jvm") version "2.2.10"
    `java-library`
    `maven-publish`
    signing
}

group = providers.gradleProperty("group").orNull ?: "dev.jaeyoung"
version = providers.gradleProperty("version").orNull ?: "0.1.3"

description = "Fileloom PDF security/decryption core library"

val centralPublishingDir = layout.buildDirectory.dir("central-publishing")
val mavenCentralBundleDir = layout.buildDirectory.dir("maven-central-bundle")

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    withSourcesJar()
    withJavadocJar()
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api("dev.jaeyoung:fileloom-pdf-parser-core:0.3.0")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

val streamingMemoryTest by tasks.registering(Test::class) {
    description = "Runs the large-stream PDF decrypt regression under a bounded heap."
    group = "verification"
    useJUnitPlatform()
    maxHeapSize = "128m"
    filter {
        includeTestsMatching(
            "dev.jaeyoung.fileloom.pdf.security.FileloomPdfStreamingMemoryTest"
        )
    }
    shouldRunAfter(tasks.test)
}

tasks.named("check") {
    dependsOn(streamingMemoryTest)
}

val requiresSigning = !version.toString().endsWith("SNAPSHOT") &&
    gradle.startParameter.taskNames.any { it.contains("publish", ignoreCase = true) }

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("fileloom-pdf-security-core")
                description.set(project.description)
                url.set("https://github.com/beefiker/fileloom-pdf-security-core")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("jaeyoung")
                        name.set("Jaeyoung")
                    }
                }
                scm {
                    url.set("https://github.com/beefiker/fileloom-pdf-security-core")
                    connection.set("scm:git:https://github.com/beefiker/fileloom-pdf-security-core.git")
                    developerConnection.set("scm:git:ssh://git@github.com:beefiker/fileloom-pdf-security-core.git")
                }
            }
        }
    }

    repositories {
        maven {
            name = "centralPublishing"
            url = centralPublishingDir.get().asFile.toURI()
        }
    }
}

signing {
    isRequired = requiresSigning
    if (requiresSigning) {
        useGpgCmd()
    }
    sign(publishing.publications["mavenJava"])
}

tasks.withType<org.gradle.plugins.signing.Sign>().configureEach {
    onlyIf { requiresSigning }
}

val cleanMavenCentralBundle by tasks.registering(Delete::class) {
    delete(centralPublishingDir, mavenCentralBundleDir)
}

tasks.named("publishMavenJavaPublicationToCentralPublishingRepository") {
    dependsOn(cleanMavenCentralBundle)
}

tasks.register<Zip>("publishToMavenCentralBundle") {
    description = "Builds a Maven Central upload bundle ZIP under build/maven-central-bundle/."
    group = "publishing"
    dependsOn("publishMavenJavaPublicationToCentralPublishingRepository")
    from(centralPublishingDir)
    destinationDirectory.set(mavenCentralBundleDir)
    archiveFileName.set("${project.name}-${project.version}-maven-central-bundle.zip")
    doLast {
        logger.lifecycle("Maven Central bundle ready at ${archiveFile.get().asFile.absolutePath}")
        logger.lifecycle("Upload at https://central.sonatype.com/publishing")
    }
}
