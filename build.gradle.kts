plugins {
    kotlin("jvm") version "2.2.10"
    `java-library`
    `maven-publish`
    signing
}

group = providers.gradleProperty("group").orNull ?: "dev.jaeyoung"
version = providers.gradleProperty("version").orNull ?: "0.1.0"

description = "Fileloom PDF security/decryption core library"

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
            url = layout.buildDirectory.dir("central-publishing").get().asFile.toURI()
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
