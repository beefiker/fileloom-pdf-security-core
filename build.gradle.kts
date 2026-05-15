plugins {
    kotlin("jvm") version "2.2.10"
    `java-library`
    `maven-publish`
}

group = providers.gradleProperty("group").orNull ?: "dev.jaeyoung"
version = providers.gradleProperty("version").orNull ?: "0.1.0-SNAPSHOT"

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
}
