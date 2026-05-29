import java.io.ByteArrayOutputStream

plugins {
    `java-library`
    `maven-publish`
    id("com.diffplug.spotless") version "6.25.0"
}

group = "com.github.FedericoPonzi"
version = providers.gradleProperty("version").orNull ?: gitVersion()

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
    withSourcesJar()
    withJavadocJar()
}

repositories {
    mavenCentral()
}

spotless {
    java {
        googleJavaFormat("1.22.0")
        target("src/**/*.java")
    }
}

dependencies {
    api("com.google.crypto.tink:tink:1.21.0")

    api(platform("com.azure:azure-sdk-bom:1.2.31"))
    // TokenCredential (azure-core, pulled in transitively) appears in the public API of
    // AzureKeyVaultClient, and the README shows DefaultAzureCredentialBuilder (azure-identity),
    // so both must be on the consumer compile classpath.
    api("com.azure:azure-identity")
    implementation("com.azure:azure-security-keyvault-keys")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.google.truth:truth:1.4.4")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}

tasks.test {
    testLogging {
        events("passed", "skipped", "failed")
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            pom {
                name.set("tink-java-azurekv")
                description.set("Google Tink KMS integration for Azure Key Vault")
                url.set("https://github.com/FedericoPonzi/tink-java-azurekv")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
            }
        }
    }
}

/** Derives the project version from the current git tag (SemVer `vX.Y.Z`). */
fun gitVersion(): String {
    return try {
        val out = ByteArrayOutputStream()
        val result = exec {
            commandLine("git", "describe", "--tags", "--always", "--dirty")
            standardOutput = out
            errorOutput = ByteArrayOutputStream()
            isIgnoreExitValue = true
        }
        if (result.exitValue != 0) return "0.0.0-SNAPSHOT"
        val raw = out.toString().trim().removePrefix("v")
        if (raw.isEmpty()) "0.0.0-SNAPSHOT" else raw
    } catch (e: Exception) {
        "0.0.0-SNAPSHOT"
    }
}
