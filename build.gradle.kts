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

<<<<<<< Updated upstream
spotless {
    java {
        googleJavaFormat("1.22.0")
        target("src/**/*.java")
    }
}

=======
sourceSets {
    create("integrationTest") {
        compileClasspath += sourceSets["main"].output
        runtimeClasspath += sourceSets["main"].output
    }
}

val integrationTestImplementation: Configuration by configurations.getting {
    extendsFrom(configurations.implementation.get(), configurations.testImplementation.get())
}
configurations["integrationTestRuntimeOnly"].extendsFrom(configurations.runtimeOnly.get())

>>>>>>> Stashed changes
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

    // The record/replay integration tests reuse the main Azure/Tink deps and the JUnit4 + Truth
    // stack from the test configuration (inherited via `integrationTestImplementation`). The
    // self-contained VCR (`RecordingHttpClient`) only needs azure-core + azure-json, both of
    // which are already on the classpath transitively, so no extra dependencies are declared.
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

val integrationTest by tasks.registering(Test::class) {
    description = "Runs Azure Managed HSM record/replay integration tests (opt-in; not part of build)."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnit()
    shouldRunAfter(tasks.named("test"))
    // Azure Key Vault's challenge-auth cache is process-static; isolate each test class in its
    // own JVM so the recorded 401-challenge handshake is reproduced deterministically on replay.
    setForkEvery(1)
    maxParallelForks = 1
    // Forward the record/replay controls from the invoking shell into the forked test JVM.
    System.getenv("AZURE_TEST_MODE")?.let { environment("AZURE_TEST_MODE", it) }
    System.getenv("AZURE_MANAGED_HSM_KEY_ID")?.let { environment("AZURE_MANAGED_HSM_KEY_ID", it) }
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
