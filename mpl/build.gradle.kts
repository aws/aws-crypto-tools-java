// Native (non-Dafny) Java implementation of the AWS Cryptographic Material Providers Library,
// with an idiomatic API in software.amazon.cryptography.materialproviders and software.amazon.cryptography.keystore.
// It replaces the Dafny-based MPL as major version 2 of the same artifact, in the same packages;
// the two are not meant to share a classpath.
// Behavioral reference: the Dafny source on aws-cryptographic-material-providers-library `main`.
//
// The toolchain is pinned to Java 8 so the tests prove Java 8 support.

import me.champeau.gradle.japicmp.JapicmpTask

plugins {
    `java-library`
    jacoco
    id("com.diffplug.spotless") version "8.11.0"
    id("net.ltgt.errorprone") version "5.2.0"
    id("info.solidsoft.pitest") version "1.19.0"
    id("me.champeau.gradle.japicmp") version "0.4.6"
}

group = "software.amazon.cryptography"
version = "2.0.0-SNAPSHOT"

java {
    toolchain.languageVersion = JavaLanguageVersion.of(8)
}

repositories {
    mavenCentral()
}

val junitVersion: String by project
val jacocoVersion: String by project

dependencies {
    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.junit.platform:junit-platform-launcher")
    testCompileOnly("org.jacoco:org.jacoco.agent:$jacocoVersion:runtime")
    errorprone("com.google.errorprone:error_prone_core:2.52.0")
}

tasks.withType<JavaCompile>().configureEach {
    // Error Prone runs inside javac and needs Java 21.
    // --release 8 still limits the code to the Java 8 API.
    javaCompiler = javaToolchains.compilerFor { languageVersion = JavaLanguageVersion.of(21) }
    options.release = 8
    options.encoding = "UTF-8"
    // -options: javac 21 warns that release 8 is obsolete.
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial,-options", "-Werror"))
}

// -PtestJavaVersion=N runs the tests on Java N.
val testJavaVersion = providers.gradleProperty("testJavaVersion").map { JavaLanguageVersion.of(it) }

tasks.test {
    useJUnitPlatform()
    if (testJavaVersion.isPresent) {
        javaLauncher = javaToolchains.launcherFor { languageVersion = testJavaVersion }
    }
    finalizedBy(tasks.jacocoTestReport)
}

jacoco {
    toolVersion = jacocoVersion
}

tasks.jacocoTestReport {
    reports.xml.required = true
}

spotless {
    java {
        googleJavaFormat("1.28.0")
    }
}

pitest {
    pitestVersion = "1.30.2"
    junit5PluginVersion = "1.2.3"
    // -PpitestClasses=a.B,a.B$* mutates only those classes.
    targetClasses = providers.gradleProperty("pitestClasses").map { it.split(",") }.orElse(listOf("$group.*"))
    // Without this, PIT runs only the tests whose names match targetClasses.
    targetTests = listOf("*")
    threads = Runtime.getRuntime().availableProcessors()
    // PIT writes the full mutation matrix only in XML.
    outputFormats = listOf("XML")
    timestampedReports = false
    // PIT finds nothing to mutate in a class with only constants or an interface.
    failWhenNoMutations = false
    // Keep each mutant's full list of killing tests for the dashboard.
    fullMutationMatrix = true
}

tasks.pitest {
    // PIT 1.30 needs Java 11 or later.
    javaLauncher = javaToolchains.launcherFor { languageVersion = JavaLanguageVersion.of(17) }
}

// The newest release with the same major version as this build, if there is one.
val apiBaseline =
    configurations.detachedConfiguration(
        dependencies.create("$group:${project.name}:${version.toString().substringBefore('.')}.+") { isTransitive = false },
    )

// Report only: lists the API changes since apiBaseline and never fails on them.
tasks.register<JapicmpTask>("apiCompatibility") {
    onlyIf("a release with this major version exists") {
        apiBaseline.resolvedConfiguration.lenientConfiguration.files.isNotEmpty()
    }
    oldClasspath.from(apiBaseline)
    newClasspath.from(tasks.jar)
    onlyModified = true
    failOnModification = false
    htmlOutputFile = layout.buildDirectory.file("reports/api-compatibility.html")
    txtOutputFile = layout.buildDirectory.file("reports/api-compatibility.txt")
}
