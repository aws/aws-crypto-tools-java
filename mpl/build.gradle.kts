// Native (non-Dafny) Java implementation of the AWS Cryptographic Material Providers Library,
// with an idiomatic API in software.amazon.cryptography.materialproviders and software.amazon.cryptography.keystore.
// It replaces the Dafny-based MPL as major version 2 of the same artifact, in the same packages;
// the two are not meant to share a classpath.
// Behavioral reference: the Dafny source on aws-cryptographic-material-providers-library `main`.
//
// The toolchain is pinned to Java 8 so both compilation and tests prove Java 8 support.

plugins {
    `java-library`
}

group = "software.amazon.cryptography"
version = "2.0.0-SNAPSHOT"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(8))
}

repositories {
    mavenCentral()
}

val junitVersion: String by project

dependencies {
    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
}
