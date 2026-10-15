// Native (non-Dafny) Java implementation of the AWS Cryptographic Material Providers Library,
// with an idiomatic API in software.amazon.cryptography.mpl.
// Behavioral reference: the Dafny source on aws-cryptographic-material-providers-library `main`.
//
// The toolchain is pinned to Java 8 so both compilation and tests prove Java 8 support.

plugins {
    `java-library`
}

group = "software.amazon.cryptography"
version = "0.1.0-SNAPSHOT"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(8))
}

repositories {
    mavenCentral()
}

val junitVersion: String by project
val awsSdkVersion: String by project

dependencies {
    // The copied old-API model classes take KmsClient and DynamoDbClient.
    testImplementation(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    testImplementation("software.amazon.awssdk:kms")
    testImplementation("software.amazon.awssdk:dynamodb")

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
