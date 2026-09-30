// Native (non-Dafny) MPL-free core of the DynamoDbItemEncryptor: config validation,
// version derivation, encryption-context construction (V1/V2), crypto/authenticate
// schema, signature scope, and plaintext-policy routing. The CMM-facing EncryptItem/
// DecryptItem orchestration lives at the test-server seam (it needs MPL), mirroring
// how StructuredEncryption's core is MPL-free and NativeStructuredClient is the seam.
// Parity target: DynamoDbItemEncryptor/dafny/DynamoDbItemEncryptor/src/{Index,Operations,Util}.dfy.
// Build with a JDK 21+.

plugins {
    `java-library`
}

group = "software.amazon.cryptography.dbesdk"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

val junitVersion: String by project

dependencies {
    api("software.amazon.cryptography.dbesdk:dbesdk-dynamodb-encryption:0.1.0-SNAPSHOT")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
