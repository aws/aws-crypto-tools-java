// Native (non-Dafny) Java implementation of the DynamoDbEncryption module's
// DynamoToStruct: DynamoDB AttributeValue <-> StructuredEncryption terminal
// (value bytes + 2-byte type id). Behavioral parity target: the Dafny source at
// DynamoDbEncryption/dafny/DynamoDbEncryption/src/DynamoToStruct.dfy.
// See .agent-reports/dbesdk-native-java/dbesdk-behavior/DynamoToStruct.md.
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
val awsSdkVersion: String by project

dependencies {
    // Terminal (value + type id) is part of DynamoToStruct's public surface.
    api("software.amazon.cryptography.dbesdk:dbesdk-structured-encryption:0.1.0-SNAPSHOT")
    // The DynamoDB AttributeValue type this module serializes.
    api(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    api("software.amazon.awssdk:dynamodb")

    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}
