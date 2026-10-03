// Native (non-Dafny) Java implementation of the DB-ESDK, built as one module and
// published as one artifact. Package boundaries mirror the Dafny source modules:
//   software.amazon.cryptography.dbesdk.structuredencryption   — StructuredEncryption core, wire, crypto
//   software.amazon.cryptography.dbesdk.dynamodbencryption      — DynamoToStruct + beacons
//   software.amazon.cryptography.dbesdk.dynamodbitemencryptor   — DynamoDbItemEncryptor core
// Behavioral parity target: the Dafny source under
// aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny. Build with a JDK 21+
// (set JAVA_HOME to a JDK 21 or newer); no toolchain is pinned.

plugins {
    `java-library`
}

group = "software.amazon.cryptography.dbesdk"
version = "0.1.0-SNAPSHOT"

repositories {
    mavenLocal()
    mavenCentral()
}

val jqwikVersion: String by project
val junitVersion: String by project
val dbeVersion: String by project
val materialProvidersVersion: String by project
val awsSdkVersion: String by project

dependencies {
    // The DynamoDB AttributeValue type the DynamoToStruct layer serializes.
    api(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    api("software.amazon.awssdk:dynamodb")

    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")

    // Test-only: the published Dafny DBE library + MPL, used solely to prove
    // byte-level interop (native encrypt <-> Dafny decrypt). Main code has no
    // dependency on either — this stays in the test classpath.
    testImplementation("software.amazon.cryptography:aws-database-encryption-sdk-dynamodb:$dbeVersion")
    testImplementation("software.amazon.cryptography:aws-cryptographic-material-providers:$materialProvidersVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        includeEngines("jqwik", "junit-jupiter")
    }
}
