// Native (non-Dafny) Java implementation of the DB-ESDK StructuredEncryption
// core. Behavioral parity target: the Dafny source under
// aws-database-encryption-sdk-dynamodb/DynamoDbEncryption/dafny/StructuredEncryption.
// See .agent-reports/dbesdk-native-java/planning/structuredencryption-native-implementation-plan.md
// and the behavior spec in .agent-reports/dbesdk-native-java/dbesdk-behavior/StructuredEncryption.md.
//
// Dependencies are added per component as they are first needed (the MPL is
// declared when the materials/CMM path lands). Build with a JDK 21+ (set
// JAVA_HOME to a JDK 21 or newer); no toolchain is pinned, mirroring the
// test-server module.

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

dependencies {
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")

    // Test-only: the published Dafny DBE library + MPL, used solely to prove
    // byte-level interop (native encrypt <-> Dafny decrypt). The main module has
    // no dependency on either — this stays in the test classpath.
    testImplementation("software.amazon.cryptography:aws-database-encryption-sdk-dynamodb:$dbeVersion")
    testImplementation("software.amazon.cryptography:aws-cryptographic-material-providers:$materialProvidersVersion")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        includeEngines("jqwik", "junit-jupiter")
    }
}
