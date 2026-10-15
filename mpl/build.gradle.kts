// Native (non-Dafny) Java implementation of the AWS Cryptographic Material Providers Library,
// with an idiomatic API in software.amazon.cryptography.mpl.
// Behavioral reference: the Dafny source on aws-cryptographic-material-providers-library `main`;
// the published Dafny-based MPL (`referenceMplVersion`) is the differential-test oracle.
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
val referenceMplVersion: String by project
val jacksonVersion: String by project

// The published Dafny-based MPL and its runtime dependencies.
// Kept off every compile and runtime classpath: it declares the same class names as this module.
// The differential tests load it in an isolated class loader (ReferenceMpl).
val referenceMpl: Configuration by configurations.creating

dependencies {
    // The public API takes AWS SDK clients: a KmsClient (KMS keyrings, BranchKeyStore) and a DynamoDbClient (BranchKeyStore).
    api(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    api("software.amazon.awssdk:kms")
    api("software.amazon.awssdk:dynamodb")
    // MaterialProvidersException.isRetryable reads the retryable flag of an AWS SDK cause.
    implementation("software.amazon.awssdk:sdk-core")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // Reads the JSON test vectors under src/test/resources/vectors.
    testImplementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")

    referenceMpl("software.amazon.cryptography:aws-cryptographic-material-providers:$referenceMplVersion")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
    inputs.files(referenceMpl)
    systemProperty("mpl.reference.classpath", referenceMpl.asPath)
}
