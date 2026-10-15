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

// Usage examples, written as the ESDK and DB-ESDK (and their customers) would use the library.
// They compile against the public API only; the tests run them against the in-process fake AWS endpoint.
val examples: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.main.get().output + configurations.compileClasspath.get()
    runtimeClasspath += output + compileClasspath
}
sourceSets.test {
    compileClasspath += examples.output
    runtimeClasspath += examples.output
}
// Differential tests against real AWS KMS and DynamoDB, on top of the test sources (adapter, reference oracle).
// Compiled by `build`; run only by `integrationTest`, which needs MPL_IT_PROFILE and MPL_IT_RESOURCES.
val integrationTest: SourceSet by sourceSets.creating {
    compileClasspath += sourceSets.test.get().output + sourceSets.test.get().compileClasspath
    runtimeClasspath += output + compileClasspath + sourceSets.test.get().runtimeClasspath
}

dependencies {
    // The public API takes AWS SDK clients: a KmsClient (KMS keyrings, BranchKeyStore) and a DynamoDbClient (BranchKeyStore).
    api(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    api("software.amazon.awssdk:kms")
    api("software.amazon.awssdk:dynamodb")
    // MaterialProvidersException.isRetryable reads the retryable flag of an AWS SDK cause.
    implementation("software.amazon.awssdk:sdk-core")
    // RSA, ECDH, and PEM/DER parsing through the same BouncyCastle calls as the Dafny-based MPL.
    implementation("org.bouncycastle:bcprov-jdk18on:1.83")

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

tasks.check {
    dependsOn(integrationTest.classesTaskName)
}

tasks.register<Test>("integrationTest") {
    description = "Runs the native and the reference MPL against real AWS. Needs MPL_IT_PROFILE and MPL_IT_RESOURCES."
    group = "verification"
    testClassesDirs = integrationTest.output.classesDirs
    classpath = integrationTest.runtimeClasspath
    useJUnitPlatform()
    systemProperty("mpl.reference.classpath", referenceMpl.asPath)
    val profile = System.getenv("MPL_IT_PROFILE")
    onlyIf("MPL_IT_PROFILE is set") { profile != null }
    // The default client suppliers and key store clients of both MPLs use the default credential chain.
    if (profile != null) {
        environment("AWS_PROFILE", profile)
    }
    // Real services change between runs; a cached result says nothing about them.
    outputs.upToDateWhen { false }
}
