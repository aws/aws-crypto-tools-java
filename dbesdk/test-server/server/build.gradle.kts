// Builds the Java Language_Server for the ESDK TestServer service over the
// rpcv2Cbor protocol. The server scaffolding (request decoding, response
// encoding, routing, error serialization) is generated from the single
// source-of-truth Smithy model hosted in the aws-crypto-tools-commons
// repository (esdk/test-server/model), supplied via the REQUIRED `modelDir`
// Gradle property, by the smithy-java `java-codegen` build plugin in SERVER
// mode (Requirement 1.7); only the operation handler bodies are hand-written.
//
// This repository carries NO copy of the model: the orchestrator always passes
// -PmodelDir=<resolved commons root>/esdk/test-server/model, and a developer
// running this module standalone passes it manually.
//
// The wire contract is identical to the one the single generated Java
// Test_Client (commons esdk/test-server/client-java) speaks, because both are
// generated from the same model with the same protocol declared once at the
// service level.

plugins {
    `java-library`
    // Runs the Smithy build (and thus the java-codegen plugin) during the
    // Gradle build. Version comes from gradle.properties via settings.
    id("software.amazon.smithy.gradle.smithy-base")
}

repositories {
    // mavenLocal() is listed FIRST so that when the resolved ESDK Java library
    // source has been installed to the local Maven repository (by the
    // orchestrator's JavaLaunchPlan: mvn versions:set -> install -> revert
    // under a distinct version), a matching
    // `com.amazonaws:aws-encryption-sdk-java:<esdkVersion>` there is consumed
    // as the LIVE source in place of the published GA artifact. The live flow
    // installs a DISTINCT version (e.g. 3.0.2-LIVE-SNAPSHOT) and passes
    // `-PesdkVersion=<that version>`, so head/default runs still resolve the
    // published artifact from Maven Central below and only an explicit live
    // run picks up the local build.
    mavenLocal()
    mavenCentral()
}

// smithy-java 1.x baselines on Java 21. Build with a JDK 21+ (set JAVA_HOME to a
// JDK 21 or newer when invoking Gradle). We intentionally do not pin a Java
// toolchain version here so the build uses whatever compatible JDK 21+ is
// configured for Gradle in the environment / CI, mirroring the client-java
// module.

val smithyJavaVersion: String by project
val smithyProtocolTraitsVersion: String by project
val dbeVersion: String by project
val materialProvidersVersion: String by project
val awsSdkVersion: String by project
val jqwikVersion: String by project
val junitVersion: String by project

dependencies {
    // --- Code generation (smithy build classpath only) ---
    // The smithy-java code generation plugins, discovered by the smithyBuild
    // task via SPI.
    smithyBuild("software.amazon.smithy.java:codegen-plugin:$smithyJavaVersion")
    // The rpcv2Cbor protocol trait definition must be resolvable while the
    // model is built so `smithy.protocols#rpcv2Cbor` is understood by codegen.
    smithyBuild("software.amazon.smithy:smithy-protocol-traits:$smithyProtocolTraitsVersion")

    // --- Runtime dependencies of the generated server ---
    api("software.amazon.smithy.java:server-core:$smithyJavaVersion")
    api("software.amazon.smithy.java:server-rpcv2-cbor:$smithyJavaVersion")
    implementation("software.amazon.smithy.java:cbor-codec:$smithyJavaVersion")
    runtimeOnly("software.amazon.smithy.java:server-netty:$smithyJavaVersion")

    // --- Real DBE Java delegation ---
    // The CreateClient/EncryptItem/DecryptItem handlers delegate to the real
    // AWS Database Encryption SDK for DynamoDB (Java). This pass consumes the
    // published GA artifact from Maven Central; a follow-up wires a
    // live-tree flow the same way the ESDK server does.
    implementation("software.amazon.cryptography:aws-database-encryption-sdk-dynamodb:$dbeVersion")
    // The handlers/factory import the Material Providers keyring & CMM types
    // directly, so declare the library explicitly.
    implementation("software.amazon.cryptography:aws-cryptographic-material-providers:$materialProvidersVersion")
    // AWS SDK v2 for the AttributeValue type (DDB item shape) and the KMS
    // client (KMS keyring variants). The BOM aligns their versions.
    implementation(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    implementation("software.amazon.awssdk:dynamodb")
    implementation("software.amazon.awssdk:kms")

    // --- Test dependencies ---
    testImplementation("net.jqwik:jqwik:$jqwikVersion")
    testImplementation("org.junit.jupiter:junit-jupiter-api:$junitVersion")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junitVersion")
}

// The shared model is owned by the model/ package; this server only consumes
// it. Disable the formatter so building the server never rewrites the single
// source-of-truth model file (Requirement 1.1).
smithy {
    format.set(false)
}

// Use the single source-of-truth model hosted in the Commons_Repository
// (Requirement 1.7) rather than a copy. The location is supplied via the
// REQUIRED `modelDir` Gradle property; fail fast with a clear message when it
// is absent so a bare `./gradlew build` cannot silently pick up a stale or
// wrong model.
val modelDir: String = providers.gradleProperty("modelDir").orNull
    ?: throw GradleException(
        "The Java Language_Server consumes the Smithy model from the commons repository: " +
            "pass -PmodelDir=<abs path to the commons esdk/test-server/model>"
    )

sourceSets {
    main {
        smithy {
            srcDir(modelDir)
        }
    }
}

// Add the generated server sources/resources to the main sourceSet so they are
// compiled alongside the hand-written handlers.
afterEvaluate {
    val serverPath = smithy.getPluginProjectionPath(smithy.sourceProjection.get(), "java-codegen").get()
    sourceSets {
        main {
            java {
                srcDir("$serverPath/java")
            }
            resources {
                srcDir("$serverPath/resources")
            }
        }
    }
}

// Ensure code generation runs before compilation / resource processing.
tasks.named("compileJava") {
    dependsOn("smithyBuild")
}

tasks.named("processResources") {
    dependsOn("smithyBuild")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform {
        // jqwik registers its own JUnit Platform engine; include it explicitly.
        includeEngines("jqwik", "junit-jupiter")
    }
}

// A minimal runnable launcher for the Java Language_Server (task 5 support, NOT
// the full orchestrator of task 7). Starts the smithy-java rpcv2Cbor HTTP server
// on a configurable port so a user can run a real over-HTTP round trip manually:
//
//   Terminal 1 (start the server on port 8080):
//     JAVA_HOME=<jdk21+> ./gradlew runServer
//     # or choose a port:
//     JAVA_HOME=<jdk21+> ./gradlew runServer --args="9090"
//     # or:  JAVA_HOME=<jdk21+> ./gradlew runServer -Pport=9090
//
//   Terminal 2 (point the Tests at it — from ../../tests):
//     JAVA_HOME=<jdk21+> ./gradlew test -Ddbesdk.testserver.endpoints=http://127.0.0.1:8080
//
// The port may also be supplied via -Pport=<n>, the system property
// dbesdk.testserver.port, or the DBESDK_TESTSERVER_PORT env var (see ServerBootstrap).
tasks.register<JavaExec>("runServer") {
    group = "application"
    description = "Start the Java Language_Server (rpcv2Cbor HTTP) on a configurable port."
    mainClass.set("aws.cryptography.dbesdk.testserver.server.launcher.ServerBootstrap")
    classpath = sourceSets["main"].runtimeClasspath
    // Allow `-Pport=<n>` as a convenience in addition to CLI args / sys prop / env.
    (project.findProperty("port") as String?)?.let {
        systemProperty("dbesdk.testserver.port", it)
    }
}
