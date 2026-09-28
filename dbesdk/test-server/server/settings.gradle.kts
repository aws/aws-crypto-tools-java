// The Java Language_Server for the ESDK TestServer. Generated from the single
// source-of-truth Smithy model via smithy-java SERVER codegen (Requirement 1.7).
pluginManagement {
    val smithyGradleVersion: String by settings
    plugins {
        id("software.amazon.smithy.gradle.smithy-base").version(smithyGradleVersion)
    }
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "dbesdk-test-server-java"

// The native (non-Dafny) StructuredEncryption implementation is a sibling Gradle
// build; include it so the Language_Server delegates structured-encryption
// operations to native code (via NativeStructuredClient) instead of the
// published Dafny library.
includeBuild("../../structured-encryption")
