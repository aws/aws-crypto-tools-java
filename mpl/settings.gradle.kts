pluginManagement {
    // Provides the crypto-tools.java-library plugin.
    includeBuild("../build-logic")
}

plugins {
    // Downloads a JDK that the build needs (8, 17 or 21) when this machine has none.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    versionCatalogs {
        create("libs") { from(files("../gradle/libs.versions.toml")) }
    }
}

// Builds the per-test coverage listener from source for the tests.
includeBuild("../build-logic")

rootProject.name = "aws-cryptographic-material-providers"
