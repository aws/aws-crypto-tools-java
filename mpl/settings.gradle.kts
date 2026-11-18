plugins {
    // Downloads a JDK that the build needs (8, 17 or 21) when this machine has none.
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "aws-cryptographic-material-providers"
