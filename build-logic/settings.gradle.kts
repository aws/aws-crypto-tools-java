// Build code that every library in this repository shares.
// A library uses it by including this build in its settings.gradle.kts
// and applying the crypto-tools.java-library plugin.

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    versionCatalogs {
        create("libs") { from(files("../gradle/libs.versions.toml")) }
    }
}

rootProject.name = "build-logic"

include("per-test-coverage")
