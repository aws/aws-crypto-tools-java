// Build code that every library in this repository shares.
// A library uses it by including this build in its settings.gradle.kts
// and applying a plugin from src/main/kotlin.

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "build-logic"
