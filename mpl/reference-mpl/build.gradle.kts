// The published Dafny-based MPL (this artifact's 1.x line) and its runtime dependencies, copied for the
// differential tests of the root project. Gradle resolves a dependency on the root project's coordinates
// to the root project in two places: in the root project's own configurations, so this project resolves it,
// and in a composite such as mpl-test-server's, so this configuration ignores the composite's substitutions.

repositories {
    mavenCentral()
}

val referenceMplVersion: String by project

val referenceMpl: Configuration by configurations.creating {
    resolutionStrategy.useGlobalDependencySubstitutionRules.set(false)
}

dependencies {
    referenceMpl("software.amazon.cryptography:aws-cryptographic-material-providers:$referenceMplVersion")
}

tasks.register<Sync>("classpath") {
    from(referenceMpl)
    into(rootProject.layout.buildDirectory.dir("reference-mpl"))
}
