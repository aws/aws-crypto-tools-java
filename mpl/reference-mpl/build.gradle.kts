// Resolves the published Dafny-based MPL for the tests. A separate project because the root project's own coordinates
// would otherwise resolve to the root project itself.

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
