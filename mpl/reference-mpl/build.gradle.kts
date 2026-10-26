// The published Dafny-based MPL (this artifact's 1.x line) and its runtime dependencies, copied for the
// differential tests of the root project. Resolved in this project because, in the root project,
// a dependency on the root project's own coordinates resolves to the root project.

repositories {
    mavenCentral()
}

val referenceMplVersion: String by project

val referenceMpl: Configuration by configurations.creating

dependencies {
    referenceMpl("software.amazon.cryptography:aws-cryptographic-material-providers:$referenceMplVersion")
}

tasks.register<Sync>("classpath") {
    from(referenceMpl)
    into(rootProject.layout.buildDirectory.dir("reference-mpl"))
}
