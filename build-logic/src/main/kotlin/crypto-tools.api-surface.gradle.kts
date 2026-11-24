// Adds the apiSurface task, which writes build/api-examples/surface.json.
// The library id is the library's directory name (mpl, esdk).
// The tests also build build/generated/api-example-combos, where CI has
// aws-crypto-tools-commons' api-examples/combos.py write a test for each call
// that the API examples page can make.

import software.amazon.cryptography.build.ApiSurfaceTask

plugins {
    java
}

val main = the<SourceSetContainer>().named("main")

the<SourceSetContainer>().named("test") {
    java.srcDir(layout.buildDirectory.dir("generated/api-example-combos"))
}

tasks.register<ApiSurfaceTask>("apiSurface") {
    library.convention(project.projectDir.name)
    classesDirs.from(main.map { it.output.classesDirs })
    classpath.from(main.map { it.runtimeClasspath })
    outputFile.convention(layout.buildDirectory.file("api-examples/surface.json"))
}
