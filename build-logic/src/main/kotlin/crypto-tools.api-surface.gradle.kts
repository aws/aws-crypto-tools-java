// Adds the apiSurface task, which writes build/api-examples/surface.json.
// The library id is the library's directory name (mpl, esdk).

import software.amazon.cryptography.build.ApiSurfaceTask

plugins {
    java
}

val main = the<SourceSetContainer>().named("main")

tasks.register<ApiSurfaceTask>("apiSurface") {
    library.convention(project.projectDir.name)
    classesDirs.from(main.map { it.output.classesDirs })
    classpath.from(main.map { it.runtimeClasspath })
    outputFile.convention(layout.buildDirectory.file("api-examples/surface.json"))
}
