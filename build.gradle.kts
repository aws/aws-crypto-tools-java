// `./gradlew build`, `check` and `test` at the repository root run them in every included build.
// `./gradlew apiSurface` writes every library's build/api-examples/surface.json.
listOf("build", "check", "clean", "test", "apiSurface").forEach { name ->
    tasks.register(name) {
        dependsOn(gradle.includedBuilds.map { it.task(":$name") })
    }
}
