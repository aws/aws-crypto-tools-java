// `./gradlew build` and `./gradlew check` at the repository root run them in every included build.
// `./gradlew apiSurface` writes every library's build/api-examples/surface.json.
listOf("build", "check", "clean", "apiSurface").forEach { name ->
    tasks.register(name) {
        dependsOn(gradle.includedBuilds.map { it.task(":$name") })
    }
}
