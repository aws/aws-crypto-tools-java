// `./gradlew build` and `./gradlew check` at the repository root run them in every included build.
listOf("build", "check", "clean").forEach { name ->
    tasks.register(name) {
        dependsOn(gradle.includedBuilds.map { it.task(":$name") })
    }
}
