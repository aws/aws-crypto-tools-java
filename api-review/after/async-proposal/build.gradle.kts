// The async proposal: the spike, the proposal stubs, and the ESDK 4.0 sketch with async keyrings on its
// requests (src/esdk-overlay replaces the sketch's EncryptRequest and DecryptRequest).
val standIns = project(":stand-ins").file("src/main/java")
val overlaid = setOf("EncryptRequest.java", "DecryptRequest.java")

sourceSets {
    main {
        java {
            srcDir("src/esdk-overlay/java")
            srcDir(standIns)
            exclude { it.file.startsWith(standIns) && it.name in overlaid }
        }
    }
}

tasks.withType<JavaCompile>().configureEach {
    // The stand-ins compile with -nowarn in their own project; here they are compiled again.
    options.compilerArgs.clear()
    options.compilerArgs.addAll(listOf("-Xlint:all,-cast,-rawtypes,-unchecked,-deprecation", "-Werror"))
}
