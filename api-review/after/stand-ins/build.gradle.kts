// Stand-ins, not for review: the ESDK 4.0 sketch and DB-ESDK types the examples use, with bodies that throw.

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.clear()
    options.compilerArgs.add("-nowarn")
}
