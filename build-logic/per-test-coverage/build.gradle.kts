// The JUnit listener that writes each test's coverage to its own file.
// crypto-tools.java-library puts this jar on every library's test runtime classpath.

plugins {
    `java-library`
}

group = "software.amazon.cryptography.build"

tasks.compileJava {
    // It runs inside the library's tests, which run on Java 8.
    options.release = 8
}

dependencies {
    compileOnly(libs.junit.platform.launcher)
    compileOnly(variantOf(libs.jacoco.agent) { classifier("runtime") })
}
