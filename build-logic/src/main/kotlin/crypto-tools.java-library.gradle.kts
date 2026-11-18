// The checks every Java library in this repository gets: Java 8 support, JUnit 5,
// format and lint, line and branch coverage, per-test coverage, mutation testing and an API report.
// A library applies this plugin and sets only its own group, version and dependencies.

import me.champeau.gradle.japicmp.JapicmpTask

plugins {
    `java-library`
    jacoco
    id("com.diffplug.spotless")
    id("net.ltgt.errorprone")
    id("info.solidsoft.pitest")
}

val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")
fun version(name: String) = libs.findVersion(name).get().requiredVersion
fun library(name: String) = libs.findLibrary(name).get()

java {
    // The tests run on Java 8, which proves Java 8 support.
    toolchain.languageVersion = JavaLanguageVersion.of(8)
}

repositories {
    mavenCentral()
}

dependencies {
    "testImplementation"(platform(library("junit-bom")))
    "testImplementation"("org.junit.jupiter:junit-jupiter")
    "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
    // The library's settings.gradle.kts includes build-logic, so Gradle builds this jar from source.
    "testRuntimeOnly"("software.amazon.cryptography.build:per-test-coverage")
    "errorprone"(library("error-prone-core"))
}

tasks.withType<JavaCompile>().configureEach {
    // Error Prone runs inside javac and needs Java 21.
    // --release 8 still limits the code to the Java 8 API.
    javaCompiler = javaToolchains.compilerFor { languageVersion = JavaLanguageVersion.of(21) }
    options.release = 8
    options.encoding = "UTF-8"
    // -options: javac 21 warns that release 8 is obsolete.
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial,-options", "-Werror"))
}

// -PtestJavaVersion=N runs the tests on Java N.
val testJavaVersion = providers.gradleProperty("testJavaVersion").map { JavaLanguageVersion.of(it) }

jacoco {
    toolVersion = version("jacoco")
}

tasks.jacocoTestReport {
    reports.xml.required = true
}

// Writes build/reports/jacoco/test/lcov.info, the report CI's coverage checks read.
val jacocoLcov =
    tasks.register<JacocoLcov>("jacocoLcov") {
        report.from(tasks.jacocoTestReport.map { it.reports.xml.outputLocation.get() })
        sourceDirectories.from(sourceSets.main.map { it.java.srcDirs })
        repositoryRoot = generateSequence(rootDir) { it.parentFile }.first { File(it, ".git").exists() }
        lcov = layout.buildDirectory.file("reports/jacoco/test/lcov.info")
    }

tasks.test {
    useJUnitPlatform()
    if (testJavaVersion.isPresent) {
        javaLauncher = javaToolchains.launcherFor { languageVersion = testJavaVersion }
    }
    finalizedBy(jacocoLcov)
}

spotless {
    java {
        googleJavaFormat(version("google-java-format"))
    }
}

pitest {
    pitestVersion = version("pitest")
    junit5PluginVersion = version("pitest-junit5")
    // -PpitestClasses=a.B,a.B$* mutates only those classes.
    targetClasses = providers.gradleProperty("pitestClasses").map { it.split(",") }.orElse(provider { listOf("${project.group}.*") })
    // Without this, PIT runs only the tests whose names match targetClasses.
    targetTests = listOf("*")
    threads = Runtime.getRuntime().availableProcessors()
    // PIT writes the full mutation matrix only in XML.
    outputFormats = listOf("XML")
    timestampedReports = false
    // PIT finds nothing to mutate in a class with only constants or an interface.
    failWhenNoMutations = false
    // Keep each mutant's full list of killing tests for the dashboard.
    fullMutationMatrix = true
}

tasks.pitest {
    // PIT 1.30 needs Java 11 or later.
    javaLauncher = javaToolchains.launcherFor { languageVersion = JavaLanguageVersion.of(17) }
}

// The newest release with the same major version as this build, if there is one.
val apiBaseline =
    configurations.detachedConfiguration().apply {
        isTransitive = false
        defaultDependencies {
            add(project.dependencies.create("${project.group}:${project.name}:${project.version.toString().substringBefore('.')}.+"))
        }
    }

// Empty, not an error, before the first release with this major version.
val apiBaselineJars = apiBaseline.incoming.artifactView { isLenient = true }.files

// Report only: lists the API changes since apiBaseline and never fails on them.
tasks.register<JapicmpTask>("apiCompatibility") {
    onlyIf("a release with this major version exists") { !apiBaselineJars.isEmpty }
    oldClasspath.from(apiBaselineJars)
    newClasspath.from(tasks.jar)
    onlyModified = true
    failOnModification = false
    htmlOutputFile = layout.buildDirectory.file("reports/api-compatibility.html")
    txtOutputFile = layout.buildDirectory.file("reports/api-compatibility.txt")
}
