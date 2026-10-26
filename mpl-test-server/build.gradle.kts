// rpcv2Cbor HTTP Language_Server for the MPL TestServer (commons repository,
// mpl/test-server/model/mpl-test-server.smithy). Every operation delegates to the
// public API of the native Java MPL (software.amazon.cryptography.materialproviders and
// software.amazon.cryptography.keystore), built from ../mpl.
//
// The server source compiles for Java 8, like the library, so the server can run on any JDK
// the library supports. The orchestrator launches it with `./gradlew runServer --args=<port>`
// under a JDK 21+ and passes -PmodelDir, which this hand-written server does not need.

plugins {
    java
}

repositories {
    mavenCentral()
}

val jacksonVersion: String by project
val junitVersion: String by project

dependencies {
    // Substituted by the included ../mpl build.
    implementation("software.amazon.cryptography:aws-cryptographic-material-providers:2.0.0-SNAPSHOT")
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:$jacksonVersion")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
    options.encoding = "UTF-8"
    // -options: javac 9+ warns that release 8 is deprecated.
    options.compilerArgs.addAll(listOf("-Xlint:all,-options", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
}

tasks.register<JavaExec>("runServer") {
    group = "application"
    description = "Start the MPL TestServer on the port given as the first argument."
    mainClass.set("aws.cryptography.mpl.testserver.server.ServerMain")
    classpath = sourceSets["main"].runtimeClasspath
}
