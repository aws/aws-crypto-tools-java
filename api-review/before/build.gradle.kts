plugins {
    java
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(8))
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(platform("software.amazon.awssdk:bom:2.31.48"))
    implementation("software.amazon.cryptography:aws-cryptographic-material-providers:1.11.1")
    implementation("com.amazonaws:aws-encryption-sdk-java:3.0.2")
    implementation("software.amazon.cryptography:aws-database-encryption-sdk-dynamodb:3.3.0")
    implementation("software.amazon.awssdk:kms")
    implementation("software.amazon.awssdk:dynamodb")
}

// ESDK 3.0.2 asks for MPL 1.7.0; the review compares against 1.11.1, the latest 1.x.
configurations.all {
    resolutionStrategy.force("software.amazon.cryptography:aws-cryptographic-material-providers:1.11.1")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-classfile,-options", "-Werror"))
}
