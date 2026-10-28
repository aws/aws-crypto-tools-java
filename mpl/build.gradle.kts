// Native (non-Dafny) Java implementation of the AWS Cryptographic Material Providers Library,
// with an idiomatic API in software.amazon.cryptography.materialproviders and software.amazon.cryptography.keystore.
// It replaces the Dafny-based MPL as major version 2 of the same artifact, in the same packages;
// the two are not meant to share a classpath.
// Behavioral reference: the Dafny source on aws-cryptographic-material-providers-library `main`.
//
// The toolchain is pinned to Java 8 so both compilation and tests prove Java 8 support.

import java.net.URI
import java.security.MessageDigest

plugins {
    `java-library`
}

group = "software.amazon.cryptography"
version = "2.0.0-SNAPSHOT"

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(8))
}

repositories {
    mavenCentral()
}

val junitVersion: String by project
val awsSdkVersion: String by project

dependencies {
    // The old-API model classes take KmsClient and DynamoDbClient.
    testImplementation(platform("software.amazon.awssdk:bom:$awsSdkVersion"))
    testImplementation("software.amazon.awssdk:kms")
    testImplementation("software.amazon.awssdk:dynamodb")

    testImplementation(platform("org.junit:junit-bom:$junitVersion"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all,-serial", "-Werror"))
}

tasks.test {
    useJUnitPlatform()
}

// Old (smithy-generated) API of the Dafny-based MPL, used only by the test adapter. Generated from upstream at a
// pinned commit, with packages moved under software.amazon.cryptography.oldapi; the result's SHA-256 is pinned.
val oldApiModelCommit: String by project
val oldApiModelSha256: String by project
val oldApiModelArchive = layout.buildDirectory.file("oldapi-model/$oldApiModelCommit.tar.gz")
val oldApiModelSources = layout.buildDirectory.dir("generated/sources/oldapi-model")
// Upstream directory -> paths under software/amazon/cryptography to take.
val oldApiModelPaths = mapOf(
    "AwsCryptographicMaterialProviders/runtimes/java/src/main/smithy-generated" to listOf(
        "materialproviders/model/**",
        "keystore/model/**",
        "materialproviders/IKeyring.java",
        "materialproviders/ICryptographicMaterialsManager.java",
        "materialproviders/ICryptographicMaterialsCache.java",
        "materialproviders/IClientSupplier.java",
        "materialproviders/IBranchKeyIdSupplier.java",
    ),
    "AwsCryptographyPrimitives/runtimes/java/src/main/smithy-generated" to listOf("primitives/model/**"),
)
// Model classes that need test code a later change adds; each leaves this list with that change.
val oldApiModelNotYet = listOf(
    "materialproviders/model/CreateAwsKmsHierarchicalKeyringInput.java", // takes the key store adapter
)

val oldApiModel = tasks.register("oldApiModel") {
    description = "Generates the old-API model sources for the test adapter from the Dafny-based MPL's sources."
    inputs.property("commit", oldApiModelCommit)
    inputs.property("sha256", oldApiModelSha256)
    inputs.property("paths", oldApiModelPaths.toString() + oldApiModelNotYet)
    outputs.dir(oldApiModelSources)
    doLast {
        val archive = oldApiModelArchive.get().asFile
        if (!archive.exists()) {
            archive.parentFile.mkdirs()
            val url = "https://codeload.github.com/aws/aws-cryptographic-material-providers-library/tar.gz/$oldApiModelCommit"
            URI(url).toURL().openStream().use { input -> archive.outputStream().use { input.copyTo(it) } }
        }
        val out = oldApiModelSources.get().asFile
        delete(out)
        val top = "aws-cryptographic-material-providers-library-$oldApiModelCommit"
        oldApiModelPaths.forEach { (root, paths) ->
            val base = "$top/$root/software/amazon/cryptography/"
            copy {
                from(tarTree(resources.gzip(archive)))
                include(paths.map { base + it })
                exclude(oldApiModelNotYet.map { base + it })
                eachFile { path = "software/amazon/cryptography/oldapi/" + path.removePrefix(base) }
                includeEmptyDirs = false
                into(out)
            }
        }
        val header = Regex("^// Do not modify this file\\. This file is machine generated.*\\R", RegexOption.MULTILINE)
        val names = Regex("^((?:package|import) software\\.amazon\\.cryptography\\.)(materialproviders|keystore|primitives)([.;])", RegexOption.MULTILINE)
        val digest = MessageDigest.getInstance("SHA-256")
        out.walkTopDown().filter { it.isFile }.sortedBy { it.relativeTo(out).invariantSeparatorsPath }.forEach { file ->
            val text = names.replace(header.replace(file.readText(), ""), "$1oldapi.$2$3")
            file.writeText(text)
            digest.update(file.relativeTo(out).invariantSeparatorsPath.toByteArray())
            digest.update(text.toByteArray())
        }
        val actual = digest.digest().joinToString("") { "%02x".format(it) }
        check(actual == oldApiModelSha256) {
            "Old-API model sources at $oldApiModelCommit hash to $actual, not oldApiModelSha256=$oldApiModelSha256 " +
                "in gradle.properties. Set it to $actual after checking that the change is intended."
        }
    }
}

sourceSets.test {
    java.srcDir(oldApiModel)
}
