// Native (non-Dafny) Java implementation of the AWS Cryptographic Material Providers Library,
// with an idiomatic API in software.amazon.cryptography.materialproviders and software.amazon.cryptography.keystore.
// It replaces the Dafny-based MPL as major version 2 of the same artifact, in the same packages;
// the two are not meant to share a classpath.
// Behavioral reference: the Dafny source on aws-cryptographic-material-providers-library `main`.

plugins {
    id("crypto-tools.java-library")
}

group = "software.amazon.cryptography"
version = "2.0.0-SNAPSHOT"
