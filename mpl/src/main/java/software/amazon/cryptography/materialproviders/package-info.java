// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
/**
 * Material Providers Library: keyrings, cryptographic materials managers, caches, and the branch key store
 * that the AWS Encryption SDK and the AWS Database Encryption SDK use to obtain data keys.
 *
 * <p>This is major version 2 of {@code software.amazon.cryptography:aws-cryptographic-material-providers}.
 * It replaces the Dafny-based 1.x releases in the same packages, so the two cannot share a classpath.
 *
 * <p>Every component builds itself with a static {@code builder()} or {@code of(...)}; there is no factory client.
 *
 * <table>
 *   <caption>Where to start</caption>
 *   <tr><th>To</th><th>Use</th></tr>
 *   <tr><td>Protect data keys with AWS KMS</td><td>{@link software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring}</td></tr>
 *   <tr><td>Decrypt with any KMS key a filter allows</td><td>{@link software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryKeyring}</td></tr>
 *   <tr><td>Cache data keys protected by a branch key</td><td>{@link software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring}</td></tr>
 *   <tr><td>Create and version branch keys</td><td>{@link software.amazon.cryptography.keystore.BranchKeyStore}</td></tr>
 *   <tr><td>Use a local AES, RSA, or ECDH key</td><td>{@code RawAesKeyring}, {@code RawRsaKeyring}, {@code RawEcdhKeyring}</td></tr>
 *   <tr><td>Combine keyrings</td><td>{@link software.amazon.cryptography.materialproviders.keyrings.MultiKeyring}</td></tr>
 *   <tr><td>Turn a keyring into materials</td><td>{@link software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager}</td></tr>
 * </table>
 *
 * <p>Contracts that hold for every public type unless its documentation says otherwise:
 * <ul>
 *   <li>Keyrings, materials managers, caches, and key stores are thread-safe; builders are not.</li>
 *   <li>Value types are immutable. Byte arrays and collections are copied when passed in and when returned.</li>
 *   <li>No method returns null; absent values are {@link java.util.Optional} or empty collections.</li>
 *   <li>The library never closes an AWS SDK client it was given. It closes clients it created when the owner is closed.</li>
 *   <li>Failures the library reports extend
 *       {@link software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException}; message text is not a contract.
 *       Misuse is reported the standard Java way: a null argument throws {@link NullPointerException}, and using a
 *       destroyed {@link software.amazon.cryptography.materialproviders.SecretBytes} throws {@link IllegalStateException}.
 *       Exceptions: the static methods of {@link software.amazon.cryptography.materialproviders.keyrings.RawEcdhStaticConfigurations}
 *       and {@link software.amazon.cryptography.materialproviders.keyrings.KmsEcdhStaticConfigurations} report a null argument with
 *       {@link software.amazon.cryptography.materialproviders.exceptions.ValidationException}, as a builder reports a missing field;
 *       and the {@code grantTokens}, {@code kmsKeyIds}, and {@code regions} setters of the AWS KMS keyring builders,
 *       which take a null collection as an empty one.</li>
 * </ul>
 */
package software.amazon.cryptography.materialproviders;
