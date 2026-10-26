// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

//= spec/framework/cmm-interface.md#supported-cmms
//= type=implication
//# Note: A user MAY create their own custom CMM.
//
//= spec/framework/cmm-interface.md#overview
//= type=implication
//# The CMM interface describes the interface that all CMMs MUST implement.
//
//= spec/framework/cmm-interface.md#behaviors
//= type=implication
//# The CMM Interface MUST support the following behaviors:
/**
 * Assembles the materials an encryption SDK uses for one message: picks the algorithm suite,
 * adds signing keys, and asks keyrings for data keys.
 *
 * <p>Implement this to customize materials, usually by wrapping another manager. Implementations must be thread-safe.
 *
 * <p>The built-in managers check what their keyrings return,
 * and {@link software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager} checks the manager it wraps;
 * nothing else checks what a manager returns.
 * Code that calls a manager it did not write, such as an encryption SDK, should check each result before using it,
 * as the AWS Encryption SDK does:
 * <ul>
 *   <li>the commitment policy allows the suite ({@link CommitmentPolicy#allowsEncrypt}, {@link CommitmentPolicy#allowsDecrypt});
 *   <li>the suite fits: one of the caller's message format on encrypt, the message's own suite on decrypt;
 *   <li>the materials are {@link EncryptionMaterials#isReadyForEncrypt()} or {@link DecryptionMaterials#isReadyForDecrypt()};
 *   <li>the encryption context and encrypted data keys fit the caller's limits, such as a maximum number of keys.
 * </ul>
 *
 * <p>Each method takes a request object and returns a response object,
 * so a later version can add fields to either without breaking managers that callers implement.
 *
 * <p>The caller owns the returned materials and may {@code destroy()} them once the message is done.
 *
 * <p>Specification: <a href="https://github.com/awslabs/aws-encryption-sdk-specification/blob/HEAD/framework/cmm-interface.md">CMM interface</a>.
 */
public interface CryptographicMaterialsManager {
  GetEncryptionMaterialsResponse getEncryptionMaterials(GetEncryptionMaterialsRequest request);

  DecryptMaterialsResponse decryptMaterials(DecryptMaterialsRequest request);
}
