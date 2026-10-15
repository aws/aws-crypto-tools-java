// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk.integration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.DecryptMaterialsRequest;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.GetEncryptionMaterialsRequest;

/**
 * The MPL half of the ESDK's {@code CMMHandler}: turns the ESDK's materials requests into native MPL requests.
 * The legacy {@code CryptoMaterialsManager} half is unchanged and not shown.
 */
public final class CmmHandler {

  private final CryptographicMaterialsManager cmm;

  public CmmHandler(CryptographicMaterialsManager cmm) {
    this.cmm = Objects.requireNonNull(cmm, "cmm");
  }

  /**
   * @param requestedAlgorithm the algorithm set on the client, or null for the policy's default
   * @param plaintextSize the plaintext length, or -1 when unknown (streaming), as in {@code EncryptionMaterialsRequest}
   */
  public EncryptionMaterialsHandler getMaterialsForEncrypt(
    Map<String, String> context,
    CryptoAlgorithm requestedAlgorithm,
    CommitmentPolicy commitmentPolicy,
    long plaintextSize
  ) {
    GetEncryptionMaterialsRequest.Builder request = GetEncryptionMaterialsRequest
      .builder()
      .encryptionContext(context)
      .commitmentPolicy(commitmentPolicy.getMplCommitmentPolicy());
    if (requestedAlgorithm != null) {
      request.algorithmSuiteId(requestedAlgorithm.algorithmSuite());
    }
    // ESDK 3.x sent -1 as a length; the native request models "unknown" as absent.
    if (plaintextSize >= 0) {
      request.maxPlaintextLength(plaintextSize);
    }
    return new EncryptionMaterialsHandler(cmm.getEncryptionMaterials(request.build()));
  }

  /**
   * @param storedContext the context from the message header
   * @param reproducedContext the context the caller passed to decrypt, or null
   */
  public DecryptionMaterialsHandler decryptMaterials(
    CryptoAlgorithm algorithm,
    Map<String, String> storedContext,
    List<KeyBlob> keyBlobs,
    Map<String, String> reproducedContext,
    CommitmentPolicy commitmentPolicy
  ) {
    List<EncryptedDataKey> edks = new ArrayList<>(keyBlobs.size());
    for (KeyBlob keyBlob : keyBlobs) {
      edks.add(keyBlob.toEncryptedDataKey());
    }
    DecryptMaterialsRequest.Builder request = DecryptMaterialsRequest
      .builder()
      .algorithmSuiteId(algorithm.algorithmSuite())
      .commitmentPolicy(commitmentPolicy.getMplCommitmentPolicy())
      .encryptedDataKeys(edks)
      .encryptionContext(storedContext);
    if (reproducedContext != null) {
      request.reproducedEncryptionContext(reproducedContext);
    }
    return new DecryptionMaterialsHandler(cmm.decryptMaterials(request.build()));
  }
}
