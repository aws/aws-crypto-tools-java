// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk.integration;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;

/**
 * The MPL half of the ESDK's {@code DecryptionMaterialsHandler}: what the message format code reads from decryption materials.
 */
public final class DecryptionMaterialsHandler {

  private final DecryptionMaterials materials;

  public DecryptionMaterialsHandler(DecryptionMaterials materials) {
    this.materials = materials;
  }

  public CryptoAlgorithm getAlgorithm() {
    return CryptoAlgorithm.of(materials.algorithmSuite());
  }

  public boolean isReadyForDecrypt() {
    return materials.isReadyForDecrypt();
  }

  /** The caller owns the materials the manager returned; this clears their secrets once the message is read. */
  public void destroy() {
    materials.destroy();
  }

  /** The stored context plus any reproduced pairs the message did not store. */
  public Map<String, String> getEncryptionContext() {
    return materials.encryptionContext();
  }

  public List<String> getRequiredEncryptionContextKeys() {
    return materials.requiredEncryptionContextKeys();
  }

  public SecretKey getDataKey() {
    return materials
      .plaintextDataKey()
      .orElseThrow(() -> new InvalidMaterialsException("Materials have no plaintext data key"))
      .toSecretKey(getAlgorithm().getDataKeyAlgo());
  }

  /**
   * Replaces {@code TrailingSignatureAlgorithm.decompressPublicKey(verificationKey())}: the MPL decodes the SEC 1 point.
   * Null for a suite that does not sign.
   *
   * @throws software.amazon.cryptography.mpl.exceptions.ValidationException if the point is not on the curve
   *   (ESDK 3.x threw IllegalArgumentException)
   */
  public PublicKey getTrailingSignatureKey() {
    return materials.verificationPublicKey().orElse(null);
  }
}
