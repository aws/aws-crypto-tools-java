// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk.integration;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.crypto.SecretKey;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;

/**
 * The MPL half of the ESDK's {@code EncryptionMaterialsHandler}: what the message format code reads from encryption materials.
 */
public final class EncryptionMaterialsHandler {

  private final EncryptionMaterials materials;

  public EncryptionMaterialsHandler(EncryptionMaterials materials) {
    this.materials = materials;
  }

  /** Whether the materials hold a data key and at least one encrypted copy; a customer's manager may return less. */
  public boolean isReadyForEncrypt() {
    return materials.isReadyForEncrypt();
  }

  /** The caller owns the materials the manager returned; this clears their secrets once the message is written. */
  public void destroy() {
    materials.destroy();
  }

  public CryptoAlgorithm getAlgorithm() {
    return CryptoAlgorithm.of(materials.algorithmSuite());
  }

  /** Includes the required (authenticate-only) keys; the caller splits them off. */
  public Map<String, String> getEncryptionContext() {
    return materials.encryptionContext();
  }

  public List<String> getRequiredEncryptionContextKeys() {
    return materials.requiredEncryptionContextKeys();
  }

  public List<KeyBlob> getEncryptedDataKeys() {
    List<KeyBlob> keyBlobs = new ArrayList<>();
    for (EncryptedDataKey edk : materials.encryptedDataKeys()) {
      keyBlobs.add(KeyBlob.from(edk));
    }
    return keyBlobs;
  }

  /** The data key as the JCA key the ESDK's key derivation takes. */
  public SecretKey getCleartextDataKey() {
    // A built-in manager never returns materials without a data key; a customer's manager might.
    return materials
      .plaintextDataKey()
      .orElseThrow(() -> new InvalidMaterialsException("Materials have no plaintext data key"))
      .toSecretKey(getAlgorithm().getDataKeyAlgo());
  }

  /**
   * Replaces {@code TrailingSignatureAlgorithm.privateKeyFromByteBuffer(signingKey())}: the MPL decodes the scalar.
   * Null for a suite that does not sign, as in ESDK 3.x.
   */
  public PrivateKey getTrailingSignatureKey() {
    return materials.signingPrivateKey().orElse(null);
  }
}
