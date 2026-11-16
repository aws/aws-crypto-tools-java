// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkValidationException;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkCommitmentPolicy;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Chooses an algorithm suite per request and a commitment policy per client, with one materials manager built
 * up front and reused for every call.
 *
 * <p>Shows a committing suite without a signature, the policy for migrating from ESDK 1.x, and how the default
 * policy refuses both to decrypt a message without key commitment and to encrypt with a suite without it.
 *
 * <p>No arguments; runs without AWS (the materials manager uses a raw AES keyring).
 */
public final class CommitmentPolicyAndAlgorithmExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CommitmentPolicyAndAlgorithmExample() {}

  public static void main(String[] args) {
    run();
  }

  public static void run() {
    // 1. Build one materials manager and reuse it.
    // Setting the keyring on each request instead wraps it in a new default manager per call, with the same messages.
    CryptographicMaterialsManager cmm;
    try (SecretBytes wrappingKey = SecretBytes.random(32)) {
      cmm =
        DefaultCryptographicMaterialsManager.create(
          RawAesKeyring
            .builder()
            .keyNamespace("example-namespace")
            .keyName("example-key")
            .wrappingKey(wrappingKey)
            .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
            .build()
        );
    }
    Map<String, String> encryptionContext = Collections.singletonMap("ExampleContextKey", "ExampleContextValue");

    // 2. The default policy, REQUIRE_ENCRYPT_REQUIRE_DECRYPT, with a committing suite that does not sign.
    // Without a signature, anyone who can decrypt can also forge a message, so choose it only when that is acceptable.
    EsdkClient esdk = EsdkClient.create();
    EncryptResponse committed = esdk.encrypt(b ->
      b
        .plaintext(EXAMPLE_DATA)
        .materialsManager(cmm)
        .encryptionContext(encryptionContext)
        .algorithmSuite(EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
    );
    DecryptResponse decrypted = esdk.decrypt(b ->
      b.ciphertext(committed.ciphertext()).materialsManager(cmm).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decrypted.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }
    if (decrypted.algorithmSuite() != EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY) {
      throw new IllegalStateException("The message uses " + decrypted.algorithmSuite());
    }

    // 3. Migrating from ESDK 1.x: write messages that 1.x readers understand, and read messages with and without
    // key commitment.
    EsdkClient legacyWriter = EsdkClient
      .builder()
      .commitmentPolicy(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
      .build();
    EncryptResponse uncommitted = legacyWriter.encrypt(b ->
      b.plaintext(EXAMPLE_DATA).materialsManager(cmm).encryptionContext(encryptionContext)
    );
    if (uncommitted.algorithmSuite().isCommitting()) {
      throw new IllegalStateException("The legacy writer used a committing suite");
    }
    for (EncryptResponse message : Arrays.asList(committed, uncommitted)) {
      DecryptResponse response = legacyWriter.decrypt(b -> b.ciphertext(message.ciphertext()).materialsManager(cmm));
      if (!Arrays.equals(response.plaintext(), EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }
    }

    // 4. The default policy refuses to decrypt a message without key commitment ...
    try {
      esdk.decrypt(b -> b.ciphertext(uncommitted.ciphertext()).materialsManager(cmm));
      throw new IllegalStateException("The default policy decrypted a message without key commitment");
    } catch (EsdkValidationException expected) {
      // A commitment policy conflict is a configuration error.
    }

    // 5. ... and to encrypt with a suite without key commitment.
    try {
      esdk.encrypt(b ->
        b
          .plaintext(EXAMPLE_DATA)
          .materialsManager(cmm)
          .algorithmSuite(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384)
      );
      throw new IllegalStateException("The default policy encrypted with a suite without key commitment");
    } catch (EsdkValidationException expected) {
      // A commitment policy conflict is a configuration error.
    }
  }
}
