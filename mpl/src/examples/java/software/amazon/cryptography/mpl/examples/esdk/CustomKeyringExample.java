// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.mpl.DecryptionMaterials;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.OnDecryptRequest;
import software.amazon.cryptography.mpl.OnDecryptResponse;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.OnEncryptResponse;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.keyrings.MultiKeyring;

/**
 * A keyring the customer implements, here for a key held by an in-house key service (modeled by a local AES key).
 * It generates the data key when it is the generator, binds each wrapped key to the encryption context,
 * and reports why it could not decrypt. No ESDK example.
 */
public final class CustomKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CustomKeyringExample() {}

  public static void encryptAndDecrypt() {
    EsdkLikeClient crypto = EsdkLikeClient.builder().build();
    byte[] keyBytes = new byte[32];
    new SecureRandom().nextBytes(keyBytes);
    Keyring keyService = new KeyServiceKeyring("key-1", new SecretKeySpec(keyBytes, "AES"));
    Map<String, String> encryptionContext = Collections.singletonMap("purpose", "example");

    byte[] ciphertext = crypto.encryptData(keyService, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(keyService, ciphertext, encryptionContext).getResult());

    // As a child of a multi keyring it adds its copy of a data key another keyring generated.
    Keyring withEscrowCopy = MultiKeyring.builder().generator(keyService).childKeyrings(Collections.singletonList(
      new KeyServiceKeyring("key-2", new SecretKeySpec(keyBytes, "AES"))
    )).build();
    byte[] twoCopies = crypto.encryptData(withEscrowCopy, EXAMPLE_DATA, encryptionContext);
    Expect.equal(EXAMPLE_DATA, crypto.decryptData(new KeyServiceKeyring("key-2", new SecretKeySpec(keyBytes, "AES")), twoCopies).getResult());

    // Another key name finds no encrypted data key of its own.
    Keyring otherKey = new KeyServiceKeyring("key-3", new SecretKeySpec(keyBytes, "AES"));
    Expect.failure(NoMatchingDataKeyException.class, () -> crypto.decryptData(otherKey, ciphertext));
  }

  /** Provider id {@code example-key-service}; provider info = key name; ciphertext = IV || AES-GCM(data key) with the context as AAD. */
  static final class KeyServiceKeyring implements Keyring {

    private static final String PROVIDER_ID = "example-key-service";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String keyName;
    private final SecretKey wrappingKey;

    KeyServiceKeyring(String keyName, SecretKey wrappingKey) {
      this.keyName = keyName;
      this.wrappingKey = wrappingKey;
    }

    @Override
    public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
      EncryptionMaterials materials = request.materials();
      EncryptionMaterials withKey = materials;
      if (!materials.plaintextDataKey().isPresent()) {
        // withPlaintextDataKey keeps a copy; this one is destroyed when the block ends.
        try (SecretBytes dataKey = SecretBytes.random(materials.algorithmSuite().dataKeyLength())) {
          withKey = materials.withPlaintextDataKey(dataKey);
        }
      }
      byte[] iv = new byte[12];
      RANDOM.nextBytes(iv);
      byte[] aad = materials.encryptionContext().canonicalBytes();
      byte[] dataKey = withKey.plaintextDataKey().get().toByteArray();
      byte[] wrapped;
      try {
        wrapped = gcm(Cipher.ENCRYPT_MODE, iv, aad, dataKey);
      } finally {
        Arrays.fill(dataKey, (byte) 0);
      }
      byte[] ciphertext = ByteBuffer.allocate(iv.length + wrapped.length).put(iv).put(wrapped).array();
      return OnEncryptResponse.of(withKey.withEncryptedDataKey(EncryptedDataKey.of(PROVIDER_ID, keyName.getBytes(StandardCharsets.UTF_8), ciphertext)));
    }

    @Override
    public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
      DecryptionMaterials materials = request.materials();
      if (materials.plaintextDataKey().isPresent()) {
        throw new InvalidMaterialsException("Decryption materials already hold a data key");
      }
      byte[] aad = materials.encryptionContext().canonicalBytes();
      List<Throwable> failures = new ArrayList<>();
      for (EncryptedDataKey edk : request.encryptedDataKeys()) {
        if (!PROVIDER_ID.equals(edk.keyProviderId()) || !Arrays.equals(keyName.getBytes(StandardCharsets.UTF_8), edk.keyProviderInfo())) {
          continue;
        }
        byte[] ciphertext = edk.ciphertext();
        byte[] dataKey = null;
        try {
          dataKey = gcm(Cipher.DECRYPT_MODE, Arrays.copyOf(ciphertext, 12), aad, Arrays.copyOfRange(ciphertext, 12, ciphertext.length));
          try (SecretBytes secret = SecretBytes.copyOf(dataKey)) {
            return OnDecryptResponse.of(materials.withPlaintextDataKey(secret));
          }
        } catch (IllegalStateException e) {
          failures.add(e);
        } finally {
          if (dataKey != null) {
            Arrays.fill(dataKey, (byte) 0);
          }
        }
      }
      throw new NoMatchingDataKeyException("No encrypted data key for " + keyName + " decrypted", failures);
    }

    private byte[] gcm(int mode, byte[] iv, byte[] aad, byte[] input) {
      try {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, wrappingKey, new GCMParameterSpec(128, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException("AES-GCM failed for " + keyName, e);
      }
    }
  }
}
