// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

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
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkNoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;

/**
 * Encrypts and decrypts messages with a keyring the application implements, for keys the MPL has no keyring
 * for, such as keys in an in-house key service. Here a local AES-GCM key stands in for that service.
 *
 * <p>As the first keyring (the generator) it creates the data key; as a child of a multi keyring it only wraps it.
 * It binds each wrapped key to the encryption context and reports why it could not decrypt.
 *
 * <p>No arguments; runs without AWS.
 */
public final class CustomKeyringExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  private CustomKeyringExample() {}

  public static void main(String[] args) {
    run();
  }

  public static void run() {
    // 1. Instantiate the ESDK.
    EsdkClient esdk = EsdkClient.create();

    // 2. Create the custom keyring.
    Keyring keyring = new KeyServiceKeyring("key-1", newAesKey());

    // 3. Encrypt and decrypt.
    Map<String, String> encryptionContext = Collections.singletonMap("purpose", "example");
    EncryptResponse encryptResponse = esdk.encrypt(b ->
      b.plaintext(EXAMPLE_DATA).keyring(keyring).encryptionContext(encryptionContext)
    );
    DecryptResponse decryptResponse = esdk.decrypt(b ->
      b.ciphertext(encryptResponse.ciphertext()).keyring(keyring).encryptionContext(encryptionContext)
    );
    if (!Arrays.equals(decryptResponse.plaintext(), EXAMPLE_DATA)) {
      throw new IllegalStateException("Decrypted plaintext does not match");
    }

    // 4. As a child of a multi keyring, it wraps the data key the generator made, so either key decrypts.
    Keyring escrowKeyring = new KeyServiceKeyring("key-2", newAesKey());
    Keyring multiKeyring = MultiKeyring.builder().generator(keyring).childKeyrings(escrowKeyring).build();
    byte[] twoCopies = esdk.encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(multiKeyring)).ciphertext();
    for (Keyring eitherKeyring : Arrays.asList(keyring, escrowKeyring)) {
      if (!Arrays.equals(esdk.decrypt(b -> b.ciphertext(twoCopies).keyring(eitherKeyring)).plaintext(), EXAMPLE_DATA)) {
        throw new IllegalStateException("A copy of the data key did not decrypt");
      }
    }

    // 5. A keyring for another key name finds no encrypted data key of its own, so it tries none.
    Keyring otherName = new KeyServiceKeyring("key-3", newAesKey());
    try {
      esdk.decrypt(b -> b.ciphertext(encryptResponse.ciphertext()).keyring(otherName));
      throw new IllegalStateException("Another key name decrypted the message");
    } catch (EsdkNoMatchingDataKeyException expected) {
      if (!expected.failures().isEmpty()) {
        throw new IllegalStateException("A keyring tried an encrypted data key that was not its own");
      }
    }

    // 6. A keyring with the right name but the wrong key tries the encrypted data key and records why it failed.
    Keyring wrongKey = new KeyServiceKeyring("key-1", newAesKey());
    try {
      esdk.decrypt(b -> b.ciphertext(encryptResponse.ciphertext()).keyring(wrongKey));
      throw new IllegalStateException("The wrong key decrypted the message");
    } catch (EsdkNoMatchingDataKeyException expected) {
      if (expected.failures().size() != 1) {
        throw new IllegalStateException("Expected one failed attempt, got " + expected.failures());
      }
    }
  }

  // A real application keeps its keys in its key service; this one makes a random key.
  // SecretBytes is destroyed at the end of the block; the SecretKey holds its own copy.
  private static SecretKey newAesKey() {
    try (SecretBytes keyBytes = SecretBytes.random(32)) {
      return keyBytes.toSecretKey("AES");
    }
  }

  /**
   * Provider id {@code example-key-service}; provider info: the key name; ciphertext: a 12-byte IV followed by
   * AES-GCM of the data key, with the canonical encryption context as additional authenticated data.
   */
  static final class KeyServiceKeyring implements Keyring {

    private static final String PROVIDER_ID = "example-key-service";
    private static final int IV_LENGTH = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String keyName;
    private final SecretKey wrappingKey;

    KeyServiceKeyring(String keyName, SecretKey wrappingKey) {
      this.keyName = keyName;
      this.wrappingKey = wrappingKey;
    }

    @Override
    public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
      EncryptionMaterials input = request.materials();
      EncryptionMaterials withKey = input;
      try {
        // The first keyring generates the data key; later ones only wrap it.
        if (!input.plaintextDataKey().isPresent()) {
          try (SecretBytes generated = SecretBytes.random(input.algorithmSuite().dataKeyLength())) {
            withKey = input.withPlaintextDataKey(generated);
          }
        }
        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);
        byte[] dataKey = withKey.plaintextDataKey().get().toByteArray();
        byte[] wrapped;
        try {
          wrapped = gcm(Cipher.ENCRYPT_MODE, iv, input.encryptionContext().canonicalBytes(), dataKey);
        } finally {
          Arrays.fill(dataKey, (byte) 0);
        }
        byte[] ciphertext = Arrays.copyOf(iv, IV_LENGTH + wrapped.length);
        System.arraycopy(wrapped, 0, ciphertext, IV_LENGTH, wrapped.length);
        EncryptedDataKey edk = EncryptedDataKey
          .builder()
          .keyProviderId(PROVIDER_ID)
          .keyProviderInfo(keyName.getBytes(StandardCharsets.UTF_8))
          .ciphertext(ciphertext)
          .build();
        return OnEncryptResponse.builder().materials(withKey.withEncryptedDataKey(edk)).build();
      } finally {
        // Each with* call copies the data key, so the in-between materials hold a copy no caller will destroy.
        if (withKey != input) {
          withKey.destroy();
        }
      }
    }

    @Override
    public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
      DecryptionMaterials materials = request.materials();
      if (materials.plaintextDataKey().isPresent()) {
        throw new InvalidMaterialsException("Decryption materials already hold a data key");
      }
      byte[] aad = materials.encryptionContext().canonicalBytes();
      byte[] providerInfo = keyName.getBytes(StandardCharsets.UTF_8);
      // Each failed attempt is kept and the next key is tried, so the caller can see why no key decrypted.
      List<Throwable> failures = new ArrayList<>();
      for (EncryptedDataKey edk : request.encryptedDataKeys()) {
        if (!PROVIDER_ID.equals(edk.keyProviderId()) || !Arrays.equals(providerInfo, edk.keyProviderInfo())) {
          continue;
        }
        byte[] ciphertext = edk.ciphertext();
        byte[] dataKey = null;
        try {
          byte[] iv = Arrays.copyOf(ciphertext, IV_LENGTH);
          dataKey = gcm(Cipher.DECRYPT_MODE, iv, aad, Arrays.copyOfRange(ciphertext, IV_LENGTH, ciphertext.length));
          try (SecretBytes secret = SecretBytes.copyOf(dataKey)) {
            return OnDecryptResponse.builder().materials(materials.withPlaintextDataKey(secret)).build();
          }
        } catch (RuntimeException e) {
          // A short ciphertext, a tag that does not verify, or a key of the wrong length.
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
