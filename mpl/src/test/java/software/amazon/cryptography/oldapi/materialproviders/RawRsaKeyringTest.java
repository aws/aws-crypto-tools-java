// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawRsaKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.PaddingScheme;

// Differential tests of the Raw RSA keyring against the published Dafny-based MPL.
// Encryption is randomized, so each side decrypts both sides' encrypted data keys;
// decryption and every failure are deterministic and compared exactly.
class RawRsaKeyringTest {

  private static final String NAMESPACE = "namespace";
  private static final String NAME = "name";
  private static final KeyPair RSA_2048 = keyPair(2048);
  private static final KeyPair RSA_1024 = keyPair(1024);

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  @Test
  //= spec/framework/raw-rsa-keyring.md#changelog
  //= type=test
  //# Raw RSA keyring MUST NOT accept a key namespace of "aws-kms".
  void create() {
    String surrogate = "a\uD800b";
    List<CreateRawRsaKeyringInput> inputs = new ArrayList<>();
    for (String namespace : Arrays.asList(NAMESPACE, "aws-kms", surrogate, repeat('n', 65535), repeat('n', 65536))) {
      inputs.add(input(namespace, NAME, PaddingScheme.PKCS1, publicPem(RSA_2048), privatePem(RSA_2048)));
    }
    for (String name : Arrays.asList("", surrogate, repeat('n', 65536))) {
      inputs.add(input(NAMESPACE, name, PaddingScheme.PKCS1, publicPem(RSA_2048), null));
    }
    inputs.add(input(NAMESPACE, NAME, PaddingScheme.PKCS1, null, null));
    inputs.add(input("aws-kms", surrogate, PaddingScheme.PKCS1, null, null));
    inputs.add(input(surrogate, NAME, PaddingScheme.PKCS1, null, null));
    inputs.add(input(NAMESPACE, NAME, PaddingScheme.PKCS1, new byte[0], null));
    inputs.add(input(NAMESPACE, NAME, PaddingScheme.PKCS1, null, new byte[0]));
    inputs.add(input(NAMESPACE, NAME, PaddingScheme.PKCS1, bytes(10, 1), bytes(10, 2)));
    for (CreateRawRsaKeyringInput input : inputs) {
      String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "CreateRawRsaKeyring", input) == null ? "null" : "keyring");
      String actual = ReferenceMpl.outcome(() -> MPL.CreateRawRsaKeyring(input) == null ? "null" : "keyring");
      assertEquals(expected, actual, ReferenceMpl.describe(input.keyNamespace()) + " " + ReferenceMpl.describe(input.keyName()));
      outcomes.record("Create", actual);
    }
    outcomes.assertBothSeen("Create");
  }

  @Test
  //= spec/framework/raw-rsa-keyring.md#onencrypt
  //= type=test
  //# The keyring MUST attempt to encrypt the plaintext data key in the
  //# [encryption materials](structures.md#encryption-materials) using RSA.
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=test
  //# If any decryption succeeds, this keyring MUST immediately return the
  //# input [decryption materials](structures.md#decryption-materials),
  //# modified in the following ways:
  void eachSideDecryptsTheOther() {
    for (PaddingScheme padding : PaddingScheme.values()) {
      Pair keyring = rsa(input(NAMESPACE, NAME, padding, publicPem(RSA_2048), privatePem(RSA_2048)));
      for (AlgorithmSuiteId suite : allSuites()) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
          String context = padding + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
          keyring.assertSameEncrypt(outcomes, start, context);
          for (EncryptionMaterials result : Arrays.asList(keyring.nativeEncrypt(start), keyring.referenceEncrypt(start))) {
            String decrypted = keyring.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context);
            assertEquals(ReferenceMpl.describe(expectedDecryption(result)), decrypted, context);
          }
        }
      }
    }
  }

  @Test
  //= spec/framework/raw-rsa-keyring.md#onencrypt
  //= type=test
  //# OnEncrypt MUST fail if this keyring does not have a specified [public
  //# key](#public-key).
  void encryptFailures() {
    List<CreateRawRsaKeyringInput> inputs = Arrays.asList(
      input(NAMESPACE, NAME, PaddingScheme.PKCS1, null, privatePem(RSA_2048)),
      input(NAMESPACE, NAME, PaddingScheme.PKCS1, new byte[0], privatePem(RSA_2048)),
      input(NAMESPACE, NAME, PaddingScheme.PKCS1, bytes(10, 1), null),
      input(NAMESPACE, NAME, PaddingScheme.PKCS1, privatePem(RSA_2048), null),
      // 1024-bit OAEP with SHA-512 has no room for any plaintext.
      input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA512_MGF1, publicPem(RSA_1024), null),
      input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA384_MGF1, publicPem(RSA_1024), null)
    );
    for (CreateRawRsaKeyringInput input : inputs) {
      Pair keyring = rsa(input);
      for (AlgorithmSuiteId suite : allSuites()) {
        keyring.assertSameEncrypt(outcomes, encryptionMaterials(suite, map("a", "b"), false), input.paddingScheme().toString());
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  @Test
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=test
  //# If no decryption succeeds, the keyring MUST fail and MUST NOT modify
  //# the [decryption materials](structures.md#decryption-materials).
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=test
  //# The keyring MUST attempt to decrypt the input encrypted data keys, in
  //# list order, until it successfully decrypts one.
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=test
  //# OnDecrypt MUST fail if this keyring does not have a specified [private
  //# key](#private-key).
  //= spec/framework/raw-rsa-keyring.md#ondecrypt
  //= type=test
  //# If the decryption materials already contain a plaintext data key, the
  //# keyring MUST fail and MUST NOT modify the [decryption materials]
  //# (structures.md#decryption-materials).
  void decryptFailures() {
    Pair keyring = rsa(input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA256_MGF1, publicPem(RSA_2048), privatePem(RSA_2048)));
    List<Pair> others = Arrays.asList(
      rsa(input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA256_MGF1, publicPem(RSA_2048), null)),
      rsa(input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA256_MGF1, null, new byte[0])),
      rsa(input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA256_MGF1, null, bytes(20, 3))),
      rsa(input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA1_MGF1, null, privatePem(RSA_2048))),
      rsa(input(NAMESPACE, NAME, PaddingScheme.PKCS1, null, privatePem(RSA_2048))),
      rsa(input(NAMESPACE, NAME, PaddingScheme.OAEP_SHA256_MGF1, null, privatePem(RSA_1024)))
    );
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials encrypted = keyring.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      int dataKeyLength = array(encrypted.plaintextDataKey()).length;
      byte[] name = NAME.getBytes(StandardCharsets.UTF_8);

      List<List<EncryptedDataKey>> edkLists = new ArrayList<>();
      edkLists.add(Collections.emptyList());
      edkLists.add(Collections.singletonList(good));
      edkLists.add(Collections.singletonList(edk("other", name, ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, "nam".getBytes(StandardCharsets.UTF_8), ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, new byte[] { (byte) 0xff }, ciphertext)));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, name, new byte[0])));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, name, flip(ciphertext, 10))));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, name, Arrays.copyOf(ciphertext, 100))));
      edkLists.add(Collections.singletonList(edk(NAMESPACE, name, Arrays.copyOf(ciphertext, ciphertext.length - 1))));
      // A wrapped key of the wrong length.
      for (int wrongLength : new int[] { 1, dataKeyLength - 1, dataKeyLength + 1 }) {
        edkLists.add(Collections.singletonList(edk(NAMESPACE, name, oaepSha256(bytes(wrongLength, 5)))));
      }
      edkLists.add(Arrays.asList(edk("other", name, ciphertext), edk(NAMESPACE, name, flip(ciphertext, 3)), good));

      for (List<EncryptedDataKey> edks : edkLists) {
        keyring.assertSameDecrypt(outcomes, materials, edks, ReferenceMpl.describe(suite));
        for (Pair other : others) {
          other.assertSameDecrypt(outcomes, materials, edks, ReferenceMpl.describe(suite));
        }
      }
      DecryptionMaterials decrypted = keyring.nativeDecrypt(materials, Collections.singletonList(good));
      keyring.assertSameDecrypt(outcomes, decrypted, Collections.singletonList(good), ReferenceMpl.describe(suite));
      DecryptionMaterials invalid = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
      keyring.assertSameDecrypt(outcomes, invalid, Collections.singletonList(good), ReferenceMpl.describe(suite));
      others.get(0).assertSameDecrypt(outcomes, decrypted, Collections.singletonList(good), ReferenceMpl.describe(suite));
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  private Pair rsa(CreateRawRsaKeyringInput input) {
    return new Pair(MPL.CreateRawRsaKeyring(input), ReferenceMpl.call(reference, "CreateRawRsaKeyring", input));
  }

  private static CreateRawRsaKeyringInput input(String namespace, String name, PaddingScheme padding, byte[] publicKey, byte[] privateKey) {
    return CreateRawRsaKeyringInput
      .builder()
      .keyNamespace(namespace)
      .keyName(name)
      .paddingScheme(padding)
      .publicKey(publicKey == null ? null : ByteBuffer.wrap(publicKey))
      .privateKey(privateKey == null ? null : ByteBuffer.wrap(privateKey))
      .build();
  }

  private static ByteBuffer oaepSha256(byte[] plaintext) {
    try {
      Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
      cipher.init(
        Cipher.ENCRYPT_MODE,
        RSA_2048.getPublic(),
        new javax.crypto.spec.OAEPParameterSpec("SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, javax.crypto.spec.PSource.PSpecified.DEFAULT)
      );
      return ByteBuffer.wrap(cipher.doFinal(plaintext));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static KeyPair keyPair(int bits) {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(bits);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] publicPem(KeyPair pair) {
    return pem("PUBLIC KEY", pair.getPublic().getEncoded());
  }

  private static byte[] privatePem(KeyPair pair) {
    return pem("PRIVATE KEY", pair.getPrivate().getEncoded());
  }

  private static byte[] pem(String type, byte[] der) {
    String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    return ("-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n").getBytes(StandardCharsets.US_ASCII);
  }
}
