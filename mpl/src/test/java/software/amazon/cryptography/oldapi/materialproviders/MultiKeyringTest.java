// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;

// Differential tests of the multi keyring against the published Dafny-based MPL, over built-in children,
// nested multi keyrings, and caller-implemented keyrings that fail or return invalid materials.
class MultiKeyringTest {

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  private final Pair a = aes("a-namespace", "a", 32, AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16);
  private final Pair b = aes("b-namespace", "b", 16, AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16);
  private final Map<String, Pair> custom = customKeyrings();

  @Test
  //= spec/framework/multi-keyring.md#inputs
  //= type=test
  //# On keyring initialization, a keyring MUST define at least one of the
  //# following:
  void create() {
    List<CreateMultiKeyringInput> inputs = Arrays.asList(
      multiInput(null, Collections.emptyList()),
      multiInput(a, Collections.emptyList()),
      multiInput(null, Collections.singletonList(b)),
      multiInput(a, Arrays.asList(b, a))
    );
    for (CreateMultiKeyringInput input : inputs) {
      String expected = ReferenceMpl.outcome(() -> created(ReferenceMpl.call(reference, "CreateMultiKeyring", input)));
      String actual = ReferenceMpl.outcome(() -> created(MPL.CreateMultiKeyring(input)));
      assertEquals(expected, actual);
      outcomes.record("CreateMultiKeyring", actual);
    }
    outcomes.assertBothSeen("CreateMultiKeyring");
  }

  @Test
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# If this keyring has a generator keyring, this keyring MUST first
  //# generate a plaintext data key using the generator keyring:
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# *  This keyring MUST first call the generator keyring's OnEncrypt
  //# using the input encryption materials as input.
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# Next, for each [keyring](keyring-interface.md) in this keyring's list
  //# of [child keyring](#child-keyrings), the keyring MUST call [OnEncrypt]
  //# (keyring-interface.md#onencrypt).
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# If all previous [OnEncrypt](keyring-interface.md#onencrypt) calls
  //# succeeded, this keyring MUST return the [encryption materials]
  //# (structures.md#encryption-materials) returned by the last OnEncrypt
  //# call.
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# If the child keyring's [OnEncrypt](keyring-
  //# interface.md#onencrypt) fails, this OnEncrypt MUST also fail.
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# *  If the generator keyring fails OnEncrypt, this OnEncrypt MUST also
  //# fail.
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# *  If the generator keyring returns encryption materials missing a
  //# plaintext data key, OnEncrypt MUST fail.
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# If this keyring does not have a [generator keyring](#generator-keyring),
  //# and the input [encryption materials](structures.md#encryption-
  //# materials) does not include a plaintext data key, OnEncrypt MUST
  //# fail.
  //= spec/framework/multi-keyring.md#onencrypt
  //= type=test
  //# - If the input encryption materials already include a plaintext data
  //# key, OnEncrypt MUST fail.
  void encrypt() {
    for (Map.Entry<String, Pair> generator : generators().entrySet()) {
      for (Map.Entry<String, List<Pair>> children : childLists().entrySet()) {
        if (generator.getValue() == null && children.getValue().isEmpty()) {
          continue;
        }
        Pair multi = multi(generator.getValue(), children.getValue());
        for (AlgorithmSuiteId suite : suites()) {
          for (boolean withDataKey : new boolean[] { false, true }) {
            EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
            String context = "generator " + generator.getKey() + " children " + children.getKey() + " data key " + withDataKey;
            String outcome = multi.assertSameEncrypt(outcomes, start, context);
            assertSameReceived(context);
            if (!outcome.startsWith("throws")) {
              // Each side recovers the data key from the other's encrypted data keys, and each key on its own
              // yields the symmetric signing key at its position.
              for (EncryptionMaterials result : Arrays.asList(multi.nativeEncrypt(start), multi.referenceEncrypt(start))) {
                String decrypted = multi.assertSameDecrypt(outcomes, decryptionMaterials(result), result.encryptedDataKeys(), context);
                assertEquals(false, decrypted.startsWith("throws"), context + " " + decrypted);
                List<EncryptedDataKey> edks = result.encryptedDataKeys();
                for (int i = 0; i < edks.size(); i++) {
                  String one = multi.assertSameDecrypt(outcomes, decryptionMaterials(result), Collections.singletonList(edks.get(i)), context);
                  if (!one.startsWith("throws")) {
                    assertEquals(ReferenceMpl.describe(expectedDecryption(result, i)), one, context + " edk " + i);
                  }
                }
              }
              forgetReceived();
            }
          }
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  @Test
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# Otherwise, OnDecrypt MUST first attempt to decrypt the [encrypted data
  //# keys](structures.md#encrypted-data-keys-1) in the input [decryption
  //# materials](structures.md#decryption-materials) using its
  //# [generator keyring](#generator-keyring).
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# If the generator keyring is unable to
  //# decrypt the materials, the multi-keyring MUST attempt to decrypt
  //# using its child keyrings, until one either succeeds in decryption or
  //# all have failed.
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# For each [keyring](keyring-interface.md) to be used for decryption,
  //# the multi-keyring MUST call that keyring's [OnDecrypt](keyring-
  //# interface.md#ondecrypt) using the unmodified [decryption materials]
  //# (structures.md#decryption-materials) and the input [encrypted data key]
  //# (structures.md#encrypted-data-key) list.
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# If [OnDecrypt](keyring-
  //# interface.md#ondecrypt) returns [decryption materials]
  //# (structures.md#decryption-materials) containing a plaintext data key,
  //# the multi-keyring MUST immediately return the modified decryption
  //# materials.
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# If the child keyring's OnDecrypt call fails, the multi-
  //# keyring MUST collect the error and continue to the next keyring, if
  //# any.
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# If, after calling [OnDecrypt](keyring-interface.md#ondecrypt) on every
  //# [child keyring](#child-keyrings) (and possibly the [generator keyring]
  //# (#generator-keyring)), the [decryption materials](structures.md#decryption-
  //# materials) still do not contain a plaintext data key, OnDecrypt MUST
  //# return a failure message containing the collected failure messages
  //# from the child keyrings.
  //= spec/framework/multi-keyring.md#ondecrypt
  //= type=test
  //# If the decryption materials already contain a plaintext data key, the
  //# keyring MUST fail and MUST NOT modify the [decryption materials]
  //# (structures.md#decryption-materials).
  void decrypt() {
    for (AlgorithmSuiteId suite : suites()) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      EncryptedDataKey fromA = a.nativeEncrypt(start).encryptedDataKeys().get(0);
      EncryptionMaterials encrypted = b.nativeEncrypt(start);
      EncryptedDataKey fromB = encrypted.encryptedDataKeys().get(0);
      EncryptedDataKey junk = edk("a-namespace", new byte[3], new byte[3]);
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      DecryptionMaterials withDataKey = b.nativeDecrypt(materials, Collections.singletonList(fromB));
      DecryptionMaterials invalid = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
      List<List<EncryptedDataKey>> edkLists = Arrays.asList(
        Collections.<EncryptedDataKey>emptyList(),
        Collections.singletonList(fromA),
        Collections.singletonList(fromB),
        Arrays.asList(fromB, fromA),
        Arrays.asList(junk, fromA),
        Collections.singletonList(junk)
      );
      for (Map.Entry<String, Pair> generator : generators().entrySet()) {
        for (Map.Entry<String, List<Pair>> children : childLists().entrySet()) {
          if (generator.getValue() == null && children.getValue().isEmpty()) {
            continue;
          }
          Pair multi = multi(generator.getValue(), children.getValue());
          String context = ReferenceMpl.describe(suite) + " generator " + generator.getKey() + " children " + children.getKey();
          for (List<EncryptedDataKey> edks : edkLists) {
            multi.assertSameDecrypt(outcomes, materials, edks, context);
            assertSameReceived(context);
          }
          multi.assertSameDecrypt(outcomes, withDataKey, Collections.singletonList(fromB), context);
          multi.assertSameDecrypt(outcomes, invalid, Collections.singletonList(fromB), context);
        }
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  private void assertSameReceived(String context) {
    for (Pair keyring : custom.values()) {
      keyring.assertSameReceived(context);
    }
  }

  // The extra encrypts for cross-decryption reach the caller keyrings with fresh random materials.
  private void forgetReceived() {
    for (Pair keyring : custom.values()) {
      keyring.assertSameReceived("");
    }
  }

  private Map<String, Pair> generators() {
    Map<String, Pair> generators = new LinkedHashMap<>();
    generators.put("none", null);
    generators.put("a", a);
    generators.put("multi(a, [b])", multi(a, Collections.singletonList(b)));
    generators.putAll(custom);
    return generators;
  }

  private Map<String, List<Pair>> childLists() {
    Map<String, List<Pair>> lists = new LinkedHashMap<>();
    lists.put("[]", Collections.emptyList());
    lists.put("[b]", Collections.singletonList(b));
    lists.put("[b, a]", Arrays.asList(b, a));
    lists.put("[multi(none, [b])]", Collections.singletonList(multi(null, Collections.singletonList(b))));
    for (Map.Entry<String, Pair> entry : custom.entrySet()) {
      lists.put("[" + entry.getKey() + "]", Collections.singletonList(entry.getValue()));
      lists.put("[" + entry.getKey() + ", a]", Arrays.asList(entry.getValue(), a));
    }
    return lists;
  }

  // Keyrings a caller might implement; all but the delegating one are wrong in some way.
  private Map<String, Pair> customKeyrings() {
    Map<String, Pair> keyrings = new LinkedHashMap<>();
    keyrings.put("delegates to a", Pair.custom(a::OnEncrypt, a::OnDecrypt));
    keyrings.put(
      "throws",
      Pair.custom(
        input -> {
          throw AwsCryptographicMaterialProvidersException.builder().message("custom failure").build();
        },
        input -> {
          throw AwsCryptographicMaterialProvidersException.builder().message("custom failure").build();
        }
      )
    );
    keyrings.put(
      "throws IllegalStateException",
      Pair.custom(
        input -> {
          throw new IllegalStateException("boom");
        },
        input -> {
          throw new IllegalStateException("boom");
        }
      )
    );
    keyrings.put(
      "returns its input",
      Pair.custom(
        input -> OnEncryptOutput.builder().materials(input.materials()).build(),
        input -> OnDecryptOutput.builder().materials(input.materials()).build()
      )
    );
    keyrings.put(
      "changes the context",
      Pair.custom(
        input -> {
          EncryptionMaterials m = a.OnEncrypt(input).materials();
          return OnEncryptOutput.builder().materials(m.toBuilder().encryptionContext(with(m.encryptionContext(), "x", "y")).build()).build();
        },
        input -> {
          DecryptionMaterials m = a.OnDecrypt(input).materials();
          return OnDecryptOutput.builder().materials(m.toBuilder().encryptionContext(with(m.encryptionContext(), "x", "y")).build()).build();
        }
      )
    );
    keyrings.put(
      "returns a context that is not UTF-8",
      Pair.custom(
        input -> {
          EncryptionMaterials m = a.OnEncrypt(input).materials();
          return OnEncryptOutput.builder().materials(m.toBuilder().encryptionContext(with(m.encryptionContext(), "x", "\uD800")).build()).build();
        },
        input -> {
          DecryptionMaterials m = a.OnDecrypt(input).materials();
          return OnDecryptOutput.builder().materials(m.toBuilder().encryptionContext(with(m.encryptionContext(), "x", "\uD800")).build()).build();
        }
      )
    );
    keyrings.put(
      "drops encrypted data keys",
      Pair.custom(
        input -> {
          EncryptionMaterials m = a.OnEncrypt(input).materials();
          return OnEncryptOutput.builder().materials(m.toBuilder().encryptedDataKeys(Collections.emptyList()).build()).build();
        },
        input -> {
          DecryptionMaterials m = a.OnDecrypt(input).materials();
          return OnDecryptOutput.builder().materials(m.toBuilder().plaintextDataKey(ByteBuffer.wrap(new byte[3])).build()).build();
        }
      )
    );
    return keyrings;
  }

  private Pair multi(Pair generator, List<Pair> children) {
    CreateMultiKeyringInput input = multiInput(generator, children);
    List<IKeyring> nativeChildren = new ArrayList<>();
    for (Pair child : children) {
      nativeChildren.add(child.nativeKeyring);
    }
    CreateMultiKeyringInput.Builder nativeInput = CreateMultiKeyringInput.builder().childKeyrings(nativeChildren);
    if (generator != null) {
      nativeInput.generator(generator.nativeKeyring);
    }
    return new Pair(MPL.CreateMultiKeyring(nativeInput.build()), ReferenceMpl.call(reference, "CreateMultiKeyring", input));
  }

  private static CreateMultiKeyringInput multiInput(Pair generator, List<Pair> children) {
    CreateMultiKeyringInput.Builder input = CreateMultiKeyringInput.builder().childKeyrings(new ArrayList<>(children));
    if (generator != null) {
      input.generator(generator);
    }
    return input.build();
  }

  private Pair aes(String namespace, String name, int keyLength, AesWrappingAlg alg) {
    CreateRawAesKeyringInput input = CreateRawAesKeyringInput
      .builder()
      .keyNamespace(namespace)
      .keyName(name)
      .wrappingKey(ByteBuffer.wrap(bytes(keyLength, name.charAt(0))))
      .wrappingAlg(alg)
      .build();
    return new Pair(MPL.CreateRawAesKeyring(input), ReferenceMpl.call(reference, "CreateRawAesKeyring", input));
  }

  private static List<AlgorithmSuiteId> suites() {
    return Arrays.asList(
      AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF).build(),
      AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384).build(),
      AlgorithmSuiteId.builder().DBE(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384).build()
    );
  }

  private static Map<String, String> with(Map<String, String> base, String key, String value) {
    Map<String, String> copy = new java.util.HashMap<>(base);
    copy.put(key, value);
    return copy;
  }

  private static String created(Object keyring) {
    return keyring == null ? "null" : "keyring";
  }
}
