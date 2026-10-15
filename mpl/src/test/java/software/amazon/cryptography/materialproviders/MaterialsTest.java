// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.InitializeDecryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.InitializeEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.ValidDecryptionMaterialsTransitionInput;
import software.amazon.cryptography.materialproviders.model.ValidEncryptionMaterialsTransitionInput;

// Differential tests against the published Dafny-based MPL.
// Each case runs on both libraries and must produce the same result or the same exception and message.
// Materials come from a per-suite pool of valid and deliberately invalid variants;
// the transition tests run every ordered pair from the pool.
class MaterialsTest {

  private static final String PUBLIC_KEY_FIELD = "aws-crypto-public-key";

  private final MaterialProviders mpl = MaterialProviders
    .builder()
    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.materialProviders();
  private final Map<String, Integer> outcomes = new TreeMap<>();

  @Test
  void initializeEncryptionMaterials() {
    for (AlgorithmSuiteId suite : allSuites()) {
      for (Map<String, String> encryptionContext : encryptionContexts()) {
        for (List<String> required : requiredKeyLists()) {
          for (ByteBuffer[] keys : signingKeyPairs()) {
            InitializeEncryptionMaterialsInput input = InitializeEncryptionMaterialsInput
              .builder()
              .algorithmSuiteId(suite)
              .encryptionContext(encryptionContext)
              .requiredEncryptionContextKeys(required)
              .signingKey(keys[0])
              .verificationKey(keys[1])
              .build();
            assertSame("InitializeEncryptionMaterials", input, () -> mpl.InitializeEncryptionMaterials(input));
          }
        }
      }
    }
    assertBothOutcomesSeen("InitializeEncryptionMaterials");
  }

  @Test
  void initializeDecryptionMaterials() {
    for (AlgorithmSuiteId suite : allSuites()) {
      List<Map<String, String>> contexts = new ArrayList<>(encryptionContexts());
      for (String encoded : verificationKeyEncodings()) {
        contexts.add(map("a", "b", PUBLIC_KEY_FIELD, encoded));
      }
      for (Map<String, String> encryptionContext : contexts) {
        for (List<String> required : requiredKeyLists()) {
          InitializeDecryptionMaterialsInput input = InitializeDecryptionMaterialsInput
            .builder()
            .algorithmSuiteId(suite)
            .encryptionContext(encryptionContext)
            .requiredEncryptionContextKeys(required)
            .build();
          assertSame("InitializeDecryptionMaterials", input, () -> mpl.InitializeDecryptionMaterials(input));
        }
      }
    }
    assertBothOutcomesSeen("InitializeDecryptionMaterials");
  }

  //= spec/framework/structures.md#signing-key
  //= type=test
  //# If the
  //# algorithm suite does not contain an asymmetric signing algorithm, the signing key
  //# MUST NOT be present.
  //
  //= spec/framework/structures.md#plaintext-data-key
  //= type=test
  //# The plaintext data key MUST:
  //# - Fit the specification for the [key derivation algorithm](algorithm-
  //#   suites.md#key-derivation-algorithm) included in this decryption
  //#   material's [algorithm suite](#algorithm-suite).
  //
  //= spec/framework/structures.md#encrypted-data-keys
  //= type=test
  //# If the plaintext data key is not included in this set of encryption
  //# materials, this list MUST be empty.
  //
  //= spec/framework/structures.md#encryption-context-1
  //= type=test
  //# If an [encryption material](#encryption-materials) contains a [signing key]
  //# (#signing-key), the [encryption context](#encryption-context) SHOULD
  //# include the reserved key `aws-crypto-public-key`.
  //
  //= spec/framework/structures.md#symmetric-signing-keys
  //= type=test
  //# If the algorithm suite does contain a symmetric signing algorithm, this list MUST have length equal to the [encrypted data key list](#encrypted-data-keys).
  //
  //= spec/framework/structures.md#required-encryption-context-keys
  //= type=test
  //# Every key in Required Encryption Context Keys
  //# MUST be a key in the [encryption context](#encryption-context-1).
  //
  //= spec/framework/cmm-interface.md#get-encryption-materials
  //= type=test
  //# The encryption materials returned MUST include the following:
  @Test
  void encryptionMaterialsPredicatesAndTransitions() {
    for (AlgorithmSuiteId suite : allSuites()) {
      List<EncryptionMaterials> pool = encryptionPool(suite);
      for (EncryptionMaterials materials : pool) {
        assertSame("EncryptionMaterialsHasPlaintextDataKey", materials, () -> {
          mpl.EncryptionMaterialsHasPlaintextDataKey(materials);
          return null;
        });
      }
      for (EncryptionMaterials start : pool) {
        for (EncryptionMaterials stop : pool) {
          ValidEncryptionMaterialsTransitionInput input = ValidEncryptionMaterialsTransitionInput
            .builder()
            .start(start)
            .stop(stop)
            .build();
          assertSame("ValidEncryptionMaterialsTransition", input, () -> {
            mpl.ValidEncryptionMaterialsTransition(input);
            return null;
          });
        }
      }
    }
    assertBothOutcomesSeen("EncryptionMaterialsHasPlaintextDataKey");
    assertBothOutcomesSeen("ValidEncryptionMaterialsTransition");
  }

  //= spec/framework/structures.md#plaintext-data-key-1
  //= type=test
  //# The plaintext data key MUST:
  //# - Fit the specification for the [encryption algorithm](algorithm-
  //# suites.md#encryption-algorithm)  included in this decryption
  //# material's [algorithm suite](#algorithm-suite-1).
  //
  //= spec/framework/structures.md#encryption-context-2
  //= type=test
  //# If a [decryption materials](#decryption-materials) contains a [verification key]
  //# (#verification-key), the [encryption context](#encryption-context) SHOULD
  //# include the reserved key `aws-crypto-public-key`.
  //
  //= spec/framework/structures.md#symmetric-signing-key
  //= type=test
  //# If the algorithm suite does contain a symmetric signing algorithm,
  //# the symmetric signing key MUST also be included in the materials
  //# if and only if the materials also include a [plaintext data key](#plaintext-data-key-1).
  //
  //= spec/framework/structures.md#symmetric-signing-key
  //= type=test
  //# If the algorithm suite does not contain a symmetric signing algorithm,
  //# the symmetric signing key MUST NOT be included in the materials.
  //
  //= spec/framework/structures.md#required-encryption-context-keys-1
  //= type=test
  //# Every key in Required Encryption Context Keys
  //# MUST be a key in the [encryption context](#encryption-context-2).
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //= type=test
  //# The decryption materials returned MUST include the following:
  @Test
  void decryptionMaterialsPredicatesAndTransitions() {
    for (AlgorithmSuiteId suite : allSuites()) {
      List<DecryptionMaterials> pool = decryptionPool(suite);
      for (DecryptionMaterials materials : pool) {
        assertSame("DecryptionMaterialsWithPlaintextDataKey", materials, () -> {
          mpl.DecryptionMaterialsWithPlaintextDataKey(materials);
          return null;
        });
      }
      for (DecryptionMaterials start : pool) {
        for (DecryptionMaterials stop : pool) {
          ValidDecryptionMaterialsTransitionInput input = ValidDecryptionMaterialsTransitionInput
            .builder()
            .start(start)
            .stop(stop)
            .build();
          assertSame("ValidDecryptionMaterialsTransition", input, () -> {
            mpl.ValidDecryptionMaterialsTransition(input);
            return null;
          });
        }
      }
    }
    assertBothOutcomesSeen("DecryptionMaterialsWithPlaintextDataKey");
    assertBothOutcomesSeen("ValidDecryptionMaterialsTransition");
  }

  // Valid encryption materials at each stage, then single-field breakages of the most complete one.
  private List<EncryptionMaterials> encryptionPool(AlgorithmSuiteId suite) {
    EncryptionMaterials empty = initialEncryptionMaterials(suite);
    boolean symmetric = empty.symmetricSigningKeys() != null;
    int keyLength = empty.algorithmSuite().encrypt().AES_GCM().keyLength();
    EncryptionMaterials withKey = empty.toBuilder().plaintextDataKey(bytes(keyLength, 1)).build();
    EncryptionMaterials oneEdk = addEdks(withKey, symmetric, edk(1));
    EncryptionMaterials twoEdks = addEdks(oneEdk, symmetric, edk(2));

    Map<String, Function<EncryptionMaterials.Builder, EncryptionMaterials.Builder>> breakages = new LinkedHashMap<>();
    breakages.put("short plaintext data key", b -> b.plaintextDataKey(bytes(keyLength - 1, 1)));
    breakages.put("different plaintext data key", b -> b.plaintextDataKey(bytes(keyLength, 9)));
    breakages.put("no plaintext data key", b -> b.plaintextDataKey(null));
    breakages.put("extra encryption context", b -> b.encryptionContext(with(twoEdks.encryptionContext(), "x", "y")));
    breakages.put("no required keys", b -> b.requiredEncryptionContextKeys(new ArrayList<>()));
    breakages.put("required key not in context", b -> b.requiredEncryptionContextKeys(Arrays.asList("a", "missing")));
    breakages.put("different signing key", b -> b.signingKey(bytes(48, 7)));
    breakages.put("no signing key", b -> b.signingKey(null));
    breakages.put("reordered edks", b -> b.encryptedDataKeys(reversed(twoEdks.encryptedDataKeys()))
      .symmetricSigningKeys(symmetric ? reversed(twoEdks.symmetricSigningKeys()) : null));
    breakages.put("duplicated edk", b -> b.encryptedDataKeys(Arrays.asList(edk(1), edk(1)))
      .symmetricSigningKeys(symmetric ? Arrays.asList(bytes(32, 1), bytes(32, 1)) : null));
    breakages.put("replaced edk", b -> b.encryptedDataKeys(Arrays.asList(edk(1), edk(3))));
    breakages.put("symmetric keys absent", b -> b.symmetricSigningKeys(null));
    breakages.put("symmetric keys empty", b -> b.symmetricSigningKeys(new ArrayList<>()));
    breakages.put("one symmetric key short", b -> b.symmetricSigningKeys(Collections.singletonList(bytes(32, 1))));
    breakages.put("other suite", b -> b.algorithmSuite(otherSuite(suite)));
    breakages.put("public key field removed", b -> b.encryptionContext(without(twoEdks.encryptionContext(), PUBLIC_KEY_FIELD)));
    breakages.put("context value changed", b -> b.encryptionContext(with(twoEdks.encryptionContext(), "a", "changed")));
    breakages.put("edk provider id changed", b -> b.encryptedDataKeys(Arrays.asList(edk(1), edk(2).toBuilder().keyProviderId("other").build())));
    breakages.put("edk provider info changed", b -> b.encryptedDataKeys(Arrays.asList(edk(1), edk(2).toBuilder().keyProviderInfo(bytes(4, 99)).build())));
    breakages.put("edk ciphertext changed", b -> b.encryptedDataKeys(Arrays.asList(edk(1), edk(2).toBuilder().ciphertext(bytes(16, 99)).build())));
    breakages.put("symmetric keys changed", b -> b.symmetricSigningKeys(symmetric ? Arrays.asList(bytes(32, 98), bytes(32, 99)) : null));
    breakages.put("suite description altered", b -> b.algorithmSuite(twoEdks.algorithmSuite().toBuilder().messageVersion(9).build()));
    breakages.put("plaintext data key read past position", b -> b.plaintextDataKey(positioned(keyLength, 3)));
    breakages.put("plaintext data key at an offset", b -> b.plaintextDataKey(ByteBuffer.wrap(new byte[keyLength + 2], 2, keyLength)));
    breakages.put("lone surrogate in context", b -> b.encryptionContext(with(twoEdks.encryptionContext(), "x", "\uD800")));
    breakages.put("null symmetric key", b -> b.symmetricSigningKeys(symmetric ? Arrays.asList(bytes(32, 1), null) : null));

    List<EncryptionMaterials> pool = new ArrayList<>(Arrays.asList(empty, withKey, oneEdk, twoEdks));
    pool.add(empty.toBuilder().symmetricSigningKeys(null).build());
    pool.add(empty.toBuilder().encryptedDataKeys(Collections.singletonList(edk(1))).build());
    for (Function<EncryptionMaterials.Builder, EncryptionMaterials.Builder> breakage : breakages.values()) {
      pool.add(breakage.apply(twoEdks.toBuilder()).build());
    }
    // Same context and required keys in two orders: the Dafny-based MPL compares the list, not the set.
    Map<String, String> wider = with(twoEdks.encryptionContext(), "c", "d");
    pool.add(twoEdks.toBuilder().encryptionContext(wider).requiredEncryptionContextKeys(Arrays.asList("a", "c")).build());
    pool.add(twoEdks.toBuilder().encryptionContext(wider).requiredEncryptionContextKeys(Arrays.asList("c", "a")).build());
    return pool;
  }

  private List<DecryptionMaterials> decryptionPool(AlgorithmSuiteId suite) {
    Map<String, String> encryptionContext = map("a", "b");
    EncryptionMaterials encryption = initialEncryptionMaterials(suite);
    if (encryption.encryptionContext().containsKey(PUBLIC_KEY_FIELD)) {
      encryptionContext.put(PUBLIC_KEY_FIELD, encryption.encryptionContext().get(PUBLIC_KEY_FIELD));
    }
    DecryptionMaterials empty = mpl.InitializeDecryptionMaterials(
      InitializeDecryptionMaterialsInput
        .builder()
        .algorithmSuiteId(suite)
        .encryptionContext(encryptionContext)
        .requiredEncryptionContextKeys(Collections.singletonList("a"))
        .build()
    );
    boolean symmetric = encryption.symmetricSigningKeys() != null;
    int keyLength = empty.algorithmSuite().encrypt().AES_GCM().keyLength();
    DecryptionMaterials withKey = empty
      .toBuilder()
      .plaintextDataKey(bytes(keyLength, 1))
      .symmetricSigningKey(symmetric ? bytes(32, 2) : null)
      .build();

    List<DecryptionMaterials> pool = new ArrayList<>(Arrays.asList(empty, withKey));
    pool.add(withKey.toBuilder().plaintextDataKey(bytes(keyLength + 1, 1)).build());
    pool.add(withKey.toBuilder().plaintextDataKey(bytes(keyLength, 9)).build());
    pool.add(withKey.toBuilder().symmetricSigningKey(symmetric ? null : bytes(32, 2)).build());
    pool.add(empty.toBuilder().symmetricSigningKey(bytes(32, 2)).build());
    pool.add(withKey.toBuilder().encryptionContext(with(withKey.encryptionContext(), "x", "y")).build());
    pool.add(withKey.toBuilder().requiredEncryptionContextKeys(new ArrayList<>()).build());
    pool.add(withKey.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build());
    pool.add(withKey.toBuilder().verificationKey(bytes(97, 5)).build());
    pool.add(withKey.toBuilder().verificationKey(null).build());
    pool.add(withKey.toBuilder().algorithmSuite(otherSuite(suite)).build());
    pool.add(withKey.toBuilder().encryptionContext(without(withKey.encryptionContext(), PUBLIC_KEY_FIELD)).build());
    pool.add(withKey.toBuilder().encryptionContext(with(withKey.encryptionContext(), "a", "changed")).build());
    pool.add(withKey.toBuilder().algorithmSuite(withKey.algorithmSuite().toBuilder().messageVersion(9).build()).build());
    pool.add(withKey.toBuilder().plaintextDataKey(positioned(keyLength, 3)).build());
    pool.add(withKey.toBuilder().plaintextDataKey(ByteBuffer.wrap(new byte[keyLength + 2], 2, keyLength)).build());
    pool.add(withKey.toBuilder().encryptionContext(with(withKey.encryptionContext(), "x", "\uD800")).build());
    Map<String, String> wider = with(empty.encryptionContext(), "c", "d");
    pool.add(empty.toBuilder().encryptionContext(wider).requiredEncryptionContextKeys(Arrays.asList("a", "c")).build());
    pool.add(withKey.toBuilder().encryptionContext(wider).requiredEncryptionContextKeys(Arrays.asList("c", "a")).build());
    return pool;
  }

  private EncryptionMaterials initialEncryptionMaterials(AlgorithmSuiteId suite) {
    boolean signing = mpl.GetAlgorithmSuiteInfo(binaryId(suite)).signature().ECDSA() != null;
    return mpl.InitializeEncryptionMaterials(
      InitializeEncryptionMaterialsInput
        .builder()
        .algorithmSuiteId(suite)
        .encryptionContext(map("a", "b"))
        .requiredEncryptionContextKeys(Collections.singletonList("a"))
        .signingKey(signing ? bytes(48, 3) : null)
        .verificationKey(signing ? bytes(49, 4) : null)
        .build()
    );
  }

  private static EncryptionMaterials addEdks(EncryptionMaterials materials, boolean symmetric, EncryptedDataKey edk) {
    List<EncryptedDataKey> edks = new ArrayList<>(materials.encryptedDataKeys());
    edks.add(edk);
    EncryptionMaterials.Builder builder = materials.toBuilder().encryptedDataKeys(edks);
    if (symmetric) {
      List<ByteBuffer> keys = new ArrayList<>(materials.symmetricSigningKeys());
      keys.add(bytes(32, edks.size()));
      builder.symmetricSigningKeys(keys);
    }
    return builder.build();
  }

  private ByteBuffer binaryId(AlgorithmSuiteId suite) {
    String hex = suite.ESDK() != null ? suite.ESDK().toString() : suite.DBE().toString();
    int value = Integer.parseInt(hex.substring(2), 16);
    return ByteBuffer.wrap(new byte[] { (byte) (value >> 8), (byte) value });
  }

  // The suite after this one in id order, as an AlgorithmSuiteInfo.
  private software.amazon.cryptography.materialproviders.model.AlgorithmSuiteInfo otherSuite(AlgorithmSuiteId suite) {
    List<AlgorithmSuiteId> suites = allSuites();
    for (int i = 0; i < suites.size(); i++) {
      if (same(suites.get(i), suite)) {
        return mpl.GetAlgorithmSuiteInfo(binaryId(suites.get((i + 1) % suites.size())));
      }
    }
    throw new IllegalStateException();
  }

  private static boolean same(AlgorithmSuiteId a, AlgorithmSuiteId b) {
    return a.ESDK() == b.ESDK() && a.DBE() == b.DBE();
  }

  private static List<Map<String, String>> encryptionContexts() {
    return Arrays.asList(
      map(),
      map("a", "b"),
      map("a", "b", "c", "d"),
      map("a", "b", PUBLIC_KEY_FIELD, "AQ=="),
      map("\uD800", "lone high surrogate key"),
      map("a", "\uDC00 lone low surrogate value")
    );
  }

  private static List<List<String>> requiredKeyLists() {
    return Arrays.asList(
      new ArrayList<>(),
      Collections.singletonList("a"),
      Arrays.asList("a", "c"),
      Collections.singletonList("missing")
    );
  }

  private static List<ByteBuffer[]> signingKeyPairs() {
    return Arrays.asList(
      new ByteBuffer[] { null, null },
      new ByteBuffer[] { bytes(48, 1), null },
      new ByteBuffer[] { null, bytes(97, 2) },
      new ByteBuffer[] { bytes(48, 1), bytes(97, 2) },
      new ByteBuffer[] { bytes(48, 1), bytes(0, 2) },
      new ByteBuffer[] { bytes(48, 1), bytes(1, 2) },
      new ByteBuffer[] { bytes(48, 1), bytes(2, 2) }
    );
  }

  private static List<String> verificationKeyEncodings() {
    return Arrays.asList(
      "", "AQ==", "AQI=", "AQID", "AQ", "AR==", "AQJ=", "A===", "====", "A Q==", "AQ==\n", "-_8=", "AQ==AQ==", "\u00e9"
    );
  }

  // A buffer of the given length whose position is past its first bytes.
  private static ByteBuffer positioned(int length, int position) {
    ByteBuffer buffer = bytes(length, 1);
    buffer.position(position);
    return buffer;
  }

  private static EncryptedDataKey edk(int seed) {
    return EncryptedDataKey
      .builder()
      .keyProviderId("provider-" + seed)
      .keyProviderInfo(bytes(4, seed))
      .ciphertext(bytes(16, seed + 10))
      .build();
  }

  private static ByteBuffer bytes(int length, int seed) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, (byte) seed);
    return ByteBuffer.wrap(bytes);
  }

  private static Map<String, String> map(String... keysAndValues) {
    Map<String, String> map = new HashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      map.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return map;
  }

  private static Map<String, String> with(Map<String, String> base, String key, String value) {
    Map<String, String> copy = new HashMap<>(base);
    copy.put(key, value);
    return copy;
  }

  private static Map<String, String> without(Map<String, String> base, String key) {
    Map<String, String> copy = new HashMap<>(base);
    copy.remove(key);
    return copy;
  }

  private static <T> List<T> reversed(List<T> list) {
    List<T> copy = new ArrayList<>(list);
    Collections.reverse(copy);
    return copy;
  }

  private static List<AlgorithmSuiteId> allSuites() {
    List<AlgorithmSuiteId> suites = new ArrayList<>();
    for (ESDKAlgorithmSuiteId id : ESDKAlgorithmSuiteId.values()) {
      suites.add(AlgorithmSuiteId.builder().ESDK(id).build());
    }
    for (DBEAlgorithmSuiteId id : DBEAlgorithmSuiteId.values()) {
      suites.add(AlgorithmSuiteId.builder().DBE(id).build());
    }
    return suites;
  }

  private void assertSame(String operation, Object input, Supplier<Object> nativeCall) {
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, operation, input));
    String actual = ReferenceMpl.outcome(nativeCall);
    assertEquals(expected, actual, operation + " on " + ReferenceMpl.describe(input));
    outcomes.merge(operation + (actual.startsWith("throws") ? " throws" : " returns"), 1, Integer::sum);
  }

  // Guards against a vacuous run in which every case succeeds or every case fails.
  private void assertBothOutcomesSeen(String operation) {
    assertTrue(outcomes.containsKey(operation + " returns"), operation + " never succeeded: " + outcomes);
    assertTrue(outcomes.containsKey(operation + " throws"), operation + " never failed: " + outcomes);
  }
}
