// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.vectors;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.keyrings.PaddingScheme;
import software.amazon.cryptography.materialproviders.vectors.TestVectors.EncryptKind;
import software.amazon.cryptography.materialproviders.vectors.TestVectors.EncryptVector;

/**
 * CompleteVectors.AllPositiveKeyringTests: the encrypt vectors the Dafny runner generates (VectorsComposition/*.dfy).
 * Dafny builds them as a set, so equal vectors collapse; {@link #all()} keeps one of each by their manifest JSON.
 */
final class CompleteVectors {

  private CompleteVectors() {}

  // EncryptionContextUtils.dfy, as the UTF-8 strings its byte sequences encode.
  private static final String NORMAL = utf8(0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0xed, 0x80, 0x80);
  private static final String PSI = utf8(0xf0, 0x90, 0x80, 0x82);
  private static final String REPLACEMENT_CHAR = utf8(0xef, 0xbf, 0xbd);
  private static final String ASCII1 = utf8(0x31);
  private static final String ASCII2 = utf8(0xc2, 0xa0);
  private static final String ASCII3 = utf8(0x55);
  private static final String ASCII4 = utf8(0xc2, 0xb6);
  private static final String UTF8_2_1 = utf8(0xc4, 0x80);
  private static final String UTF8_2_2 = utf8(0xd4, 0x98);
  private static final String UTF8_2_3 = utf8(0xd4, 0x88);
  private static final String UTF8_3_1 = utf8(0xe0, 0xa0, 0x80);
  private static final String UTF8_3_2 = utf8(0xe0, 0xb7, 0xb4);
  private static final String UTF8_3_3 = utf8(0xe2, 0x88, 0xb0);
  private static final String UTF8_4_1 = utf8(0xf0, 0x92, 0x80, 0x80);
  private static final String UTF8_4_2 = utf8(0xf0, 0x93, 0x80, 0xa3);
  private static final String UTF8_4_3 = utf8(0xf0, 0x93, 0x89, 0xa9);

  private static final Map<String, String> WITH_PSI = map(NORMAL, NORMAL, PSI, PSI);
  private static final Map<String, String> WITH_REPLACEMENT = map(NORMAL, NORMAL, REPLACEMENT_CHAR, REPLACEMENT_CHAR);
  private static final Map<String, String> CONTROL = map(NORMAL, NORMAL);
  private static final Map<String, String> BASIC = map("a", "a");
  private static final List<Map<String, String>> VARIED_UTF8 = Arrays.asList(
    map(ASCII4, ASCII4),
    map(UTF8_2_3, UTF8_2_3),
    map(UTF8_3_3, UTF8_3_3),
    map(UTF8_4_1, UTF8_4_1),
    WITH_REPLACEMENT
  );
  private static final List<Map<String, String>> MULTIPLE_UTF8 = Arrays.asList(
    map(ASCII1, ASCII1, ASCII2, ASCII2, ASCII3, ASCII3),
    map(UTF8_2_1, UTF8_2_1, UTF8_2_2, UTF8_2_2, UTF8_2_3, UTF8_2_3),
    map(UTF8_3_1, UTF8_3_1, UTF8_3_2, UTF8_3_2, UTF8_3_3, UTF8_3_3),
    map(UTF8_4_1, UTF8_4_1, UTF8_4_2, UTF8_4_2, UTF8_4_3, UTF8_4_3)
  );

  // AllRawAES.aesPersistentKeyNames.
  static final List<String> AES_KEY_NAMES = Arrays.asList(
    "aes-128",
    "aes-256",
    "\uD835\uDFC1-nonascii-\uD800\uDC02-aes-256-\uD835\uDFC1-with-\uFFFD"
  );

  static List<EncryptVector> all() {
    Map<String, EncryptVector> vectors = new LinkedHashMap<>();
    Consumer<EncryptVector> add = v -> vectors.putIfAbsent(v.toJson().toString(), v);
    defaultCmm(add);
    hierarchy(add);
    kms(add);
    kmsMrkAware(add);
    kmsMrkAwareDiscovery(add);
    kmsRsa(add);
    rawAes(add);
    rawRsa(add);
    multi(add);
    requiredEncryptionContextCmm(add);
    rawEcdh(add);
    kmsEcdh(add);
    return new ArrayList<>(vectors.values());
  }

  private static EncryptVector positive(
    String name,
    Map<String, String> encryptionContext,
    AlgorithmSuite suite,
    KeyDescription encrypt,
    KeyDescription decrypt
  ) {
    return EncryptVector.generated(EncryptKind.POSITIVE, name, encryptionContext, suite, null, null, encrypt, decrypt, null);
  }

  // AllRawAES.
  private static void rawAes(Consumer<EncryptVector> add) {
    List<KeyDescription.RawAes> descriptions = new ArrayList<>();
    for (String key : AES_KEY_NAMES) {
      descriptions.add(new KeyDescription.RawAes(key, "aws-raw-vectors-persistent-" + key));
      descriptions.add(new KeyDescription.RawAes(key, "aws-raw-vectors-persistent-" + key + "-\uD835\uDFC1"));
    }
    for (KeyDescription.RawAes d : descriptions) {
      for (AlgorithmSuite suite : TestVectors.allSuites()) {
        add.accept(positive("Generated RawAES No Encryption Context " + d.keyId, map(), suite, d, d));
        add.accept(positive("Generated RawAES Encryption Context With Psi " + d.keyId, WITH_PSI, suite, d, d));
        add.accept(positive("Generated RawAES Basic Encryption Context " + d.keyId, BASIC, suite, d, d));
        add.accept(positive("Generated RawAES Control Encryption Context " + d.keyId, CONTROL, suite, d, d));
        add.accept(positive("Generated RawAES Encryption Context With Psi " + d.keyId, WITH_REPLACEMENT, suite, d, d));
        for (Map<String, String> ec : MULTIPLE_UTF8) {
          add.accept(positive("Generated RawAES Multiple UTF8 Entries EC " + d.keyId, ec, suite, d, d));
        }
      }
    }
  }

  // AllRawRSA: every padding, encrypting with the public key and decrypting with the private one.
  private static void rawRsa(Consumer<EncryptVector> add) {
    for (PaddingScheme padding : PaddingScheme.values()) {
      KeyDescription encrypt = new KeyDescription.RawRsa("rsa-4096-public", "aws-raw-vectors-persistent-rsa-4096", padding);
      KeyDescription decrypt = new KeyDescription.RawRsa("rsa-4096-private", "aws-raw-vectors-persistent-rsa-4096", padding);
      for (AlgorithmSuite suite : TestVectors.allSuites()) {
        add.accept(positive("Generated RawRSA rsa-4096", map(), suite, encrypt, decrypt));
      }
    }
  }

  // AllRawECDH.
  private static void rawEcdh(Consumer<EncryptVector> add) {
    for (String curve : Arrays.asList("ecc-256", "ecc-384", "ecc-521")) {
      String key = curve + "-private";
      KeyDescription.RawEcdh ephemeral = new KeyDescription.RawEcdh(
        "ephemeral",
        key,
        "ephemeral",
        "recipient-material-public-key",
        "aws-raw-vectors-persistent-ephemeral " + curve,
        curve,
        "ephemeral"
      );
      KeyDescription.RawEcdh discovery = new KeyDescription.RawEcdh(
        "discovery",
        key,
        "discovery",
        "recipient-material-public-key",
        "aws-raw-vectors-persistent-discovery " + curve,
        curve,
        "discovery"
      );
      KeyDescription.RawEcdh sender = new KeyDescription.RawEcdh(
        key,
        key,
        "sender-material-public-key",
        "recipient-material-public-key",
        "aws-raw-vectors-persistent-static " + curve,
        curve,
        "static"
      );
      for (AlgorithmSuite suite : TestVectors.allSuites()) {
        add.accept(positive("Generated RawECDH Ephemeral-Discovery ephemeral " + key, map(), suite, ephemeral, discovery));
        add.accept(positive("Generated RawECDH Static " + key + " " + key, map(), suite, sender, sender));
        add.accept(positive("Generated RawECDH Static " + key + " Discovery " + key, map(), suite, sender, discovery));
      }
    }
  }

  // AllMulti: a generator alone, and a generator with the other AES keys as children.
  private static void multi(Consumer<EncryptVector> add) {
    for (String key : AES_KEY_NAMES) {
      KeyDescription generator = new KeyDescription.RawAes(key, "aws-raw-vectors-persistent-" + key);
      List<KeyDescription> children = new ArrayList<>();
      for (String other : AES_KEY_NAMES) {
        if (!other.equals(key)) {
          children.add(new KeyDescription.RawAes(other, "aws-raw-vectors-persistent-" + other));
        }
      }
      for (KeyDescription d : Arrays.asList(
        new KeyDescription.Multi(generator, Collections.emptyList()),
        new KeyDescription.Multi(generator, children)
      )) {
        for (AlgorithmSuite suite : TestVectors.allSuites()) {
          add.accept(positive("MultiKeyring " + key, map(), suite, d, d));
        }
      }
    }
  }

  // AllKms.
  private static void kms(Consumer<EncryptVector> add) {
    for (String key : Arrays.asList("us-west-2-decryptable", "us-west-2-mrk")) {
      KeyDescription d = new KeyDescription.Kms(key);
      for (AlgorithmSuite suite : TestVectors.allSuites()) {
        add.accept(positive("Generated KMS No Encryption Context" + key, map(), suite, d, d));
        add.accept(positive("Generated KMS Encryption Context With Psi " + key, WITH_PSI, suite, d, d));
        add.accept(positive("Generated KMS Basic Encryption Context " + key, BASIC, suite, d, d));
        add.accept(positive("Generated KMS Control Encryption Context " + key, CONTROL, suite, d, d));
        for (Map<String, String> ec : VARIED_UTF8) {
          add.accept(positive("Generated KMS Basic Encryption Context " + key, ec, suite, d, d));
        }
        add.accept(positive("Generated KMS Encryption Context With Replacement Char " + key, WITH_REPLACEMENT, suite, d, d));
      }
    }
  }

  private static final List<String> MRK_KEYS = Arrays.asList("us-west-2-mrk", "us-east-1-mrk");

  // AllKmsMrkAware: every encrypt and decrypt replica pair.
  private static void kmsMrkAware(Consumer<EncryptVector> add) {
    for (String encrypt : MRK_KEYS) {
      for (String decrypt : MRK_KEYS) {
        for (AlgorithmSuite suite : TestVectors.allSuites()) {
          add.accept(
            positive("Generated KMS MRK " + encrypt + "->" + decrypt, map(), suite, new KeyDescription.KmsMrk(encrypt), new KeyDescription.KmsMrk(decrypt))
          );
        }
      }
    }
  }

  // AllKmsMrkAwareDiscovery.
  private static void kmsMrkAwareDiscovery(Consumer<EncryptVector> add) {
    List<Optional<KeyDescription.KmsMrkDiscovery.Filter>> filters = Arrays.asList(
      Optional.of(new KeyDescription.KmsMrkDiscovery.Filter("aws", Collections.singletonList("658956600833"))),
      Optional.empty()
    );
    for (String encrypt : MRK_KEYS) {
      for (Optional<KeyDescription.KmsMrkDiscovery.Filter> filter : filters) {
        KeyDescription decrypt = new KeyDescription.KmsMrkDiscovery("", "us-west-2", filter);
        String name =
          "Generated Discovery KMS MRK " + encrypt + "->" +
          (filter.isPresent() ? "Filter " + filter.get().partition + " " + String.join("", filter.get().accountIds) : "No Filter");
        for (AlgorithmSuite suite : TestVectors.allSuites()) {
          add.accept(positive(name, map(), suite, new KeyDescription.KmsMrk(encrypt), decrypt));
        }
      }
    }
  }

  // AllKmsRsa: not with an ECDSA suite, which the KMS RSA keyring cannot use.
  private static void kmsRsa(Consumer<EncryptVector> add) {
    for (String algorithm : KeyDescription.KmsRsa.ALGORITHMS) {
      KeyDescription d = new KeyDescription.KmsRsa("us-west-2-rsa-mrk", algorithm);
      for (AlgorithmSuite suite : TestVectors.allSuites()) {
        if (!suite.signature().isPresent()) {
          add.accept(positive("Generated KMS RSA us-west-2-rsa-mrk", map(), suite, d, d));
        }
      }
    }
  }

  // AllKmsEcdh.
  private static void kmsEcdh(Consumer<EncryptVector> add) {
    for (String key : KeyDescription.KmsEcdh.CURVES) {
      KeyDescription sender = new KeyDescription.KmsEcdh(key, key, "sender-material-public-key", "recipient-material-public-key", key, "static");
      KeyDescription discovery = new KeyDescription.KmsEcdh("discovery", key, "discovery", "recipient-material-public-key", key, "discovery");
      for (AlgorithmSuite suite : TestVectors.allSuites()) {
        add.accept(positive("AWS KMS ECDH Static " + key + " " + key, map(), suite, sender, sender));
        add.accept(positive("AWS KMS ECDH Discovery " + key + " discovery", map(), suite, sender, discovery));
      }
    }
  }

  // AllHierarchy.
  private static void hierarchy(Consumer<EncryptVector> add) {
    KeyDescription d = new KeyDescription.Hierarchy("static-branch-key-1");
    for (AlgorithmSuite suite : TestVectors.allSuites()) {
      add.accept(positive("Generated Hierarchy KMS static-branch-key-1", map(), suite, d, d));
    }
  }

  private static final AlgorithmSuite STATIC_SUITE = EsdkAlgorithmSuite.ALG_AES_128_GCM_IV12_TAG16_NO_KDF;
  private static final KeyDescription STATIC_PLAINTEXT_DATA_KEY = new KeyDescription.Static("static-plaintext-data-key");
  private static final KeyDescription STATIC_NO_PLAINTEXT_DATA_KEY = new KeyDescription.Static("no-plaintext-data-key");
  // AllDefaultCmm.RawAesKeyring: the last AES key name.
  private static final String DEFAULT_CMM_AES_KEY = AES_KEY_NAMES.get(AES_KEY_NAMES.size() - 1);
  private static final KeyDescription RAW_AES = new KeyDescription.RawAes(DEFAULT_CMM_AES_KEY, "aws-raw-vectors-persistent-" + DEFAULT_CMM_AES_KEY);
  private static final Map<String, String> ROOT_CONTEXT = map("a", "a", "b", "b");
  private static final Map<String, String> DISJOINT_CONTEXT = map("a", "c", "b", "c", "c", "c");

  // AllDefaultCmm.
  private static void defaultCmm(Consumer<EncryptVector> add) {
    add.accept(positive("Simplest possible happy path", map(), STATIC_SUITE, STATIC_PLAINTEXT_DATA_KEY, STATIC_PLAINTEXT_DATA_KEY));
    add.accept(positive("SurrogatePair Encryption Context Test", map(PSI, PSI), STATIC_SUITE, RAW_AES, RAW_AES));
    add.accept(
      EncryptVector.generated(
        EncryptKind.NEGATIVE_ENCRYPT,
        "Missing plaintext data key on decrypt",
        map(),
        STATIC_SUITE,
        null,
        null,
        STATIC_NO_PLAINTEXT_DATA_KEY,
        null,
        "No plaintext data key on encrypt fails"
      )
    );
    add.accept(
      EncryptVector.generated(
        EncryptKind.NEGATIVE_DECRYPT,
        "Missing plaintext data key on decrypt",
        map(),
        STATIC_SUITE,
        null,
        null,
        STATIC_PLAINTEXT_DATA_KEY,
        STATIC_NO_PLAINTEXT_DATA_KEY,
        "No plaintext data key on encrypt fails"
      )
    );
    requiredAndReproduced(add, ROOT_CONTEXT, true, required -> RAW_AES);
  }

  // AllRequiredEncryptionContextCmm.
  private static void requiredEncryptionContextCmm(Consumer<EncryptVector> add) {
    KeyDescription kms = new KeyDescription.Kms("us-west-2-decryptable");
    requiredAndReproduced(add, ROOT_CONTEXT, false, required -> new KeyDescription.RequiredEncryptionContext(RAW_AES, required));
    successOnly(add, map("a", "a", PSI, PSI), required -> new KeyDescription.RequiredEncryptionContext(kms, required));
    successOnly(add, map("a", "a", REPLACEMENT_CHAR, REPLACEMENT_CHAR), required -> new KeyDescription.RequiredEncryptionContext(kms, required));
  }

  /**
   * SuccessTestingRequiredEncryptionContextKeysReproducedEncryptionContext and FailureBadReproducedEncryptionContext:
   * every required key subset (the empty one only for the default CMM), with every reproduced context that covers it,
   * and then with every reproduced context made wrong by a disjoint context.
   */
  private static void requiredAndReproduced(
    Consumer<EncryptVector> add,
    Map<String, String> context,
    boolean emptyRequired,
    java.util.function.Function<List<String>, KeyDescription> description
  ) {
    successOnly(add, context, emptyRequired, description);
    for (Map<String, String> requiredSubset : subsets(context)) {
      if (!emptyRequired && requiredSubset.isEmpty()) {
        continue;
      }
      List<String> required = sortedKeys(requiredSubset);
      KeyDescription d = description.apply(required);
      for (Map<String, String> incorrect : subsets(DISJOINT_CONTEXT)) {
        if (incorrect.isEmpty()) {
          continue;
        }
        for (Map<String, String> subset : subsets(context)) {
          Map<String, String> reproduced = new LinkedHashMap<>(subset);
          reproduced.putAll(incorrect);
          add.accept(
            EncryptVector.generated(
              EncryptKind.NEGATIVE_DECRYPT,
              "Failure of reproducedEncryptionContext",
              context,
              STATIC_SUITE,
              required,
              reproduced,
              d,
              d,
              "The reproducedEncryptionContext is not correct"
            )
          );
        }
      }
    }
  }

  private static void successOnly(
    Consumer<EncryptVector> add,
    Map<String, String> context,
    java.util.function.Function<List<String>, KeyDescription> description
  ) {
    successOnly(add, context, false, description);
  }

  private static void successOnly(
    Consumer<EncryptVector> add,
    Map<String, String> context,
    boolean emptyRequired,
    java.util.function.Function<List<String>, KeyDescription> description
  ) {
    for (Map<String, String> requiredSubset : subsets(context)) {
      if (!emptyRequired && requiredSubset.isEmpty()) {
        continue;
      }
      List<String> required = sortedKeys(requiredSubset);
      KeyDescription d = description.apply(required);
      for (Map<String, String> reproduced : subsets(context)) {
        if (!reproduced.keySet().containsAll(requiredSubset.keySet())) {
          continue;
        }
        add.accept(
          EncryptVector.generated(
            EncryptKind.POSITIVE,
            "Success testing requiredEncryptionContextKeys/reproducedEncryptionContext",
            context,
            STATIC_SUITE,
            required,
            reproduced,
            d,
            d,
            null
          )
        );
      }
    }
  }

  // AllDefaultCmm.SubSets: every sub-map.
  static List<Map<String, String>> subsets(Map<String, String> map) {
    List<Map<String, String>> subsets = new ArrayList<>();
    subsets.add(new LinkedHashMap<>());
    for (Map.Entry<String, String> entry : Json.sortedByUtf8(map).entrySet()) {
      int size = subsets.size();
      for (int i = 0; i < size; i++) {
        Map<String, String> with = new LinkedHashMap<>(subsets.get(i));
        with.put(entry.getKey(), entry.getValue());
        subsets.add(with);
      }
    }
    return subsets;
  }

  // SortedSets.ComputeSetToOrderedSequence2 over UTF-8 bytes.
  private static List<String> sortedKeys(Map<String, String> map) {
    return new ArrayList<>(Json.sortedByUtf8(map).keySet());
  }

  private static Map<String, String> map(String... keysAndValues) {
    Map<String, String> map = new LinkedHashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      map.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return map;
  }

  private static String utf8(int... bytes) {
    byte[] b = new byte[bytes.length];
    for (int i = 0; i < bytes.length; i++) {
      b[i] = (byte) bytes[i];
    }
    return new String(b, StandardCharsets.UTF_8);
  }
}
