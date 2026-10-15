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
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import software.amazon.cryptography.materialproviders.internal.Convert;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.InitializeDecryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.InitializeEncryptionMaterialsInput;
import software.amazon.cryptography.materialproviders.model.MaterialProvidersConfig;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptOutput;

/** Shared pieces of the keyring differential tests. */
final class KeyringTests {

  static final MaterialProviders MPL = MaterialProviders
    .builder()
    .MaterialProvidersConfig(MaterialProvidersConfig.builder().build())
    .build();

  // The raw AES keyring's provider info ends with its random IV.
  private static final int IV_LENGTH = 12;

  private KeyringTests() {}

  /**
   * A keyring built on both sides from the same input. It stands for the native keyring in native inputs
   * and for the reference keyring in inputs rebuilt for the reference MPL.
   */
  static final class Pair implements IKeyring, ReferenceMpl.Paired {

    final IKeyring nativeKeyring;
    final Object referenceKeyring;

    Pair(IKeyring nativeKeyring, Object referenceKeyring) {
      this.nativeKeyring = nativeKeyring;
      this.referenceKeyring = referenceKeyring;
    }

    /**
     * A keyring a caller implemented: the same native behavior behind each side's keyring interface.
     * Each side records what its keyring received (random parts masked); see {@link #assertSameReceived}.
     */
    static Pair custom(Function<OnEncryptInput, OnEncryptOutput> onEncrypt, Function<OnDecryptInput, OnDecryptOutput> onDecrypt) {
      List<String> nativeReceived = new ArrayList<>();
      List<String> referenceReceived = new ArrayList<>();
      IKeyring keyring = new IKeyring() {
        @Override
        public OnEncryptOutput OnEncrypt(OnEncryptInput input) {
          nativeReceived.add(received(input));
          return onEncrypt.apply(input);
        }

        @Override
        public OnDecryptOutput OnDecrypt(OnDecryptInput input) {
          nativeReceived.add(received(input));
          return onDecrypt.apply(input);
        }
      };
      Object reference = ReferenceMpl.customer(
        "materialproviders.IKeyring",
        new ArrayList<>(),
        argument -> {
          referenceReceived.add(received(argument));
          return argument instanceof OnEncryptInput ? onEncrypt.apply((OnEncryptInput) argument) : onDecrypt.apply((OnDecryptInput) argument);
        }
      );
      Pair pair = new Pair(keyring, reference);
      pair.nativeReceived = nativeReceived;
      pair.referenceReceived = referenceReceived;
      return pair;
    }

    private List<String> nativeReceived;
    private List<String> referenceReceived;

    /** For a caller keyring: asserts both sides' keyrings received the same inputs since the last call, then forgets them. */
    void assertSameReceived(String context) {
      if (nativeReceived == null) {
        return;
      }
      assertEquals(referenceReceived, nativeReceived, "inputs received, " + context);
      nativeReceived.clear();
      referenceReceived.clear();
    }

    // An empty symmetric signing key list is rendered as absent: the Dafny-based MPL passed either, depending on
    // whether the materials had crossed its Java boundary before; the test adapter cannot track that.
    private static String received(Object input) {
      if (input instanceof OnEncryptInput) {
        EncryptionMaterials materials = ((OnEncryptInput) input).materials();
        if (materials.symmetricSigningKeys() != null && materials.symmetricSigningKeys().isEmpty()) {
          materials = materials.toBuilder().symmetricSigningKeys(null).build();
        }
        return "OnEncrypt " + masked(materials, false);
      }
      return "OnDecrypt " + ReferenceMpl.describe(input);
    }

    @Override
    public Object reference() {
      return referenceKeyring;
    }

    @Override
    public OnEncryptOutput OnEncrypt(OnEncryptInput input) {
      return nativeKeyring.OnEncrypt(input);
    }

    @Override
    public OnDecryptOutput OnDecrypt(OnDecryptInput input) {
      return nativeKeyring.OnDecrypt(input);
    }

    EncryptionMaterials nativeEncrypt(EncryptionMaterials materials) {
      return nativeKeyring.OnEncrypt(OnEncryptInput.builder().materials(materials).build()).materials();
    }

    EncryptionMaterials referenceEncrypt(EncryptionMaterials materials) {
      Object output = ReferenceMpl.call(referenceKeyring, "OnEncrypt", OnEncryptInput.builder().materials(materials).build());
      return ((OnEncryptOutput) ReferenceMpl.fromReference(output)).materials();
    }

    DecryptionMaterials nativeDecrypt(DecryptionMaterials materials, List<EncryptedDataKey> edks) {
      return nativeKeyring.OnDecrypt(decryptInput(materials, edks)).materials();
    }

    /** Asserts both sides decrypt alike and returns the outcome. */
    String assertSameDecrypt(Outcomes outcomes, DecryptionMaterials materials, List<EncryptedDataKey> edks, String context) {
      OnDecryptInput input = decryptInput(materials, edks);
      String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(referenceKeyring, "OnDecrypt", input));
      String actual = ReferenceMpl.outcome(() -> nativeKeyring.OnDecrypt(input));
      assertEquals(expected, actual, context + " " + ReferenceMpl.describe(input));
      return outcomes.record("OnDecrypt", actual);
    }

    /** Asserts both sides encrypt alike, up to the random parts (see {@link #masked}), and returns the outcome. */
    String assertSameEncrypt(Outcomes outcomes, EncryptionMaterials materials, String context) {
      return assertSameEncrypt(outcomes, materials, context, IV_LENGTH);
    }

    /** As {@link #assertSameEncrypt(Outcomes, EncryptionMaterials, String)}, masking the last {@code randomInfo} bytes of each provider info. */
    String assertSameEncrypt(Outcomes outcomes, EncryptionMaterials materials, String context, int randomInfo) {
      boolean dataKeyGiven = materials.plaintextDataKey() != null;
      String expected = ReferenceMpl.outcome(() -> masked(referenceEncrypt(materials), dataKeyGiven, randomInfo));
      String actual = ReferenceMpl.outcome(() -> masked(nativeEncrypt(materials), dataKeyGiven, randomInfo));
      assertEquals(expected, actual, context + " " + ReferenceMpl.describe(materials));
      return outcomes.record("OnEncrypt", actual);
    }
  }

  /** Counts outcomes per operation, to guard against a vacuous run in which every case succeeds or every case fails. */
  static final class Outcomes {

    private final Map<String, Integer> counts = new TreeMap<>();

    String record(String operation, String outcome) {
      counts.merge(operation + (outcome.startsWith("throws") ? " throws" : " returns"), 1, Integer::sum);
      return outcome;
    }

    void assertBothSeen(String operation) {
      assertTrue(counts.containsKey(operation + " returns"), operation + " never succeeded: " + counts);
      assertTrue(counts.containsKey(operation + " throws"), operation + " never failed: " + counts);
    }
  }

  static OnDecryptInput decryptInput(DecryptionMaterials materials, List<EncryptedDataKey> edks) {
    return OnDecryptInput.builder().materials(materials).encryptedDataKeys(edks).build();
  }

  /** Fresh materials for {@code suite}, with a fixed data key if {@code withDataKey}; signing suites get a placeholder key pair. */
  static EncryptionMaterials encryptionMaterials(AlgorithmSuiteId suite, Map<String, String> encryptionContext, boolean withDataKey) {
    boolean signing = Convert.suite(suite).isSigning();
    EncryptionMaterials materials = MPL.InitializeEncryptionMaterials(
      InitializeEncryptionMaterialsInput
        .builder()
        .algorithmSuiteId(suite)
        .encryptionContext(encryptionContext)
        .requiredEncryptionContextKeys(Collections.emptyList())
        .signingKey(signing ? ByteBuffer.wrap(bytes(48, 3)) : null)
        .verificationKey(signing ? ByteBuffer.wrap(bytes(49, 4)) : null)
        .build()
    );
    if (!withDataKey) {
      return materials;
    }
    int length = materials.algorithmSuite().encrypt().AES_GCM().keyLength();
    return materials.toBuilder().plaintextDataKey(ByteBuffer.wrap(bytes(length, 9))).build();
  }

  /** Decryption materials matching {@code encrypted}: its suite, context, and verification key. */
  static DecryptionMaterials decryptionMaterials(EncryptionMaterials encrypted) {
    return decryptionMaterials(encrypted, encrypted.encryptionContext());
  }

  /** As {@link #decryptionMaterials(EncryptionMaterials)}, with another context (the verification key kept). */
  static DecryptionMaterials decryptionMaterials(EncryptionMaterials encrypted, Map<String, String> encryptionContext) {
    Map<String, String> context = new HashMap<>(encryptionContext);
    String publicKey = encrypted.encryptionContext().get("aws-crypto-public-key");
    if (publicKey != null) {
      context.put("aws-crypto-public-key", publicKey);
    }
    return MPL.InitializeDecryptionMaterials(
      InitializeDecryptionMaterialsInput
        .builder()
        .algorithmSuiteId(encrypted.algorithmSuite().id())
        .encryptionContext(context)
        .requiredEncryptionContextKeys(Collections.emptyList())
        .build()
    );
  }

  /** The decrypt output that recovers {@code encrypted}'s data key through its first encrypted data key. */
  static OnDecryptOutput expectedDecryption(EncryptionMaterials encrypted) {
    return expectedDecryption(encrypted, 0);
  }

  /** The decrypt output that recovers {@code encrypted}'s data key through encrypted data key {@code index}. */
  static OnDecryptOutput expectedDecryption(EncryptionMaterials encrypted, int index) {
    List<ByteBuffer> symmetric = encrypted.symmetricSigningKeys();
    return OnDecryptOutput
      .builder()
      .materials(
        decryptionMaterials(encrypted)
          .toBuilder()
          .plaintextDataKey(encrypted.plaintextDataKey())
          .symmetricSigningKey(symmetric == null || symmetric.isEmpty() ? null : symmetric.get(index))
          .build()
      )
      .build();
  }

  /**
   * Encryption output with the random parts replaced by their lengths: each raw AES IV (the last 12 bytes of the provider info),
   * each ciphertext, a generated data key, and the symmetric signing keys.
   */
  static String masked(EncryptionMaterials materials, boolean dataKeyGiven) {
    return masked(materials, dataKeyGiven, IV_LENGTH);
  }

  /** As {@link #masked(EncryptionMaterials, boolean)}, with the last {@code randomInfo} bytes of each provider info random. */
  static String masked(EncryptionMaterials materials, boolean dataKeyGiven, int randomInfo) {
    List<String> edks = new ArrayList<>();
    for (EncryptedDataKey edk : materials.encryptedDataKeys()) {
      byte[] info = array(edk.keyProviderInfo());
      edks.add(
        edk.keyProviderId() + " info " + ReferenceMpl.describe(ByteBuffer.wrap(Arrays.copyOf(info, Math.max(0, info.length - randomInfo)))) +
        " random " + Math.min(randomInfo, info.length) + " ciphertext " + edk.ciphertext().remaining()
      );
    }
    List<Integer> symmetric = new ArrayList<>();
    if (materials.symmetricSigningKeys() != null) {
      for (ByteBuffer key : materials.symmetricSigningKeys()) {
        symmetric.add(key.remaining());
      }
    }
    EncryptionMaterials rest = materials
      .toBuilder()
      .encryptedDataKeys(Collections.emptyList())
      .symmetricSigningKeys(null)
      .plaintextDataKey(dataKeyGiven ? materials.plaintextDataKey() : null)
      .build();
    return (
      ReferenceMpl.describe(rest) + " data key " + (materials.plaintextDataKey() == null ? "none" : array(materials.plaintextDataKey()).length) +
      " edks " + edks + " symmetric signing keys " + (materials.symmetricSigningKeys() == null ? "null" : symmetric)
    );
  }

  static EncryptedDataKey edk(String providerId, byte[] info, byte[] ciphertext) {
    return edk(providerId, info, ByteBuffer.wrap(ciphertext));
  }

  static EncryptedDataKey edk(String providerId, byte[] info, ByteBuffer ciphertext) {
    return EncryptedDataKey.builder().keyProviderId(providerId).keyProviderInfo(ByteBuffer.wrap(info)).ciphertext(ciphertext).build();
  }

  static byte[] flip(byte[] bytes, int index) {
    byte[] copy = bytes.clone();
    copy[index] ^= 1;
    return copy;
  }

  /** Bytes {@code [0, limit)}, as the Dafny-based MPL read a buffer. */
  static byte[] array(ByteBuffer buffer) {
    ByteBuffer copy = buffer.duplicate();
    copy.rewind();
    byte[] bytes = new byte[copy.limit()];
    copy.get(bytes);
    return bytes;
  }

  static byte[] bytes(int length, int seed) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < length; i++) {
      bytes[i] = (byte) (seed + i);
    }
    return bytes;
  }

  static String repeat(char c, int count) {
    char[] chars = new char[count];
    Arrays.fill(chars, c);
    return new String(chars);
  }

  static Map<String, String> map(String... keysAndValues) {
    Map<String, String> map = new HashMap<>();
    for (int i = 0; i < keysAndValues.length; i += 2) {
      map.put(keysAndValues[i], keysAndValues[i + 1]);
    }
    return map;
  }

  static List<AlgorithmSuiteId> allSuites() {
    List<AlgorithmSuiteId> suites = new ArrayList<>();
    for (ESDKAlgorithmSuiteId id : ESDKAlgorithmSuiteId.values()) {
      suites.add(AlgorithmSuiteId.builder().ESDK(id).build());
    }
    for (DBEAlgorithmSuiteId id : DBEAlgorithmSuiteId.values()) {
      suites.add(AlgorithmSuiteId.builder().DBE(id).build());
    }
    return suites;
  }
}
