// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.model.AesWrappingAlg;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRawAesKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateRequiredEncryptionContextCMMInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.InitializeDecryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.InitializeEncryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptInput;

// Differential tests of the required encryption context CMM against the published Dafny-based MPL,
// over caller-implemented underlying CMMs, valid and not.
// The order of required keys in results is compared sorted: the Dafny-based MPL's order came from a hash set.
class RequiredEncryptionContextCmmTest {

  private static final AlgorithmSuiteId SUITE = AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_128_GCM_IV12_TAG16_NO_KDF).build();
  private static final CommitmentPolicy POLICY = CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT).build();

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final IKeyring keyring = MPL.CreateRawAesKeyring(
    CreateRawAesKeyringInput
      .builder()
      .keyNamespace("ns")
      .keyName("name")
      .wrappingKey(ByteBuffer.wrap(bytes(16, 1)))
      .wrappingAlg(AesWrappingAlg.ALG_AES128_GCM_IV12_TAG16)
      .build()
  );
  private final Map<String, CmmPair> underlying = underlyingCmms();

  @Test
  void create() {
    String surrogate = "a\uD800";
    List<CreateRequiredEncryptionContextCMMInput> inputs = new ArrayList<>();
    for (List<String> keys : Arrays.asList(
      Collections.<String>emptyList(),
      Collections.singletonList("a"),
      Arrays.asList("a", "a"),
      Arrays.asList("a", surrogate)
    )) {
      inputs.add(CreateRequiredEncryptionContextCMMInput.builder().underlyingCMM(underlying.get("valid")).requiredEncryptionContextKeys(keys).build());
    }
    inputs.add(CreateRequiredEncryptionContextCMMInput.builder().requiredEncryptionContextKeys(Collections.singletonList("a")).build());
    for (CreateRequiredEncryptionContextCMMInput input : inputs) {
      String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, "CreateRequiredEncryptionContextCMM", input) == null ? "null" : "cmm");
      String actual = ReferenceMpl.outcome(() -> MPL.CreateRequiredEncryptionContextCMM(input) == null ? "null" : "cmm");
      assertEquals(expected, actual, ReferenceMpl.describe(input.requiredEncryptionContextKeys()));
      outcomes.record("Create", actual);
    }
    outcomes.assertBothSeen("Create");
  }

  //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
  //= type=test
  //# The encryption context on the [encryption materials request](./cmm-interface.md#encryption-materials-request)
  //# MUST contain a value for every key in the configured [required encryption context keys](#required-encryption-context-keys)
  //# or this request MUST fail.
  //
  //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
  //= type=test
  //# The Required Encryption Context CMM MUST attempt to obtain [encryption materials](./structures.md#encryption-materials)
  //# by making a call to the [underlying CMM's](#underlying-cryptographic-materials-manager)
  //# [Get Encryption Materials](cmm-interface.md#get-encryption-materials).
  //
  //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
  //= type=test
  //# All configured [required encryption context keys](#required-encryption-context-keys)
  //# MUST exist in the required encryption context keys
  //# of the [encryption materials request](./cmm-interface.md#encryption-materials-request)
  //# to the [underlying CMM's](#underlying-cryptographic-materials-manager).
  //
  //= spec/framework/required-encryption-context-cmm.md#get-encryption-materials
  //= type=test
  //# The obtained [encryption materials](./structures.md#encryption-materials) MUST
  //# have all configured [required encryption context keys](#required-encryption-context-keys)
  //# in it's [required encryption context keys](./structures.md#required-encryption-context-keys).
  @Test
  void getEncryptionMaterials() {
    List<Map<String, String>> contexts = Arrays.asList(map(), map("a", "1"), map("a", "1", "c", "2"), map("c", "2"), map("a", "1", "b", "3", "c", "2"));
    List<List<String>> callerKeys = Arrays.asList(
      null,
      Collections.<String>emptyList(),
      Collections.singletonList("c"),
      Collections.singletonList("x"),
      Collections.singletonList("a"),
      Collections.singletonList("b"),
      Arrays.asList("b", "c", "b")
    );
    for (Map.Entry<String, CmmPair> cmm : underlying.entrySet()) {
      for (List<String> required : Arrays.asList(Collections.singletonList("a"), Arrays.asList("c", "a"), Arrays.asList("a", "c", "a"))) {
        CmmPair requiredCmm = required(cmm.getValue(), required);
        for (Map<String, String> context : contexts) {
          for (List<String> keys : callerKeys) {
            boolean optionalFields = keys != null && keys.size() == 1;
            GetEncryptionMaterialsInput input = GetEncryptionMaterialsInput
              .builder()
              .encryptionContext(context)
              .commitmentPolicy(POLICY)
              .algorithmSuiteId(optionalFields ? SUITE : null)
              .maxPlaintextLength(optionalFields ? 50L : null)
              .requiredEncryptionContextKeys(keys)
              .build();
            String expected = ReferenceMpl.outcome(
              () -> masked(((GetEncryptionMaterialsOutput) ReferenceMpl.fromReference(ReferenceMpl.call(requiredCmm.referenceCmm, "GetEncryptionMaterials", input))).encryptionMaterials())
            );
            String actual = ReferenceMpl.outcome(() -> masked(requiredCmm.nativeCmm.GetEncryptionMaterials(input).encryptionMaterials()));
            assertEquals(expected, actual, cmm.getKey() + " required " + required + " " + ReferenceMpl.describe(input));
            cmm.getValue().assertSameReceived(keys == null ? 0 : keys.size(), cmm.getKey() + " " + ReferenceMpl.describe(input));
            outcomes.record("GetEncryptionMaterials", actual);
          }
        }
      }
    }
    outcomes.assertBothSeen("GetEncryptionMaterials");
  }

  //= spec/framework/required-encryption-context-cmm.md#decrypt-materials
  //= type=test
  //# The reproduced encryption context on the [decrypt materials request](./cmm-interface.md#decrypt-materials-request)
  //# MUST contain a value for every key in the configured [required encryption context keys](#required-encryption-context-keys)
  //# or this request MUST fail.
  //
  //= spec/framework/required-encryption-context-cmm.md#decrypt-materials
  //= type=test
  //# The Required Encryption Context
  //# CMM MUST attempt to obtain [decryption materials](./structures.md#decryption-materials)
  //# by making a call to the [underlying CMM's](#underlying-cryptographic-materials-manager)
  //# [decrypt materials](cmm-interface.md#decrypt-materials) interface
  //# with the unchanged [decrypt materials request](./cmm-interface.md#decrypt-materials-request).
  //
  //= spec/framework/required-encryption-context-cmm.md#decrypt-materials
  //= type=test
  //# The obtained [decryption materials](./structures.md#decryption-materials) MUST
  //# have all configured [required encryption context keys](#required-encryption-context-keys)
  //# in it's [encryption context](./structures.md#encryption-context-2).
  @Test
  void decryptMaterials() {
    EncryptionMaterials encrypted = keyring
      .OnEncrypt(OnEncryptInput.builder().materials(initialEncryption(map("a", "1", "c", "2"), Collections.singletonList("c"))).build())
      .materials();
    List<Map<String, String>> reproduced = Arrays.asList(null, map(), map("a", "1"), map("a", "x"), map("c", "2"), map("a", "1", "c", "2"), map("c", "2", "d", "3"));
    for (Map.Entry<String, CmmPair> cmm : underlying.entrySet()) {
      for (List<String> required : Arrays.asList(Collections.singletonList("c"), Arrays.asList("c", "a"))) {
        CmmPair requiredCmm = required(cmm.getValue(), required);
        for (Map<String, String> stored : Arrays.asList(map("a", "1"), map())) {
          for (Map<String, String> context : reproduced) {
            DecryptMaterialsInput input = DecryptMaterialsInput
              .builder()
              .algorithmSuiteId(SUITE)
              .commitmentPolicy(POLICY)
              .encryptedDataKeys(encrypted.encryptedDataKeys())
              .encryptionContext(stored)
              .reproducedEncryptionContext(context)
              .build();
            String expected = ReferenceMpl.outcome(
              () -> sortedKeys(((DecryptMaterialsOutput) ReferenceMpl.fromReference(ReferenceMpl.call(requiredCmm.referenceCmm, "DecryptMaterials", input))).decryptionMaterials())
            );
            String actual = ReferenceMpl.outcome(() -> sortedKeys(requiredCmm.nativeCmm.DecryptMaterials(input).decryptionMaterials()));
            assertEquals(expected, actual, cmm.getKey() + " required " + required + " " + ReferenceMpl.describe(input));
            cmm.getValue().assertSameReceived(0, cmm.getKey() + " " + ReferenceMpl.describe(input));
            outcomes.record("DecryptMaterials", actual);
          }
        }
      }
    }
    outcomes.assertBothSeen("DecryptMaterials");
  }

  /** A materials manager built on both sides, standing for the native one in native inputs and the reference one in rebuilt inputs. */
  private static final class CmmPair implements ICryptographicMaterialsManager, ReferenceMpl.Paired {

    final ICryptographicMaterialsManager nativeCmm;
    final Object referenceCmm;

    CmmPair(ICryptographicMaterialsManager nativeCmm, Object referenceCmm) {
      this.nativeCmm = nativeCmm;
      this.referenceCmm = referenceCmm;
    }

    static CmmPair custom(
      Function<GetEncryptionMaterialsInput, GetEncryptionMaterialsOutput> onEncrypt,
      Function<DecryptMaterialsInput, DecryptMaterialsOutput> onDecrypt
    ) {
      List<Object> nativeReceived = new ArrayList<>();
      List<Object> referenceReceived = new ArrayList<>();
      ICryptographicMaterialsManager cmm = new ICryptographicMaterialsManager() {
        @Override
        public GetEncryptionMaterialsOutput GetEncryptionMaterials(GetEncryptionMaterialsInput input) {
          nativeReceived.add(input);
          return onEncrypt.apply(input);
        }

        @Override
        public DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input) {
          nativeReceived.add(input);
          return onDecrypt.apply(input);
        }
      };
      Object reference = ReferenceMpl.customer(
        "materialproviders.ICryptographicMaterialsManager",
        new ArrayList<>(),
        argument -> {
          referenceReceived.add(argument);
          return argument instanceof GetEncryptionMaterialsInput
            ? onEncrypt.apply((GetEncryptionMaterialsInput) argument)
            : onDecrypt.apply((DecryptMaterialsInput) argument);
        }
      );
      CmmPair pair = new CmmPair(cmm, reference);
      pair.nativeReceived = nativeReceived;
      pair.referenceReceived = referenceReceived;
      return pair;
    }

    private List<Object> nativeReceived = new ArrayList<>();
    private List<Object> referenceReceived = new ArrayList<>();

    /**
     * Asserts both sides' managers received the same requests since the last call, then forgets them.
     * Required keys after the caller's own ({@code callerKeyCount}) are compared as a set: the Dafny-based MPL
     * appended the CMM's keys in hash-set order.
     */
    void assertSameReceived(int callerKeyCount, String context) {
      assertEquals(view(referenceReceived, callerKeyCount), view(nativeReceived, callerKeyCount), "requests received, " + context);
      nativeReceived.clear();
      referenceReceived.clear();
    }

    private static List<String> view(List<Object> requests, int callerKeyCount) {
      List<String> views = new ArrayList<>();
      for (Object request : requests) {
        if (request instanceof GetEncryptionMaterialsInput) {
          GetEncryptionMaterialsInput input = (GetEncryptionMaterialsInput) request;
          List<String> keys = new ArrayList<>(input.requiredEncryptionContextKeys());
          List<String> appended = new ArrayList<>(keys.subList(Math.min(callerKeyCount, keys.size()), keys.size()));
          Collections.sort(appended);
          List<String> normalized = new ArrayList<>(keys.subList(0, Math.min(callerKeyCount, keys.size())));
          normalized.addAll(appended);
          views.add(ReferenceMpl.describe(input.toBuilder().requiredEncryptionContextKeys(normalized).build()));
        } else {
          views.add(ReferenceMpl.describe(request));
        }
      }
      return views;
    }

    @Override
    public Object reference() {
      return referenceCmm;
    }

    @Override
    public GetEncryptionMaterialsOutput GetEncryptionMaterials(GetEncryptionMaterialsInput input) {
      return nativeCmm.GetEncryptionMaterials(input);
    }

    @Override
    public DecryptMaterialsOutput DecryptMaterials(DecryptMaterialsInput input) {
      return nativeCmm.DecryptMaterials(input);
    }
  }

  private CmmPair required(CmmPair underlyingCmm, List<String> keys) {
    CreateRequiredEncryptionContextCMMInput input = CreateRequiredEncryptionContextCMMInput
      .builder()
      .underlyingCMM(underlyingCmm)
      .requiredEncryptionContextKeys(keys)
      .build();
    CreateRequiredEncryptionContextCMMInput nativeInput = input.toBuilder().underlyingCMM(underlyingCmm.nativeCmm).build();
    return new CmmPair(MPL.CreateRequiredEncryptionContextCMM(nativeInput), ReferenceMpl.call(reference, "CreateRequiredEncryptionContextCMM", input));
  }

  // Underlying managers a caller might implement; all but "valid" are wrong in some way.
  private Map<String, CmmPair> underlyingCmms() {
    Map<String, CmmPair> cmms = new LinkedHashMap<>();
    cmms.put("valid", CmmPair.custom(this::encrypt, this::decrypt));
    cmms.put(
      "throws",
      CmmPair.custom(
        input -> {
          throw AwsCryptographicMaterialProvidersException.builder().message("custom failure").build();
        },
        input -> {
          throw AwsCryptographicMaterialProvidersException.builder().message("custom failure").build();
        }
      )
    );
    cmms.put(
      "drops required keys",
      CmmPair.custom(input -> withRequired(encrypt(input), Collections.emptyList()), this::decrypt)
    );
    cmms.put(
      "keeps only its own required keys",
      CmmPair.custom(
        input -> {
          GetEncryptionMaterialsOutput output = encrypt(input);
          List<String> keys = new ArrayList<>(output.encryptionMaterials().requiredEncryptionContextKeys());
          keys.removeAll(input.requiredEncryptionContextKeys() == null ? Collections.<String>emptyList() : input.requiredEncryptionContextKeys());
          keys.add("a");
          keys.add("c");
          return withRequired(output, keys);
        },
        this::decrypt
      )
    );
    cmms.put(
      "returns no data key",
      CmmPair.custom(
        input -> GetEncryptionMaterialsOutput.builder().encryptionMaterials(initialEncryption(input.encryptionContext(), required(input))).build(),
        input -> DecryptMaterialsOutput.builder().decryptionMaterials(initialDecryption(input)).build()
      )
    );
    cmms.put(
      "drops a reproduced key",
      CmmPair.custom(
        this::encrypt,
        input -> {
          DecryptionMaterials materials = decrypt(input).decryptionMaterials();
          Map<String, String> context = new HashMap<>(materials.encryptionContext());
          context.remove("c");
          return DecryptMaterialsOutput.builder().decryptionMaterials(materials.toBuilder().encryptionContext(context).build()).build();
        }
      )
    );
    cmms.put(
      "changes a reproduced value",
      CmmPair.custom(
        this::encrypt,
        input -> {
          DecryptionMaterials materials = decrypt(input).decryptionMaterials();
          Map<String, String> context = new HashMap<>(materials.encryptionContext());
          context.put("a", "changed");
          return DecryptMaterialsOutput.builder().decryptionMaterials(materials.toBuilder().encryptionContext(context).build()).build();
        }
      )
    );
    return cmms;
  }

  private GetEncryptionMaterialsOutput encrypt(GetEncryptionMaterialsInput input) {
    EncryptionMaterials start = initialEncryption(input.encryptionContext(), required(input));
    return GetEncryptionMaterialsOutput.builder().encryptionMaterials(keyring.OnEncrypt(OnEncryptInput.builder().materials(start).build()).materials()).build();
  }

  private DecryptMaterialsOutput decrypt(DecryptMaterialsInput input) {
    DecryptionMaterials start = initialDecryption(input);
    return DecryptMaterialsOutput
      .builder()
      .decryptionMaterials(
        keyring.OnDecrypt(OnDecryptInput.builder().materials(start).encryptedDataKeys(input.encryptedDataKeys()).build()).materials()
      )
      .build();
  }

  private static List<String> required(GetEncryptionMaterialsInput input) {
    return input.requiredEncryptionContextKeys() == null ? Collections.<String>emptyList() : input.requiredEncryptionContextKeys();
  }

  private static EncryptionMaterials initialEncryption(Map<String, String> context, List<String> requiredKeys) {
    return MPL.InitializeEncryptionMaterials(
      InitializeEncryptionMaterialsInput.builder().algorithmSuiteId(SUITE).encryptionContext(context).requiredEncryptionContextKeys(requiredKeys).build()
    );
  }

  private static DecryptionMaterials initialDecryption(DecryptMaterialsInput input) {
    Map<String, String> context = new HashMap<>(input.encryptionContext());
    List<String> requiredKeys = new ArrayList<>();
    if (input.reproducedEncryptionContext() != null) {
      for (Map.Entry<String, String> entry : input.reproducedEncryptionContext().entrySet()) {
        if (!context.containsKey(entry.getKey())) {
          requiredKeys.add(entry.getKey());
        }
        context.put(entry.getKey(), entry.getValue());
      }
    }
    Collections.sort(requiredKeys);
    return MPL.InitializeDecryptionMaterials(
      InitializeDecryptionMaterialsInput.builder().algorithmSuiteId(SUITE).encryptionContext(context).requiredEncryptionContextKeys(requiredKeys).build()
    );
  }

  private static GetEncryptionMaterialsOutput withRequired(GetEncryptionMaterialsOutput output, List<String> keys) {
    return GetEncryptionMaterialsOutput.builder().encryptionMaterials(output.encryptionMaterials().toBuilder().requiredEncryptionContextKeys(keys).build()).build();
  }

  private static String masked(EncryptionMaterials materials) {
    List<String> keys = new ArrayList<>(materials.requiredEncryptionContextKeys());
    Collections.sort(keys);
    return KeyringTests.masked(materials.toBuilder().requiredEncryptionContextKeys(keys).build(), false);
  }

  private static String sortedKeys(DecryptionMaterials materials) {
    List<String> keys = new ArrayList<>(materials.requiredEncryptionContextKeys());
    Collections.sort(keys);
    return ReferenceMpl.describe(materials.toBuilder().requiredEncryptionContextKeys(keys).build());
  }
}
