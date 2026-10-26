// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.decryptionMaterials;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.expectedDecryption;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.internal.Convert;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateDefaultCryptographicMaterialsManagerInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DBECommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptMaterialsOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsOutput;

/** Keyring and default CMM comparisons of the two sides over real AWS. */
final class RealChecks {

  /** Encryption output with the random parts masked, given whether the data key was given. */
  interface Mask extends BiFunction<EncryptionMaterials, Boolean, String> {}

  /** For keyrings whose provider info is a key ARN: KMS ciphertexts, data keys, and symmetric signing keys masked. */
  static final Mask KMS = KmsKeyringTests::maskedKms;

  private static final String PUBLIC_KEY_FIELD = "aws-crypto-public-key";

  private RealChecks() {}

  /** As {@link #KMS}, for binary provider info whose last {@code randomInfo} bytes are random. */
  static Mask binaryInfo(int randomInfo) {
    return (materials, dataKeyGiven) -> KeyringTests.masked(materials, dataKeyGiven, randomInfo);
  }

  static String assertSameEncrypt(Outcomes outcomes, Pair keyring, EncryptionMaterials materials, Mask mask, String context) {
    boolean dataKeyGiven = materials.plaintextDataKey() != null;
    return RealAws.assertSame(
      outcomes,
      "OnEncrypt",
      () -> mask.apply(keyring.referenceEncrypt(materials), dataKeyGiven),
      () -> mask.apply(keyring.nativeEncrypt(materials), dataKeyGiven),
      context + " " + ReferenceMpl.describe(materials)
    );
  }

  static String assertSameDecrypt(Outcomes outcomes, Pair keyring, DecryptionMaterials materials, List<EncryptedDataKey> edks, String context) {
    return RealAws.assertSame(
      outcomes,
      "OnDecrypt",
      () -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", KeyringTests.decryptInput(materials, edks)),
      () -> keyring.nativeKeyring.OnDecrypt(KeyringTests.decryptInput(materials, edks)),
      context + " " + ReferenceMpl.describe(KeyringTests.decryptInput(materials, edks))
    );
  }

  /** The materials as each side's {@code encryptor} encrypts them: the native result, then the reference result. */
  static List<EncryptionMaterials> encryptedByBoth(Pair encryptor, EncryptionMaterials start) {
    return Arrays.asList(encryptor.nativeEncrypt(start), encryptor.referenceEncrypt(start));
  }

  /**
   * Each decryptor, on both sides, recovers each result's data key through one of its encrypted data keys
   * (the symmetric signing key shows which one).
   */
  static void assertEachDecrypts(Outcomes outcomes, List<EncryptionMaterials> results, List<Pair> decryptors, String context) {
    for (EncryptionMaterials result : results) {
      List<String> expected = new ArrayList<>();
      for (int edk = 0; edk < result.encryptedDataKeys().size(); edk++) {
        expected.add(ReferenceMpl.describe(expectedDecryption(result, edk)));
      }
      for (int i = 0; i < decryptors.size(); i++) {
        String decrypted = assertSameDecrypt(outcomes, decryptors.get(i), decryptionMaterials(result), result.encryptedDataKeys(), context + " decryptor " + i);
        assertTrue(expected.contains(decrypted), context + " decryptor " + i + ": " + decrypted);
      }
    }
  }

  /** Each decryptor fails alike on both sides; returns the last failure. */
  static String assertEachFails(Outcomes outcomes, List<EncryptionMaterials> results, List<Pair> decryptors, String context) {
    String failure = null;
    for (EncryptionMaterials result : results) {
      for (int i = 0; i < decryptors.size(); i++) {
        failure = assertSameDecrypt(outcomes, decryptors.get(i), decryptionMaterials(result), result.encryptedDataKeys(), context + " decryptor " + i);
        assertTrue(failure.startsWith("throws"), context + " decryptor " + i + ": " + failure);
      }
    }
    return failure;
  }

  /**
   * The default CMM over {@code encryptor} on each side gets the same materials (masked) for {@code suite},
   * and the default CMM over {@code decryptor} on each side recovers the data key of both sides' materials.
   */
  static void assertCmmRoundTrip(Object reference, Outcomes outcomes, Pair encryptor, Pair decryptor, AlgorithmSuiteId suite, Mask mask, String context) {
    Cmm encrypting = new Cmm(reference, encryptor);
    Cmm decrypting = new Cmm(reference, decryptor);
    CommitmentPolicy policy = encryptPolicy(suite);
    GetEncryptionMaterialsInput input = GetEncryptionMaterialsInput
      .builder()
      .encryptionContext(KeyringTests.map("tenant", "a", "purpose", "it"))
      .commitmentPolicy(policy)
      .algorithmSuiteId(suite)
      .maxPlaintextLength(1024L)
      .build();
    String label = context + " CMM " + ReferenceMpl.describe(suite);
    RealAws.assertSame(
      outcomes,
      "GetEncryptionMaterials",
      () -> masked(encrypting.referenceEncrypt(input), mask),
      () -> masked(encrypting.nativeEncrypt(input), mask),
      label
    );
    for (EncryptionMaterials encrypted : Arrays.asList(encrypting.nativeEncrypt(input), encrypting.referenceEncrypt(input))) {
      DecryptMaterialsInput decrypt = DecryptMaterialsInput
        .builder()
        .algorithmSuiteId(suite)
        .commitmentPolicy(policy)
        .encryptedDataKeys(encrypted.encryptedDataKeys())
        .encryptionContext(encrypted.encryptionContext())
        .build();
      RealAws.assertSame(
        outcomes,
        "DecryptMaterials",
        () -> sortedKeys(decrypting.referenceDecrypt(decrypt)),
        () -> sortedKeys(decrypting.nativeCmm.DecryptMaterials(decrypt).decryptionMaterials()),
        label
      );
      DecryptionMaterials decrypted = decrypting.nativeCmm.DecryptMaterials(decrypt).decryptionMaterials();
      assertEquals(ReferenceMpl.describe(encrypted.plaintextDataKey()), ReferenceMpl.describe(decrypted.plaintextDataKey()), label);
    }
  }

  /** A policy that allows encrypting and decrypting with {@code suite}. */
  static CommitmentPolicy encryptPolicy(AlgorithmSuiteId suite) {
    if (suite.DBE() != null) {
      return CommitmentPolicy.builder().DBE(DBECommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build();
    }
    return CommitmentPolicy
      .builder()
      .ESDK(Convert.suite(suite).isCommitting() ? ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT : ESDKCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
      .build();
  }

  // The random signing key and the verification key in the context masked, on top of the keyring masking.
  private static String masked(EncryptionMaterials materials, Mask mask) {
    Map<String, String> context = new HashMap<>(materials.encryptionContext());
    String publicKey = context.get(PUBLIC_KEY_FIELD);
    if (publicKey != null) {
      context.put(PUBLIC_KEY_FIELD, "base64 of length " + publicKey.length());
    }
    EncryptionMaterials rest = materials
      .toBuilder()
      .encryptionContext(context)
      .signingKey(materials.signingKey() == null ? null : ByteBuffer.wrap(new byte[1]))
      .build();
    return mask.apply(rest, false);
  }

  private static String sortedKeys(DecryptionMaterials materials) {
    List<String> keys = new ArrayList<>(materials.requiredEncryptionContextKeys());
    Collections.sort(keys);
    return ReferenceMpl.describe(materials.toBuilder().requiredEncryptionContextKeys(keys).build());
  }

  /** The default CMM over one keyring pair, on each side. */
  private static final class Cmm {

    final ICryptographicMaterialsManager nativeCmm;
    final Object referenceCmm;

    Cmm(Object reference, Pair keyring) {
      nativeCmm = KeyringTests.MPL.CreateDefaultCryptographicMaterialsManager(
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring.nativeKeyring).build()
      );
      referenceCmm = ReferenceMpl.call(
        reference,
        "CreateDefaultCryptographicMaterialsManager",
        CreateDefaultCryptographicMaterialsManagerInput.builder().keyring(keyring).build()
      );
    }

    EncryptionMaterials nativeEncrypt(GetEncryptionMaterialsInput input) {
      return nativeCmm.GetEncryptionMaterials(input).encryptionMaterials();
    }

    EncryptionMaterials referenceEncrypt(GetEncryptionMaterialsInput input) {
      return ((GetEncryptionMaterialsOutput) ReferenceMpl.fromReference(ReferenceMpl.call(referenceCmm, "GetEncryptionMaterials", input))).encryptionMaterials();
    }

    DecryptionMaterials referenceDecrypt(DecryptMaterialsInput input) {
      return ((DecryptMaterialsOutput) ReferenceMpl.fromReference(ReferenceMpl.call(referenceCmm, "DecryptMaterials", input))).decryptionMaterials();
    }
  }
}
