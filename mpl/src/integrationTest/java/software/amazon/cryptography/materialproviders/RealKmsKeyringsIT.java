// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.materialproviders.KeyringTests.array;
import static software.amazon.cryptography.materialproviders.KeyringTests.decryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.edk;
import static software.amazon.cryptography.materialproviders.KeyringTests.encryptionMaterials;
import static software.amazon.cryptography.materialproviders.KeyringTests.flip;
import static software.amazon.cryptography.materialproviders.KeyringTests.map;
import static software.amazon.cryptography.materialproviders.RealChecks.KMS;
import static software.amazon.cryptography.materialproviders.RealChecks.assertCmmRoundTrip;
import static software.amazon.cryptography.materialproviders.RealChecks.assertEachDecrypts;
import static software.amazon.cryptography.materialproviders.RealChecks.assertEachFails;
import static software.amazon.cryptography.materialproviders.RealChecks.assertSameDecrypt;
import static software.amazon.cryptography.materialproviders.RealChecks.assertSameEncrypt;
import static software.amazon.cryptography.materialproviders.RealChecks.encryptedByBoth;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.KmsKeyringTests.Supplied;
import software.amazon.cryptography.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsDiscoveryKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsDiscoveryMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkDiscoveryKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkDiscoveryMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.materialproviders.model.CreateDefaultClientSupplierInput;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.GetClientInput;

// The KMS keyring, the MRK keyring, the discovery keyrings, and the KMS multi keyrings, native and reference,
// against real KMS: each side decrypts the other's encrypted data keys, and both fail alike where KMS refuses.
class RealKmsKeyringsIT {

  private static RealAws aws;
  private static KmsClient kms;
  private static KmsClient replicaKms;
  private static Supplied supplier;

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();

  @BeforeAll
  static void clients() {
    aws = RealAws.fromEnvironment();
    kms = aws.kms(aws.region);
    replicaKms = aws.kms(aws.replicaRegion);
    supplier = aws.supplier();
  }

  @AfterAll
  static void close() {
    aws.close();
  }

  @Test
  void eachSideDecryptsTheOther() {
    DiscoveryFilter account = filter(aws.account);
    Map<String, Pair> encryptors = new LinkedHashMap<>();
    Map<Pair, List<Pair>> decryptors = new LinkedHashMap<>();
    Map<Pair, List<Pair>> nonDecryptors = new LinkedHashMap<>();

    Pair byArn = kmsKeyring(aws.sym, kms, null);
    encryptors.put("KMS keyring, key ARN", byArn);
    encryptors.put("KMS keyring, key id", kmsKeyring(RealAws.keyId(aws.sym), kms, null));
    for (Pair encryptor : encryptors.values()) {
      decryptors.put(
        encryptor,
        Arrays.asList(byArn, mrkKeyring(aws.sym, kms), discovery(kms, account), discovery(kms, null), mrkDiscovery(kms, aws.region, account))
      );
      nonDecryptors.put(
        encryptor,
        Arrays.asList(
          discovery(kms, filter(RealAws.OTHER_ACCOUNT)),
          // A single-Region key: the MRK discovery keyring in another Region skips it without calling KMS.
          mrkDiscovery(replicaKms, aws.replicaRegion, account),
          kmsKeyring(aws.mrk, kms, null)
        )
      );
    }
    Pair mrkWest = mrkKeyring(aws.mrk, kms);
    encryptors.put("MRK keyring, multi-Region key", mrkWest);
    decryptors.put(
      mrkWest,
      Arrays.asList(
        mrkWest,
        kmsKeyring(aws.mrk, kms, null),
        // The replica in the other Region decrypts what the primary encrypted.
        mrkKeyring(aws.mrkReplica, replicaKms),
        mrkDiscovery(replicaKms, aws.replicaRegion, account),
        discovery(kms, account)
      )
    );
    nonDecryptors.put(
      mrkWest,
      Arrays.asList(
        // A KMS keyring is not MRK-aware: the replica's ARN does not match the primary's.
        kmsKeyring(aws.mrkReplica, replicaKms, null),
        mrkDiscovery(replicaKms, aws.replicaRegion, filter(RealAws.OTHER_ACCOUNT))
      )
    );
    Pair mrkEast = mrkKeyring(aws.mrkReplica, replicaKms);
    encryptors.put("MRK keyring, replica", mrkEast);
    decryptors.put(mrkEast, Arrays.asList(mrkEast, mrkWest, mrkDiscovery(kms, aws.region, account)));
    nonDecryptors.put(mrkEast, Collections.singletonList(kmsKeyring(aws.mrk, kms, null)));

    for (Map.Entry<String, Pair> encryptor : encryptors.entrySet()) {
      for (AlgorithmSuiteId suite : RealAws.SUITES) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b", "\u00fc", "\ud83d\ude00"), withDataKey);
          String context = encryptor.getKey() + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
          assertSameEncrypt(outcomes, encryptor.getValue(), start, KMS, context);
          List<EncryptionMaterials> results = encryptedByBoth(encryptor.getValue(), start);
          assertEachDecrypts(outcomes, results, decryptors.get(encryptor.getValue()), context);
          assertEachFails(outcomes, results, nonDecryptors.get(encryptor.getValue()), context);
        }
        assertCmmRoundTrip(reference, outcomes, encryptor.getValue(), decryptors.get(encryptor.getValue()).get(0), suite, KMS, encryptor.getKey());
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // What real KMS refuses: another key's ciphertext, a key ARN of another Region, malformed ciphertext,
  // and another encryption context.
  @Test
  void kmsFailures() {
    Pair sym = kmsKeyring(aws.sym, kms, null);
    Pair mrkWest = mrkKeyring(aws.mrk, kms);
    Map<String, Pair> wrongRegion = new LinkedHashMap<>();
    wrongRegion.put("KMS keyring", kmsKeyring(aws.sym, replicaKms, null));
    wrongRegion.put("MRK keyring", mrkKeyring(aws.sym, replicaKms));
    wrongRegion.put("MRK keyring, multi-Region key", mrkKeyring(aws.mrk, replicaKms));
    Pair badGrantToken = kmsKeyring(aws.sym, kms, Collections.singletonList("not-a-grant-token"));
    Pair discoveryInOtherRegion = discovery(replicaKms, null);
    for (AlgorithmSuiteId suite : RealAws.SUITES) {
      String label = ReferenceMpl.describe(suite);
      for (Map.Entry<String, Pair> keyring : wrongRegion.entrySet()) {
        String failed = assertSameEncrypt(outcomes, keyring.getValue(), encryptionMaterials(suite, map("a", "b"), false), KMS, label + " wrong Region " + keyring.getKey());
        assertTrue(failed.startsWith("throws"), failed);
        failed = assertSameEncrypt(outcomes, keyring.getValue(), encryptionMaterials(suite, map("a", "b"), true), KMS, label + " wrong Region, data key given " + keyring.getKey());
        assertTrue(failed.startsWith("throws"), keyring.getKey() + ": " + failed);
      }
      // KMS ignores a grant token that names no grant when the key policy allows the call.
      assertFalse(assertSameEncrypt(outcomes, badGrantToken, encryptionMaterials(suite, map("a", "b"), false), KMS, label + " grant token").startsWith("throws"));

      EncryptionMaterials encrypted = sym.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false).toBuilder().plaintextDataKey(encrypted.plaintextDataKey()).build();
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      EncryptedDataKey mrkEdk = mrkWest.nativeEncrypt(start).encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      byte[] info = array(good.keyProviderInfo());
      DecryptionMaterials materials = decryptionMaterials(encrypted);

      Map<String, List<EncryptedDataKey>> edkLists = new LinkedHashMap<>();
      edkLists.put("another key's ciphertext", Collections.singletonList(edk("aws-kms", info, array(mrkEdk.ciphertext()))));
      edkLists.put("last byte flipped", Collections.singletonList(edk("aws-kms", info, flip(ciphertext, ciphertext.length - 1))));
      edkLists.put("key id byte flipped", Collections.singletonList(edk("aws-kms", info, flip(ciphertext, 10))));
      edkLists.put("truncated", Collections.singletonList(edk("aws-kms", info, Arrays.copyOf(ciphertext, 20))));
      edkLists.put("empty", Collections.singletonList(edk("aws-kms", info, new byte[0])));
      edkLists.put("garbage", Collections.singletonList(edk("aws-kms", info, KeyringTests.bytes(150, 3))));
      edkLists.put("malformed, then good", Arrays.asList(edk("aws-kms", info, flip(ciphertext, ciphertext.length - 1)), good));
      for (Pair keyring : Arrays.asList(sym, mrkKeyring(aws.sym, kms), discovery(kms, filter(aws.account)), mrkDiscovery(kms, aws.region, null))) {
        for (Map.Entry<String, List<EncryptedDataKey>> edks : edkLists.entrySet()) {
          String outcome = assertSameDecrypt(outcomes, keyring, materials, edks.getValue(), label + " " + edks.getKey());
          assertEquals(!edks.getKey().endsWith("then good"), outcome.startsWith("throws"), edks.getKey() + ": " + outcome);
        }
        String otherContext = assertSameDecrypt(outcomes, keyring, decryptionMaterials(encrypted, map("a", "c")), encrypted.encryptedDataKeys(), label + " other context");
        assertTrue(otherContext.startsWith("throws"), otherContext);
      }
      for (Map.Entry<String, Pair> keyring : wrongRegion.entrySet()) {
        EncryptionMaterials own = keyring.getKey().endsWith("multi-Region key") ? mrkWest.nativeEncrypt(start) : encrypted;
        String outcome = assertSameDecrypt(outcomes, keyring.getValue(), decryptionMaterials(own), own.encryptedDataKeys(), label + " wrong Region " + keyring.getKey());
        assertTrue(outcome.startsWith("throws"), outcome);
      }
      // The discovery keyring asks its own Region's KMS for any key, so a key of another Region fails there.
      assertTrue(assertSameDecrypt(outcomes, discoveryInOtherRegion, materials, encrypted.encryptedDataKeys(), label + " discovery in another Region").startsWith("throws"));
      assertFalse(assertSameDecrypt(outcomes, badGrantToken, materials, encrypted.encryptedDataKeys(), label + " grant token").startsWith("throws"));
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  @Test
  void multiKeyrings() {
    DiscoveryFilter account = filter(aws.account);
    Pair strict = strictMulti(aws.sym, Collections.singletonList(aws.mrkReplica));
    Pair mrkStrict = mrkStrictMulti(aws.mrk, Collections.singletonList(aws.sym));
    // The same keys seen from the replica Region: MRK-aware, so the replica decrypts the primary's key.
    Pair mrkStrictReplica = mrkStrictMulti(aws.mrkReplica, null);
    Pair discoveryBoth = discoveryMulti(Arrays.asList(aws.region, aws.replicaRegion), account);
    // The first child asks the other Region for the key and fails; the second succeeds.
    Pair discoveryOtherFirst = discoveryMulti(Arrays.asList(aws.replicaRegion, aws.region), account);
    Pair mrkDiscoveryReplica = mrkDiscoveryMulti(Collections.singletonList(aws.replicaRegion), account);
    Pair discoveryOtherAccount = discoveryMulti(Collections.singletonList(aws.region), filter(RealAws.OTHER_ACCOUNT));
    Pair mrkDiscoveryOtherAccount = mrkDiscoveryMulti(Collections.singletonList(aws.replicaRegion), filter(RealAws.OTHER_ACCOUNT));

    Map<String, Pair> encryptors = new LinkedHashMap<>();
    encryptors.put("multi keyring", strict);
    encryptors.put("MRK multi keyring", mrkStrict);
    Map<Pair, List<Pair>> decryptors = new LinkedHashMap<>();
    decryptors.put(strict, Arrays.asList(strict, kmsKeyring(aws.sym, kms, null), discoveryBoth, mrkStrictReplica));
    decryptors.put(mrkStrict, Arrays.asList(mrkStrict, mrkStrictReplica, mrkDiscoveryReplica, discoveryBoth, kmsKeyring(aws.sym, kms, null)));
    for (Map.Entry<String, Pair> encryptor : encryptors.entrySet()) {
      for (AlgorithmSuiteId suite : RealAws.SUITES) {
        String context = encryptor.getKey() + " " + ReferenceMpl.describe(suite);
        // A generator needs materials without a data key.
        assertTrue(assertSameEncrypt(outcomes, encryptor.getValue(), encryptionMaterials(suite, map("a", "b"), true), KMS, context).startsWith("throws"));
        EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
        assertSameEncrypt(outcomes, encryptor.getValue(), start, KMS, context);
        supplier.assertSameCalls(context);
        List<EncryptionMaterials> results = encryptedByBoth(encryptor.getValue(), start);
        assertEachDecrypts(outcomes, results, decryptors.get(encryptor.getValue()), context);
        assertEachFails(outcomes, results, Arrays.asList(discoveryOtherAccount, mrkDiscoveryOtherAccount), context);
        if (encryptor.getValue() == strict) {
          // The child in the replica Region fails on the first key, of the other Region, and decrypts the second.
          for (EncryptionMaterials result : results) {
            String decrypted = assertSameDecrypt(outcomes, discoveryOtherFirst, decryptionMaterials(result), result.encryptedDataKeys(), context + " other Region first");
            assertEquals(ReferenceMpl.describe(KeyringTests.expectedDecryption(result, 1)), decrypted, context);
          }
        }
        // Each encrypted data key alone: the discovery multi keyring finds the Region of each.
        for (EncryptionMaterials result : results) {
          for (int i = 0; i < result.encryptedDataKeys().size(); i++) {
            List<EncryptedDataKey> edk = Collections.singletonList(result.encryptedDataKeys().get(i));
            String decrypted = assertSameDecrypt(outcomes, discoveryBoth, decryptionMaterials(result), edk, context + " key " + i + " alone");
            assertEquals(ReferenceMpl.describe(KeyringTests.expectedDecryption(result, i)), decrypted, context);
          }
        }
        assertCmmRoundTrip(reference, outcomes, encryptor.getValue(), discoveryBoth, suite, KMS, encryptor.getKey());
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  // The default client supplier of each side builds real clients from the default credential chain
  // (the integrationTest task sets AWS_PROFILE).
  // The old API has no keyring input without a supplier: the default one is passed explicitly.
  @Test
  void defaultClientSupplier() {
    DiscoveryFilter account = filter(aws.account);
    Pair encryptor = mrkStrictMulti(aws.mrk, null);
    DefaultSuppliers defaults = new DefaultSuppliers(reference);
    CreateAwsKmsMrkDiscoveryMultiKeyringInput discoveryInput = CreateAwsKmsMrkDiscoveryMultiKeyringInput
      .builder()
      .regions(Collections.singletonList(aws.replicaRegion))
      .discoveryFilter(account)
      .clientSupplier(defaults)
      .build();
    Pair defaultDiscovery = new Pair(
      KeyringTests.MPL.CreateAwsKmsMrkDiscoveryMultiKeyring(discoveryInput),
      ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryMultiKeyring", discoveryInput)
    );
    CreateAwsKmsMrkMultiKeyringInput input = CreateAwsKmsMrkMultiKeyringInput.builder().generator(aws.mrkReplica).clientSupplier(defaults).build();
    Pair defaultStrict = new Pair(KeyringTests.MPL.CreateAwsKmsMrkMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkMultiKeyring", input));
    for (AlgorithmSuiteId suite : RealAws.SUITES) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      String context = ReferenceMpl.describe(suite);
      assertSameEncrypt(outcomes, defaultStrict, start, KMS, context + " default supplier");
      List<EncryptionMaterials> results = encryptedByBoth(encryptor, start);
      assertEachDecrypts(outcomes, results, Arrays.asList(defaultDiscovery, defaultStrict), context);
    }
  }

  private Pair kmsKeyring(String keyId, KmsClient client, List<String> grantTokens) {
    CreateAwsKmsKeyringInput input = CreateAwsKmsKeyringInput.builder().kmsKeyId(keyId).kmsClient(client).grantTokens(grantTokens).build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsKeyring", input));
  }

  private Pair mrkKeyring(String keyId, KmsClient client) {
    CreateAwsKmsMrkKeyringInput input = CreateAwsKmsMrkKeyringInput.builder().kmsKeyId(keyId).kmsClient(client).build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsMrkKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkKeyring", input));
  }

  private Pair discovery(KmsClient client, DiscoveryFilter filter) {
    CreateAwsKmsDiscoveryKeyringInput input = CreateAwsKmsDiscoveryKeyringInput.builder().kmsClient(client).discoveryFilter(filter).build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsDiscoveryKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryKeyring", input));
  }

  private Pair mrkDiscovery(KmsClient client, String region, DiscoveryFilter filter) {
    CreateAwsKmsMrkDiscoveryKeyringInput input = CreateAwsKmsMrkDiscoveryKeyringInput
      .builder()
      .kmsClient(client)
      .region(region)
      .discoveryFilter(filter)
      .build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsMrkDiscoveryKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryKeyring", input));
  }

  private Pair strictMulti(String generator, List<String> keys) {
    CreateAwsKmsMultiKeyringInput input = CreateAwsKmsMultiKeyringInput.builder().generator(generator).kmsKeyIds(keys).clientSupplier(supplier).build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMultiKeyring", input));
  }

  private Pair mrkStrictMulti(String generator, List<String> keys) {
    CreateAwsKmsMrkMultiKeyringInput input = CreateAwsKmsMrkMultiKeyringInput.builder().generator(generator).kmsKeyIds(keys).clientSupplier(supplier).build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsMrkMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkMultiKeyring", input));
  }

  private Pair discoveryMulti(List<String> regions, DiscoveryFilter filter) {
    CreateAwsKmsDiscoveryMultiKeyringInput input = CreateAwsKmsDiscoveryMultiKeyringInput
      .builder()
      .regions(regions)
      .discoveryFilter(filter)
      .clientSupplier(supplier)
      .build();
    return new Pair(KeyringTests.MPL.CreateAwsKmsDiscoveryMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryMultiKeyring", input));
  }

  private Pair mrkDiscoveryMulti(List<String> regions, DiscoveryFilter filter) {
    CreateAwsKmsMrkDiscoveryMultiKeyringInput input = CreateAwsKmsMrkDiscoveryMultiKeyringInput
      .builder()
      .regions(regions)
      .discoveryFilter(filter)
      .clientSupplier(supplier)
      .build();
    return new Pair(
      KeyringTests.MPL.CreateAwsKmsMrkDiscoveryMultiKeyring(input),
      ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryMultiKeyring", input)
    );
  }

  /** Each side's default client supplier, standing for the native one in native inputs and the reference one in reference inputs. */
  private static final class DefaultSuppliers implements IClientSupplier, ReferenceMpl.Paired {

    private final IClientSupplier nativeSupplier = KeyringTests.MPL.CreateDefaultClientSupplier(CreateDefaultClientSupplierInput.builder().build());
    private final Object referenceSupplier;

    DefaultSuppliers(Object reference) {
      referenceSupplier = ReferenceMpl.call(reference, "CreateDefaultClientSupplier", CreateDefaultClientSupplierInput.builder().build());
    }

    @Override
    public KmsClient GetClient(GetClientInput input) {
      return nativeSupplier.GetClient(input);
    }

    @Override
    public Object reference() {
      return referenceSupplier;
    }
  }

  static DiscoveryFilter filter(String account) {
    return DiscoveryFilter.builder().accountIds(Collections.singletonList(account)).partition("aws").build();
  }
}
