// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.base64;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.created;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.decode;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.grantTokenLists;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.remove;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.serviceErrors;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.*;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsDiscoveryKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMrkDiscoveryKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;

// Differential tests of the AWS KMS discovery keyring and the AWS KMS MRK discovery keyring against the published
// Dafny-based MPL, on one fake KMS. Two agreed fixes (B1, B2) make some plain discovery decryptions succeed that the
// reference fails; those cases are pinned separately.
class AwsKmsDiscoveryKeyringTest {

  private static final String OTHER_ACCOUNT = "444455556666";

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = ReferenceAws.kms(aws, REGION);
  private final KmsClient otherKms = ReferenceAws.kms(aws, OTHER_REGION);

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void create() {
    List<DiscoveryFilter> filters = filters();
    for (DiscoveryFilter filter : filters) {
      for (List<String> grantTokens : grantTokenLists()) {
        CreateAwsKmsDiscoveryKeyringInput input = CreateAwsKmsDiscoveryKeyringInput
          .builder()
          .kmsClient(kms)
          .discoveryFilter(filter)
          .grantTokens(grantTokens)
          .build();
        assertSame(
          aws,
          outcomes,
          "CreateAwsKmsDiscoveryKeyring",
          () -> created(ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryKeyring", input)),
          () -> created(MPL.CreateAwsKmsDiscoveryKeyring(input)),
          ReferenceMpl.describe(filter) + " " + grantTokens
        );
        for (String region : Arrays.asList(REGION, OTHER_REGION, "")) {
          CreateAwsKmsMrkDiscoveryKeyringInput mrkInput = CreateAwsKmsMrkDiscoveryKeyringInput
            .builder()
            .kmsClient(kms)
            .discoveryFilter(filter)
            .grantTokens(grantTokens)
            .region(region)
            .build();
          assertSame(
            aws,
            outcomes,
            "CreateAwsKmsMrkDiscoveryKeyring",
            () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryKeyring", mrkInput)),
            () -> created(MPL.CreateAwsKmsMrkDiscoveryKeyring(mrkInput)),
            ReferenceMpl.describe(filter) + " " + grantTokens + " " + region
          );
        }
      }
    }
    outcomes.assertBothSeen("CreateAwsKmsDiscoveryKeyring");
    outcomes.assertBothSeen("CreateAwsKmsMrkDiscoveryKeyring");
  }

  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#onencrypt
  //= type=test
  //# This function MUST fail.

  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#onencrypt
  //= type=test
  //# This function MUST fail.
  @Test
  void encryptFails() {
    for (Pair keyring : Arrays.asList(discovery(kms, null, null), mrkDiscovery(kms, REGION, null))) {
      for (AlgorithmSuiteId suite : allSuites()) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          String outcome = assertSameEncrypt(aws, outcomes, keyring, encryptionMaterials(suite, map("a", "b"), withDataKey), "");
          assertTrue(outcome.endsWith("Encryption is not supported with a Discovery Keyring."), outcome);
        }
      }
    }
  }

  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //= type=test
  //# - The provider info MUST be a [valid AWS KMS ARN](aws-kms-key
  //# -arn.md#a-valid-aws-kms-arn) with a resource type of `key` or
  //# OnDecrypt MUST fail.

  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //= type=test
  //# The set of encrypted data keys MUST first be filtered to match this
  //# keyring’s configuration.

  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
  //= type=test
  //# The set of encrypted data keys MUST first be filtered to match this
  //# keyring’s configuration.

  //= spec/framework/aws-kms/aws-kms-mrk-discovery-keyring.md#ondecrypt
  //= type=test
  //# - `KeyId`: If the provider info’s resource type is `key` and its
  //# resource is a multi-Region key then a new ARN MUST be created
  //# where the region part MUST equal the AWS KMS client region and
  //# every other part MUST equal the provider info.

  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //= type=test
  //# - The `KeyId` field in the response MUST equal the AWS KMS ARN from the provider info
  @Test
  void decrypt() {
    String arn = aws.kms().createSymmetricKey(REGION);
    String otherRegionArn = aws.kms().createSymmetricKey(OTHER_REGION);
    List<String> replicas = aws.kms().createMultiRegionKey(REGION, OTHER_REGION);
    String prefix = arn.substring(0, arn.indexOf("key/"));
    Map<String, Pair> keyrings = new LinkedHashMap<>();
    for (DiscoveryFilter filter : matchingFilters()) {
      String name = filter == null ? "no filter" : ReferenceMpl.describe(filter);
      keyrings.put("discovery " + name, discovery(kms, filter, Collections.singletonList("token")));
      keyrings.put("MRK discovery " + REGION + " " + name, mrkDiscovery(kms, REGION, filter));
      keyrings.put("MRK discovery " + OTHER_REGION + " " + name, mrkDiscovery(otherKms, OTHER_REGION, filter));
    }
    // The region is not checked against the client's: KMS is asked through the client, with the configured region in the ARN.
    keyrings.put("MRK discovery, client in another region", mrkDiscovery(kms, OTHER_REGION, null));
    Pair encryptor = kmsKeyring(arn, kms);
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials encrypted = encryptor.nativeEncrypt(encryptionMaterials(suite, map("a", "b"), false));
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false).toBuilder().plaintextDataKey(encrypted.plaintextDataKey()).build();
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      EncryptedDataKey otherRegion = kmsKeyring(otherRegionArn, otherKms).nativeEncrypt(start).encryptedDataKeys().get(0);
      EncryptedDataKey replica = kmsKeyring(replicas.get(0), kms).nativeEncrypt(start).encryptedDataKeys().get(0);
      EncryptedDataKey otherReplica = kmsKeyring(replicas.get(1), otherKms).nativeEncrypt(start).encryptedDataKeys().get(0);
      byte[] ciphertext = array(good.ciphertext());
      DecryptionMaterials materials = decryptionMaterials(encrypted);

      List<List<EncryptedDataKey>> edkLists = new ArrayList<>();
      edkLists.add(Collections.emptyList());
      for (EncryptedDataKey edk : Arrays.asList(good, otherRegion, replica, otherReplica)) {
        edkLists.add(Collections.singletonList(edk));
      }
      edkLists.add(Arrays.asList(otherRegion, good));
      edkLists.add(Arrays.asList(otherReplica, replica));
      edkLists.add(Arrays.asList(good, otherRegion));
      // A key ARN as another provider's info is skipped by both MPLs.
      edkLists.add(Arrays.asList(edk("other", array(good.keyProviderInfo()), ciphertext), good));
      edkLists.add(Collections.singletonList(edk("other", array(good.keyProviderInfo()), ciphertext)));
      // An aws-kms key whose provider info is not a key ARN fails the whole call.
      edkLists.add(Arrays.asList(good, edk("aws-kms", new byte[] { (byte) 0xff }, ciphertext)));
      for (String info : Arrays.asList("not an arn", prefix + "alias/named", "key/abc", prefix + "key/", "arn:aws:kms:" + REGION + ":x:key/a:b")) {
        edkLists.add(Arrays.asList(good, edk("aws-kms", info.getBytes(StandardCharsets.UTF_8), ciphertext)));
      }
      // Key ARNs that parse but that ValidateKmsKeyId rejects, or that name a key KMS does not know.
      for (String info : Arrays.asList(prefix + "key/é", prefix + "key/" + repeat('a', 2048), prefix + "key/mrk-unknown", prefix.replace("arn:aws:", "arn:aws-cn:") + "key/a")) {
        edkLists.add(Arrays.asList(edk("aws-kms", info.getBytes(StandardCharsets.UTF_8), ciphertext), good));
      }
      edkLists.add(Collections.singletonList(edk("aws-kms", array(good.keyProviderInfo()), flip(ciphertext, ciphertext.length - 1))));
      edkLists.add(Collections.singletonList(edk("aws-kms", array(good.keyProviderInfo()), new byte[0])));
      // An ARN as provider info, so the reference's discovery keyring gets past it (see B2).
      edkLists.add(Collections.singletonList(edk("aws-kms-hierarchy", array(good.keyProviderInfo()), bytes(100, 7))));

      for (Map.Entry<String, Pair> keyring : keyrings.entrySet()) {
        String context = keyring.getKey() + " " + ReferenceMpl.describe(suite);
        for (List<EncryptedDataKey> edks : edkLists) {
          assertSameDecrypt(aws, outcomes, keyring.getValue(), materials, edks, context);
        }
      }

      String context = ReferenceMpl.describe(suite);
      for (Pair keyring : Arrays.asList(keyrings.get("discovery no filter"), keyrings.get("MRK discovery " + OTHER_REGION + " no filter"))) {
        List<EncryptedDataKey> edks = keyring == keyrings.get("discovery no filter") ? Collections.singletonList(good) : Collections.singletonList(replica);
        for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
          aws.kms().fail("Decrypt", null, error.getValue());
          assertSameDecrypt(aws, outcomes, keyring, materials, edks, context + " " + error.getKey());
          aws.kms().clearFailures();
        }
        Map<String, UnaryOperator<ObjectNode>> edits = new LinkedHashMap<>();
        edits.put("no KeyId", r -> remove(r, "KeyId"));
        edits.put("other KeyId", r -> r.put("KeyId", otherRegionArn));
        edits.put("replica KeyId", r -> r.put("KeyId", replicas.get(0)));
        edits.put("no Plaintext", r -> remove(r, "Plaintext"));
        edits.put("long Plaintext", r -> r.put("Plaintext", base64(Arrays.copyOf(decode(r, "Plaintext"), decode(r, "Plaintext").length + 1))));
        for (Map.Entry<String, UnaryOperator<ObjectNode>> edit : edits.entrySet()) {
          aws.kms().editResponses("Decrypt", edit.getValue());
          assertSameDecrypt(aws, outcomes, keyring, materials, edks, context + " " + edit.getKey());
          aws.kms().clearFailures();
        }
        assertSameDecrypt(aws, outcomes, keyring, decryptionMaterials(encrypted, map("a", "c")), edks, context + " other context");
        DecryptionMaterials missingRequired = materials.toBuilder().requiredEncryptionContextKeys(Collections.singletonList("missing")).build();
        assertSameDecrypt(aws, outcomes, keyring, missingRequired, edks, context + " invalid");
        assertSameDecrypt(aws, outcomes, keyring, keyring.nativeDecrypt(materials, edks), edks, context + " has data key");
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  /**
   * B1: the reference matches a filter's account list as a prefix of the key's one-element account list,
   * so a filter with two or more accounts matches no key. Native matches by membership.
   */
  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //= type=test
  //# - If a discovery filter is configured, its set of accounts MUST contain the provider info account.
  @Test
  void filterWithSeveralAccountsMatchesEachAccount() {
    String arn = aws.kms().createSymmetricKey(REGION);
    EncryptionMaterials encrypted = kmsKeyring(arn, kms).nativeEncrypt(encryptionMaterials(allSuites().get(0), map("a", "b"), false));
    DecryptionMaterials materials = decryptionMaterials(encrypted);
    for (List<String> accounts : Arrays.asList(Arrays.asList(FakeKms.ACCOUNT, OTHER_ACCOUNT), Arrays.asList(OTHER_ACCOUNT, FakeKms.ACCOUNT))) {
      Pair keyring = discovery(kms, DiscoveryFilter.builder().accountIds(accounts).partition("aws").build(), null);
      String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", decryptInput(materials, encrypted.encryptedDataKeys())));
      assertTrue(expected.contains("Unable to decrypt data key: No Encrypted Data Keys found to match."), expected);
      assertEquals(
        ReferenceMpl.describe(expectedDecryption(encrypted).materials()),
        ReferenceMpl.describe(keyring.nativeDecrypt(materials, encrypted.encryptedDataKeys()))
      );
    }
  }

  /**
   * B2: the reference parses every encrypted data key's provider info as a KMS ARN before checking the provider id,
   * so another keyring's key fails the call. Native skips keys of other providers first, as the MRK discovery keyring does.
   */
  //= spec/framework/aws-kms/aws-kms-discovery-keyring.md#ondecrypt
  //= type=test
  //# - Its provider ID MUST exactly match the value “aws-kms”.
  @Test
  void keysOfOtherProvidersAreSkipped() {
    String arn = aws.kms().createSymmetricKey(REGION);
    EncryptionMaterials encrypted = kmsKeyring(arn, kms).nativeEncrypt(encryptionMaterials(allSuites().get(0), map("a", "b"), false));
    DecryptionMaterials materials = decryptionMaterials(encrypted);
    EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
    String alias = arn.substring(0, arn.indexOf("key/")) + "alias/named";
    Map<EncryptedDataKey, String> others = new LinkedHashMap<>();
    others.put(edk("raw-aes", new byte[] { (byte) 0xff }, new byte[3]), "Invalid AWS KMS encoding, provider info is not UTF8.");
    others.put(edk("raw-aes", "name".getBytes(StandardCharsets.UTF_8), new byte[3]), "Malformed arn: name");
    others.put(edk("other", alias.getBytes(StandardCharsets.UTF_8), new byte[3]), "Only AWS KMS Keys supported");
    Pair keyring = discovery(kms, null, null);
    for (Map.Entry<EncryptedDataKey, String> other : others.entrySet()) {
      List<EncryptedDataKey> edks = Arrays.asList(other.getKey(), good);
      String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(keyring.referenceKeyring, "OnDecrypt", decryptInput(materials, edks)));
      assertTrue(expected.endsWith(other.getValue()), expected);
      assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted).materials()), ReferenceMpl.describe(keyring.nativeDecrypt(materials, edks)));
    }
  }

  /** Filters every create input accepts or rejects. */
  static List<DiscoveryFilter> filters() {
    List<DiscoveryFilter> filters = new ArrayList<>();
    filters.add(null);
    filters.addAll(matchingFilters().subList(1, matchingFilters().size()));
    filters.add(DiscoveryFilter.builder().accountIds(Collections.emptyList()).partition("aws").build());
    filters.add(DiscoveryFilter.builder().accountIds(Collections.singletonList("")).partition("aws").build());
    filters.add(DiscoveryFilter.builder().accountIds(Arrays.asList(FakeKms.ACCOUNT, "")).partition("").build());
    filters.add(DiscoveryFilter.builder().accountIds(Collections.singletonList(" ")).partition(" ").build());
    filters.add(DiscoveryFilter.builder().accountIds(Collections.singletonList(FakeKms.ACCOUNT)).partition("").build());
    filters.add(DiscoveryFilter.builder().accountIds(Collections.emptyList()).partition("").build());
    return filters;
  }

  /** Valid filters on which both MPLs agree: none, one account (matching or not), another partition. */
  static List<DiscoveryFilter> matchingFilters() {
    return Arrays.asList(
      null,
      DiscoveryFilter.builder().accountIds(Collections.singletonList(FakeKms.ACCOUNT)).partition("aws").build(),
      DiscoveryFilter.builder().accountIds(Collections.singletonList(OTHER_ACCOUNT)).partition("aws").build(),
      DiscoveryFilter.builder().accountIds(Collections.singletonList(FakeKms.ACCOUNT)).partition("aws-cn").build()
    );
  }

  private Pair discovery(KmsClient client, DiscoveryFilter filter, List<String> grantTokens) {
    CreateAwsKmsDiscoveryKeyringInput input = CreateAwsKmsDiscoveryKeyringInput
      .builder()
      .kmsClient(client)
      .discoveryFilter(filter)
      .grantTokens(grantTokens)
      .build();
    return new Pair(MPL.CreateAwsKmsDiscoveryKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryKeyring", input));
  }

  private Pair mrkDiscovery(KmsClient client, String region, DiscoveryFilter filter) {
    CreateAwsKmsMrkDiscoveryKeyringInput input = CreateAwsKmsMrkDiscoveryKeyringInput
      .builder()
      .kmsClient(client)
      .region(region)
      .discoveryFilter(filter)
      .grantTokens(Collections.singletonList("token"))
      .build();
    return new Pair(MPL.CreateAwsKmsMrkDiscoveryKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryKeyring", input));
  }

  private Pair kmsKeyring(String keyId, KmsClient client) {
    CreateAwsKmsKeyringInput input = CreateAwsKmsKeyringInput.builder().kmsKeyId(keyId).kmsClient(client).build();
    return new Pair(MPL.CreateAwsKmsKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsKeyring", input));
  }
}
