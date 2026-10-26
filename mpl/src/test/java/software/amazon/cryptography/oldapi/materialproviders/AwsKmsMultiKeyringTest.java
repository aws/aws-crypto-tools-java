// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.created;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.remove;
import static software.amazon.cryptography.oldapi.materialproviders.AwsKmsKeyringTest.serviceErrors;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.oldapi.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.Supplied;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsDiscoveryMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMrkDiscoveryMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.DiscoveryFilter;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;

// Differential tests of the four KMS multi keyrings against the published Dafny-based MPL, on one fake KMS,
// with a client supplier whose calls are compared too.
class AwsKmsMultiKeyringTest {

  private final Object reference = ReferenceMpl.materialProviders();
  private final Outcomes outcomes = new Outcomes();
  private final FakeAws aws = FakeAws.start();
  private final Supplied supplier = supplier(aws);

  @AfterEach
  void close() {
    aws.close();
  }

  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
  //= type=test
  //# If any of the AWS KMS key identifiers is not a [valid AWS KMS key ARN]
  //# (aws-kms-key-arn.md#a-valid-aws-kms-arn), this function MUST fail.

  //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
  //= type=test
  //# All
  //# AWS KMS identifiers are passed to [Assert AWS KMS MRK are unique](aws-
  //# kms-mrk-are-unique.md#Implementation) and the function MUST return
  //# success otherwise this MUST fail.
  @Test
  void createStrict() {
    String prefix = "arn:aws:kms:" + REGION + ":" + FakeKms.ACCOUNT + ":";
    String otherPrefix = "arn:aws:kms:" + OTHER_REGION + ":" + FakeKms.ACCOUNT + ":";
    List<String> generators = Arrays.asList(
      null,
      prefix + "key/k1",
      prefix + "key/mrk-1",
      "k1",
      "mrk-1",
      "alias/name",
      otherPrefix + "alias/name",
      "",
      "key/k1",
      "alias/é",
      "alias/" + repeat('a', 2042),
      // Non-ASCII and too long: IsAwsKmsIdentifierString reports the ASCII failure first; too long and unparsable: length first.
      "alias/\u00e9" + repeat('a', 2050),
      "key/" + repeat('a', 2050),
      "alias/" + repeat('a', 2043)
    );
    //= spec/framework/aws-kms/aws-kms-mrk-are-unique.md#implementation
    //= type=test
    //# If any duplicate multi-region resource ids exist, this function MUST
    //# yield an error that includes all identifiers with duplicate resource
    //# ids not only the first duplicate found.
    List<List<String>> keyLists = Arrays.asList(
      null,
      Collections.<String>emptyList(),
      Collections.singletonList(otherPrefix + "key/k2"),
      Arrays.asList("k2", prefix + "alias/a"),
      Collections.singletonList(otherPrefix + "key/mrk-1"),
      Arrays.asList(prefix + "key/mrk-2", "mrk-2"),
      Arrays.asList(prefix + "key/mrk-1", "alias/mrk-1"),
      Arrays.asList("mrk-3", "mrk-3"),
      Arrays.asList(prefix + "key/k2", "arn:aws:kms"),
      Arrays.asList("", "k2"),
      Arrays.asList("k2", "alias/é")
    );
    for (String generator : generators) {
      for (List<String> keys : keyLists) {
        for (List<String> grantTokens : Arrays.asList(null, Collections.singletonList(""))) {
          String context = generator + " " + keys + " " + grantTokens;
          CreateAwsKmsMultiKeyringInput input = CreateAwsKmsMultiKeyringInput
            .builder()
            .generator(generator)
            .kmsKeyIds(keys)
            .clientSupplier(supplier)
            .grantTokens(grantTokens)
            .build();
          assertSame(
            aws,
            outcomes,
            "CreateAwsKmsMultiKeyring",
            () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMultiKeyring", input)),
            () -> created(MPL.CreateAwsKmsMultiKeyring(input)),
            context
          );
          supplier.assertSameCalls(context);
          CreateAwsKmsMrkMultiKeyringInput mrkInput = CreateAwsKmsMrkMultiKeyringInput
            .builder()
            .generator(generator)
            .kmsKeyIds(keys)
            .clientSupplier(supplier)
            .grantTokens(grantTokens)
            .build();
          assertSame(
            aws,
            outcomes,
            "CreateAwsKmsMrkMultiKeyring",
            () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMrkMultiKeyring", mrkInput)),
            () -> created(MPL.CreateAwsKmsMrkMultiKeyring(mrkInput)),
            context
          );
          supplier.assertSameCalls(context);
        }
      }
    }
    outcomes.assertBothSeen("CreateAwsKmsMultiKeyring");
    outcomes.assertBothSeen("CreateAwsKmsMrkMultiKeyring");
  }

  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
  //= type=test
  //# If an empty set of Region is provided this function MUST fail.

  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
  //= type=test
  //# If
  //# any element of the set of regions is null or an empty string this
  //# function MUST fail.

  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
  //= type=test
  //# A set of AWS KMS clients MUST be created by calling regional client
  //# supplier for each region in the input set of regions.

  //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
  //= type=test
  //# If an empty set of Region is provided this function MUST fail.

  //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
  //= type=test
  //# If
  //# any element of the set of regions is null or an empty string this
  //# function MUST fail.

  //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
  //= type=test
  //# A set of AWS KMS clients MUST be created by calling regional client
  //# supplier for each region in the input set of regions.
  @Test
  void createDiscovery() {
    List<List<String>> regionLists = Arrays.asList(
      Collections.<String>emptyList(),
      Collections.singletonList(""),
      Arrays.asList(REGION, ""),
      Collections.singletonList(REGION),
      Arrays.asList(REGION, OTHER_REGION),
      Arrays.asList(OTHER_REGION, OTHER_REGION)
    );
    for (List<String> regions : regionLists) {
      for (DiscoveryFilter filter : AwsKmsDiscoveryKeyringTest.matchingFilters()) {
        for (List<String> grantTokens : Arrays.asList(null, Collections.singletonList(""))) {
          String context = regions + " " + ReferenceMpl.describe(filter) + " " + grantTokens;
          CreateAwsKmsDiscoveryMultiKeyringInput input = CreateAwsKmsDiscoveryMultiKeyringInput
            .builder()
            .regions(regions)
            .discoveryFilter(filter)
            .clientSupplier(supplier)
            .grantTokens(grantTokens)
            .build();
          assertSame(
            aws,
            outcomes,
            "CreateAwsKmsDiscoveryMultiKeyring",
            () -> created(ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryMultiKeyring", input)),
            () -> created(MPL.CreateAwsKmsDiscoveryMultiKeyring(input)),
            context
          );
          supplier.assertSameCalls(context);
          CreateAwsKmsMrkDiscoveryMultiKeyringInput mrkInput = CreateAwsKmsMrkDiscoveryMultiKeyringInput
            .builder()
            .regions(regions)
            .discoveryFilter(filter)
            .clientSupplier(supplier)
            .grantTokens(grantTokens)
            .build();
          assertSame(
            aws,
            outcomes,
            "CreateAwsKmsMrkDiscoveryMultiKeyring",
            () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryMultiKeyring", mrkInput)),
            () -> created(MPL.CreateAwsKmsMrkDiscoveryMultiKeyring(mrkInput)),
            context
          );
          supplier.assertSameCalls(context);
        }
      }
    }
    outcomes.assertBothSeen("CreateAwsKmsDiscoveryMultiKeyring");
    outcomes.assertBothSeen("CreateAwsKmsMrkDiscoveryMultiKeyring");
  }

  @Test
  void supplierFailures() {
    List<Supplied> suppliers = Arrays.asList(
      new Supplied(input -> {
        throw AwsCryptographicMaterialProvidersException.builder().message("no client for " + input.region()).build();
      }),
      new Supplied(input -> {
        throw new IllegalStateException("boom " + input.region());
      })
    );
    for (Supplied failing : suppliers) {
      CreateAwsKmsMultiKeyringInput strict = CreateAwsKmsMultiKeyringInput
        .builder()
        .kmsKeyIds(Collections.singletonList("arn:aws:kms:" + REGION + ":" + FakeKms.ACCOUNT + ":key/k1"))
        .clientSupplier(failing)
        .build();
      assertSame(
        aws,
        outcomes,
        "create",
        () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMultiKeyring", strict)),
        () -> created(MPL.CreateAwsKmsMultiKeyring(strict)),
        "strict"
      );
      CreateAwsKmsMrkMultiKeyringInput mrk = CreateAwsKmsMrkMultiKeyringInput.builder().generator("k1").clientSupplier(failing).build();
      assertSame(
        aws,
        outcomes,
        "create",
        () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMrkMultiKeyring", mrk)),
        () -> created(MPL.CreateAwsKmsMrkMultiKeyring(mrk)),
        "mrk"
      );
      CreateAwsKmsDiscoveryMultiKeyringInput discovery = CreateAwsKmsDiscoveryMultiKeyringInput
        .builder()
        .regions(Collections.singletonList(REGION))
        .clientSupplier(failing)
        .build();
      assertSame(
        aws,
        outcomes,
        "create",
        () -> created(ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryMultiKeyring", discovery)),
        () -> created(MPL.CreateAwsKmsDiscoveryMultiKeyring(discovery)),
        "discovery"
      );
      CreateAwsKmsMrkDiscoveryMultiKeyringInput mrkDiscovery = CreateAwsKmsMrkDiscoveryMultiKeyringInput
        .builder()
        .regions(Collections.singletonList(REGION))
        .clientSupplier(failing)
        .build();
      assertSame(
        aws,
        outcomes,
        "create",
        () -> created(ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryMultiKeyring", mrkDiscovery)),
        () -> created(MPL.CreateAwsKmsMrkDiscoveryMultiKeyring(mrkDiscovery)),
        "mrk discovery"
      );
    }
  }

  @Test
  void strictEncryptAndDecrypt() {
    String generator = aws.kms().createSymmetricKey(REGION);
    String child = aws.kms().createSymmetricKey(OTHER_REGION);
    List<String> replicas = aws.kms().createMultiRegionKey(REGION, OTHER_REGION);
    String childId = child.substring(child.indexOf("key/") + 4);
    Map<String, Pair> multis = new LinkedHashMap<>();
    multis.put("generator and children", strict(false, generator, Arrays.asList(child, replicas.get(1))));
    multis.put("generator only", strict(false, generator, null));
    multis.put("children only", strict(false, null, Arrays.asList(child, generator)));
    multis.put("key id child", strict(false, generator, Collections.singletonList(childId)));
    multis.put("MRK generator and children", strict(true, replicas.get(0), Collections.singletonList(child)));
    multis.put("MRK children only", strict(true, null, Arrays.asList(replicas.get(1), generator)));
    Pair replicaDecryptor = strict(true, replicas.get(1), null);
    for (Map.Entry<String, Pair> multi : multis.entrySet()) {
      for (AlgorithmSuiteId suite : allSuites()) {
        for (boolean withDataKey : new boolean[] { false, true }) {
          EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), withDataKey);
          String context = multi.getKey() + " " + ReferenceMpl.describe(suite) + " data key " + withDataKey;
          String outcome = assertSameEncrypt(aws, outcomes, multi.getValue(), start, context);
          if (outcome.startsWith("throws")) {
            continue;
          }
          for (EncryptionMaterials result : Arrays.asList(multi.getValue().nativeEncrypt(start), multi.getValue().referenceEncrypt(start))) {
            for (Pair decryptor : Arrays.asList(multi.getValue(), replicaDecryptor)) {
              assertSameDecrypt(aws, outcomes, decryptor, decryptionMaterials(result), result.encryptedDataKeys(), context);
            }
            // Each encrypted data key alone, and in reverse order.
            List<EncryptedDataKey> reversed = new ArrayList<>(result.encryptedDataKeys());
            Collections.reverse(reversed);
            assertSameDecrypt(aws, outcomes, multi.getValue(), decryptionMaterials(result), reversed, context);
            for (int i = 0; i < result.encryptedDataKeys().size(); i++) {
              List<EncryptedDataKey> one = Collections.singletonList(result.encryptedDataKeys().get(i));
              String decrypted = assertSameDecrypt(aws, outcomes, multi.getValue(), decryptionMaterials(result), one, context);
              // For intermediate-wrapping suites, each encrypted data key has its own symmetric signing key.
              List<java.nio.ByteBuffer> signingKeys = result.symmetricSigningKeys();
              EncryptionMaterials alone = result
                .toBuilder()
                .symmetricSigningKeys(signingKeys == null || signingKeys.isEmpty() ? signingKeys : Collections.singletonList(signingKeys.get(i)))
                .build();
              assertEquals(ReferenceMpl.describe(expectedDecryption(alone)), decrypted, context);
            }
          }
        }
      }
    }
    outcomes.assertBothSeen("OnEncrypt");
  }

  @Test
  void strictFailures() {
    String generator = aws.kms().createSymmetricKey(REGION);
    String child = aws.kms().createSymmetricKey(OTHER_REGION);
    Pair multi = strict(false, generator, Collections.singletonList(child));
    Pair childrenOnly = strict(false, null, Collections.singletonList(child));
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      EncryptionMaterials encrypted = multi.nativeEncrypt(start);
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      for (Map.Entry<String, ServiceError> error : serviceErrors().entrySet()) {
        String context = ReferenceMpl.describe(suite) + " " + error.getKey();
        for (String keyArn : Arrays.asList(generator, child)) {
          for (String operation : Arrays.asList("GenerateDataKey", "Encrypt", "Decrypt")) {
            aws.kms().fail(operation, keyArn, error.getValue());
            assertSameEncrypt(aws, outcomes, multi, start, context + " " + operation + " " + keyArn);
            assertSameEncrypt(aws, outcomes, childrenOnly, encryptionMaterials(suite, map("a", "b"), true), context + " " + operation + " " + keyArn);
            assertSameDecrypt(aws, outcomes, multi, materials, encrypted.encryptedDataKeys(), context + " " + operation + " " + keyArn);
            aws.kms().clearFailures();
          }
        }
      }
      aws.kms().fail("Decrypt", null, ServiceError.accessDenied("no"));
      assertSameDecrypt(aws, outcomes, multi, materials, encrypted.encryptedDataKeys(), "every key denied");
      aws.kms().clearFailures();
      // A misbehaving response for one key only: the generator's Decrypt names another key, the child's succeeds.
      aws.kms().editResponses("Decrypt", generator, r -> r.put("KeyId", child));
      assertSameDecrypt(aws, outcomes, multi, materials, encrypted.encryptedDataKeys(), "generator response names another key");
      aws.kms().editResponses("Encrypt", child, r -> remove(r, "CiphertextBlob"));
      assertSameEncrypt(aws, outcomes, multi, start, "child response without ciphertext");
      aws.kms().clearFailures();
      assertSameEncrypt(aws, outcomes, childrenOnly, start, "children only, no data key");
    }
    outcomes.assertBothSeen("OnEncrypt");
    outcomes.assertBothSeen("OnDecrypt");
  }

  @Test
  void discoveryDecrypt() {
    String key = aws.kms().createSymmetricKey(REGION);
    String otherKey = aws.kms().createSymmetricKey(OTHER_REGION);
    List<String> replicas = aws.kms().createMultiRegionKey(OTHER_REGION, REGION);
    Map<String, Pair> multis = new LinkedHashMap<>();
    for (DiscoveryFilter filter : AwsKmsDiscoveryKeyringTest.matchingFilters()) {
      String name = filter == null ? "no filter" : ReferenceMpl.describe(filter);
      multis.put("discovery " + name, discovery(false, Arrays.asList(REGION, OTHER_REGION), filter));
      multis.put("MRK discovery " + name, discovery(true, Arrays.asList(REGION, OTHER_REGION), filter));
    }
    multis.put("MRK discovery, other region only", discovery(true, Collections.singletonList(OTHER_REGION), null));
    multis.put("discovery, other region only", discovery(false, Collections.singletonList(OTHER_REGION), null));
    for (AlgorithmSuiteId suite : allSuites()) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      EncryptionMaterials encrypted = kmsKeyring(key, REGION).nativeEncrypt(start);
      EncryptionMaterials withKey = start.toBuilder().plaintextDataKey(encrypted.plaintextDataKey()).build();
      EncryptedDataKey good = encrypted.encryptedDataKeys().get(0);
      EncryptedDataKey other = kmsKeyring(otherKey, OTHER_REGION).nativeEncrypt(withKey).encryptedDataKeys().get(0);
      EncryptedDataKey replica = kmsKeyring(replicas.get(1), REGION).nativeEncrypt(withKey).encryptedDataKeys().get(0);
      DecryptionMaterials materials = decryptionMaterials(encrypted);
      List<List<EncryptedDataKey>> edkLists = Arrays.asList(
        Collections.<EncryptedDataKey>emptyList(),
        Collections.singletonList(good),
        Collections.singletonList(other),
        Collections.singletonList(replica),
        Arrays.asList(other, good),
        Arrays.asList(replica, other)
      );
      for (Map.Entry<String, Pair> multi : multis.entrySet()) {
        for (List<EncryptedDataKey> edks : edkLists) {
          assertSameDecrypt(aws, outcomes, multi.getValue(), materials, edks, multi.getKey() + " " + ReferenceMpl.describe(suite));
        }
        aws.kms().fail("Decrypt", null, ServiceError.throttling("slow down"));
        assertSameDecrypt(aws, outcomes, multi.getValue(), materials, Arrays.asList(other, good), multi.getKey() + " throttled");
        aws.kms().clearFailures();
        for (boolean dataKey : new boolean[] { false, true }) {
          assertSameEncrypt(aws, outcomes, multi.getValue(), encryptionMaterials(suite, map("a", "b"), dataKey), multi.getKey());
        }
      }
    }
    outcomes.assertBothSeen("OnDecrypt");
  }

  /**
   * The discovery multi keyrings take the filter as is in the reference, while native filters are validated when built.
   * A filter the single-Region discovery keyrings reject is rejected here too (open decision X1).
   */
  @Test
  void invalidFilterRejectedAtCreation() {
    Map<DiscoveryFilter, String> filters = new LinkedHashMap<>();
    filters.put(DiscoveryFilter.builder().accountIds(Collections.emptyList()).partition("aws").build(), "Discovery filter must have at least one account ID");
    filters.put(DiscoveryFilter.builder().accountIds(Collections.singletonList("")).partition("aws").build(), "Discovery filter account IDs cannot be blank");
    filters.put(DiscoveryFilter.builder().accountIds(Collections.singletonList(FakeKms.ACCOUNT)).partition("").build(), "Discovery filter partition cannot be blank");
    for (Map.Entry<DiscoveryFilter, String> filter : filters.entrySet()) {
      Object[] inputs = {
        CreateAwsKmsDiscoveryMultiKeyringInput.builder().regions(Collections.singletonList(REGION)).discoveryFilter(filter.getKey()).clientSupplier(supplier).build(),
        CreateAwsKmsMrkDiscoveryMultiKeyringInput.builder().regions(Collections.singletonList(REGION)).discoveryFilter(filter.getKey()).clientSupplier(supplier).build(),
      };
      for (Object input : inputs) {
        String operation = input.getClass().getSimpleName().replace("Input", "");
        assertEquals("\"keyring\"", ReferenceMpl.outcome(() -> created(ReferenceMpl.call(reference, operation, input))), operation);
        String actual = ReferenceMpl.outcome(() ->
          created(
            input instanceof CreateAwsKmsDiscoveryMultiKeyringInput
              ? MPL.CreateAwsKmsDiscoveryMultiKeyring((CreateAwsKmsDiscoveryMultiKeyringInput) input)
              : MPL.CreateAwsKmsMrkDiscoveryMultiKeyring((CreateAwsKmsMrkDiscoveryMultiKeyringInput) input)
          )
        );
        assertTrue(actual.endsWith("AwsCryptographicMaterialProvidersException: " + filter.getValue()), operation + " " + actual);
      }
    }
  }

  /** X1 matters for the plain discovery multi keyring: with no accounts, the reference's filter matches every account. */
  @Test
  void referenceEmptyFilterMatchesEveryAccount() {
    String key = aws.kms().createSymmetricKey(REGION);
    DiscoveryFilter empty = DiscoveryFilter.builder().accountIds(Collections.emptyList()).partition("aws").build();
    CreateAwsKmsDiscoveryMultiKeyringInput input = CreateAwsKmsDiscoveryMultiKeyringInput
      .builder()
      .regions(Collections.singletonList(REGION))
      .discoveryFilter(empty)
      .clientSupplier(supplier)
      .build();
    Object referenceKeyring = ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryMultiKeyring", input);
    EncryptionMaterials encrypted = kmsKeyring(key, REGION).nativeEncrypt(encryptionMaterials(allSuites().get(0), map("a", "b"), false));
    String decrypted = ReferenceMpl.outcome(() ->
      ReferenceMpl.call(referenceKeyring, "OnDecrypt", decryptInput(decryptionMaterials(encrypted), encrypted.encryptedDataKeys()))
    );
    assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted)), decrypted);
  }

  private Pair strict(boolean mrk, String generator, List<String> keys) {
    if (mrk) {
      CreateAwsKmsMrkMultiKeyringInput input = CreateAwsKmsMrkMultiKeyringInput
        .builder()
        .generator(generator)
        .kmsKeyIds(keys)
        .clientSupplier(supplier)
        .grantTokens(Collections.singletonList("token"))
        .build();
      return new Pair(MPL.CreateAwsKmsMrkMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkMultiKeyring", input));
    }
    CreateAwsKmsMultiKeyringInput input = CreateAwsKmsMultiKeyringInput
      .builder()
      .generator(generator)
      .kmsKeyIds(keys)
      .clientSupplier(supplier)
      .grantTokens(Collections.singletonList("token"))
      .build();
    return new Pair(MPL.CreateAwsKmsMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMultiKeyring", input));
  }

  private Pair discovery(boolean mrk, List<String> regions, DiscoveryFilter filter) {
    if (mrk) {
      CreateAwsKmsMrkDiscoveryMultiKeyringInput input = CreateAwsKmsMrkDiscoveryMultiKeyringInput
        .builder()
        .regions(regions)
        .discoveryFilter(filter)
        .clientSupplier(supplier)
        .build();
      return new Pair(MPL.CreateAwsKmsMrkDiscoveryMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsMrkDiscoveryMultiKeyring", input));
    }
    CreateAwsKmsDiscoveryMultiKeyringInput input = CreateAwsKmsDiscoveryMultiKeyringInput
      .builder()
      .regions(regions)
      .discoveryFilter(filter)
      .clientSupplier(supplier)
      .build();
    return new Pair(MPL.CreateAwsKmsDiscoveryMultiKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsDiscoveryMultiKeyring", input));
  }

  private Pair kmsKeyring(String keyId, String region) {
    KmsClient client = ReferenceAws.kms(aws, region);
    CreateAwsKmsKeyringInput input = CreateAwsKmsKeyringInput.builder().kmsKeyId(keyId).kmsClient(client).build();
    return new Pair(MPL.CreateAwsKmsKeyring(input), ReferenceMpl.call(reference, "CreateAwsKmsKeyring", input));
  }
}
