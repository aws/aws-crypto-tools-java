// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.OTHER_REGION;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.REGION;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.retry.AwsRetryStrategy;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.FakeKms;
import software.amazon.cryptography.materialproviders.fakeaws.ServiceError;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.exceptions.ErrorKind;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.ClientSupplier;
import software.amazon.cryptography.materialproviders.keyrings.DiscoveryFilter;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;

// What the new API adds over the old one for the KMS keyrings, which the differential tests cannot see:
// error kinds with the SDK exception as cause, accessors, builder checks, and the discovery filter value type.
class KmsKeyringsNativeApiTest {

  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = aws.kmsClient("native", REGION);
  private final String key = aws.kms().createSymmetricKey(REGION);
  private final EncryptionMaterials start = EncryptionMaterials
    .builder(EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF)
    .encryptionContext(EncryptionContext.of("a", "b"))
    .build();

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void kmsFailuresHaveAKindAndTheSdkCause() {
    Map<ServiceError, ErrorKind> kinds = new LinkedHashMap<>();
    kinds.put(ServiceError.of("NotFoundException", "gone"), ErrorKind.RESOURCE_NOT_FOUND);
    kinds.put(ServiceError.accessDenied("no"), ErrorKind.ACCESS_DENIED);
    kinds.put(ServiceError.throttling("slow"), ErrorKind.THROTTLING);
    kinds.put(ServiceError.of("ThrottledException", "slow"), ErrorKind.THROTTLING);
    kinds.put(ServiceError.of("LimitExceededException", "quota"), ErrorKind.THROTTLING);
    kinds.put(ServiceError.of("InvalidGrantTokenException", "bad token"), ErrorKind.ACCESS_DENIED);
    kinds.put(ServiceError.of("DisabledException", "off"), ErrorKind.SERVICE);
    kinds.put(ServiceError.of("SomethingNewException", "new"), ErrorKind.SERVICE);
    AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).build();
    for (Map.Entry<ServiceError, ErrorKind> kind : kinds.entrySet()) {
      aws.kms().fail("GenerateDataKey", null, kind.getKey());
      MaterialProvidersException e = assertThrows(MaterialProvidersException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build()));
      assertEquals(kind.getValue(), e.kind(), kind.getKey().type());
      KmsException cause = e.findCause(KmsException.class).get();
      assertSame(cause, e.getCause());
      assertEquals(kind.getKey().type(), cause.awsErrorDetails().errorCode());
      assertEquals(cause.getMessage(), e.getMessage());
      assertEquals(kind.getValue() == ErrorKind.THROTTLING, e.isRetryable(), kind.getKey().type());
      aws.kms().clearFailures();
    }
  }

  @Test
  void anUnreachableEndpointIsADispatchFailure() {
    // Nothing listens on port 1 of the loopback interface, so the connection is refused at once.
    KmsClient unreachable = KmsClient
      .builder()
      .endpointOverride(URI.create("http://127.0.0.1:1"))
      .region(Region.of(REGION))
      .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("AKIAFAKEAWS000000000", "fake")))
      .overrideConfiguration(c -> c.retryStrategy(AwsRetryStrategy.doNotRetry()))
      .build();
    try {
      AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(unreachable).build();
      MaterialProvidersException e = assertThrows(MaterialProvidersException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build()));
      assertEquals(ErrorKind.DISPATCH, e.kind());
      assertTrue(e.getCause() instanceof SdkClientException, String.valueOf(e.getCause()));
      assertTrue(e.isRetryable());
    } finally {
      unreachable.close();
    }
  }

  @Test
  void unexpectedResponsesAreServiceFailures() {
    aws.kms().editResponses("GenerateDataKey", r -> r.put("KeyId", "foo/bar"));
    AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).build();
    MaterialProvidersException e = assertThrows(MaterialProvidersException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build()));
    assertEquals(ErrorKind.SERVICE, e.kind());
    assertEquals("Invalid response from KMS GenerateDataKey:: Invalid Key Id", e.getMessage());
  }

  @Test
  void exceptionsOfACallersClientPropagate() {
    IllegalStateException failure = new IllegalStateException("caller's client");
    KmsClient client = new KmsClient() {
      @Override
      public GenerateDataKeyResponse generateDataKey(GenerateDataKeyRequest request) {
        throw failure;
      }

      @Override
      public DecryptResponse decrypt(DecryptRequest request) {
        throw failure;
      }

      @Override
      public String serviceName() {
        return "kms";
      }

      @Override
      public void close() {}
    };
    AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(client).build();
    assertSame(failure, assertThrows(IllegalStateException.class, () -> keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build())));
    // On decrypt it is collected with the other attempts' failures.
    EncryptionMaterials encrypted = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).build().onEncrypt(OnEncryptRequest.builder().materials(start).build()).materials();
    DecryptionMaterials materials = DecryptionMaterials.builder(start.algorithmSuite()).encryptionContext(start.encryptionContext()).build();
    NoMatchingDataKeyException e = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(materials).encryptedDataKeys(encrypted.encryptedDataKeys()).build()));
    assertEquals(Collections.<Throwable>singletonList(failure), e.failures());
  }

  @Test
  void decryptFailuresAreCollectedWithTheirKinds() {
    AwsKmsKeyring keyring = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).build();
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(start).build()).materials();
    DecryptionMaterials materials = DecryptionMaterials.builder(start.algorithmSuite()).encryptionContext(start.encryptionContext()).build();
    aws.kms().fail("Decrypt", null, ServiceError.accessDenied("no"));
    NoMatchingDataKeyException e = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(materials).encryptedDataKeys(encrypted.encryptedDataKeys()).build()));
    assertEquals(1, e.failures().size());
    assertEquals(ErrorKind.ACCESS_DENIED, ((MaterialProvidersException) e.failures().get(0)).kind());
    assertTrue(e.findCause(SdkException.class).isPresent());
    // No encrypted data key for this keyring is also a no-match failure, with nothing attempted.
    NoMatchingDataKeyException none = assertThrows(NoMatchingDataKeyException.class, () -> keyring.onDecrypt(OnDecryptRequest.builder().materials(materials).encryptedDataKeys(Collections.emptyList()).build()));
    assertTrue(none.failures().isEmpty());
  }

  // A generator's KMS failure is its own kind; a child's is wrapped by the multi keyring. Either way the code is found.
  @Test
  void kmsErrorCodeOnEncrypt() {
    String generatorArn = aws.kms().createSymmetricKey(REGION);
    String childArn = aws.kms().createSymmetricKey(REGION);
    ClientSupplier clients = region -> kms;
    AwsKmsMultiKeyring generatorOnly = AwsKmsMultiKeyring.builder().generator(generatorArn).clientSupplier(clients).build();
    AwsKmsMultiKeyring withChild = AwsKmsMultiKeyring
      .builder()
      .generator(generatorArn)
      .kmsKeyIds(Collections.singletonList(childArn))
      .clientSupplier(clients)
      .build();

    aws.kms().fail("Encrypt", childArn, ServiceError.accessDenied("not for you"));
    MaterialProvidersException child = assertThrows(MaterialProvidersException.class, () -> withChild.onEncrypt(OnEncryptRequest.builder().materials(start).build()));
    assertEquals(ErrorKind.INVALID_MATERIALS, child.kind());
    assertEquals("AccessDeniedException", child.findCause(KmsException.class).get().awsErrorDetails().errorCode());

    aws.kms().fail("GenerateDataKey", generatorArn, ServiceError.accessDenied("not for you"));
    MaterialProvidersException generator = assertThrows(MaterialProvidersException.class, () -> generatorOnly.onEncrypt(OnEncryptRequest.builder().materials(start).build()));
    assertEquals(ErrorKind.ACCESS_DENIED, generator.kind());
    assertEquals("AccessDeniedException", generator.findCause(KmsException.class).get().awsErrorDetails().errorCode());
  }

  @Test
  void accessors() {
    List<String> tokens = new ArrayList<>(Arrays.asList("t1", "t2"));
    AwsKmsKeyring strict = AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).grantTokens(tokens).build();
    tokens.add("t3");
    assertEquals(key, strict.kmsKeyId());
    assertSame(kms, strict.kmsClient());
    assertEquals(Arrays.asList("t1", "t2"), strict.grantTokens());
    assertThrows(UnsupportedOperationException.class, () -> strict.grantTokens().add("x"));
    AwsKmsMrkKeyring mrk = AwsKmsMrkKeyring.builder().kmsKeyId(key).kmsClient(kms).build();
    assertEquals(key, mrk.kmsKeyId());
    assertSame(kms, mrk.kmsClient());
    assertEquals(Collections.emptyList(), mrk.grantTokens());

    DiscoveryFilter filter = DiscoveryFilter.of(Collections.singletonList(FakeKms.ACCOUNT), "aws");
    AwsKmsDiscoveryKeyring discovery = AwsKmsDiscoveryKeyring.builder().kmsClient(kms).discoveryFilter(filter).grantTokens(Collections.singletonList("t")).build();
    assertSame(kms, discovery.kmsClient());
    assertEquals(Optional.of(filter), discovery.discoveryFilter());
    assertEquals(Collections.singletonList("t"), discovery.grantTokens());
    assertEquals(Optional.empty(), AwsKmsDiscoveryKeyring.builder().kmsClient(kms).build().discoveryFilter());
    AwsKmsMrkDiscoveryKeyring mrkDiscovery = AwsKmsMrkDiscoveryKeyring.builder().kmsClient(kms).region(REGION).discoveryFilter(filter).build();
    assertEquals(REGION, mrkDiscovery.region());
    assertSame(kms, mrkDiscovery.kmsClient());
    assertEquals(Optional.of(filter), mrkDiscovery.discoveryFilter());
    assertEquals(Collections.emptyList(), mrkDiscovery.grantTokens());

    ClientSupplier supplier = region -> aws.kmsClient("native", region.isEmpty() ? REGION : region);
    List<String> keyIds = new ArrayList<>(Collections.singletonList(key));
    AwsKmsMultiKeyring multi = AwsKmsMultiKeyring.builder().generator(key).kmsKeyIds(keyIds).clientSupplier(supplier).grantTokens(Collections.singletonList("t")).build();
    keyIds.clear();
    assertEquals(Optional.of(key), multi.generator());
    assertEquals(Collections.singletonList(key), multi.kmsKeyIds());
    assertEquals(Optional.of(supplier), multi.clientSupplier());
    assertEquals(Collections.singletonList("t"), multi.grantTokens());
    AwsKmsMrkMultiKeyring mrkMulti = AwsKmsMrkMultiKeyring.builder().kmsKeyIds(Collections.singletonList(key)).clientSupplier(supplier).build();
    assertEquals(Optional.empty(), mrkMulti.generator());
    assertEquals(Collections.singletonList(key), mrkMulti.kmsKeyIds());
    assertEquals(Optional.of(supplier), mrkMulti.clientSupplier());
    assertEquals(Collections.emptyList(), mrkMulti.grantTokens());
    AwsKmsDiscoveryMultiKeyring discoveryMulti = AwsKmsDiscoveryMultiKeyring
      .builder()
      .regions(Arrays.asList(REGION, OTHER_REGION))
      .discoveryFilter(filter)
      .clientSupplier(supplier)
      .build();
    assertEquals(Arrays.asList(REGION, OTHER_REGION), discoveryMulti.regions());
    assertEquals(Optional.of(filter), discoveryMulti.discoveryFilter());
    assertEquals(Optional.of(supplier), discoveryMulti.clientSupplier());
    assertEquals(Collections.emptyList(), discoveryMulti.grantTokens());
    AwsKmsMrkDiscoveryMultiKeyring mrkDiscoveryMulti = AwsKmsMrkDiscoveryMultiKeyring
      .builder()
      .regions(Collections.singletonList(REGION))
      .clientSupplier(supplier)
      .grantTokens(Collections.singletonList("t"))
      .build();
    assertEquals(Collections.singletonList(REGION), mrkDiscoveryMulti.regions());
    assertEquals(Optional.empty(), mrkDiscoveryMulti.discoveryFilter());
    assertEquals(Collections.singletonList("t"), mrkDiscoveryMulti.grantTokens());
    // Closing a keyring with a caller's supplier closes nothing.
    multi.close();
    assertFalse(multi.onEncrypt(OnEncryptRequest.builder().materials(start).build()).materials().encryptedDataKeys().isEmpty());
  }

  @Test
  void requiredSettings() {
    assertMissing("kmsKeyId", () -> AwsKmsKeyring.builder().kmsClient(kms).build());
    assertMissing("kmsClient", () -> AwsKmsKeyring.builder().kmsKeyId(key).build());
    assertMissing("kmsKeyId", () -> AwsKmsMrkKeyring.builder().kmsClient(kms).build());
    assertMissing("kmsClient", () -> AwsKmsMrkKeyring.builder().kmsKeyId(key).build());
    assertMissing("kmsClient", () -> AwsKmsDiscoveryKeyring.builder().build());
    assertMissing("kmsClient", () -> AwsKmsMrkDiscoveryKeyring.builder().region(REGION).build());
    assertMissing("region", () -> AwsKmsMrkDiscoveryKeyring.builder().kmsClient(kms).build());
    assertThrows(NullPointerException.class, () -> AwsKmsKeyring.builder().kmsKeyId(key).kmsClient(kms).grantTokens(Collections.singletonList(null)).build());
    // Absent key ids and regions are empty lists.
    ClientSupplier supplier = region -> kms;
    assertThrows(ValidationException.class, () -> AwsKmsMultiKeyring.builder().clientSupplier(supplier).build());
    assertThrows(ValidationException.class, () -> AwsKmsDiscoveryMultiKeyring.builder().clientSupplier(supplier).build());
  }

  @Test
  void discoveryFilter() {
    List<String> accounts = new ArrayList<>(Arrays.asList("111", "222"));
    DiscoveryFilter filter = DiscoveryFilter.of(accounts, "aws");
    accounts.add("333");
    assertEquals(Arrays.asList("111", "222"), filter.accountIds());
    assertThrows(UnsupportedOperationException.class, () -> filter.accountIds().add("x"));
    assertEquals("aws", filter.partition());
    assertEquals(DiscoveryFilter.of(Arrays.asList("111", "222"), "aws"), filter);
    assertEquals(DiscoveryFilter.of(Arrays.asList("111", "222"), "aws").hashCode(), filter.hashCode());
    assertNotEquals(DiscoveryFilter.of(Arrays.asList("222", "111"), "aws"), filter);
    assertNotEquals(DiscoveryFilter.of(Arrays.asList("111", "222"), "aws-cn"), filter);
    assertNotEquals(filter, "aws");
    assertEquals("DiscoveryFilter{partition=aws, accountIds=[111, 222]}", filter.toString());
    assertThrows(NullPointerException.class, () -> DiscoveryFilter.of(Arrays.asList("111", null), "aws"));
    assertThrows(NullPointerException.class, () -> DiscoveryFilter.of(Collections.singletonList("111"), null));
  }

  private static void assertMissing(String field, org.junit.jupiter.api.function.Executable build) {
    ValidationException e = assertThrows(ValidationException.class, build);
    assertEquals("Missing value for required field `" + field + "`", e.getMessage());
  }
}
