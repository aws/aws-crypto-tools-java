// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static software.amazon.cryptography.oldapi.materialproviders.KeyringTests.*;
import static software.amazon.cryptography.oldapi.materialproviders.KmsKeyringTests.*;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.client.config.SdkAdvancedClientOption;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsDiscoveryMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMrkDiscoveryMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMrkMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateAwsKmsMultiKeyringInput;
import software.amazon.cryptography.oldapi.materialproviders.model.CreateDefaultClientSupplierInput;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.oldapi.materialproviders.model.GetClientInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnDecryptOutput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.oldapi.materialproviders.model.OnEncryptOutput;
import software.amazon.cryptography.mpl.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.mpl.keyrings.ClientSupplier;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.DefaultClientSupplier;
import software.amazon.cryptography.mpl.OnEncryptRequest;

// The default client supplier, and the KMS multi keyrings that make one, against the published Dafny-based MPL.
// System properties point the SDK's default endpoint, credentials, and Region at the fake KMS,
// so clients both MPLs build themselves never reach AWS. Both sides share one endpoint label, so calls run one side at a time.
class DefaultClientSupplierTest {

  private static final List<String> PROPERTIES = Arrays.asList("aws.endpointUrlKms", "aws.accessKeyId", "aws.secretAccessKey", "aws.region");

  private final Object reference = ReferenceMpl.materialProviders();
  private final FakeAws aws = FakeAws.start();
  private final Map<String, String> saved = new LinkedHashMap<>();

  @BeforeEach
  void pointDefaultsAtTheFake() {
    for (String property : PROPERTIES) {
      saved.put(property, System.getProperty(property));
    }
    System.setProperty("aws.endpointUrlKms", aws.endpoint("default").toString());
    System.setProperty("aws.accessKeyId", "AKIAFAKEAWS000000000");
    System.setProperty("aws.secretAccessKey", "fake-secret-access-key");
    System.setProperty("aws.region", OTHER_REGION);
  }

  @AfterEach
  void restore() {
    for (Map.Entry<String, String> property : saved.entrySet()) {
      if (property.getValue() == null) {
        System.clearProperty(property.getKey());
      } else {
        System.setProperty(property.getKey(), property.getValue());
      }
    }
    aws.close();
  }

  @Test
  void clientsAreForTheRequestedRegion() {
    Object referenceSupplier = ReferenceMpl.call(reference, "CreateDefaultClientSupplier", CreateDefaultClientSupplierInput.builder().build());
    IClientSupplier nativeSupplier = KeyringTests.MPL.CreateDefaultClientSupplier(CreateDefaultClientSupplierInput.builder().build());
    for (String region : Arrays.asList(REGION, OTHER_REGION, "ap-south-2", "")) {
      Object referenceClient = ReferenceMpl.call(referenceSupplier, "GetClient", GetClientInput.builder().region(region).build());
      KmsClient nativeClient = nativeSupplier.GetClient(GetClientInput.builder().region(region).build());
      assertEquals(region(referenceClient), nativeClient.serviceClientConfiguration().region().id(), region);
    }
    // The Region of an empty request is the SDK's default.
    assertEquals(OTHER_REGION, nativeSupplier.GetClient(GetClientInput.builder().region("").build()).serviceClientConfiguration().region().id());
  }

  /** R6: one client per Region, reused; the reference builds a new client for every request. */
  @Test
  void clientsAreReusedAndClosed() {
    Object referenceSupplier = ReferenceMpl.call(reference, "CreateDefaultClientSupplier", CreateDefaultClientSupplierInput.builder().build());
    GetClientInput input = GetClientInput.builder().region(REGION).build();
    assertNotSame(ReferenceMpl.call(referenceSupplier, "GetClient", input), ReferenceMpl.call(referenceSupplier, "GetClient", input));

    String key = aws.kms().createSymmetricKey(REGION);
    DefaultClientSupplier supplier = ClientSupplier.defaultSupplier();
    KmsClient client = supplier.getClient(REGION);
    assertSame(client, supplier.getClient(REGION));
    assertNotSame(client, supplier.getClient(OTHER_REGION));
    assertEquals(key, client.generateDataKey(r -> r.keyId(key).numberOfBytes(16)).keyId());
    supplier.close();
    assertThrows(IllegalStateException.class, () -> client.generateDataKey(r -> r.keyId(key).numberOfBytes(16)));
    // A closed supplier makes new clients.
    assertNotSame(client, supplier.getClient(REGION));
    supplier.close();
  }

  /** R7: clients the supplier builds carry the library's user agent suffix. */
  @Test
  void clientsCarryTheUserAgentSuffix() {
    try (DefaultClientSupplier supplier = ClientSupplier.defaultSupplier()) {
      for (String region : Arrays.asList(REGION, "")) {
        Optional<String> suffix = supplier
          .getClient(region)
          .serviceClientConfiguration()
          .overrideConfiguration()
          .advancedOption(SdkAdvancedClientOption.USER_AGENT_SUFFIX);
        assertEquals(Optional.of("AwsCryptographicMPL-Java"), suffix, region);
      }
    }
  }

  /** Without a default Region, a client for the empty Region cannot be built. */
  @Test
  void noDefaultRegion() throws IOException {
    assumeTrue(System.getenv("AWS_REGION") == null && System.getenv("AWS_DEFAULT_REGION") == null, "a Region is set in the environment");
    File empty = File.createTempFile("aws-config", "");
    empty.deleteOnExit();
    Map<String, String> properties = new LinkedHashMap<>();
    properties.put("aws.configFile", empty.getPath());
    properties.put("aws.sharedCredentialsFile", empty.getPath());
    properties.put("aws.disableEc2Metadata", "true");
    Map<String, String> previous = new LinkedHashMap<>();
    for (Map.Entry<String, String> property : properties.entrySet()) {
      previous.put(property.getKey(), System.setProperty(property.getKey(), property.getValue()));
    }
    System.clearProperty("aws.region");
    try (DefaultClientSupplier supplier = ClientSupplier.defaultSupplier()) {
      ValidationException e = assertThrows(ValidationException.class, () -> supplier.getClient(""));
      assertTrue(e.getCause() instanceof SdkClientException, String.valueOf(e.getCause()));
    } finally {
      for (Map.Entry<String, String> property : previous.entrySet()) {
        if (property.getValue() == null) {
          System.clearProperty(property.getKey());
        } else {
          System.setProperty(property.getKey(), property.getValue());
        }
      }
    }
  }

  /** A KMS multi keyring closes the clients of the default supplier it made, and only those. */
  @Test
  void multiKeyringClosesOnlyItsOwnClients() {
    String key = aws.kms().createSymmetricKey(REGION);
    software.amazon.cryptography.mpl.EncryptionMaterials start = software.amazon.cryptography.mpl.EncryptionMaterials
      .builder(software.amazon.cryptography.mpl.AlgorithmSuite.ALG_AES_128_GCM_IV12_TAG16_NO_KDF)
      .build();
    AwsKmsMultiKeyring owning = AwsKmsMultiKeyring.builder().generator(key).build();
    owning.onEncrypt(OnEncryptRequest.builder().materials(start).build());
    owning.close();
    assertThrows(IllegalStateException.class, () -> owning.onEncrypt(OnEncryptRequest.builder().materials(start).build()));

    DefaultClientSupplier supplier = ClientSupplier.defaultSupplier();
    AwsKmsMultiKeyring borrowing = AwsKmsMultiKeyring.builder().generator(key).clientSupplier(supplier).build();
    borrowing.close();
    assertFalse(borrowing.onEncrypt(OnEncryptRequest.builder().materials(start).build()).materials().encryptedDataKeys().isEmpty());
    supplier.close();
  }

  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-multi-keyring
  //= type=test
  //# If a regional client supplier is not passed, then a default MUST be
  //# created that takes a region string and generates a default AWS SDK
  //# client for the given region.

  //= spec/framework/aws-kms/aws-kms-multi-keyrings.md#aws-kms-discovery-multi-keyring
  //= type=test
  //# If a regional client supplier is not passed, then a default MUST be created that takes a region string and generates a default AWS SDK client for the given region.

  //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-multi-keyring
  //= type=test
  //# If a regional client supplier is not passed, then a default MUST be created that takes a region string and generates a default AWS SDK client for the given region.

  //= spec/framework/aws-kms/aws-kms-mrk-multi-keyrings.md#aws-kms-mrk-discovery-multi-keyring
  //= type=test
  //# If a regional client supplier is not passed, then a default MUST be created that takes a region string and generates a default AWS SDK client for the given region.
  @Test
  void multiKeyringsWithTheDefaultSupplier() {
    String generator = aws.kms().createSymmetricKey(REGION);
    String child = aws.kms().createSymmetricKey(OTHER_REGION);
    List<String> replicas = aws.kms().createMultiRegionKey(REGION, OTHER_REGION);
    // A key id has no Region, so its client is for the default Region.
    String childId = child.substring(child.indexOf("key/") + 4);
    Map<String, Object> inputs = new LinkedHashMap<>();
    inputs.put("CreateAwsKmsMultiKeyring", CreateAwsKmsMultiKeyringInput.builder().generator(generator).kmsKeyIds(Arrays.asList(childId, replicas.get(1))).build());
    inputs.put("CreateAwsKmsMrkMultiKeyring", CreateAwsKmsMrkMultiKeyringInput.builder().generator(replicas.get(0)).kmsKeyIds(Collections.singletonList(childId)).build());
    for (AlgorithmSuiteId suite : Arrays.asList(allSuites().get(0), allSuites().get(allSuites().size() - 1))) {
      EncryptionMaterials start = encryptionMaterials(suite, map("a", "b"), false);
      for (Map.Entry<String, Object> input : inputs.entrySet()) {
        IKeyring nativeKeyring = (IKeyring) invoke(MPL, input.getKey(), input.getValue());
        Object referenceKeyring = ReferenceMpl.call(reference, input.getKey(), input.getValue());
        OnEncryptOutput encryptedOutput = assertSameOneSideAtATime(
          () -> (OnEncryptOutput) ReferenceMpl.fromReference(ReferenceMpl.call(referenceKeyring, "OnEncrypt", OnEncryptInput.builder().materials(start).build())),
          () -> nativeKeyring.OnEncrypt(OnEncryptInput.builder().materials(start).build()),
          output -> maskedKms(output.materials(), false),
          input.getKey()
        );
        EncryptionMaterials encrypted = encryptedOutput.materials();
        List<Object> decryptors = Arrays.asList(
          input.getValue(),
          CreateAwsKmsDiscoveryMultiKeyringInput.builder().regions(Arrays.asList(REGION, OTHER_REGION)).build(),
          CreateAwsKmsMrkDiscoveryMultiKeyringInput.builder().regions(Collections.singletonList(REGION)).build()
        );
        for (Object decryptorInput : decryptors) {
          String operation = decryptorInput.getClass().getSimpleName().replace("Input", "");
          IKeyring nativeDecryptor = (IKeyring) invoke(MPL, operation, decryptorInput);
          Object referenceDecryptor = ReferenceMpl.call(reference, operation, decryptorInput);
          OnDecryptOutput decrypted = assertSameOneSideAtATime(
            () ->
              (OnDecryptOutput) ReferenceMpl.fromReference(
                ReferenceMpl.call(referenceDecryptor, "OnDecrypt", decryptInput(decryptionMaterials(encrypted), encrypted.encryptedDataKeys()))
              ),
            () -> nativeDecryptor.OnDecrypt(decryptInput(decryptionMaterials(encrypted), encrypted.encryptedDataKeys())),
            ReferenceMpl::describe,
            operation
          );
          assertEquals(ReferenceMpl.describe(expectedDecryption(encrypted)), ReferenceMpl.describe(decrypted), operation);
        }
      }
    }
  }

  // Runs the reference, then native, comparing rendered outcomes and the KMS requests each made; returns the native result.
  private <T> T assertSameOneSideAtATime(Supplier<T> referenceCall, Supplier<T> nativeCall, Function<T, String> render, String context) {
    aws.clearRequests();
    String expected = normalized(ReferenceMpl.outcome(() -> render.apply(referenceCall.get())));
    // The generated data key differs between the sides, and children encrypt it.
    List<String> referenceRequests = RecordedRequest.describe(aws.requests(), "Plaintext");
    aws.clearRequests();
    List<T> result = new ArrayList<>();
    String actual = normalized(
      ReferenceMpl.outcome(() -> {
        result.add(nativeCall.get());
        return render.apply(result.get(0));
      })
    );
    assertEquals(expected, actual, context);
    assertEquals(referenceRequests, RecordedRequest.describe(aws.requests(), "Plaintext"), context);
    assertFalse(result.isEmpty(), context + " " + actual);
    return result.get(0);
  }

  private static Object invoke(Object target, String method, Object argument) {
    try {
      Method m = target.getClass().getMethod(method, argument.getClass());
      return m.invoke(target, argument);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Method accessible(Method method) {
    method.setAccessible(true);
    return method;
  }

  private static String region(Object referenceClient) {
    try {
      Object configuration = accessible(referenceClient.getClass().getMethod("serviceClientConfiguration")).invoke(referenceClient);
      Object value = accessible(configuration.getClass().getMethod("region")).invoke(configuration);
      return (String) accessible(value.getClass().getMethod("id")).invoke(value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }
}
