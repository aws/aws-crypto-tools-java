// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.WildcardType;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsEcdhKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkDiscoveryMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMrkMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsMultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsRsaKeyring;
import software.amazon.cryptography.materialproviders.keyrings.EcdhCurveSpec;
import software.amazon.cryptography.materialproviders.keyrings.KmsEcdhKeyAgreementScheme;
import software.amazon.cryptography.materialproviders.keyrings.MultiKeyring;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;
import software.amazon.cryptography.materialproviders.keystore.GetKeyStoreInfoResponse;
import software.amazon.cryptography.materialproviders.keystore.KmsConfiguration;

// Each varargs setter must behave as its Collection twin: the same values, and the same failure for a null array,
// a null element, or a value the builder rejects.
class VarargsSettersTest {

  private static final String REGION = "us-west-2";
  private static final String KEY = "arn:aws:kms:us-west-2:111122223333:key/k1";
  private static final String OTHER_KEY = "arn:aws:kms:us-east-1:111122223333:key/k2";
  private static final AlgorithmSuite SUITE = EsdkAlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF;

  private static final String[][] TOKENS = {
    { "t1", "t2" },
    {},
    null,
    { "t1", null },
    { "" },
    { "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11" },
  };
  private static final String[][] KEY_IDS = { { KEY, OTHER_KEY }, {}, null, { KEY, null }, { "" }, { KEY, KEY } };
  private static final String[][] REGIONS = { { "us-west-2", "us-east-1" }, {}, null, { "us-west-2", null }, { "" }, { "us-west-2", "us-west-2" } };
  private static final String[][] CONTEXT_KEYS = { { "a" }, { "a", "a", "b" }, {}, null, { "a", null }, { "missing" } };

  private final FakeAws aws = FakeAws.start();
  private final KmsClient kms = aws.kmsClient("varargs", REGION);
  // The asymmetric keyrings read their public key from KMS when built.
  private final String rsaKey = aws.kms().createRsaKey(REGION, "RSA_2048");
  private final String eccKey = aws.kms().createEccKeyAgreementKey(REGION, "ECC_NIST_P256");

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void kmsKeyringGrantTokens() {
    matches(
      TOKENS,
      t -> AwsKmsKeyring.builder().kmsKeyId(KEY).kmsClient(kms).grantTokens(t).build(),
      t -> AwsKmsKeyring.builder().kmsKeyId(KEY).kmsClient(kms).grantTokens(t).build(),
      AwsKmsKeyring::grantTokens
    );
    matches(
      TOKENS,
      t -> AwsKmsMrkKeyring.builder().kmsKeyId(KEY).kmsClient(kms).grantTokens(t).build(),
      t -> AwsKmsMrkKeyring.builder().kmsKeyId(KEY).kmsClient(kms).grantTokens(t).build(),
      AwsKmsMrkKeyring::grantTokens
    );
    matches(
      TOKENS,
      t -> AwsKmsDiscoveryKeyring.builder().kmsClient(kms).grantTokens(t).build(),
      t -> AwsKmsDiscoveryKeyring.builder().kmsClient(kms).grantTokens(t).build(),
      AwsKmsDiscoveryKeyring::grantTokens
    );
    matches(
      TOKENS,
      t -> AwsKmsMrkDiscoveryKeyring.builder().kmsClient(kms).region(REGION).grantTokens(t).build(),
      t -> AwsKmsMrkDiscoveryKeyring.builder().kmsClient(kms).region(REGION).grantTokens(t).build(),
      AwsKmsMrkDiscoveryKeyring::grantTokens
    );
  }

  @Test
  void asymmetricKmsKeyringGrantTokens() {
    matches(
      TOKENS,
      t -> rsa().grantTokens(t).build(),
      t -> rsa().grantTokens(t).build(),
      AwsKmsRsaKeyring::grantTokens
    );
    matches(
      TOKENS,
      t -> ecdh().grantTokens(t).build(),
      t -> ecdh().grantTokens(t).build(),
      AwsKmsEcdhKeyring::grantTokens
    );
  }

  @Test
  void multiKeyringKeyIdsAndGrantTokens() {
    matches(
      KEY_IDS,
      ids -> AwsKmsMultiKeyring.builder().clientSupplier(region -> kms).kmsKeyIds(ids).build(),
      ids -> AwsKmsMultiKeyring.builder().clientSupplier(region -> kms).kmsKeyIds(ids).build(),
      AwsKmsMultiKeyring::kmsKeyIds
    );
    matches(
      TOKENS,
      t -> AwsKmsMultiKeyring.builder().clientSupplier(region -> kms).generator(KEY).grantTokens(t).build(),
      t -> AwsKmsMultiKeyring.builder().clientSupplier(region -> kms).generator(KEY).grantTokens(t).build(),
      AwsKmsMultiKeyring::grantTokens
    );
    matches(
      KEY_IDS,
      ids -> AwsKmsMrkMultiKeyring.builder().clientSupplier(region -> kms).kmsKeyIds(ids).build(),
      ids -> AwsKmsMrkMultiKeyring.builder().clientSupplier(region -> kms).kmsKeyIds(ids).build(),
      AwsKmsMrkMultiKeyring::kmsKeyIds
    );
    matches(
      TOKENS,
      t -> AwsKmsMrkMultiKeyring.builder().clientSupplier(region -> kms).generator(KEY).grantTokens(t).build(),
      t -> AwsKmsMrkMultiKeyring.builder().clientSupplier(region -> kms).generator(KEY).grantTokens(t).build(),
      AwsKmsMrkMultiKeyring::grantTokens
    );
  }

  @Test
  void discoveryMultiKeyringRegionsAndGrantTokens() {
    matches(
      REGIONS,
      r -> AwsKmsDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(r).build(),
      r -> AwsKmsDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(r).build(),
      AwsKmsDiscoveryMultiKeyring::regions
    );
    matches(
      TOKENS,
      t -> AwsKmsDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(REGION).grantTokens(t).build(),
      t -> AwsKmsDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(REGION).grantTokens(t).build(),
      AwsKmsDiscoveryMultiKeyring::grantTokens
    );
    matches(
      REGIONS,
      r -> AwsKmsMrkDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(r).build(),
      r -> AwsKmsMrkDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(r).build(),
      AwsKmsMrkDiscoveryMultiKeyring::regions
    );
    matches(
      TOKENS,
      t -> AwsKmsMrkDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(REGION).grantTokens(t).build(),
      t -> AwsKmsMrkDiscoveryMultiKeyring.builder().clientSupplier(region -> kms).regions(REGION).grantTokens(t).build(),
      AwsKmsMrkDiscoveryMultiKeyring::grantTokens
    );
  }

  @Test
  void multiKeyringChildKeyrings() {
    Keyring a = aes("a");
    Keyring b = aes("b");
    Keyring[][] children = { { a, b }, {}, null, { a, null } };
    matches(
      children,
      c -> MultiKeyring.builder().generator(aes("g")).childKeyrings(c).build(),
      c -> MultiKeyring.builder().generator(aes("g")).childKeyrings(c).build(),
      MultiKeyring::childKeyrings
    );
    // With no generator, the children are what makes the keyring valid.
    matches(
      children,
      c -> MultiKeyring.builder().childKeyrings(c).build(),
      c -> MultiKeyring.builder().childKeyrings(c).build(),
      MultiKeyring::childKeyrings
    );
  }

  @Test
  void branchKeyStoreGrantTokens() {
    matches(TOKENS, t -> store().grantTokens(t).build(), t -> store().grantTokens(t).build(), s -> {
      try (DynamoDbKeyStore closing = s) {
        return closing.getKeyStoreInfo().grantTokens();
      }
    });
  }

  @Test
  void keyStoreInfoGrantTokens() {
    matches(TOKENS, t -> info().grantTokens(t).build(), t -> info().grantTokens(t).build(), GetKeyStoreInfoResponse::grantTokens);
  }

  private static GetKeyStoreInfoResponse.Builder info() {
    return GetKeyStoreInfoResponse.builder().keyStoreId("id").keyStoreName("table").logicalKeyStoreName("logical").kmsConfiguration(KmsConfiguration.discovery());
  }

  @Test
  void requiredEncryptionContextKeys() {
    CryptographicMaterialsManager underlying = DefaultCryptographicMaterialsManager.create(aes("a"));
    matches(
      CONTEXT_KEYS,
      k -> RequiredEncryptionContextCryptographicMaterialsManager.builder().underlyingCmm(underlying).requiredEncryptionContextKeys(k).build(),
      k -> RequiredEncryptionContextCryptographicMaterialsManager.builder().underlyingCmm(underlying).requiredEncryptionContextKeys(k).build(),
      RequiredEncryptionContextCryptographicMaterialsManager::requiredEncryptionContextKeys
    );
    EncryptionContext context = EncryptionContext.of("a", "1", "b", "2");
    matches(
      CONTEXT_KEYS,
      k -> EncryptionMaterials.builder(SUITE).encryptionContext(context).requiredEncryptionContextKeys(k).build(),
      k -> EncryptionMaterials.builder(SUITE).encryptionContext(context).requiredEncryptionContextKeys(k).build(),
      EncryptionMaterials::requiredEncryptionContextKeys
    );
    matches(
      CONTEXT_KEYS,
      k -> DecryptionMaterials.builder(SUITE).encryptionContext(context).requiredEncryptionContextKeys(k).build(),
      k -> DecryptionMaterials.builder(SUITE).encryptionContext(context).requiredEncryptionContextKeys(k).build(),
      DecryptionMaterials::requiredEncryptionContextKeys
    );
    matches(
      CONTEXT_KEYS,
      k -> GetEncryptionMaterialsRequest.builder().encryptionContext(context).commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).requiredEncryptionContextKeys(k).build(),
      k -> GetEncryptionMaterialsRequest.builder().encryptionContext(context).commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).requiredEncryptionContextKeys(k).build(),
      GetEncryptionMaterialsRequest::requiredEncryptionContextKeys
    );
  }

  @Test
  void encryptedDataKeys() {
    EncryptedDataKey first = EncryptedDataKey.builder()
        .keyProviderId("p")
        .keyProviderInfo(new byte[] { 1 })
        .ciphertext(new byte[] { 2 })
        .build();
    EncryptedDataKey second = EncryptedDataKey.builder()
        .keyProviderId("q")
        .keyProviderInfo(new byte[] { 3 })
        .ciphertext(new byte[] { 4 })
        .build();
    EncryptedDataKey[][] keys = { { first, second }, {}, null, { first, null } };
    DecryptionMaterials materials = DecryptionMaterials.builder(SUITE).build();
    matches(
      keys,
      k -> OnDecryptRequest.builder().materials(materials).encryptedDataKeys(k).build(),
      k -> OnDecryptRequest.builder().materials(materials).encryptedDataKeys(k).build(),
      OnDecryptRequest::encryptedDataKeys
    );
    matches(
      keys,
      k -> decryptMaterials().encryptedDataKeys(k).build(),
      k -> decryptMaterials().encryptedDataKeys(k).build(),
      DecryptMaterialsRequest::encryptedDataKeys
    );
  }

  // Keeps the cases above complete: a new Collection setter changes the count, and one without a varargs twin fails.
  @Test
  void everyCollectionSetterHasAVarargsTwin() throws IOException, URISyntaxException, ClassNotFoundException {
    Path classes = Paths.get(Keyring.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    List<String> builders;
    try (Stream<Path> files = Files.walk(classes)) {
      builders = files
        .map(file -> classes.relativize(file).toString())
        .filter(name -> name.endsWith("$Builder.class") && !name.contains("internal"))
        .map(name -> name.substring(0, name.length() - ".class".length()).replace('/', '.').replace('\\', '.'))
        .collect(Collectors.toList());
    }
    List<String> setters = new ArrayList<>();
    List<String> missing = new ArrayList<>();
    for (String name : builders) {
      Class<?> builder = Class.forName(name);
      if (!Modifier.isPublic(builder.getModifiers())) {
        continue;
      }
      for (Method setter : builder.getMethods()) {
        if (setter.getParameterCount() != 1 || setter.getParameterTypes()[0] != Collection.class) {
          continue;
        }
        Class<?> element = elementType(setter.getGenericParameterTypes()[0]);
        setters.add(builder.getName() + "." + setter.getName());
        try {
          builder.getMethod(setter.getName(), Array.newInstance(element, 0).getClass());
        } catch (NoSuchMethodException e) {
          missing.add(builder.getName() + "." + setter.getName());
        }
      }
    }
    assertEquals(23, setters.size(), setters.toString());
    assertEquals(new ArrayList<String>(), missing);
  }

  private static Class<?> elementType(Type collection) {
    Type argument = ((ParameterizedType) collection).getActualTypeArguments()[0];
    if (argument instanceof WildcardType) {
      argument = ((WildcardType) argument).getUpperBounds()[0];
    }
    return (Class<?>) argument;
  }

  // For each case, the array overload and the Collection overload either produce equal views or fail alike.
  private static <E, T> void matches(E[][] cases, Function<E[], T> withArray, Function<List<E>, T> withCollection, Function<T, ?> view) {
    boolean anyFailure = false;
    for (E[] values : cases) {
      List<E> collection = values == null ? null : Arrays.asList(values);
      Object expected = outcome(() -> view.apply(withCollection.apply(collection)));
      Object actual = outcome(() -> view.apply(withArray.apply(values)));
      assertEquals(expected, actual, Arrays.toString(values));
      anyFailure |= expected instanceof Failure;
    }
    assertTrue(anyFailure, "the cases should include a rejected value");
  }

  private static Object outcome(Supplier<Object> run) {
    try {
      return run.get();
    } catch (RuntimeException e) {
      return new Failure(e);
    }
  }

  // A failure compares by exception class and message.
  private static final class Failure {

    private final String description;

    Failure(RuntimeException e) {
      this.description = e.getClass().getName() + ": " + e.getMessage();
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof Failure && ((Failure) other).description.equals(description);
    }

    @Override
    public int hashCode() {
      return description.hashCode();
    }

    @Override
    public String toString() {
      return description;
    }
  }

  private AwsKmsRsaKeyring.Builder rsa() {
    return AwsKmsRsaKeyring.builder().kmsKeyId(rsaKey).encryptionAlgorithm(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256).kmsClient(kms);
  }

  private AwsKmsEcdhKeyring.Builder ecdh() {
    return AwsKmsEcdhKeyring.builder()
      .keyAgreementScheme(KmsEcdhKeyAgreementScheme.kmsPublicKeyDiscovery().recipientKmsIdentifier(eccKey).build())
      .curveSpec(EcdhCurveSpec.ECC_NIST_P256)
      .kmsClient(kms);
  }

  private DynamoDbKeyStore.Builder store() {
    return DynamoDbKeyStore.builder()
      .ddbTableName("KeyStoreTable")
      .logicalKeyStoreName("logical")
      .kmsConfiguration(KmsConfiguration.kmsKeyArn(KEY))
      .kmsClient(kms)
      .ddbClient(aws.dynamoDbClient("varargs", REGION));
  }

  private static DecryptMaterialsRequest.Builder decryptMaterials() {
    return DecryptMaterialsRequest.builder()
      .algorithmSuite(SUITE)
      .commitmentPolicy(EsdkCommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)
      .encryptionContext(EncryptionContext.empty());
  }

  private static RawAesKeyring aes(String name) {
    return RawAesKeyring.builder()
      .keyNamespace("ns")
      .keyName(name)
      .wrappingKey(SecretBytes.copyOf(new byte[32]))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
  }
}
