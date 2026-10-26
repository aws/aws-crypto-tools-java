// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

import com.fasterxml.jackson.databind.JsonNode;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyStoreInput;
import software.amazon.cryptography.oldapi.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.KMSConfiguration;
import software.amazon.cryptography.oldapi.keystore.model.KeyStoreConfig;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.oldapi.primitives.model.RSAEncryptInput;
import software.amazon.cryptography.oldapi.primitives.model.RSAPaddingMode;

// The fake AWS endpoint shared by this module's AWS SDK and the reference MPL's copy.
class ReferenceAwsTest {

  private static final String REGION = "us-west-2";

  private final FakeAws aws = FakeAws.start();

  @AfterEach
  void close() {
    aws.close();
  }

  @Test
  void twinReplacesTheNativeClient() {
    KmsClient kms = ReferenceAws.kms(aws, REGION);
    Object twin = ReferenceMpl.toReference(kms);
    assertNotSame(kms, twin);
    assertSame(ReferenceMpl.loader(), twin.getClass().getClassLoader());
    assertEquals("software.amazon.awssdk.services.kms.KmsClient", twin.getClass().getInterfaces()[0].getName());
    assertSame(twin, ReferenceMpl.toReference(twin));
  }

  @Test
  void dataKeysCrossSdkCopies() {
    String key = aws.kms().createSymmetricKey(REGION);
    KmsClient kms = ReferenceAws.kms(aws, REGION);
    Object referenceKms = ReferenceMpl.toReference(kms);
    Map<String, String> context = Collections.singletonMap("purpose", "cross");

    Object generated = call(
      referenceKms,
      "generateDataKey",
      request("GenerateDataKeyRequest", "keyId", key, "numberOfBytes", 32, "encryptionContext", context)
    );
    assertEquals(key, call(generated, "keyId"));
    byte[] plaintext = sdkBytes(call(generated, "plaintext"));
    byte[] blob = sdkBytes(call(generated, "ciphertextBlob"));
    assertArrayEquals(
      plaintext,
      kms.decrypt(r -> r.ciphertextBlob(SdkBytes.fromByteArray(blob)).encryptionContext(context)).plaintext().asByteArray()
    );

    // The same call from each side is recorded the same.
    Object decrypted = call(
      referenceKms,
      "decrypt",
      request("DecryptRequest", "ciphertextBlob", referenceSdkBytes(blob), "encryptionContext", context)
    );
    assertArrayEquals(plaintext, sdkBytes(call(decrypted, "plaintext")));
    assertEquals(
      RecordedRequest.describe(aws.requests(ReferenceAws.NATIVE)),
      RecordedRequest.describe(aws.requests(ReferenceAws.REFERENCE).subList(1, 2))
    );

    byte[] nativeBlob = kms.encrypt(r -> r.keyId(key).plaintext(SdkBytes.fromByteArray(plaintext))).ciphertextBlob().asByteArray();
    Object fromNative = call(referenceKms, "decrypt", request("DecryptRequest", "ciphertextBlob", referenceSdkBytes(nativeBlob)));
    assertArrayEquals(plaintext, sdkBytes(call(fromNative, "plaintext")));
    assertEquals(key, call(fromNative, "keyId"));
  }

  // The MPL's RSA keyring encrypts with BouncyCastle's OAEP, whose MGF1 hash is the OAEP hash.
  @Test
  void rsaCiphertextFromTheMplDecrypts() {
    String key = aws.kms().createRsaKey(REGION, "RSA_2048");
    KmsClient kms = ReferenceAws.kms(aws, REGION);
    Object primitives = ReferenceMpl.atomicPrimitives();
    RSAPaddingMode[] paddings = { RSAPaddingMode.OAEP_SHA1, RSAPaddingMode.OAEP_SHA256 };
    EncryptionAlgorithmSpec[] algorithms = { EncryptionAlgorithmSpec.RSAES_OAEP_SHA_1, EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256 };
    for (int i = 0; i < paddings.length; i++) {
      RSAEncryptInput input = RSAEncryptInput
        .builder()
        .padding(paddings[i])
        .publicKey(ByteBuffer.wrap(aws.kms().publicKeyPem(key).getBytes(StandardCharsets.UTF_8)))
        .plaintext(ByteBuffer.wrap(new byte[] { 1, 2, 3 }))
        .build();
      ByteBuffer ciphertext = (ByteBuffer) ReferenceMpl.call(primitives, "RSAEncrypt", input);
      EncryptionAlgorithmSpec algorithm = algorithms[i];
      byte[] plaintext = kms
        .decrypt(r -> r.keyId(key).encryptionAlgorithm(algorithm).ciphertextBlob(SdkBytes.fromByteBuffer(ciphertext)))
        .plaintext()
        .asByteArray();
      assertArrayEquals(new byte[] { 1, 2, 3 }, plaintext, paddings[i].name());
    }
  }

  // The reference key store's own calls, through twins in ReferenceMpl.call, against the Dafny source's request order.
  @Test
  void referenceKeyStoreRunsOnTheFake() {
    String kmsKey = aws.kms().createSymmetricKey(REGION);
    KmsClient kms = ReferenceAws.kms(aws, REGION);
    DynamoDbClient ddb = ReferenceAws.dynamoDb(aws, REGION);
    KeyStoreConfig config = KeyStoreConfig
      .builder()
      .ddbTableName("KeyStoreTable")
      .logicalKeyStoreName("KeyStoreTable")
      .kmsConfiguration(KMSConfiguration.builder().kmsKeyArn(kmsKey).build())
      .grantTokens(Arrays.asList("grant"))
      .kmsClient(kms)
      .ddbClient(ddb)
      .build();
    Object keyStore = referenceKeyStore(config);

    ReferenceMpl.call(keyStore, "CreateKeyStore", CreateKeyStoreInput.builder().build());
    Map<String, String> customContext = Collections.singletonMap("tenant", "a");
    Object created = ReferenceMpl.call(
      keyStore,
      "CreateKey",
      CreateKeyInput.builder().branchKeyIdentifier("branch-1").encryptionContext(customContext).build()
    );
    assertEquals("branch-1", call(created, "branchKeyIdentifier"));
    Object active = ReferenceMpl.call(keyStore, "GetActiveBranchKey", GetActiveBranchKeyInput.builder().branchKeyIdentifier("branch-1").build());
    ByteBuffer branchKey = (ByteBuffer) call(call(active, "branchKeyMaterials"), "branchKey");

    List<RecordedRequest> requests = aws.requests(ReferenceAws.REFERENCE);
    assertEquals(
      Arrays.asList(
        "dynamodb DescribeTable",
        "dynamodb CreateTable",
        "kms GenerateDataKeyWithoutPlaintext",
        "kms ReEncrypt",
        "kms GenerateDataKeyWithoutPlaintext",
        "dynamodb TransactWriteItems",
        "dynamodb GetItem",
        "kms Decrypt"
      ),
      operations(requests)
    );
    for (RecordedRequest request : requests) {
      assertEquals(REGION, request.region());
      if (request.service().equals("kms")) {
        assertEquals("[\"grant\"]", request.body().get("GrantTokens").toString(), request.operation());
      }
    }

    // The branch key the reference unwrapped through its client, unwrapped again through the native client.
    JsonNode decrypt = requests.get(7).body();
    assertEquals(kmsKey, decrypt.get("KeyId").asText());
    byte[] nativePlaintext = kms
      .decrypt(r ->
        r
          .keyId(decrypt.get("KeyId").asText())
          .ciphertextBlob(SdkBytes.fromByteArray(Base64.getDecoder().decode(decrypt.get("CiphertextBlob").asText())))
          .encryptionContext(strings(decrypt.get("EncryptionContext")))
          .grantTokens("grant")
      )
      .plaintext()
      .asByteArray();
    byte[] referencePlaintext = new byte[branchKey.remaining()];
    branchKey.duplicate().get(referencePlaintext);
    assertArrayEquals(referencePlaintext, nativePlaintext);
    assertEquals("a", decrypt.get("EncryptionContext").get("aws-crypto-ec:tenant").asText());
  }

  private static Object referenceKeyStore(KeyStoreConfig config) {
    Object builder = call(null, referenceClass("software.amazon.cryptography.keystore.KeyStore"), "builder");
    call(builder, "KeyStoreConfig", ReferenceMpl.toReference(config));
    return call(builder, "build");
  }

  private static List<String> operations(List<RecordedRequest> requests) {
    List<String> operations = new ArrayList<>();
    for (RecordedRequest request : requests) {
      operations.add(request.service() + " " + request.operation());
    }
    return operations;
  }

  private static Map<String, String> strings(JsonNode object) {
    Map<String, String> map = new HashMap<>();
    Iterator<Map.Entry<String, JsonNode>> fields = object.fields();
    while (fields.hasNext()) {
      Map.Entry<String, JsonNode> field = fields.next();
      map.put(field.getKey(), field.getValue().asText());
    }
    return map;
  }

  // A reference-side KMS request: builder(), then name/value setter pairs, then build().
  private static Object request(String model, Object... settersAndValues) {
    Object builder = call(null, referenceClass("software.amazon.awssdk.services.kms.model." + model), "builder");
    for (int i = 0; i < settersAndValues.length; i += 2) {
      call(builder, (String) settersAndValues[i], settersAndValues[i + 1]);
    }
    return call(builder, "build");
  }

  private static Object referenceSdkBytes(byte[] bytes) {
    return call(null, referenceClass("software.amazon.awssdk.core.SdkBytes"), "fromByteArray", (Object) bytes);
  }

  private static byte[] sdkBytes(Object referenceSdkBytes) {
    return (byte[]) call(referenceSdkBytes, "asByteArray");
  }

  private static Class<?> referenceClass(String name) {
    try {
      return Class.forName(name, true, ReferenceMpl.loader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }

  private static Object call(Object target, String name, Object... args) {
    return call(target, target.getClass(), name, args);
  }

  // The public method of that name and arity whose parameter types accept the arguments.
  private static Object call(Object target, Class<?> type, String name, Object... args) {
    for (Method method : type.getMethods()) {
      if (method.getName().equals(name) && method.getParameterCount() == args.length && accepts(method, args)) {
        try {
          method.setAccessible(true);
          return method.invoke(target, args);
        } catch (InvocationTargetException e) {
          throw new IllegalStateException(e.getCause());
        } catch (IllegalAccessException e) {
          throw new IllegalStateException(e);
        }
      }
    }
    throw new IllegalArgumentException("no method " + name + "/" + args.length + " on " + type.getName());
  }

  private static boolean accepts(Method method, Object[] args) {
    Class<?>[] types = method.getParameterTypes();
    for (int i = 0; i < args.length; i++) {
      Class<?> type = types[i] == int.class ? Integer.class : types[i];
      if (args[i] != null && !type.isInstance(args[i])) {
        return false;
      }
    }
    return true;
  }
}
