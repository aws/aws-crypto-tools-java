package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling.customcomponent;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import javax.crypto.KeyGenerator;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.CustomComponentException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ThrottlingException;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.KeyringResource;
import software.amazon.cryptography.materialproviders.keyrings.AesWrappingAlg;
import software.amazon.cryptography.materialproviders.keyrings.RawAesKeyring;

/**
 * Shows what the DB-ESDK throws when a keyring that you implemented throws a materialproviders
 * exception.
 *
 * <p>When a component that you implemented throws, its exception arrives as the cause of a {@link
 * CustomComponentException}, whose {@code resource()} names the component.
 *
 * <p>When your component throws an AWS SDK exception or a materialproviders exception, the DB-ESDK
 * reports it with that exception's kind instead, so a throttled call stays retryable.
 *
 * <p>Running this example needs AWS credentials and a Region for the DynamoDB client. The keyring
 * fails before the request is sent, so the table does not have to exist.
 */
public class CustomKeyringErrorsExample {

  private static final String PARTITION_KEY = "partition_key";
  private static final String SORT_KEY = "sort_key";
  private static final String ENCRYPTED_ATTRIBUTE = "attribute1";

  public static void writeWithThrottlingKeyring(String tableName) {
    Keyring rawAesKeyring = RawAesKeyring
      .builder()
      .keyName("my-aes-key-name")
      .keyNamespace("my-key-namespace")
      .wrappingKey(SecretBytes.copyOf(generateAesKeyBytes()))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    // The limit is zero calls a second, so the first write is throttled.
    Keyring rateLimitedKeyring = new RateLimitedKeyring(rawAesKeyring, 0);

    ItemEncryptionSchema schema = ItemEncryptionSchema
      .builder()
      .partitionKeyName(PARTITION_KEY)
      .sortKeyName(SORT_KEY)
      .encryptAndSign(ENCRYPTED_ATTRIBUTE)
      .build();
    DynamoDbTableEncryptionConfig tableConfig = DynamoDbTableEncryptionConfig
      .builder()
      .tableName(tableName)
      .schema(schema)
      .keyring(rateLimitedKeyring)
      .build();
    DynamoDbEncryptionInterceptor encryptionInterceptor =
      DynamoDbEncryptionInterceptor.builder().tableConfigs(tableConfig).build();

    try (
      DynamoDbClient dynamoDbClient = DynamoDbClient
        .builder()
        .overrideConfiguration(overrides ->
          overrides.addExecutionInterceptor(encryptionInterceptor)
        )
        .build()
    ) {
      putItemWhenKeyringThrottles(dynamoDbClient, tableName);
    }
  }

  /**
   * A keyring that limits how often this application asks the keyring it wraps for data keys, and
   * throws the materialproviders ThrottlingException when the limit is reached.
   */
  static final class RateLimitedKeyring implements Keyring {

    private static final long WINDOW_NANOS = Duration.ofSeconds(1).toNanos();

    private final Keyring delegate;
    private final int maxCallsPerSecond;
    private long windowStart = System.nanoTime();
    private int callsInWindow;

    RateLimitedKeyring(Keyring delegate, int maxCallsPerSecond) {
      this.delegate = delegate;
      this.maxCallsPerSecond = maxCallsPerSecond;
    }

    @Override
    public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
      acquire();
      return delegate.onEncrypt(request);
    }

    @Override
    public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
      acquire();
      return delegate.onDecrypt(request);
    }

    private synchronized void acquire() {
      long now = System.nanoTime();
      if (now - windowStart >= WINDOW_NANOS) {
        windowStart = now;
        callsInWindow = 0;
      }
      if (callsInWindow >= maxCallsPerSecond) {
        throw new software.amazon.cryptography.materialproviders.exceptions.ThrottlingException(
          "More than " + maxCallsPerSecond + " data key calls this second"
        );
      }
      callsInWindow++;
    }
  }

  // Your keyring can throw a materialproviders exception, such as ThrottlingException, to report a
  // failure of that kind. The DB-ESDK reports it with the same kind, so this one is retryable, and
  // resource() names your keyring.
  private static void putItemWhenKeyringThrottles(
    DynamoDbClient dynamoDbClient,
    String tableName
  ) {
    PutItemRequest write = PutItemRequest
      .builder()
      .tableName(tableName)
      .item(
        Map.of(
          PARTITION_KEY,
          AttributeValue.fromS("CustomKeyringErrorsExample"),
          SORT_KEY,
          AttributeValue.fromN("0"),
          ENCRYPTED_ATTRIBUTE,
          AttributeValue.fromS("encrypt and sign me!")
        )
      )
      .build();
    try {
      dynamoDbClient.putItem(write);
    } catch (ThrottlingException exception) {
      // isRetryable() is true and retryKind() is THROTTLING, as for an AWS throttling error, so
      // the same retry logic covers both. resource() says which keyring throttled the call.
      // TODO(native MPL error handling): assumes the MPL defines KeyringResource to name the
      // keyring that failed; native MPL has no resource types. Update this check once the MPL
      // decides how a failure names its resource.
      if (exception.resource() instanceof KeyringResource throttledKeyring) {
        System.err.println(
          "The keyring " +
          throttledKeyring.name() +
          " throttled the write (" +
          exception.retryKind() +
          "). Retry later with backoff."
        );
        return;
      }
      throw exception;
    }
    throw new IllegalStateException(
      "A write through a keyring with a limit of zero succeeded"
    );
  }

  public static void main(String[] args) {
    if (args.length < 1) {
      throw new IllegalArgumentException(
        "To run this example, include the table name in args"
      );
    }
    writeWithThrottlingKeyring(args[0]);
  }

  private static byte[] generateAesKeyBytes() {
    // This example uses the JCA KeyGenerator to generate the key bytes. In practice, do not
    // generate this key in your code; get it from a key management system, such as an HSM.
    KeyGenerator aesKeyGenerator;
    try {
      aesKeyGenerator = KeyGenerator.getInstance("AES");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(
        "This JVM does not support AES key generation",
        exception
      );
    }
    aesKeyGenerator.init(256, new SecureRandom());
    return aesKeyGenerator.generateKey().getEncoded();
  }
}
