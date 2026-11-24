// Section 1.6 of the API review doc: ESDK and DB-ESDK calls (proposal)
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.ItemEncryptionSchema;
import software.amazon.cryptography.esdk.DecryptResponse;
import software.amazon.cryptography.esdk.DecryptingInputStream;
import software.amazon.cryptography.esdk.EncryptResponse;
import software.amazon.cryptography.esdk.EncryptingOutputStream;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkException;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.Keyring;

final class Section1_6EsdkAndDbEsdkCalls {
  private Section1_6EsdkAndDbEsdkCalls() {}

  // 1.6: The ESDK takes request objects
  static Map<String, String> esdkCalls(Keyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 15-request
    EsdkClient esdk = EsdkClient.create();
    EncryptResponse encrypted = esdk.encrypt(b -> b
        .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext));
    byte[] ciphertext = encrypted.ciphertext();
    DecryptResponse decrypted = esdk.decrypt(b -> b
        .ciphertext(ciphertext).keyring(keyring).encryptionContext(encryptionContext));
    byte[] roundTrip = decrypted.plaintext();
    Map<String, String> context = decrypted.encryptionContext();
    // @end
    roundTrip.hashCode();
    return context;
  }

  // 1.6: The suite and frame length go on the request
  static byte[] suiteOnRequest(Keyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 15-suite
    EsdkClient esdk = EsdkClient.builder().maxEncryptedDataKeys(3).build();
    EncryptResponse encrypted = esdk.encrypt(b -> b
        .plaintext(plaintext).keyring(keyring).encryptionContext(encryptionContext)
        .algorithmSuite(EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
        .frameLength(4096));
    byte[] ciphertext = encrypted.ciphertext();
    // @end
    return ciphertext;
  }

  // 1.6: Streams in two directions
  static int streams(EsdkClient esdk, Keyring keyring, byte[] plaintext, Map<String, String> encryptionContext,
      OutputStream outputStream, InputStream inputStream, byte[] buffer) throws IOException {
    // @card 15-streams
    try (EncryptingOutputStream encrypting =
        esdk.encryptingStream(b -> b.keyring(keyring).encryptionContext(encryptionContext), outputStream)) {
      encrypting.write(plaintext);
    }
    try (DecryptingInputStream decrypting = esdk.decryptingStream(b -> b.keyring(keyring), inputStream)) {
      int read = decrypting.read(buffer);
      // @hide
      return read;
      // @show
      // ...
    }
    // @end
  }

  // 1.6: ESDK calls throw ESDK exceptions
  static String esdkExceptions(EsdkClient esdk, Keyring keyring, byte[] ciphertext) {
    // @card 15-exceptions
    try {
      byte[] plaintext = esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring)).plaintext();
      return "decrypted " + plaintext.length + " bytes";
    } catch (EsdkException e) {
      switch (e.kind()) {
        case MALFORMED_MESSAGE:
        case CRYPTOGRAPHIC:
          return "the message is malformed or was modified";
        default:
          return "decrypt failed: " + e.getMessage();
      }
    }
    // @end
  }

  // 1.6: The DB-ESDK table config takes MPL types
  static DynamoDbEncryptionInterceptor dbesdk(Keyring keyring, String tableName) {
    // @card 15-dbesdk
    ItemEncryptionSchema schema = ItemEncryptionSchema.builder()
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .encryptAndSign("attribute1")
        .signOnly("attribute2")
        .build();
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig.builder()
        .tableName(tableName)
        .logicalTableName(tableName)
        .schema(schema)
        .keyring(keyring)
        .algorithmSuite(DbeAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
        .build();
    DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder().tableConfigs(config).build();
    // @end
    return interceptor;
  }
}
