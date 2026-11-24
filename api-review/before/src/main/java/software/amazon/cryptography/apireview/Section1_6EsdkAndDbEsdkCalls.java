// Section 1.6 of the API review doc: ESDK and DB-ESDK calls (proposal)
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoAlgorithm;
import com.amazonaws.encryptionsdk.CryptoInputStream;
import com.amazonaws.encryptionsdk.CryptoOutputStream;
import com.amazonaws.encryptionsdk.CryptoResult;
import com.amazonaws.encryptionsdk.exception.AwsCryptoException;
import com.amazonaws.encryptionsdk.exception.BadCiphertextException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collections;
import java.util.Map;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.DynamoDbEncryptionInterceptor;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTableEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.model.DynamoDbTablesEncryptionConfig;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.model.CryptoAction;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.model.DBEAlgorithmSuiteId;

final class Section1_6EsdkAndDbEsdkCalls {
  private Section1_6EsdkAndDbEsdkCalls() {}

  // 1.6: The ESDK takes request objects
  static Map<String, String> esdkCalls(IKeyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 15-request
    AwsCrypto crypto = AwsCrypto.builder().build();
    CryptoResult<byte[], ?> encrypted = crypto.encryptData(keyring, plaintext, encryptionContext);
    byte[] ciphertext = encrypted.getResult();
    CryptoResult<byte[], ?> decrypted = crypto.decryptData(keyring, ciphertext, encryptionContext);
    byte[] roundTrip = decrypted.getResult();
    Map<String, String> context = decrypted.getEncryptionContext();
    // @end
    roundTrip.hashCode();
    return context;
  }

  // 1.6: The suite and frame length go on the request
  static byte[] suiteOnClient(IKeyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    // @card 15-suite
    AwsCrypto crypto = AwsCrypto.builder()
        .withEncryptionAlgorithm(CryptoAlgorithm.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY)
        .withEncryptionFrameSize(4096)
        .withMaxEncryptedDataKeys(3)
        .build();
    byte[] ciphertext = crypto.encryptData(keyring, plaintext, encryptionContext).getResult();
    // @end
    return ciphertext;
  }

  // 1.6: Streams in two directions
  static int streams(AwsCrypto crypto, IKeyring keyring, byte[] plaintext, Map<String, String> encryptionContext,
      OutputStream outputStream, InputStream inputStream, byte[] buffer) throws IOException {
    // @card 15-streams
    try (CryptoOutputStream<?> encrypting =
        crypto.createEncryptingStream(keyring, outputStream, encryptionContext)) {
      encrypting.write(plaintext);
    }
    try (CryptoInputStream<?> decrypting = crypto.createDecryptingStream(keyring, inputStream)) {
      int read = decrypting.read(buffer);
      // @hide
      return read;
      // @show
      // ...
    }
    // @end
  }

  // 1.6: ESDK calls throw ESDK exceptions
  static String esdkExceptions(AwsCrypto crypto, IKeyring keyring, byte[] ciphertext) {
    // @card 15-exceptions
    try {
      byte[] plaintext = crypto.decryptData(keyring, ciphertext).getResult();
      return "decrypted " + plaintext.length + " bytes";
    } catch (BadCiphertextException e) {
      return "the message is malformed or was modified";
    } catch (AwsCryptoException e) {
      return "decrypt failed: " + e.getMessage();
    }
    // @end
  }

  // 1.6: The DB-ESDK table config takes MPL types
  static DynamoDbEncryptionInterceptor dbesdk(IKeyring keyring, String tableName,
      Map<String, CryptoAction> attributeActionsOnEncrypt) {
    // @card 15-dbesdk
    DynamoDbTableEncryptionConfig config = DynamoDbTableEncryptionConfig.builder()
        .logicalTableName(tableName)
        .partitionKeyName("partition_key")
        .sortKeyName("sort_key")
        .attributeActionsOnEncrypt(attributeActionsOnEncrypt)
        .keyring(keyring)
        .algorithmSuiteId(DBEAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384_SYMSIG_HMAC_SHA384)
        .build();
    DynamoDbEncryptionInterceptor interceptor = DynamoDbEncryptionInterceptor.builder()
        .config(DynamoDbTablesEncryptionConfig.builder()
            .tableEncryptionConfigs(Collections.singletonMap(tableName, config)).build())
        .build();
    // @end
    return interceptor;
  }
}
