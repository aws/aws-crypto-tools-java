// Section 2.1 of the API review doc: Errors and exceptions
// Before: the Dafny-based MPL 1.11.1, with ESDK 3.0.2 and DB-ESDK 3.3.0.
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.List;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.GetActiveBranchKeyInput;
import software.amazon.cryptography.keystore.model.KeyStoreException;
import software.amazon.cryptography.materialproviders.IKeyring;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CollectionOfErrors;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.OnDecryptInput;
import software.amazon.cryptography.materialproviders.model.OnEncryptInput;
import software.amazon.cryptography.materialproviders.model.OpaqueError;

final class Section2_1Errors {
  private Section2_1Errors() {}

  // 2.1: One root, with a kind and retryability
  static String root(KeyStore keyStore, String branchKeyId) {
    // @card 21-root
    try {
      keyStore.GetActiveBranchKey(GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build());
      return "ok";
    } catch (AwsServiceException e) {
      if (e.retryable() || e.isThrottlingException()) {
        return "retry later";
      }
      return "AWS call failed: " + e.getMessage();
    } catch (KeyStoreException e) {
      // A missing branch key carries only a message.
      return "check the branch key " + branchKeyId + ": " + e.getMessage();
    } catch (AwsCryptographicMaterialProvidersException e) {
      return "failed: " + e.getMessage();
    }
    // @end
  }

  // 2.1: AWS failures keep the SDK exception as the cause
  static String cause(KeyStore keyStore, String branchKeyId) {
    // @card 21-cause
    try {
      keyStore.GetActiveBranchKey(GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build());
      return "ok";
    } catch (KmsException e) {
      return "KMS refused the branch key: " + e.getMessage();
    } catch (DynamoDbException e) {
      return "the key store table failed: " + e.getMessage();
    }
    // @end
  }

  // 2.1: "No key decrypted" lists each attempt
  static String noMatch(IKeyring keyring, DecryptionMaterials materials, List<EncryptedDataKey> edks) {
    // @card 21-nomatch
    try {
      keyring.OnDecrypt(OnDecryptInput.builder().materials(materials).encryptedDataKeys(edks).build());
      return "decrypted";
    } catch (CollectionOfErrors e) {
      StringBuilder attempts = new StringBuilder("no encrypted data key decrypted");
      for (RuntimeException failure : e.list()) {
        attempts.append("\n  one attempt: ").append(failure.getMessage());
      }
      return attempts.toString();
    }
    // @end
  }

  // A customer's own exception, thrown by its branch key id supplier.
  static final class UnknownTenantException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    UnknownTenantException(String message) {
      super(message);
    }
  }

  // 2.1: Your own code's exceptions pass through
  static String passThrough(IKeyring keyring, EncryptionMaterials materials) {
    // @card 21-passthrough
    try {
      keyring.OnEncrypt(OnEncryptInput.builder().materials(materials).build());
      return "encrypted";
    } catch (OpaqueError e) {
      // The supplier's own exception arrives wrapped.
      if (e.obj() instanceof UnknownTenantException) {
        return "unknown tenant: " + ((UnknownTenantException) e.obj()).getMessage();
      }
      throw e;
    }
    // @end
  }

  // 2.1: More accessors on the root
  static String accessors(KeyStore keyStore, String branchKeyId) {
    // @card 21-accessors
    try {
      keyStore.GetActiveBranchKey(GetActiveBranchKeyInput.builder().branchKeyIdentifier(branchKeyId).build());
      return "ok";
    } catch (AwsServiceException e) {
      String code = e.awsErrorDetails() == null ? null : e.awsErrorDetails().errorCode();
      if ("ExpiredTokenException".equals(code)) {
        return "the AWS credentials are expired";
      }
      return (e instanceof KmsException ? "KMS" : "DynamoDB") + " call failed: " + e.getMessage();
    }
    // @end
  }
}
