// Section 2.1 of the API review doc: Errors and exceptions
// After: the native MPL 2.0.0, with the ESDK 4.0 sketch and the DB-ESDK stand-ins (proposals).
// Each "// @card id" ... "// @end" region is one block of the doc; lines between "// @hide" and
// "// @show" are not shown there.
package software.amazon.cryptography.apireview;

import java.util.List;
import java.util.Optional;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.keystore.DynamoDbKeyStore;

final class Section2_1Errors {
  private Section2_1Errors() {}

  // 2.1: One root, with a kind and retryability
  static String root(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 21-root
    try {
      keyStore.getActiveBranchKey(b -> b.branchKeyId(branchKeyId));
      return "ok";
    } catch (MaterialProvidersException e) {
      if (e.isRetryable()) {
        return "retry later";
      }
      switch (e.kind()) {
        case RESOURCE_NOT_FOUND:
          return "check the branch key " + branchKeyId + ": " + e.getMessage();
        default:
          return e.kind() + " failed: " + e.getMessage();
      }
    }
    // @end
  }

  // 2.1: AWS failures keep the SDK exception as the cause
  static String cause(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 21-cause
    try {
      keyStore.getActiveBranchKey(b -> b.branchKeyId(branchKeyId));
      return "ok";
    } catch (MaterialProvidersException e) {
      if (e.findCause(KmsException.class).isPresent()) {
        return "KMS refused the branch key: " + e.getMessage();
      }
      if (e.findCause(DynamoDbException.class).isPresent()) {
        return "the key store table failed: " + e.getMessage();
      }
      throw e;
    }
    // @end
  }

  // 2.1: "No key decrypted" lists each attempt
  static String noMatch(Keyring keyring, DecryptionMaterials materials, List<EncryptedDataKey> edks) {
    // @card 21-nomatch
    try {
      keyring.onDecrypt(OnDecryptRequest.builder().materials(materials).encryptedDataKeys(edks).build());
      return "decrypted";
    } catch (NoMatchingDataKeyException e) {
      StringBuilder attempts = new StringBuilder("no encrypted data key decrypted");
      for (Throwable failure : e.failures()) {
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
  static String passThrough(Keyring keyring, EncryptionMaterials materials) {
    // @card 21-passthrough
    try {
      keyring.onEncrypt(OnEncryptRequest.builder().materials(materials).build());
      return "encrypted";
    } catch (UnknownTenantException e) {
      // The supplier's own exception arrives unchanged.
      return "unknown tenant: " + e.getMessage();
    }
    // @end
  }

  // 2.1: More accessors on the root
  static String accessors(DynamoDbKeyStore keyStore, String branchKeyId) {
    // @card 21-accessors
    try {
      keyStore.getActiveBranchKey(b -> b.branchKeyId(branchKeyId));
      return "ok";
    } catch (MaterialProvidersException e) {
      // No isCredentials() accessor: the AWS error code is on the SDK cause.
      Optional<AwsServiceException> service = e.findCause(AwsServiceException.class);
      String code = service.map(s -> s.awsErrorDetails() == null ? null : s.awsErrorDetails().errorCode()).orElse(null);
      if ("ExpiredTokenException".equals(code)) {
        return "the AWS credentials are expired";
      }
      // No service() accessor: the SDK cause's type names the service.
      return (e.findCause(KmsException.class).isPresent() ? "KMS" : "DynamoDB") + " call failed: " + e.getMessage();
    }
    // @end
  }
}
