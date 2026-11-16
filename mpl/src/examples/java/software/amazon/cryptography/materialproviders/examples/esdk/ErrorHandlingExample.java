// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.esdk;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.cryptography.esdk.EsdkClient;
import software.amazon.cryptography.esdk.EsdkErrorKind;
import software.amazon.cryptography.esdk.EsdkException;
import software.amazon.cryptography.esdk.EsdkNoMatchingDataKeyException;
import software.amazon.cryptography.keystore.BranchKeyStore;
import software.amazon.cryptography.keystore.KmsConfiguration;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.exceptions.ErrorKind;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.materialproviders.keyrings.AwsKmsHierarchicalKeyring;

/**
 * Handles the failures of a hierarchical keyring and its key store, from coarse to fine.
 *
 * <p>Every failure of an ESDK call is an {@link EsdkException}, and every failure of an MPL call, such as the key
 * store's, is a {@link MaterialProvidersException}, so each call needs one catch. An MPL failure inside an ESDK call
 * is the {@code EsdkException}'s cause and has the same kind. An exception thrown by the caller's own code, such as
 * a branch key id supplier, passes through unchanged.
 * Decide from the accessors, never from the message text, which can change in any release:
 * {@code isRetryable()}, then {@code kind()}, then {@code findCause(Class)} for the AWS SDK exception.
 *
 * <p>Arguments: the table name, logical name, and KMS key ARN of an existing key store, and the id of one of its
 * branch keys. The KMS key is in the SDK's default Region. Only reads: calls DynamoDB GetItem and KMS Decrypt.
 */
public final class ErrorHandlingExample {

  private static final byte[] EXAMPLE_DATA = "Hello World".getBytes(StandardCharsets.UTF_8);

  // AWS error codes that reject the credentials themselves, not a permission on a resource.
  private static final Set<String> CREDENTIAL_ERROR_CODES = new HashSet<>(
    Arrays.asList(
      "UnrecognizedClientException",
      "InvalidSignatureException",
      "IncompleteSignature",
      "IncompleteSignatureException",
      "MissingAuthenticationTokenException",
      "ExpiredTokenException"
    )
  );

  private ErrorHandlingExample() {}

  public static void main(String[] args) {
    if (args.length != 4) {
      throw new IllegalArgumentException(
        "Arguments: <key-store-table> <logical-key-store-name> <kms-key-arn> <branch-key-id>"
      );
    }
    try (KmsClient kmsClient = KmsClient.create(); DynamoDbClient ddbClient = DynamoDbClient.create()) {
      run(args[0], args[1], args[2], args[3], kmsClient, ddbClient);
    }
  }

  public static void run(
    String tableName,
    String logicalKeyStoreName,
    String kmsKeyArn,
    String branchKeyId,
    KmsClient kmsClient,
    DynamoDbClient ddbClient
  ) {
    EsdkClient esdk = EsdkClient.create();
    try (
      BranchKeyStore keyStore = BranchKeyStore
        .builder()
        .ddbTableName(tableName)
        .logicalKeyStoreName(logicalKeyStoreName)
        .kmsConfiguration(KmsConfiguration.kmsKeyArn(kmsKeyArn))
        .kmsClient(kmsClient)
        .ddbClient(ddbClient)
        .build()
    ) {
      Keyring keyring = hierarchicalKeyring(keyStore, branchKeyId);
      Resources resources = new Resources(tableName, kmsKeyArn, branchKeyId);

      // 1. Encrypt. The keyring reads the branch key from DynamoDB and decrypts it with KMS, so either can fail.
      byte[] ciphertext;
      try {
        ciphertext = esdk.encrypt(b -> b.plaintext(EXAMPLE_DATA).keyring(keyring)).ciphertext();
      } catch (EsdkException e) {
        System.err.println("encrypt: " + whatToDo(e, resources));
        throw e;
      }

      // 2. Decrypt.
      byte[] plaintext;
      try {
        plaintext = esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring)).plaintext();
      } catch (EsdkException e) {
        System.err.println("decrypt: " + whatToDo(e, resources));
        throw e;
      }
      if (!Arrays.equals(plaintext, EXAMPLE_DATA)) {
        throw new IllegalStateException("Decrypted plaintext does not match");
      }

      // 3. A modified message fails, and retrying cannot help.
      byte[] tampered = ciphertext.clone();
      tampered[tampered.length - 1] ^= 1;
      EsdkException tamperedFailure = expectFailure(esdk, tampered, keyring);
      System.out.println("modified message: " + whatToDo(tamperedFailure, resources));
      if (tamperedFailure.isRetryable()) {
        throw new IllegalStateException("A modified message was reported as retryable");
      }

      // 4. A keyring for another branch key finds no encrypted data key it can use.
      Keyring otherKeyring = hierarchicalKeyring(keyStore, "another-branch-key-id");
      EsdkException notForThisKeyring = expectFailure(esdk, ciphertext, otherKeyring);
      System.out.println("other branch key: " + whatToDo(notForThisKeyring, resources));
      if (!(notForThisKeyring instanceof EsdkNoMatchingDataKeyException)) {
        throw new IllegalStateException("Expected EsdkNoMatchingDataKeyException, got " + notForThisKeyring);
      }

      // 5. A key store call: a branch key version that does not exist.
      String missingVersion = UUID.randomUUID().toString();
      try {
        keyStore.getBranchKeyVersion(b -> b.branchKeyIdentifier(branchKeyId).branchKeyVersion(missingVersion));
        throw new IllegalStateException("Found branch key version " + missingVersion);
      } catch (MaterialProvidersException e) {
        System.out.println("missing version: " + whatToDo(e, resources));
        if (e.kind() != ErrorKind.RESOURCE_NOT_FOUND) {
          throw e;
        }
      }
    }
  }

  /** What to do about a failure of an ESDK call. */
  static String whatToDo(EsdkException e, Resources resources) {
    // Bytes that are not a message. The sketch, built on ESDK 3.x, reports them as CRYPTOGRAPHIC instead.
    if (e.kind() == EsdkErrorKind.MALFORMED_MESSAGE) {
      return "the ciphertext is not an ESDK message";
    }
    // An MPL failure keeps its kind as the cause, so the MPL's handling applies to it.
    Optional<MaterialProvidersException> mpl = e.findCause(MaterialProvidersException.class);
    if (mpl.isPresent()) {
      return whatToDo(mpl.get(), resources);
    }
    if (e.isRetryable()) {
      return "retry later: " + e.getMessage();
    }
    switch (e.kind()) {
      case CRYPTOGRAPHIC:
        // A tag or signature in the message did not verify.
        return "the message is corrupt or was modified";
      default:
        // EsdkErrorKind gains values in later releases, so a default branch handles the rest.
        return "failed: " + e;
    }
  }

  /** What to do about a failure of an MPL call, deciding from coarse to fine. */
  static String whatToDo(MaterialProvidersException e, Resources resources) {
    // One check covers throttling, timeouts, and any kind whose AWS SDK cause is retryable.
    // The SDK clients already retried, so retry later. No retryKind() accessor: the caller picks the backoff.
    if (e.isRetryable()) {
      return "retry later: " + e.getMessage();
    }
    switch (e.kind()) {
      case ACCESS_DENIED:
        if (isCredentialsError(e)) {
          // No isCredentials() accessor: the AWS error code tells whether AWS rejected the credentials.
          return "the AWS credentials are expired or invalid";
        }
        // No service() or resource() accessor: the SDK exception's type names the service,
        // and the KMS key and table come from the key store's configuration.
        if (e.findCause(KmsException.class).isPresent()) {
          return "grant access to the KMS key " + resources.kmsKeyArn;
        }
        if (e.findCause(DynamoDbException.class).isPresent()) {
          return "grant access to the key store table " + resources.tableName;
        }
        return "access denied: " + e.getMessage();
      case RESOURCE_NOT_FOUND:
        if (e.findCause(KmsException.class).isPresent()) {
          return "the KMS key " + resources.kmsKeyArn + " does not exist";
        }
        if (e.findCause(DynamoDbException.class).isPresent()) {
          return "the key store table " + resources.tableName + " does not exist";
        }
        // No resource() accessor: DynamoDB returned no item, so there is no SDK cause; the id is the keyring's.
        return "create the branch key " + resources.branchKeyId + " in the key store";
      case INVALID_MATERIALS:
        // Usually a malformed key store record. No resource() accessor: the exception does not name the record.
        return "check the key store record of branch key " + resources.branchKeyId + ": " + e.getMessage();
      case CRYPTOGRAPHIC:
        // A tag or signature did not verify.
        return "the message is corrupt or was modified";
      case CONFLICT:
        // No reason() accessor: on createKey a conflict means the id exists; on versionKey, a concurrent change.
        return "the branch key changed or already exists: " + e.getMessage();
      case NO_MATCHING_DATA_KEY:
        return noMatchingDataKey((NoMatchingDataKeyException) e, resources);
      default:
        // ErrorKind gains values in later releases, so a default branch handles the rest.
        return "failed: " + e;
    }
  }

  private static String noMatchingDataKey(NoMatchingDataKeyException e, Resources resources) {
    // failures() has each attempt's exception, in order; none means no encrypted data key was for this keyring.
    // The ESDK 4.0 sketch cannot list a message's encrypted data keys, so this cannot say whose keys they were.
    if (e.failures().isEmpty()) {
      return "the message was not encrypted for this keyring's branch key";
    }
    StringBuilder attempts = new StringBuilder("no encrypted data key decrypted");
    for (Throwable failure : e.failures()) {
      attempts.append("\n  one attempt: ");
      attempts.append(
        failure instanceof MaterialProvidersException
          ? whatToDo((MaterialProvidersException) failure, resources)
          : failure.toString()
      );
    }
    return attempts.toString();
  }

  private static boolean isCredentialsError(MaterialProvidersException e) {
    return e
      .findCause(AwsServiceException.class)
      .map(AwsServiceException::awsErrorDetails)
      .map(AwsErrorDetails::errorCode)
      .filter(CREDENTIAL_ERROR_CODES::contains)
      .isPresent();
  }

  private static EsdkException expectFailure(EsdkClient esdk, byte[] ciphertext, Keyring keyring) {
    try {
      esdk.decrypt(b -> b.ciphertext(ciphertext).keyring(keyring));
    } catch (EsdkException e) {
      return e;
    }
    throw new IllegalStateException("Decrypt succeeded");
  }

  private static Keyring hierarchicalKeyring(BranchKeyStore keyStore, String branchKeyId) {
    return AwsKmsHierarchicalKeyring
      .builder()
      .keyStore(keyStore)
      .branchKeyId(branchKeyId)
      .ttl(Duration.ofMinutes(10))
      .build();
  }

  /** The resources a failure can be about, from the application's configuration. */
  static final class Resources {

    final String tableName;
    final String kmsKeyArn;
    final String branchKeyId;

    Resources(String tableName, String kmsKeyArn, String branchKeyId) {
      this.tableName = tableName;
      this.kmsKeyArn = kmsKeyArn;
      this.branchKeyId = branchKeyId;
    }
  }
}
