package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples.errorhandling;

import software.amazon.cryptography.dbencryptionsdk.dynamodb.EncryptedDataKeyDescription;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.AccessDeniedException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.CustomComponentException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.DynamoDbEncryptionException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InternalException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidConfigurationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidItemException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.InvalidMaterialsException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.MalformedHeaderOrFooterException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.MissingEncryptionAttributesException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.NoResponseException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.SecurityProviderException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ServiceException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.UnsupportedRequestException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ValidationException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.VerificationFailedException;
import software.amazon.cryptography.materialproviders.exceptions.BranchKeyResource;
import software.amazon.cryptography.materialproviders.exceptions.KeyStoreTableResource;
import software.amazon.cryptography.materialproviders.exceptions.KmsKeyResource;
import software.amazon.cryptography.materialproviders.exceptions.Service;

/**
 * A reference for handling any exception that a DB-ESDK operation throws, deciding from coarse to
 * fine. Copy {@link #handle} into your application and adapt each branch to what your application
 * does about that failure.
 *
 * <h2>How the exceptions are organized</h2>
 *
 * <p>Every failure of a DB-ESDK operation is a {@link DynamoDbEncryptionException}, an unchecked
 * exception. That includes failures in AWS KMS, in the key store, in one of the library's keyrings,
 * and in a keyring, branch key ID supplier or other component that you implemented. Reads and
 * writes throw the same exceptions.
 *
 * <p>Each kind of failure is one subclass of {@link DynamoDbEncryptionException}, and every
 * subclass is {@code final} except {@link ValidationException}. Invalid input is a {@link
 * ValidationException}, and three subclasses say where the input came from:
 *
 * <ul>
 *   <li>{@link InvalidConfigurationException}: a configuration that you built, such as a schema, a
 *       table configuration or a beacon configuration.
 *   <li>{@link UnsupportedRequestException}: a DynamoDB request that the DB-ESDK cannot rewrite for
 *       an encrypted table.
 *   <li>{@link InvalidItemException}: the content of one item.
 * </ul>
 *
 * <p>{@code catch (ValidationException e)} catches all three. To handle one of them separately,
 * catch it first.
 *
 * <p>A failure in a library that the DB-ESDK calls is reported as the DB-ESDK exception of the same
 * kind, and the other library's exception becomes its cause. The Material Providers Library (MPL)
 * and StructuredEncryption have exception classes with the same simple names, such as {@code
 * ThrottlingException}, in their own packages. Those classes are not DB-ESDK exceptions, and a
 * DB-ESDK operation never throws them, so catch only the classes in the DB-ESDK's {@code
 * exceptions} package.
 *
 * <p>A failure to get a data key when an item is encrypted or decrypted has this cause chain, one
 * level per library. A beacon key read has no StructuredEncryption level.
 *
 * <pre>
 * DB-ESDK ThrottlingException          what you catch, with every detail copied from below
 *   StructuredEncryption ThrottlingException
 *     MPL ThrottlingException          where the keyring or key store failed
 *       AWS SDK exception              what AWS returned
 * </pre>
 *
 * <p>Read the cause chain only in logs. The details that you act on are accessors on the exception
 * that you catch. Read the cause in code only for a {@link CustomComponentException}, whose {@code
 * getCause()} is the exception that your own component threw.
 *
 * <h2>Deciding what to do</h2>
 *
 * <p>Decide what to do from the exception's type and accessors, never from its message, which can
 * change in any release:
 *
 * <ol>
 *   <li>{@code isRetryable()}: whether retrying later can help. The AWS SDK clients have already
 *       retried, so retry at a higher level, with backoff.
 *   <li>The exception's class: what went wrong.
 *   <li>{@code service()} and {@code resource()}: which AWS service and which resource (KMS key,
 *       branch key, key store table) to look at.
 *   <li>{@code awsErrorCode()} and {@code requestId()}: AWS's own error code and the request ID
 *       that AWS Support asks for.
 * </ol>
 *
 * <p>One kind of failure is not a DB-ESDK exception and reaches you unchanged: DynamoDB's answer
 * to your own request, such as a failed condition, which is the AWS SDK's {@code
 * DynamoDbException}. {@code ConditionalWriteFailureExample} shows it.
 */
public final class FailureHandler {

  private FailureHandler() {}

  /** What to do about a failed DB-ESDK operation, deciding from coarse to fine. */
  static void handle(DynamoDbEncryptionException exception) {
    // One check covers throttling, timeouts and server errors, whatever their kind.
    if (exception.isRetryable()) {
      System.err.println(
        "Retry later with backoff (" +
        exception.retryKind() +
        "): " +
        exception.getMessage()
      );
      return;
    }
    // Each kind of failure has its own exception class, so test the class.
    if (exception instanceof AccessDeniedException accessDenied) {
      accessDenied(accessDenied);
    } else if (
      exception instanceof ResourceNotFoundException resourceNotFound
    ) {
      resourceNotFound(resourceNotFound);
    } else if (exception instanceof InvalidItemException) {
      // An InvalidItemException is also a ValidationException, so this test comes first.
      System.err.println(
        "Fix or skip this item; other items can still succeed: " +
        exception.getMessage()
      );
    } else if (exception instanceof ValidationException) {
      System.err.println(
        "Fix the configuration or the request: " + exception.getMessage()
      );
    } else if (exception instanceof VerificationFailedException) {
      System.err.println(
        "The item failed verification: it was changed, or the keyring has the wrong key under " +
        "the item's key name. Do not trust its contents: " +
        exception.getMessage()
      );
    } else if (exception instanceof MalformedHeaderOrFooterException) {
      System.err.println(
        "The item's aws_dbe_head or aws_dbe_foot attribute cannot be read: the item is corrupt " +
        "or was changed. Do not trust its contents: " +
        exception.getMessage()
      );
    } else if (exception instanceof MissingEncryptionAttributesException) {
      System.err.println(
        "The DB-ESDK did not write this item. Allow plaintext reads while you move the table " +
        "to encrypted items; otherwise do not trust it: " +
        exception.getMessage()
      );
    } else if (exception instanceof SecurityProviderException) {
      System.err.println(
        "The JVM could not run a cryptographic operation. Check its java.security.Provider " +
        "setup, for example a FIPS-only provider list: " +
        exception.getMessage()
      );
    } else if (
      exception instanceof NoMatchingDataKeyException noMatchingDataKey
    ) {
      noMatchingDataKey(noMatchingDataKey);
    } else if (exception instanceof InvalidMaterialsException) {
      System.err.println(
        "A keyring or cryptographic materials manager, often a custom one, returned materials " +
        "that cannot be used: " +
        exception.getMessage()
      );
    } else if (exception instanceof ServiceException serviceException) {
      service(serviceException);
    } else if (exception instanceof NoResponseException) {
      // Retryable no-response failures were handled above. One that is not retryable is usually
      // a call that ran out of its total time (ApiCallTimeoutException).
      System.err.println(
        "AWS did not respond in time. Check the network and the client's API call timeout: " +
        exception.getMessage()
      );
    } else if (exception instanceof CustomComponentException) {
      // getCause() is the exception that your own component threw.
      System.err.println(
        "A component you implemented failed: " + exception.getCause()
      );
    } else if (exception instanceof InternalException) {
      System.err.println(
        "A bug in the DB-ESDK; report it with this message: " +
        exception.getMessage()
      );
    } else {
      // Later releases can add exception classes, so handle the rest here.
      System.err.println(
        "Failed (" +
        exception.getClass().getName() +
        "): " +
        exception.getMessage()
      );
    }
  }

  private static void accessDenied(AccessDeniedException exception) {
    if (exception.isCredentialsFailure()) {
      System.err.println("The AWS credentials are expired or invalid");
      return;
    }
    if (exception.resource() instanceof KmsKeyResource kmsKey) {
      System.err.println(
        "Grant this application access to the KMS key " + kmsKey.arn()
      );
    } else if (
      exception.resource() instanceof KeyStoreTableResource keyStoreTable
    ) {
      System.err.println(
        "Grant this application access to the key store table " +
        keyStoreTable.name()
      );
    } else {
      System.err.println(
        exception.service() + " denied access: " + exception.getMessage()
      );
    }
  }

  private static void resourceNotFound(ResourceNotFoundException exception) {
    if (exception.resource() instanceof BranchKeyResource branchKey) {
      // With an AWS error code, an AWS call made while reading the branch key failed, for example
      // one made by a key store that you implemented.
      // Without one, the key store has no such branch key.
      if (exception.awsErrorCode() != null) {
        System.err.println(
          exception.service() +
          " returned " +
          exception.awsErrorCode() +
          " while reading the branch key " +
          branchKey.id() +
          ": " +
          exception.getMessage()
        );
      } else {
        System.err.println(
          "Create the branch key " + branchKey.id() + " in the key store"
        );
      }
    } else if (exception.resource() instanceof KmsKeyResource kmsKey) {
      // region() is null when the keyring names the key by an alias or a bare key ID, not an ARN.
      System.err.println(
        "The KMS key " +
        kmsKey.arn() +
        " does not exist" +
        (kmsKey.region() == null ? "" : " in Region " + kmsKey.region())
      );
    } else if (
      exception.resource() instanceof KeyStoreTableResource keyStoreTable
    ) {
      System.err.println(
        "The key store table " + keyStoreTable.name() + " does not exist"
      );
    } else {
      System.err.println("Not found: " + exception.getMessage());
    }
  }

  private static void noMatchingDataKey(NoMatchingDataKeyException exception) {
    // For AWS KMS and hierarchical keyrings, keyProviderInfo() names the KMS key or branch key.
    for (EncryptedDataKeyDescription encryptedDataKey : exception.encryptedDataKeys()) {
      System.err.println(
        "The item was encrypted for key provider " +
        encryptedDataKey.keyProviderId() +
        " " +
        encryptedDataKey.keyProviderInfo() +
        "; read it with a keyring for that key"
      );
    }
  }

  private static void service(ServiceException exception) {
    // With no AWS error code, DynamoDB answered, but its answer does not match the request.
    if (
      exception.service() == Service.DYNAMODB &&
      exception.awsErrorCode() == null
    ) {
      System.err.println(
        "DynamoDB returned a response that does not match the request: " +
        exception.getMessage()
      );
      return;
    }
    // AWS KMS rejected a stored key. For an AWS KMS keyring that is the item's data key, whose
    // encryption context comes from the item; for a hierarchical keyring it is the branch key
    // record. The exception's kind is the same for both, so match on the error code.
    if (
      exception.service() == Service.KMS &&
      "InvalidCiphertextException".equals(exception.awsErrorCode())
    ) {
      System.err.println(
        "AWS KMS rejected a stored key: the item or its branch key record was changed, or the " +
        "key store's logical name is not the one the branch key was created with. Do not use " +
        "the item's contents: " +
        exception.getMessage()
      );
      return;
    }
    System.err.println(
      exception.service() +
      " returned " +
      exception.awsErrorCode() +
      " (request " +
      exception.requestId() +
      "): " +
      exception.getMessage()
    );
  }
}
