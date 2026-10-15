// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.cryptography.mpl.exceptions.AccessDeniedException;
import software.amazon.cryptography.mpl.exceptions.ConflictException;
import software.amazon.cryptography.mpl.exceptions.DispatchException;
import software.amazon.cryptography.mpl.exceptions.MaterialProvidersException;
import software.amazon.cryptography.mpl.exceptions.ResourceNotFoundException;
import software.amazon.cryptography.mpl.exceptions.ServiceException;
import software.amazon.cryptography.mpl.exceptions.ThrottlingException;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * Classifies a failed KMS or DynamoDB call by the service's error code, with the SDK exception as the cause.
 * The throttling codes follow the AWS SDK's throttling classifier; the other lists group service error codes by meaning.
 *
 * <p>The SDK message is kept: the Dafny-based MPL surfaced the SDK exception itself,
 * and rebuilt a modeled KMS error from its message.
 */
public final class AwsErrors {

  // The SDK's own classifier knows the other throttling codes and HTTP 429.
  // DynamoDB returns LimitExceededException for too many concurrent control plane requests such as CreateTable.
  private static final Set<String> THROTTLING_CODES = codes("LimitExceededException");
  private static final Set<String> ACCESS_DENIED_CODES = codes(
    "AccessDeniedException",
    "NotAuthorized",
    "UnrecognizedClientException",
    "InvalidSignatureException",
    "IncompleteSignature",
    "IncompleteSignatureException",
    "MissingAuthenticationTokenException",
    "ExpiredTokenException",
    "InvalidGrantTokenException"
  );
  // KMS reports NotFoundException, DynamoDB ResourceNotFoundException.
  private static final Set<String> NOT_FOUND_CODES = codes("NotFoundException", "ResourceNotFoundException");
  private static final Set<String> CONFLICT_CODES = codes("ConditionalCheckFailedException", "TransactionConflictException");
  // TransactionCanceledException reason codes for a write that lost to another write.
  private static final Set<String> CONFLICT_REASONS = codes("ConditionalCheckFailed", "TransactionConflict");
  // TransactionCanceledException reason codes for an item that ran out of capacity.
  // DynamoDB sends them with HTTP 400, so the SDK does not see a throttling error.
  // A reason for a lost write takes precedence, since the caller has to read the item again before retrying.
  private static final Set<String> THROTTLING_REASONS = codes("ThrottlingError", "ProvisionedThroughputExceeded");

  private AwsErrors() {}

  private static boolean isTransportFailure(SdkException e) {
    if (e.retryable() || e instanceof ApiCallTimeoutException || e instanceof ApiCallAttemptTimeoutException) {
      return true;
    }
    for (Throwable cause = e.getCause(); cause != null; cause = cause.getCause()) {
      if (cause instanceof IOException) {
        return true;
      }
    }
    return false;
  }

  public static MaterialProvidersException from(SdkException e) {
    String message = e.getMessage();
    if (!(e instanceof AwsServiceException)) {
      // Only a transport failure is worth retrying; a client-side failure such as missing credentials is configuration.
      return isTransportFailure(e) ? new DispatchException(message, e) : new ValidationException(message, e);
    }
    AwsServiceException service = (AwsServiceException) e;
    String code = service.awsErrorDetails() == null ? null : service.awsErrorDetails().errorCode();
    if (THROTTLING_CODES.contains(code) || service.isThrottlingException()) {
      return new ThrottlingException(message, e);
    }
    if (ACCESS_DENIED_CODES.contains(code)) {
      return new AccessDeniedException(message, e);
    }
    if (NOT_FOUND_CODES.contains(code)) {
      return new ResourceNotFoundException(message, e);
    }
    if (CONFLICT_CODES.contains(code) || hasCancellationReason(e, CONFLICT_REASONS)) {
      return new ConflictException(message, e);
    }
    if (hasCancellationReason(e, THROTTLING_REASONS)) {
      return new ThrottlingException(message, e);
    }
    return new ServiceException(message, e);
  }

  private static boolean hasCancellationReason(SdkException e, Set<String> reasons) {
    if (!(e instanceof TransactionCanceledException)) {
      return false;
    }
    for (CancellationReason reason : ((TransactionCanceledException) e).cancellationReasons()) {
      if (reasons.contains(reason.code())) {
        return true;
      }
    }
    return false;
  }

  private static Set<String> codes(String... codes) {
    return new HashSet<>(Arrays.asList(codes));
  }
}
