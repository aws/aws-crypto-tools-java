// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.services.dynamodb.model.CancellationReason;
import software.amazon.awssdk.services.dynamodb.model.DynamoDbException;
import software.amazon.awssdk.services.dynamodb.model.TransactionCanceledException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.cryptography.mpl.exceptions.ErrorKind;
import software.amazon.cryptography.mpl.exceptions.MaterialProvidersException;

// The error code of every failed AWS call picks the kind; the SDK exception stays the cause.
class AwsErrorsTest {

  @Test
  void errorCodes() {
    Map<String, ErrorKind> expected = new LinkedHashMap<>();
    for (String code : Arrays.asList(
      "Throttling", "ThrottlingException", "ThrottledException", "RequestThrottledException", "TooManyRequestsException",
      "ProvisionedThroughputExceededException", "TransactionInProgressException", "RequestLimitExceeded",
      "BandwidthLimitExceeded", "LimitExceededException", "RequestThrottled", "SlowDown"
    )) {
      expected.put(code, ErrorKind.THROTTLING);
    }
    for (String code : Arrays.asList(
      "AccessDeniedException", "NotAuthorized", "UnrecognizedClientException", "InvalidSignatureException",
      "IncompleteSignature", "IncompleteSignatureException", "MissingAuthenticationTokenException",
      "ExpiredTokenException", "InvalidGrantTokenException"
    )) {
      expected.put(code, ErrorKind.ACCESS_DENIED);
    }
    expected.put("NotFoundException", ErrorKind.RESOURCE_NOT_FOUND);
    expected.put("ResourceNotFoundException", ErrorKind.RESOURCE_NOT_FOUND);
    expected.put("ConditionalCheckFailedException", ErrorKind.CONFLICT);
    expected.put("TransactionConflictException", ErrorKind.CONFLICT);
    expected.put("InvalidCiphertextException", ErrorKind.SERVICE);
    expected.put("KMSInternalException", ErrorKind.SERVICE);
    expected.put("ValidationException", ErrorKind.SERVICE);
    for (Map.Entry<String, ErrorKind> entry : expected.entrySet()) {
      for (AwsServiceException e : Arrays.asList(kms(entry.getKey(), 400), ddb(entry.getKey(), 400))) {
        MaterialProvidersException mapped = AwsErrors.from(e);
        assertEquals(entry.getValue(), mapped.kind(), entry.getKey());
        assertSame(e, mapped.getCause());
        assertEquals(e.getMessage(), mapped.getMessage());
      }
    }
  }

  @Test
  void throttlingByStatusAndUnknownCodes() {
    assertEquals(ErrorKind.THROTTLING, AwsErrors.from(kms("SomethingNew", 429)).kind());
    assertEquals(ErrorKind.SERVICE, AwsErrors.from(kms("SomethingNew", 400)).kind());
    assertEquals(ErrorKind.SERVICE, AwsErrors.from(KmsException.builder().message("no details").build()).kind());
  }

  @Test
  void transactionCancellationReasons() {
    assertEquals(ErrorKind.CONFLICT, AwsErrors.from(cancelled("None", "ConditionalCheckFailed")).kind());
    assertEquals(ErrorKind.CONFLICT, AwsErrors.from(cancelled("TransactionConflict", "None")).kind());
    assertEquals(ErrorKind.SERVICE, AwsErrors.from(cancelled("None", "ValidationError")).kind());
    assertEquals(ErrorKind.SERVICE, AwsErrors.from(cancelled()).kind());
    assertEquals(ErrorKind.THROTTLING, AwsErrors.from(cancelled("None", "ThrottlingError")).kind());
    assertEquals(ErrorKind.THROTTLING, AwsErrors.from(cancelled("ProvisionedThroughputExceeded", "None")).kind());
    assertEquals(ErrorKind.CONFLICT, AwsErrors.from(cancelled("ThrottlingError", "ConditionalCheckFailed")).kind());
  }

  // Network and timeout failures are retryable dispatch failures.
  @Test
  void requestsThatFailedToSend() {
    for (SdkException e : java.util.Arrays.<SdkException>asList(
      SdkClientException.create("Unable to execute HTTP request", new java.net.SocketTimeoutException("read timed out")),
      software.amazon.awssdk.core.exception.ApiCallTimeoutException.create(1000),
      software.amazon.awssdk.core.exception.ApiCallAttemptTimeoutException.create(1000)
    )) {
      MaterialProvidersException mapped = AwsErrors.from(e);
      assertEquals(ErrorKind.DISPATCH, mapped.kind(), e.getMessage());
      assertTrue(mapped.isRetryable(), e.getMessage());
      assertSame(e, mapped.getCause());
    }
  }

  // A client-side failure without a transport cause, such as missing credentials, is configuration and not retryable.
  @Test
  void clientFailuresWithoutATransportCause() {
    SdkException e = SdkClientException.create("Unable to load credentials from any of the providers in the chain");
    MaterialProvidersException mapped = AwsErrors.from(e);
    assertEquals(ErrorKind.VALIDATION, mapped.kind());
    assertFalse(mapped.isRetryable());
    assertSame(e, mapped.getCause());
  }

  private static AwsServiceException kms(String code, int status) {
    return KmsException.builder()
      .message(code + " message")
      .statusCode(status)
      .awsErrorDetails(AwsErrorDetails.builder().errorCode(code).errorMessage(code + " message").build())
      .build();
  }

  private static AwsServiceException ddb(String code, int status) {
    return DynamoDbException.builder()
      .message(code + " message")
      .statusCode(status)
      .awsErrorDetails(AwsErrorDetails.builder().errorCode(code).errorMessage(code + " message").build())
      .build();
  }

  private static TransactionCanceledException cancelled(String... codes) {
    CancellationReason[] reasons = new CancellationReason[codes.length];
    for (int i = 0; i < codes.length; i++) {
      reasons[i] = CancellationReason.builder().code(codes[i]).build();
    }
    return TransactionCanceledException.builder()
      .message("Transaction cancelled")
      .statusCode(400)
      .awsErrorDetails(AwsErrorDetails.builder().errorCode("TransactionCanceledException").build())
      .cancellationReasons(reasons)
      .build();
  }
}
