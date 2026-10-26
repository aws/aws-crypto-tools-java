// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/**
 * What a caller can do about a failure. Each kind has one exception class.
 * More kinds may be added; a {@code switch} needs a {@code default} branch.
 */
public enum ErrorKind {
  /** An argument or configuration is invalid; fix the input. */
  VALIDATION,
  /** Materials break their invariants, or a keyring or manager returned an invalid transition. */
  INVALID_MATERIALS,
  /** The encryption context supplied on decrypt disagrees with the one in the message. */
  ENCRYPTION_CONTEXT_MISMATCH,
  /** No keyring could decrypt any encrypted data key. */
  NO_MATCHING_DATA_KEY,
  /** A cryptographic operation failed, for example an authentication tag did not verify. */
  CRYPTOGRAPHIC,
  /** AWS denied access to a KMS key or DynamoDB table. */
  ACCESS_DENIED,
  /** A KMS key, table, or branch key does not exist. */
  RESOURCE_NOT_FOUND,
  /** A service or a storm-tracking cache asked the caller to slow down. Retryable. */
  THROTTLING,
  /** A concurrent or duplicate change, for example creating a branch key id that exists. */
  CONFLICT,
  /** An AWS service failed or returned an unexpected response. */
  SERVICE,
  /** A request could not be sent or its response not received (a network or timeout failure). Retryable. */
  DISPATCH,
  /** A library bug: an invariant that should be unreachable failed. */
  INTERNAL,
}
