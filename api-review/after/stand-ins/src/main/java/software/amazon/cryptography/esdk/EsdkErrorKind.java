// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

/**
 * What a caller can do about a failure of an ESDK operation. Each kind has one exception class.
 * The MPL's twelve kinds keep their names; {@link #MALFORMED_MESSAGE} is the ESDK's own. More kinds
 * may be added; a {@code switch} needs a {@code default} branch.
 */
public enum EsdkErrorKind {
  /** An argument or configuration is invalid; fix the input. */
  VALIDATION,
  /** Materials break their invariants, or a keyring or manager returned invalid materials. */
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
  /** A concurrent or duplicate change. */
  CONFLICT,
  /** An AWS service failed or returned an unexpected response. */
  SERVICE,
  /** A request could not be sent or its response not received. Retryable. */
  DISPATCH,
  /** A library bug: an invariant that should be unreachable failed. */
  INTERNAL,
  /** The ciphertext is not a well-formed message, so it cannot be parsed. */
  MALFORMED_MESSAGE,
}
