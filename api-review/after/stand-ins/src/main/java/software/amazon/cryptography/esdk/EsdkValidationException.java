// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

/** An argument or configuration is invalid; see {@link EsdkErrorKind#VALIDATION}. */
public final class EsdkValidationException extends EsdkException {

  private static final long serialVersionUID = 1L;

  public EsdkValidationException(final String message) {
    super(message, null);
  }

  public EsdkValidationException(final String message, final Throwable cause) {
    super(message, cause);
  }

  @Override
  public EsdkErrorKind kind() {
    return EsdkErrorKind.VALIDATION;
  }
}
