// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

/** An argument or configuration is invalid; see {@link ErrorKind#VALIDATION}. */
public final class ValidationException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public ValidationException(String message) {
    super(message, null);
  }

  public ValidationException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.VALIDATION;
  }
}
