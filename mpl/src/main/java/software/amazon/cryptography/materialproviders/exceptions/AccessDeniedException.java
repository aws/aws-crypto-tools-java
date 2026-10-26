// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#ACCESS_DENIED}; the AWS SDK exception is the cause. */
public final class AccessDeniedException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public AccessDeniedException(String message) {
    super(message, null);
  }

  public AccessDeniedException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.ACCESS_DENIED;
  }
}
