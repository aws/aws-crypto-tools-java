// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#DISPATCH}; the AWS SDK exception is the cause. */
public final class DispatchException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public DispatchException(String message) {
    super(message, null);
  }

  public DispatchException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.DISPATCH;
  }
}
