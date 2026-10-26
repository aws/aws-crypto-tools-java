// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#THROTTLING}. */
public final class ThrottlingException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public ThrottlingException(String message) {
    super(message, null);
  }

  public ThrottlingException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.THROTTLING;
  }
}
