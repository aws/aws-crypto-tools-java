// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#CONFLICT}. */
public final class ConflictException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public ConflictException(String message) {
    super(message, null);
  }

  public ConflictException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.CONFLICT;
  }
}
