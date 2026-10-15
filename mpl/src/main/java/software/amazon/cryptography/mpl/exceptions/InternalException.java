// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

/** See {@link ErrorKind#INTERNAL}. Please report it. */
public final class InternalException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public InternalException(String message) {
    super(message, null);
  }

  public InternalException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.INTERNAL;
  }
}
