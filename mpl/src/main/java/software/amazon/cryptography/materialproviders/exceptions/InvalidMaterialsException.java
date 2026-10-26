// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#INVALID_MATERIALS}. */
public final class InvalidMaterialsException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public InvalidMaterialsException(String message) {
    super(message, null);
  }

  public InvalidMaterialsException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.INVALID_MATERIALS;
  }
}
