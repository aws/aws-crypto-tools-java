// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#ENCRYPTION_CONTEXT_MISMATCH}. */
public final class EncryptionContextMismatchException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public EncryptionContextMismatchException(String message) {
    super(message, null);
  }

  public EncryptionContextMismatchException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.ENCRYPTION_CONTEXT_MISMATCH;
  }
}
