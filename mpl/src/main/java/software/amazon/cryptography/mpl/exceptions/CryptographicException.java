// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

/** See {@link ErrorKind#CRYPTOGRAPHIC}. */
public final class CryptographicException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public CryptographicException(String message) {
    super(message, null);
  }

  public CryptographicException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.CRYPTOGRAPHIC;
  }
}
