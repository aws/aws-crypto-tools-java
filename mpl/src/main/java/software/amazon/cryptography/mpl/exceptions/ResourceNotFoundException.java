// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

/** See {@link ErrorKind#RESOURCE_NOT_FOUND}. */
public final class ResourceNotFoundException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public ResourceNotFoundException(String message) {
    super(message, null);
  }

  public ResourceNotFoundException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.RESOURCE_NOT_FOUND;
  }
}
