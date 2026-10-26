// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

/** See {@link ErrorKind#SERVICE}; the AWS SDK exception, if any, is the cause. */
public final class ServiceException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  public ServiceException(String message) {
    super(message, null);
  }

  public ServiceException(String message, Throwable cause) {
    super(message, cause);
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.SERVICE;
  }
}
