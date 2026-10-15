// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

import java.util.Optional;

/** Root of every exception the library throws on purpose. Unchecked; one subclass per {@link ErrorKind}. */
public abstract class MaterialProvidersException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  // Not protected: the subclasses are exactly the ErrorKind constants, so callers can switch over kind().
  MaterialProvidersException(String message, Throwable cause) {
    super(message, cause);
  }

  public abstract ErrorKind kind();

  /**
   * Whether repeating the same call might succeed: true for {@link ErrorKind#THROTTLING} and {@link ErrorKind#DISPATCH},
   * and for other kinds whose AWS SDK cause is retryable. False whenever the thread was interrupted
   * (an {@link InterruptedException} cause): a retry would fail at once and lose the cancellation.
   */
  public boolean isRetryable() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** The first exception of {@code type} among this exception's causes and suppressed exceptions, searched depth first. */
  public <T extends Throwable> Optional<T> findCause(Class<T> type) {
    throw new UnsupportedOperationException("not implemented yet");
  }
}
