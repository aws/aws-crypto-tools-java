// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * See {@link ErrorKind#NO_MATCHING_DATA_KEY}.
 * Each attempt's failure is kept, in order, in {@link #failures()} and as a suppressed exception.
 * Search them with {@link #findCause}, for example for an {@link AccessDeniedException}.
 */
public final class NoMatchingDataKeyException extends MaterialProvidersException {

  private static final long serialVersionUID = 1L;

  private final List<Throwable> failures;

  public NoMatchingDataKeyException(String message, List<? extends Throwable> failures) {
    super(message, null);
    this.failures = Collections.unmodifiableList(new ArrayList<Throwable>(failures));
    for (Throwable failure : failures) {
      addSuppressed(failure);
    }
  }

  public List<Throwable> failures() {
    return failures;
  }

  /**
   * Also true when any of {@link #failures()} is retryable, for example a KMS call that was throttled:
   * a retry might reach the key that failed and decrypt with it.
   * False whenever the thread was interrupted.
   */
  @Override
  public boolean isRetryable() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.NO_MATCHING_DATA_KEY;
  }
}
