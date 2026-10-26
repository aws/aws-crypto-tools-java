// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.exceptions;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import software.amazon.awssdk.core.exception.SdkException;

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
    if (super.isRetryable()) {
      return true;
    }
    if (findCause(InterruptedException.class).isPresent()) {
      return false;
    }
    for (Throwable failure : failures) {
      // A caller's keyring can let an AWS SDK exception through unwrapped.
      if (failure instanceof MaterialProvidersException ? ((MaterialProvidersException) failure).isRetryable() : isRetryableSdk(failure)) {
        return true;
      }
    }
    return false;
  }

  private static boolean isRetryableSdk(Throwable failure) {
    return failure instanceof SdkException && ((SdkException) failure).retryable();
  }

  @Override
  public ErrorKind kind() {
    return ErrorKind.NO_MATCHING_DATA_KEY;
  }
}
