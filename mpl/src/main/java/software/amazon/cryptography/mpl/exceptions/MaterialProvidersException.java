// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.exceptions;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Optional;
import java.util.Set;
import software.amazon.awssdk.core.exception.SdkException;

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
    if (findCause(InterruptedException.class).isPresent()) {
      return false;
    }
    if (kind() == ErrorKind.THROTTLING || kind() == ErrorKind.DISPATCH) {
      return true;
    }
    return findCause(SdkException.class).map(SdkException::retryable).orElse(false);
  }

  /** The first exception of {@code type} among this exception's causes and suppressed exceptions, searched depth first. */
  public <T extends Throwable> Optional<T> findCause(Class<T> type) {
    return find(getCause(), type, Collections.newSetFromMap(new IdentityHashMap<>()));
  }

  private <T extends Throwable> Optional<T> find(Throwable start, Class<T> type, Set<Throwable> seen) {
    Deque<Throwable> pending = new ArrayDeque<>();
    for (Throwable suppressed : getSuppressed()) {
      pending.add(suppressed);
    }
    if (start != null) {
      pending.addFirst(start);
    }
    while (!pending.isEmpty()) {
      Throwable current = pending.removeFirst();
      if (!seen.add(current)) {
        continue;
      }
      if (type.isInstance(current)) {
        return Optional.of(type.cast(current));
      }
      Throwable[] suppressed = current.getSuppressed();
      for (int i = suppressed.length - 1; i >= 0; i--) {
        pending.addFirst(suppressed[i]);
      }
      if (current.getCause() != null) {
        pending.addFirst(current.getCause());
      }
    }
    return Optional.empty();
  }
}
