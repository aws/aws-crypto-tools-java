// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.ArrayDeque;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Optional;
import java.util.Set;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;

/**
 * Root of every exception the ESDK operations throw on purpose. Unchecked; one subclass per {@link
 * EsdkErrorKind}. A failure from the MPL is the cause, found with {@code
 * findCause(MaterialProvidersException.class)}.
 */
public abstract class EsdkException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  // Not protected: the subclasses are exactly the EsdkErrorKind constants.
  EsdkException(final String message, final Throwable cause) {
    super(message, cause);
  }

  public abstract EsdkErrorKind kind();

  /**
   * Whether repeating the same call might succeed: true for {@link EsdkErrorKind#THROTTLING} and
   * {@link EsdkErrorKind#DISPATCH}, otherwise what an MPL cause reports. False if the thread was
   * interrupted.
   */
  public boolean isRetryable() {
    if (findCause(InterruptedException.class).isPresent()) {
      return false;
    }
    if (kind() == EsdkErrorKind.THROTTLING || kind() == EsdkErrorKind.DISPATCH) {
      return true;
    }
    return findCause(MaterialProvidersException.class)
        .map(MaterialProvidersException::isRetryable)
        .orElse(false);
  }

  /**
   * The first exception of {@code type} among this exception's causes and suppressed exceptions,
   * searched depth first.
   */
  public <T extends Throwable> Optional<T> findCause(final Class<T> type) {
    final Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
    final Deque<Throwable> pending = new ArrayDeque<>();
    for (final Throwable suppressed : getSuppressed()) {
      pending.add(suppressed);
    }
    if (getCause() != null) {
      pending.addFirst(getCause());
    }
    while (!pending.isEmpty()) {
      final Throwable current = pending.removeFirst();
      if (!seen.add(current)) {
        continue;
      }
      if (type.isInstance(current)) {
        return Optional.of(type.cast(current));
      }
      final Throwable[] suppressed = current.getSuppressed();
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
