// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.cache;

import java.util.function.Predicate;
import software.amazon.cryptography.materialproviders.cache.CacheKey;

/** A {@link LocalCache} whose operations each hold one lock, per SynchronizedLocalCMC.java. */
public final class SynchronizedCache<V> implements CacheEngine<V> {

  private final Object lock = new Object();
  private final LocalCache<V> wrapped;

  public SynchronizedCache(LocalCache<V> wrapped) {
    this.wrapped = wrapped;
  }

  @Override
  public Lookup<V> get(CacheKey key) {
    synchronized (lock) {
      return wrapped.get(key);
    }
  }

  @Override
  public void put(CacheKey key, V value, long expirySeconds) {
    synchronized (lock) {
      wrapped.put(key, value, expirySeconds);
    }
  }

  @Override
  public void remove(CacheKey key) {
    synchronized (lock) {
      wrapped.remove(key);
    }
  }

  @Override
  public void retainIf(CacheKey key, Predicate<? super V> keep) {
    synchronized (lock) {
      wrapped.retainIf(key, keep);
    }
  }
}
