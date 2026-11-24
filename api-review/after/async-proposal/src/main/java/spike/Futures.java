package spike;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.function.Supplier;

/** Java 8 stand-ins for CompletableFuture methods added in Java 9 and 12. */
final class Futures {
  private Futures() {}

  /** CompletableFuture.failedFuture is Java 9+. */
  static <T> CompletableFuture<T> failed(Throwable t) {
    CompletableFuture<T> f = new CompletableFuture<>();
    f.completeExceptionally(t);
    return f;
  }

  /** Runs body; a synchronous throw becomes a failed future, so callers see one failure channel. */
  static <T> CompletableFuture<T> guard(Supplier<CompletableFuture<T>> body) {
    try {
      CompletableFuture<T> f = body.get();
      return f != null ? f : failed(new NullPointerException("async keyring returned a null future"));
    } catch (RuntimeException e) {
      return failed(e);
    }
  }

  /** The cause behind CompletionException/ExecutionException wrappers. */
  static Throwable unwrap(Throwable t) {
    while ((t instanceof CompletionException || t instanceof ExecutionException) && t.getCause() != null) {
      t = t.getCause();
    }
    return t;
  }

  /** exceptionallyCompose is Java 12+. */
  static <T> CompletableFuture<T> recoverWith(CompletableFuture<T> f, Function<Throwable, CompletableFuture<T>> fallback) {
    return f.handle((v, t) -> t == null ? CompletableFuture.completedFuture(v) : fallback.apply(unwrap(t)))
        .thenCompose(Function.identity());
  }
}
