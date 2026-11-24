package proposal;

import java.util.concurrent.CompletableFuture;

final class Stubs {
  private Stubs() {}

  static UnsupportedOperationException stub() {
    return new UnsupportedOperationException("proposal stub");
  }

  static <T> CompletableFuture<T> failed() {
    CompletableFuture<T> f = new CompletableFuture<>();
    f.completeExceptionally(stub());
    return f;
  }
}
