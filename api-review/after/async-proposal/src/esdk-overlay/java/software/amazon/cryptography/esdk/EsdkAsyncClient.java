// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package software.amazon.cryptography.esdk;

import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Proposal stub: the async twin of {@link EsdkClient}, with the same request and response types.
 * It compiles the async examples; it encrypts nothing.
 */
public interface EsdkAsyncClient {

  static EsdkAsyncClient create() {
    return new EsdkAsyncClient() {
      @Override
      public CompletableFuture<EncryptResponse> encrypt(EncryptRequest request) {
        CompletableFuture<EncryptResponse> f = new CompletableFuture<>();
        f.completeExceptionally(new UnsupportedOperationException("proposal stub"));
        return f;
      }

      @Override
      public CompletableFuture<DecryptResponse> decrypt(DecryptRequest request) {
        CompletableFuture<DecryptResponse> f = new CompletableFuture<>();
        f.completeExceptionally(new UnsupportedOperationException("proposal stub"));
        return f;
      }
    };
  }

  CompletableFuture<EncryptResponse> encrypt(EncryptRequest request);

  default CompletableFuture<EncryptResponse> encrypt(Consumer<EncryptRequest.Builder> request) {
    EncryptRequest.Builder builder = EncryptRequest.builder();
    request.accept(builder);
    return encrypt(builder.build());
  }

  CompletableFuture<DecryptResponse> decrypt(DecryptRequest request);

  default CompletableFuture<DecryptResponse> decrypt(Consumer<DecryptRequest.Builder> request) {
    DecryptRequest.Builder builder = DecryptRequest.builder();
    request.accept(builder);
    return decrypt(builder.build());
  }
}
