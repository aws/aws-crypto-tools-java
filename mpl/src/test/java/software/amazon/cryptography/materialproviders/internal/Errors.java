// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CollectionOfErrors;
import software.amazon.cryptography.mpl.exceptions.CryptographicException;
import software.amazon.cryptography.mpl.exceptions.MaterialProvidersException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.primitives.model.OpaqueError;

/** Test adapter: native exceptions as the old API threw them. */
public final class Errors {

  private Errors() {}

  public static RuntimeException toOld(RuntimeException e) {
    // ErrorMessages.IncorrectDataKeys was a plain error, not a collection.
    if (e instanceof NoMatchingDataKeyException && e.getMessage().startsWith(KeyringNames.INCORRECT_DATA_KEYS)) {
      return AwsCryptographicMaterialProvidersException.builder().message(e.getMessage()).build();
    }
    if (e instanceof NoMatchingDataKeyException) {
      List<RuntimeException> list = new ArrayList<>();
      for (Throwable failure : ((NoMatchingDataKeyException) e).failures()) {
        list.add(toOld((RuntimeException) failure));
      }
      return CollectionOfErrors.builder().message(e.getMessage()).list(list).build();
    }
    // A JCE failure inside a primitive surfaced as the primitives library's opaque error.
    if (e instanceof CryptographicException && e.getCause() instanceof GeneralSecurityException) {
      return OpaqueError.builder().obj(e.getCause()).build();
    }
    if (e instanceof MaterialProvidersException) {
      return AwsCryptographicMaterialProvidersException.builder().message(e.getMessage()).build();
    }
    return e;
  }
}
