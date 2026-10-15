// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.cryptography.keystore.internal.KeyStoreConvert;
import software.amazon.cryptography.materialproviders.model.AwsCryptographicMaterialProvidersException;
import software.amazon.cryptography.materialproviders.model.CollectionOfErrors;
import software.amazon.cryptography.mpl.exceptions.CryptographicException;
import software.amazon.cryptography.mpl.exceptions.MaterialProvidersException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;
import software.amazon.cryptography.mpl.internal.EcdhEdkWrapping;
import software.amazon.cryptography.mpl.internal.KeyringNames;
import software.amazon.cryptography.mpl.internal.keystore.KeyStoreOperations;
import software.amazon.cryptography.mpl.internal.primitives.Ecdh;
import software.amazon.cryptography.mpl.internal.primitives.Ecdsa;
import software.amazon.cryptography.mpl.internal.primitives.Rsa;
import software.amazon.cryptography.mpl.keyrings.AwsKmsHierarchicalKeyring;
import software.amazon.cryptography.primitives.AtomicPrimitives;
import software.amazon.cryptography.primitives.model.AwsCryptographicPrimitivesError;
import software.amazon.cryptography.primitives.model.OpaqueError;

/** Test adapter: native exceptions as the old API threw them. */
public final class Errors {

  private static final String KEY_STORE_INTERNALS = KeyStoreOperations.class.getPackage().getName() + ".";

  private Errors() {}

  public static RuntimeException toOld(RuntimeException e) {
    // The old API surfaced the AWS SDK exception itself.
    if (e instanceof MaterialProvidersException && e.getCause() instanceof SdkException) {
      return (SdkException) e.getCause();
    }
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
    // A failure inside an asymmetric primitive surfaced as the primitives library's error, as AtomicPrimitives reports it.
    // Classified by the primitives class that threw it; any other class there fails the test instead of guessing.
    if (e instanceof MaterialProvidersException && e.getStackTrace().length > 0) {
      String origin = e.getStackTrace()[0].getClassName();
      if (origin.startsWith(Rsa.class.getPackage().getName() + ".")) {
        if (origin.equals(Rsa.class.getName()) || origin.equals(Ecdsa.class.getName())) {
          return AtomicPrimitives.rsaOrEcdsaError((MaterialProvidersException) e);
        }
        if (origin.equals(Ecdh.class.getName())) {
          return AtomicPrimitives.ecdhError((MaterialProvidersException) e);
        }
        if (!(e instanceof CryptographicException && e.getCause() instanceof GeneralSecurityException)) {
          throw new IllegalStateException("no old-API mapping for a failure thrown in " + origin, e);
        }
      }
      // ECDH unwrapping checks the tag length where the Dafny-based MPL left it to AESDecrypt's input check.
      // Likewise the KDF's input check, which only a shared secret of the wrong length from KMS fails.
      boolean primitivesCheck = e.getMessage().equals("Request does not match algorithm.") || e.getMessage().equals(EcdhEdkWrapping.KDF_INPUT_INVALID);
      if (origin.equals(EcdhEdkWrapping.class.getName()) && primitivesCheck) {
        return AwsCryptographicPrimitivesError.builder().message(e.getMessage()).build();
      }
      // The hierarchical keyring checks the branch key length where the Dafny-based MPL left it to KdfCounterMode's input check.
      if (origin.equals(AwsKmsHierarchicalKeyring.class.getName()) && e.getMessage().equals("Kdf in Counter Mode input is invalid.")) {
        return AwsCryptographicPrimitivesError.builder().message(e.getMessage()).build();
      }
      // A key store failure inside a keyring surfaced as the key store's own error.
      if (origin.startsWith(KEY_STORE_INTERNALS)) {
        return KeyStoreConvert.toOld((MaterialProvidersException) e);
      }
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
