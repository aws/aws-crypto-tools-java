// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.util.Map;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.exceptions.AccessDeniedException;
import software.amazon.cryptography.mpl.exceptions.MaterialProvidersException;
import software.amazon.cryptography.mpl.exceptions.NoMatchingDataKeyException;

/**
 * What a caller writes to act on MPL failures. The ESDK passes MPL exceptions through unchanged (as ESDK 3.x does),
 * so this is customer code.
 */
public final class ErrorHandlingExample {

  /** What to do next. */
  public enum Outcome {
    DECRYPTED,
    RETRY_LATER,
    ACCESS_DENIED,
    NOT_FOR_THIS_KEYRING,
    INVALID_REQUEST,
  }

  private ErrorHandlingExample() {}

  public static Outcome decrypt(EsdkLikeClient crypto, Keyring keyring, byte[] ciphertext, Map<String, String> encryptionContext) {
    try {
      crypto.decryptData(keyring, ciphertext, encryptionContext);
      return Outcome.DECRYPTED;
    } catch (NoMatchingDataKeyException e) {
      // Every keyring that tried a key left its failure in e.failures(); findCause searches them, nested ones included.
      if (e.isRetryable()) {
        return Outcome.RETRY_LATER;
      }
      if (e.findCause(AccessDeniedException.class).isPresent()) {
        return Outcome.ACCESS_DENIED;
      }
      return Outcome.NOT_FOR_THIS_KEYRING;
    } catch (MaterialProvidersException e) {
      if (e.isRetryable()) {
        return Outcome.RETRY_LATER;
      }
      switch (e.kind()) {
        case ACCESS_DENIED:
          return Outcome.ACCESS_DENIED;
        case VALIDATION:
        case ENCRYPTION_CONTEXT_MISMATCH:
          return Outcome.INVALID_REQUEST;
        default:
          throw e;
      }
    }
  }
}
