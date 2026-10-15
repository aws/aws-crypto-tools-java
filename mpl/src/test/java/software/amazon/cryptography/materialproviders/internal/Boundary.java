// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import software.amazon.cryptography.materialproviders.model.CollectionOfErrors;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.OpaqueError;

/**
 * Input checks the Dafny-based MPL performed while converting public inputs, before any operation logic:
 * a null where the model allows a value throws NullPointerException,
 * and a string that is not valid UTF-16 (a lone surrogate) throws RuntimeException.
 * Operations call these first so they fail in the same cases, with the same exceptions.
 *
 * <p>The conversion also treated an empty optional list or map as absent; see {@link #optional}.
 */
public final class Boundary {

  private Boundary() {}

  /** Requires a non-null string that encodes to UTF-8, which Dafny's UTF-8 byte strings need. */
  public static String utf8(String value) {
    try {
      StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(value));
    } catch (CharacterCodingException e) {
      // Message kept from the Dafny-based MPL; see decision X10.
      throw new RuntimeException("Could not encode input to Dafny Bytes.");
    }
    return value;
  }

  /** An optional list as the Dafny-based MPL saw it: an empty list meant the field was not set. */
  public static <T> List<T> optional(List<T> values) {
    return values == null || values.isEmpty() ? null : values;
  }

  /** An optional map as the Dafny-based MPL saw it: an empty map meant the field was not set. */
  public static <K, V> Map<K, V> optional(Map<K, V> values) {
    return values == null || values.isEmpty() ? null : values;
  }

  public static void encryptionContext(Map<String, String> encryptionContext) {
    for (Map.Entry<String, String> entry : encryptionContext.entrySet()) {
      utf8(entry.getKey());
      utf8(entry.getValue());
    }
  }

  public static void utf8List(List<String> values) {
    for (String value : values) {
      utf8(value);
    }
  }

  public static void encryptionMaterials(EncryptionMaterials materials) {
    encryptionContext(materials.encryptionContext());
    for (EncryptedDataKey encryptedDataKey : materials.encryptedDataKeys()) {
      utf8(encryptedDataKey.keyProviderId());
    }
    utf8List(materials.requiredEncryptionContextKeys());
    if (materials.symmetricSigningKeys() != null) {
      for (ByteBuffer key : materials.symmetricSigningKeys()) {
        Objects.requireNonNull(key);
      }
    }
  }

  public static EncryptedDataKey encryptedDataKey(EncryptedDataKey encryptedDataKey) {
    utf8(encryptedDataKey.keyProviderId());
    return encryptedDataKey;
  }

  public static void decryptionMaterials(DecryptionMaterials materials) {
    encryptionContext(materials.encryptionContext());
    utf8List(materials.requiredEncryptionContextKeys());
  }

  /**
   * An exception from a caller's keyring or CMM after the round trip through Dafny's error type:
   * a collection's message gains the list's description again, and an exception the model does not
   * declare becomes an {@link OpaqueError} holding it.
   */
  public static RuntimeException crossing(RuntimeException e) {
    if (e instanceof CollectionOfErrors) {
      List<RuntimeException> list = new ArrayList<>();
      for (RuntimeException element : ((CollectionOfErrors) e).list()) {
        list.add(crossing(element));
      }
      return CollectionOfErrors.builder().message(e.getMessage()).list(list).build();
    }
    if (e.getClass().getName().startsWith("software.amazon.cryptography.materialproviders.model.")) {
      return e;
    }
    return OpaqueError.builder().obj(e).build();
  }
}
