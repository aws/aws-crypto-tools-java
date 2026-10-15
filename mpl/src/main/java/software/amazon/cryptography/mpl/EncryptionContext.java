// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import java.util.AbstractMap;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.internal.Utf8;

//= spec/framework/structures.md#structure-1
//= type=implication
//# The encryption context is a key-value mapping of arbitrary, non-secret, UTF-8 encoded strings.
//# It is used during [encryption](../client-apis/encrypt.md) and [decryption](../client-apis/decrypt.md) to provide additional authenticated data (AAD).
/**
 * An encryption context: non-secret key-value pairs bound to a message as additional authenticated data.
 *
 * <p>Immutable, and usable anywhere a read-only {@code Map<String, String>} is accepted;
 * the {@code Map} mutators throw {@link UnsupportedOperationException}.
 * Iteration follows the order the message format serializes in: keys sorted by their UTF-8 bytes,
 * which can differ from {@code String} order (a {@code TreeMap}) for characters outside the Basic Multilingual Plane.
 *
 * <p>Every key and value must be a well-formed UTF-16 string (no lone surrogates);
 * building a context from an invalid one throws {@link ValidationException}. Null keys or values throw NullPointerException.
 */
public final class EncryptionContext extends AbstractMap<String, String> {

  private static final EncryptionContext EMPTY = new EncryptionContext(new TreeMap<>(Utf8.BYTE_ORDER));

  private final Map<String, String> pairs;

  private EncryptionContext(TreeMap<String, String> sorted) {
    this.pairs = Collections.unmodifiableMap(sorted);
  }

  public static EncryptionContext empty() {
    return EMPTY;
  }

  /** A context with the given pairs; {@code keysAndValues} alternates key, value. */
  public static EncryptionContext of(String... keysAndValues) {
    if (keysAndValues.length % 2 != 0) {
      throw new ValidationException("keysAndValues must alternate key and value");
    }
    TreeMap<String, String> sorted = new TreeMap<>(Utf8.BYTE_ORDER);
    for (int i = 0; i < keysAndValues.length; i += 2) {
      put(sorted, keysAndValues[i], keysAndValues[i + 1]);
    }
    return new EncryptionContext(sorted);
  }

  public static EncryptionContext copyOf(Map<String, String> pairs) {
    if (pairs instanceof EncryptionContext) {
      return (EncryptionContext) pairs;
    }
    TreeMap<String, String> sorted = new TreeMap<>(Utf8.BYTE_ORDER);
    for (Map.Entry<String, String> entry : pairs.entrySet()) {
      put(sorted, entry.getKey(), entry.getValue());
    }
    return new EncryptionContext(sorted);
  }

  /**
   * A context from values held as UTF-8 bytes, as a message header stores them.
   * The keys are strings already; a caller that reads them from bytes decodes them as strictly.
   *
   * @throws ValidationException if a value is not well-formed UTF-8 or a key is not well-formed UTF-16
   */
  public static EncryptionContext fromUtf8(Map<String, byte[]> pairs) {
    TreeMap<String, String> sorted = new TreeMap<>(Utf8.BYTE_ORDER);
    for (Map.Entry<String, byte[]> entry : pairs.entrySet()) {
      String value = Utf8.decode(Objects.requireNonNull(entry.getValue(), "encryption context value"));
      if (value == null) {
        throw new ValidationException("Encryption context values must be well-formed UTF-8");
      }
      put(sorted, entry.getKey(), value);
    }
    return new EncryptionContext(sorted);
  }

  /**
   * The canonical serialization the raw keyrings bind wrapped keys to as AAD (structures.md, encryption context):
   * the uint16 pair count, then each pair in iteration order as uint16 length and UTF-8 bytes of the key, then of the value.
   * An empty context serializes to no bytes. A new array on every call.
   *
   * @throws ValidationException if the context has 2^16 or more pairs, or a key or value of 2^16 or more bytes
   */
  public byte[] canonicalBytes() {
    throw new UnsupportedOperationException("not implemented yet");
  }

  /** This context with {@code key} set to {@code value}. */
  public EncryptionContext with(String key, String value) {
    TreeMap<String, String> sorted = new TreeMap<>(Utf8.BYTE_ORDER);
    sorted.putAll(pairs);
    put(sorted, key, value);
    return new EncryptionContext(sorted);
  }

  @Override
  public Set<Entry<String, String>> entrySet() {
    return pairs.entrySet();
  }

  @Override
  public String get(Object key) {
    return pairs.get(key);
  }

  @Override
  public boolean containsKey(Object key) {
    return pairs.containsKey(key);
  }

  private static void put(TreeMap<String, String> sorted, String key, String value) {
    Objects.requireNonNull(key, "encryption context key");
    Objects.requireNonNull(value, "encryption context value");
    if (!Utf8.isEncodable(key) || !Utf8.isEncodable(value)) {
      throw new ValidationException("Encryption context keys and values must be well-formed UTF-16");
    }
    sorted.put(key, value);
  }
}
