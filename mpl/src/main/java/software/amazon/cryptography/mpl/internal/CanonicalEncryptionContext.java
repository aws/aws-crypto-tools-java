// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.internal;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

/**
 * The encryption context serialization of structures.md, per CanonicalEncryptionContext.dfy:
 * empty for an empty context, otherwise uint16 count, then for each pair in UTF-8 byte order
 * uint16 key length, key, uint16 value length, value. Used as AAD by the raw keyrings.
 */
public final class CanonicalEncryptionContext {

  private static final int UINT16_LIMIT = 1 << 16;

  private CanonicalEncryptionContext() {}

  public static byte[] serialize(EncryptionContext encryptionContext) {
    if (encryptionContext.size() >= UINT16_LIMIT) {
      throw new ValidationException("Encryption Context is too large");
    }
    if (encryptionContext.isEmpty()) {
      return new byte[0];
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeUint16(out, encryptionContext.size());
    // EncryptionContext iterates in UTF-8 byte order already.
    for (Map.Entry<String, String> entry : encryptionContext.entrySet()) {
      byte[] key = Utf8.encode(entry.getKey());
      byte[] value = Utf8.encode(entry.getValue());
      if (key.length >= UINT16_LIMIT || value.length >= UINT16_LIMIT) {
        throw new ValidationException("Unable to serialize encryption context");
      }
      writeUint16(out, key.length);
      out.write(key, 0, key.length);
      writeUint16(out, value.length);
      out.write(value, 0, value.length);
    }
    return out.toByteArray();
  }

  private static void writeUint16(ByteArrayOutputStream out, int value) {
    out.write(value >>> 8);
    out.write(value);
  }
}
