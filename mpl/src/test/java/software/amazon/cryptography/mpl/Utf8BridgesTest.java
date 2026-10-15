// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

// The UTF-8 bridges for callers that hold contexts and provider ids as bytes.
// Utf8DecodeDifferentialTest compares which bytes they accept with the reference's UTF8.Decode.
class Utf8BridgesTest {

  private static final byte[] NOT_UTF8 = { (byte) 0xC3 };

  @Test
  void contextFromUtf8Values() {
    Map<String, byte[]> bytes = new LinkedHashMap<>();
    bytes.put("\ud83d\ude00", utf8("emoji"));
    bytes.put("\uffff", utf8("\u00fc"));
    bytes.put("a", new byte[0]);
    EncryptionContext context = EncryptionContext.fromUtf8(bytes);
    assertEquals(EncryptionContext.of("a", "", "\uffff", "\u00fc", "\ud83d\ude00", "emoji"), context);
    // UTF-8 byte order, as EncryptionContext.of sorts: U+FFFF (EF BF BF) before U+1F600 (F0 ...).
    assertEquals(Arrays.asList("a", "\uffff", "\ud83d\ude00"), Arrays.asList(context.keySet().toArray()));
    assertEquals(EncryptionContext.empty(), EncryptionContext.fromUtf8(Collections.<String, byte[]>emptyMap()));
  }

  @Test
  void contextFromUtf8Failures() {
    assertEquals(
      "Encryption context values must be well-formed UTF-8",
      assertThrows(ValidationException.class, () -> EncryptionContext.fromUtf8(Collections.singletonMap("k", NOT_UTF8))).getMessage()
    );
    assertThrows(ValidationException.class, () -> EncryptionContext.fromUtf8(Collections.singletonMap("\ud800", utf8("v"))));
    assertThrows(NullPointerException.class, () -> EncryptionContext.fromUtf8(Collections.<String, byte[]>singletonMap("k", null)));
    assertThrows(NullPointerException.class, () -> EncryptionContext.fromUtf8(Collections.singletonMap((String) null, utf8("v"))));
  }

  @Test
  void encryptedDataKeyOfUtf8() {
    byte[] id = utf8("aws-kms-\u00e9");
    byte[] info = { 1, 2 };
    byte[] ciphertext = { 3 };
    EncryptedDataKey edk = EncryptedDataKey.ofUtf8(id, info, ciphertext);
    assertEquals(EncryptedDataKey.of("aws-kms-\u00e9", info, ciphertext), edk);
    info[0] = 9;
    ciphertext[0] = 9;
    assertArrayEquals(new byte[] { 1, 2 }, edk.keyProviderInfo());
    assertArrayEquals(new byte[] { 3 }, edk.ciphertext());
    assertEquals(
      "Key provider id must be well-formed UTF-8",
      assertThrows(ValidationException.class, () -> EncryptedDataKey.ofUtf8(NOT_UTF8, info, ciphertext)).getMessage()
    );
  }

  @Test
  void keyProviderIdAsUtf8() {
    EncryptedDataKey edk = EncryptedDataKey.of("\u00e9\ud83d\ude00", new byte[0], new byte[0]);
    byte[] id = edk.keyProviderIdUtf8();
    assertArrayEquals("\u00e9\ud83d\ude00".getBytes(StandardCharsets.UTF_8), id);
    id[0] = 0;
    assertNotSame(id, edk.keyProviderIdUtf8());
    assertArrayEquals("\u00e9\ud83d\ude00".getBytes(StandardCharsets.UTF_8), edk.keyProviderIdUtf8());
  }

  // A lone surrogate has no UTF-8 form, so no message could store the key; it fails when made.
  @Test
  void aKeyProviderIdThatIsNotWellFormedUtf16IsRejected() {
    for (String id : new String[] { "a\ud800", "\udc00", "\ud83d" }) {
      assertEquals(
        "Key provider id must be well-formed UTF-16",
        assertThrows(ValidationException.class, () -> EncryptedDataKey.of(id, new byte[0], new byte[0])).getMessage()
      );
    }
  }

  private static byte[] utf8(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
