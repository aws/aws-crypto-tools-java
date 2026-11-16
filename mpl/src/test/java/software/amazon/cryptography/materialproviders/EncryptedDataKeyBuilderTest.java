// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

class EncryptedDataKeyBuilderTest {

  private static EncryptedDataKey.Builder complete() {
    return EncryptedDataKey.builder().keyProviderId("aws-kms").keyProviderInfo(new byte[] { 1 }).ciphertext(new byte[] { 2 });
  }

  @Test
  void buildsAndCopies() {
    byte[] info = { 1, 2 };
    byte[] ciphertext = { 3 };
    EncryptedDataKey.Builder builder = EncryptedDataKey.builder().keyProviderId("p").keyProviderInfo(info).ciphertext(ciphertext);
    info[0] = 9;
    ciphertext[0] = 9;
    EncryptedDataKey edk = builder.build();
    assertEquals("p", edk.keyProviderId());
    assertArrayEquals(new byte[] { 1, 2 }, edk.keyProviderInfo());
    assertArrayEquals(new byte[] { 3 }, edk.ciphertext());
    assertEquals(edk, builder.build());
  }

  @Test
  void toBuilderKeepsValues() {
    EncryptedDataKey edk = complete().build();
    assertEquals(edk, edk.toBuilder().build());
    EncryptedDataKey changed = edk.toBuilder().ciphertext(new byte[] { 7 }).build();
    assertEquals("aws-kms", changed.keyProviderId());
    assertArrayEquals(new byte[] { 7 }, changed.ciphertext());
    assertArrayEquals(new byte[] { 2 }, edk.ciphertext());
  }

  @Test
  void utf8IdReplacesStringId() {
    byte[] id = "aws-kms-\u00e9".getBytes(StandardCharsets.UTF_8);
    assertEquals("aws-kms-\u00e9", complete().keyProviderIdUtf8(id).build().keyProviderId());
    assertEquals("raw", complete().keyProviderIdUtf8(id).keyProviderId("raw").build().keyProviderId());
  }

  @Test
  void rejectsMissingAndInvalidMembers() {
    assertMessage("Missing value for required field `keyProviderId`", EncryptedDataKey.builder().keyProviderInfo(new byte[0]).ciphertext(new byte[0]));
    assertMessage("Missing value for required field `keyProviderInfo`", complete().keyProviderInfo(null));
    assertMessage("Missing value for required field `ciphertext`", complete().ciphertext(null));
    assertMessage("Key provider id must be well-formed UTF-16", complete().keyProviderId("\ud800"));
    assertMessage("Key provider id must be well-formed UTF-8", complete().keyProviderIdUtf8(new byte[] { (byte) 0xC0, (byte) 0x80 }));
  }

  private static void assertMessage(String message, EncryptedDataKey.Builder builder) {
    assertEquals(message, assertThrows(ValidationException.class, builder::build).getMessage());
  }
}
