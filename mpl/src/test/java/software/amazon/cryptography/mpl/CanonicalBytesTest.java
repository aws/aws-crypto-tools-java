// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.exceptions.ValidationException;
import software.amazon.cryptography.mpl.keyrings.AesWrappingAlg;
import software.amazon.cryptography.mpl.keyrings.RawAesKeyring;

// EncryptionContext.canonicalBytes: known answers, and the AAD the raw AES keyring binds its wrapped key to.
class CanonicalBytesTest {

  @Test
  void knownAnswers() {
    assertArrayEquals(new byte[0], EncryptionContext.empty().canonicalBytes());
    // Two pairs in UTF-8 byte order: "a" -> "", then U+00E9 (C3 A9) -> "b".
    assertArrayEquals(
      new byte[] { 0, 2, 0, 1, 'a', 0, 0, 0, 2, (byte) 0xC3, (byte) 0xA9, 0, 1, 'b' },
      EncryptionContext.of("\u00e9", "b", "a", "").canonicalBytes()
    );
    EncryptionContext context = EncryptionContext.of("k", "v");
    assertNotSame(context.canonicalBytes(), context.canonicalBytes());
  }

  @Test
  void limits() {
    char[] longest = new char[65535];
    Arrays.fill(longest, 'x');
    assertEquals(2 + 2 + 1 + 2 + 65535, EncryptionContext.of("k", new String(longest)).canonicalBytes().length);
    assertThrows(ValidationException.class, () -> EncryptionContext.of("k", new String(longest) + "x").canonicalBytes());
    Map<String, String> many = new HashMap<>();
    for (int i = 0; i < 65536; i++) {
      many.put(Integer.toString(i), "");
    }
    assertThrows(ValidationException.class, () -> EncryptionContext.copyOf(many).canonicalBytes());
  }

  @Test
  void isTheRawAesKeyringsAad() throws Exception {
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 7);
    RawAesKeyring keyring = RawAesKeyring
      .builder()
      .keyNamespace("ns")
      .keyName("name")
      .wrappingKey(SecretBytes.copyOf(key))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
    EncryptionContext context = EncryptionContext.of("tenant", "a", "\ud83d\ude00", "b");
    EncryptionMaterials encrypted = keyring.onEncrypt(OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).encryptionContext(context).build()).build()).materials();
    EncryptedDataKey edk = encrypted.encryptedDataKeys().get(0);
    byte[] info = edk.keyProviderInfo();
    byte[] iv = Arrays.copyOfRange(info, info.length - 12, info.length);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
    cipher.updateAAD(context.canonicalBytes());
    assertArrayEquals(encrypted.plaintextDataKey().get().toByteArray(), cipher.doFinal(edk.ciphertext()));
  }
}
