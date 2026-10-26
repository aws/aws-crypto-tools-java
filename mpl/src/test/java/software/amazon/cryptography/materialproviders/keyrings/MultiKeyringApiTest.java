// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keyrings;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.OnDecryptRequest;
import software.amazon.cryptography.materialproviders.OnDecryptResponse;
import software.amazon.cryptography.materialproviders.OnEncryptRequest;
import software.amazon.cryptography.materialproviders.OnEncryptResponse;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.NoMatchingDataKeyException;

class MultiKeyringApiTest {

  // A list of a concrete keyring type compiles without widening.
  @Test
  void childKeyringsTakesAListOfASubtype() {
    List<RawAesKeyring> children = Arrays.asList(aes("a"), aes("b"));
    MultiKeyring multi = MultiKeyring.builder().generator(aes("g")).childKeyrings(children).build();
    assertEquals(children, multi.childKeyrings());
    EncryptionMaterials encrypted = multi.onEncrypt(
      OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build()
    ).materials();
    assertEquals(3, encrypted.encryptedDataKeys().size());
  }

  // Both MPLs fail when a keyring returns null. On encrypt the native multi keyring throws NullPointerException, where
  // Dafny reported the child failure (an exception kind, R1); on decrypt both count it as that keyring's failure.
  @Test
  void aKeyringReturningNullFails() {
    Keyring returnsNull = new Keyring() {
      @Override
      public OnEncryptResponse onEncrypt(OnEncryptRequest request) {
        return null;
      }

      @Override
      public OnDecryptResponse onDecrypt(OnDecryptRequest request) {
        return null;
      }
    };
    EncryptionMaterials start = EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build();
    OnEncryptRequest encrypt = OnEncryptRequest.builder().materials(start).build();
    assertThrows(NullPointerException.class, () -> MultiKeyring.builder().generator(returnsNull).build().onEncrypt(encrypt));
    MultiKeyring nullChild = MultiKeyring.builder().generator(aes("g")).childKeyrings(Collections.singletonList(returnsNull)).build();
    assertThrows(NullPointerException.class, () -> nullChild.onEncrypt(encrypt));

    List<EncryptedDataKey> edks = aes("g").onEncrypt(encrypt).materials().encryptedDataKeys();
    OnDecryptRequest decrypt = OnDecryptRequest
      .builder()
      .materials(DecryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build())
      .encryptedDataKeys(edks)
      .build();
    assertTrue(MultiKeyring.builder().generator(returnsNull).childKeyrings(Collections.singletonList(aes("g"))).build().onDecrypt(decrypt).materials().plaintextDataKey().isPresent());
    NoMatchingDataKeyException none = assertThrows(NoMatchingDataKeyException.class, () -> MultiKeyring.builder().generator(returnsNull).build().onDecrypt(decrypt));
    assertInstanceOf(NullPointerException.class, none.failures().get(0));
  }

  private static RawAesKeyring aes(String name) {
    return RawAesKeyring
      .builder()
      .keyNamespace("ns")
      .keyName(name)
      .wrappingKey(SecretBytes.copyOf(new byte[32]))
      .wrappingAlg(AesWrappingAlg.ALG_AES256_GCM_IV12_TAG16)
      .build();
  }
}
