// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.keyrings;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.AlgorithmSuite;
import software.amazon.cryptography.mpl.EncryptionMaterials;
import software.amazon.cryptography.mpl.OnEncryptRequest;
import software.amazon.cryptography.mpl.SecretBytes;

class MultiKeyringApiTest {

  // A list of a concrete keyring type compiles without widening.
  @Test
  void childKeyringsTakesAListOfASubtype() {
    List<RawAesKeyring> children = Arrays.asList(aes("a"), aes("b"));
    MultiKeyring multi = MultiKeyring.builder().generator(aes("g")).childKeyrings(children).build();
    assertEquals(children, multi.childKeyrings());
    EncryptionMaterials encrypted = multi.onEncrypt(
      OnEncryptRequest.builder().materials(EncryptionMaterials.builder(AlgorithmSuite.ALG_AES_256_GCM_IV12_TAG16_NO_KDF).build()).build()
    );
    assertEquals(3, encrypted.encryptedDataKeys().size());
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
