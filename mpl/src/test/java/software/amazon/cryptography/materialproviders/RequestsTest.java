// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

// The keyring requests, DecryptMaterialsRequest.toBuilder, and the builders that take any Map<String, String> as an encryption context.
class RequestsTest {

  private static final AlgorithmSuite SUITE = EsdkAlgorithmSuite.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY;
  private static final List<EncryptedDataKey> EDKS = Collections.singletonList(EncryptedDataKey.builder()
      .keyProviderId("p")
      .keyProviderInfo(new byte[] { 1 })
      .ciphertext(new byte[] { 2 })
      .build());

  @Test
  void keyringRequestsHoldTheCallersMaterialsAndACopyOfTheKeys() {
    EncryptionMaterials encryption = EncryptionMaterials.builder(SUITE).build().withPlaintextDataKey(SecretBytes.random(32));
    OnEncryptRequest encrypt = OnEncryptRequest.builder().materials(encryption).build();
    assertSame(encryption, encrypt.materials());
    assertSame(encryption, encrypt.toBuilder().build().materials());

    DecryptionMaterials decryption = DecryptionMaterials.builder(SUITE).build();
    List<EncryptedDataKey> edks = new ArrayList<>(EDKS);
    OnDecryptRequest.Builder builder = OnDecryptRequest.builder().materials(decryption).encryptedDataKeys(edks);
    edks.clear();
    OnDecryptRequest decrypt = builder.build();
    assertSame(decryption, decrypt.materials());
    assertEquals(EDKS, decrypt.encryptedDataKeys());
    assertThrows(UnsupportedOperationException.class, () -> decrypt.encryptedDataKeys().clear());
    OnDecryptRequest copy = decrypt.toBuilder().build();
    assertSame(decryption, copy.materials());
    assertEquals(EDKS, copy.encryptedDataKeys());
    DecryptionMaterials other = DecryptionMaterials.builder(SUITE).build();
    assertSame(other, decrypt.toBuilder().materials(other).build().materials());
    assertSame(decryption, decrypt.materials());
  }

  @Test
  void keyringRequestsRequireEveryField() {
    assertEquals("Missing value for required field `materials`", assertThrows(ValidationException.class, () -> OnEncryptRequest.builder().build()).getMessage());
    assertEquals(
      "Missing value for required field `materials`",
      assertThrows(ValidationException.class, () -> OnDecryptRequest.builder().encryptedDataKeys(EDKS).build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `encryptedDataKeys`",
      assertThrows(ValidationException.class, () -> OnDecryptRequest.builder().materials(DecryptionMaterials.builder(SUITE).build()).build()).getMessage()
    );
    // An empty list is a value: the keyring reports that nothing decrypted.
    assertTrue(OnDecryptRequest.builder().materials(DecryptionMaterials.builder(SUITE).build()).encryptedDataKeys(Collections.emptyList()).build().encryptedDataKeys().isEmpty());
  }

  @Test
  void responsesHoldTheMaterialsAndRequireThem() {
    EncryptionMaterials encryption = EncryptionMaterials.builder(SUITE).build();
    DecryptionMaterials decryption = DecryptionMaterials.builder(SUITE).build();
    assertSame(encryption, OnEncryptResponse.builder().materials(encryption).build().toBuilder().build().materials());
    assertSame(decryption, OnDecryptResponse.builder().materials(decryption).build().toBuilder().build().materials());
    assertSame(encryption, GetEncryptionMaterialsResponse.builder().encryptionMaterials(encryption).build().toBuilder().build().encryptionMaterials());
    assertSame(decryption, DecryptMaterialsResponse.builder().decryptionMaterials(decryption).build().toBuilder().build().decryptionMaterials());
    assertEquals("Missing value for required field `materials`", assertThrows(ValidationException.class, () -> OnEncryptResponse.builder().materials(null).build()).getMessage());
    assertEquals("Missing value for required field `materials`", assertThrows(ValidationException.class, () -> OnDecryptResponse.builder().materials(null).build()).getMessage());
    assertEquals(
      "Missing value for required field `encryptionMaterials`",
      assertThrows(ValidationException.class, () -> GetEncryptionMaterialsResponse.builder().encryptionMaterials(null).build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `decryptionMaterials`",
      assertThrows(ValidationException.class, () -> DecryptMaterialsResponse.builder().decryptionMaterials(null).build()).getMessage()
    );
  }

  @Test
  void keyringRequestsShowNoSecrets() {
    EncryptionMaterials encryption = EncryptionMaterials.builder(SUITE).build().withPlaintextDataKey(SecretBytes.copyOf(new byte[32]));
    assertEquals("OnEncryptRequest[" + encryption + "]", OnEncryptRequest.builder().materials(encryption).build().toString());
    DecryptionMaterials decryption = DecryptionMaterials.builder(SUITE).build();
    assertEquals(
      "OnDecryptRequest[" + decryption + ", 1 encrypted data keys]",
      OnDecryptRequest.builder().materials(decryption).encryptedDataKeys(EDKS).build().toString()
    );
  }

  @Test
  void decryptRequestToBuilderKeepsEveryField() {
    DecryptMaterialsRequest request = DecryptMaterialsRequest
      .builder()
      .algorithmSuite(SUITE)
      .commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
      .encryptedDataKeys(EDKS)
      .encryptionContext(EncryptionContext.of("stored", "1"))
      .reproducedEncryptionContext(EncryptionContext.of("reproduced", "2"))
      .build();
    DecryptMaterialsRequest copy = request.toBuilder().build();
    assertSame(SUITE, copy.algorithmSuite());
    assertSame(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT, copy.commitmentPolicy());
    assertEquals(EDKS, copy.encryptedDataKeys());
    assertEquals(EncryptionContext.of("stored", "1"), copy.encryptionContext());
    assertEquals(EncryptionContext.of("reproduced", "2"), copy.reproducedEncryptionContext().get());

    DecryptMaterialsRequest changed = request.toBuilder().reproducedEncryptionContext(EncryptionContext.of("other", "3")).build();
    assertEquals(EncryptionContext.of("other", "3"), changed.reproducedEncryptionContext().get());
    assertEquals(EncryptionContext.of("reproduced", "2"), request.reproducedEncryptionContext().get());
    assertEquals(request.encryptionContext(), changed.encryptionContext());

    DecryptMaterialsRequest withoutReproduced = request.toBuilder().reproducedEncryptionContext(null).build();
    assertFalse(withoutReproduced.reproducedEncryptionContext().isPresent());
    assertFalse(withoutReproduced.toBuilder().build().reproducedEncryptionContext().isPresent());
  }

  @Test
  void buildersCopyAPlainMapIntoAnEncryptionContext() {
    Map<String, String> plain = new HashMap<>();
    plain.put("b", "2");
    plain.put("a", "1");
    GetEncryptionMaterialsRequest encrypt = GetEncryptionMaterialsRequest
      .builder()
      .encryptionContext(plain)
      .commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
      .build();
    DecryptMaterialsRequest decrypt = DecryptMaterialsRequest
      .builder()
      .algorithmSuite(SUITE)
      .commitmentPolicy(EsdkCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT)
      .encryptedDataKeys(EDKS)
      .encryptionContext(plain)
      .reproducedEncryptionContext(plain)
      .build();
    EncryptionMaterials encryptionMaterials = EncryptionMaterials.builder(SUITE).encryptionContext(plain).build();
    DecryptionMaterials decryptionMaterials = DecryptionMaterials.builder(SUITE).encryptionContext(plain).build();
    plain.put("c", "3");

    EncryptionContext expected = EncryptionContext.of("a", "1", "b", "2");
    for (Map<String, String> context : Arrays.<Map<String, String>>asList(
      encrypt.encryptionContext(),
      decrypt.encryptionContext(),
      decrypt.reproducedEncryptionContext().get(),
      encryptionMaterials.encryptionContext(),
      decryptionMaterials.encryptionContext()
    )) {
      assertInstanceOf(EncryptionContext.class, context);
      assertEquals(expected, context);
      assertEquals(Arrays.asList("a", "b"), Arrays.asList(context.keySet().toArray()));
    }
  }

  @Test
  void anEncryptionContextIsTakenAsIs() {
    EncryptionContext context = EncryptionContext.of("a", "1");
    assertSame(
      context,
      GetEncryptionMaterialsRequest.builder().encryptionContext(context).commitmentPolicy(DbeCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build().encryptionContext()
    );
  }

  @Test
  void anInvalidMapFailsInTheBuilder() {
    Map<String, String> lone = Collections.singletonMap("k", "\ud800");
    assertThrows(ValidationException.class, () -> GetEncryptionMaterialsRequest.builder().encryptionContext(lone));
    assertThrows(ValidationException.class, () -> DecryptMaterialsRequest.builder().encryptionContext(lone));
    assertThrows(ValidationException.class, () -> DecryptMaterialsRequest.builder().reproducedEncryptionContext(lone));
    assertThrows(ValidationException.class, () -> EncryptionMaterials.builder(SUITE).encryptionContext(lone));
    assertThrows(ValidationException.class, () -> DecryptionMaterials.builder(SUITE).encryptionContext(lone));
    // Null still means "not set" for the requests, whose build() reports the missing field.
    assertEquals(
      "Missing value for required field `encryptionContext`",
      assertThrows(ValidationException.class, () -> GetEncryptionMaterialsRequest.builder().encryptionContext(null).commitmentPolicy(DbeCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build()).getMessage()
    );
    assertThrows(NullPointerException.class, () -> EncryptionMaterials.builder(SUITE).encryptionContext(null));
  }
}
