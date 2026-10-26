// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.oldapi.materialproviders.model.AlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.CommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKAlgorithmSuiteId;
import software.amazon.cryptography.oldapi.materialproviders.model.ESDKCommitmentPolicy;
import software.amazon.cryptography.oldapi.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.oldapi.materialproviders.model.GetEncryptionMaterialsInput;

class ReferenceMplTest {

  @Test
  void everyClassOfTheReferenceJarComesFromTheIsolatedLoader() throws IOException, ClassNotFoundException {
    ClassLoader loader = ReferenceMpl.loader();
    int classes = 0;
    try (JarFile jar = new JarFile(ReferenceMpl.jar())) {
      for (Enumeration<JarEntry> entries = jar.entries(); entries.hasMoreElements();) {
        String entry = entries.nextElement().getName();
        if (!entry.endsWith(".class") || entry.endsWith("module-info.class")) {
          continue;
        }
        String name = entry.substring(0, entry.length() - ".class".length()).replace('/', '.');
        assertSame(loader, Class.forName(name, false, loader).getClassLoader(), name);
        classes++;
      }
    }
    assertTrue(classes > 0, "no classes in " + ReferenceMpl.jar());
  }

  @Test
  void onlyBootstrapTypesAreSharedWithThisModule() throws ClassNotFoundException {
    ClassLoader loader = ReferenceMpl.loader();
    for (Class<?> type : Arrays.asList(String.class, ByteBuffer.class, Long.class)) {
      assertSame(type, Class.forName(type.getName(), false, loader));
    }
    // The reference's counterpart of an old-API model class, and the AWS SDK, which each side has its own copy of.
    for (Class<?> type : Arrays.asList(EncryptedDataKey.class, KmsClient.class)) {
      assertNotSame(type, Class.forName(ReferenceMpl.apiName(type), false, loader));
    }
    // Main classes the reference also declares, by the same name.
    for (Class<?> type : Arrays.asList(
      software.amazon.cryptography.materialproviders.Keyring.class,
      software.amazon.cryptography.materialproviders.CryptographicMaterialsManager.class
    )) {
      assertNotSame(type, Class.forName(type.getName(), false, loader));
    }
  }

  @Test
  void aModelValueRoundTripsThroughTheReferenceLoader() {
    GetEncryptionMaterialsInput value = GetEncryptionMaterialsInput
      .builder()
      .encryptionContext(Collections.singletonMap("purpose", "test"))
      .commitmentPolicy(CommitmentPolicy.builder().ESDK(ESDKCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT).build())
      .algorithmSuiteId(AlgorithmSuiteId.builder().ESDK(ESDKAlgorithmSuiteId.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY).build())
      .maxPlaintextLength(1024L)
      .requiredEncryptionContextKeys(Collections.singletonList("purpose"))
      .build();

    Object reference = ReferenceMpl.toReference(value);
    Object back = ReferenceMpl.fromReference(reference);

    assertSame(ReferenceMpl.loader(), reference.getClass().getClassLoader());
    assertEquals(GetEncryptionMaterialsInput.class, back.getClass());
    assertEquals(ReferenceMpl.describe(value), ReferenceMpl.describe(reference));
    assertEquals(ReferenceMpl.describe(value), ReferenceMpl.describe(back));
    assertNotEquals("GetEncryptionMaterialsInput{}", ReferenceMpl.describe(value));
  }
}
