// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.vectors;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A material providers implementation the runner drives: the native one, or the published Dafny-based one.
 * Values cross as plain data, so one side can decrypt what the other encrypted.
 */
interface Side {
  String name();

  /**
   * CmmFromKeyDescription.ToCmm.
   *
   * @throws Skipped if the side cannot build the description faithfully
   */
  Cmm cmm(KeyDescription description);

  interface Cmm {
    /** GetEncryptionMaterials; any failure is thrown. */
    Encrypted getEncryptionMaterials(TestVectors.EncryptVector vector);

    /** DecryptMaterials; any failure is thrown. */
    Decrypted decryptMaterials(TestVectors.DecryptVector vector);
  }

  /** The encryption materials fields the runner reads. */
  final class Encrypted {

    final Map<String, String> encryptionContext;
    final List<TestVectors.Edk> encryptedDataKeys;
    /** Null when absent. */
    final byte[] plaintextDataKey;
    final List<byte[]> symmetricSigningKeys;

    Encrypted(
      Map<String, String> encryptionContext,
      List<TestVectors.Edk> encryptedDataKeys,
      byte[] plaintextDataKey,
      List<byte[]> symmetricSigningKeys
    ) {
      this.encryptionContext = Collections.unmodifiableMap(new LinkedHashMap<>(encryptionContext));
      this.encryptedDataKeys = Collections.unmodifiableList(new ArrayList<>(encryptedDataKeys));
      this.plaintextDataKey = plaintextDataKey;
      this.symmetricSigningKeys = Collections.unmodifiableList(new ArrayList<>(symmetricSigningKeys));
    }
  }

  /** The decryption materials fields TestDecryptMaterials compares. */
  final class Decrypted {

    /** Null when absent. */
    final byte[] plaintextDataKey;
    /** Null when absent. */
    final byte[] symmetricSigningKey;
    final List<String> requiredEncryptionContextKeys;

    Decrypted(byte[] plaintextDataKey, byte[] symmetricSigningKey, List<String> requiredEncryptionContextKeys) {
      this.plaintextDataKey = plaintextDataKey;
      this.symmetricSigningKey = symmetricSigningKey;
      this.requiredEncryptionContextKeys = Collections.unmodifiableList(new ArrayList<>(requiredEncryptionContextKeys));
    }
  }

  /** A description a side does not run, with the reason; counted as skipped. */
  final class Skipped extends RuntimeException {

    private static final long serialVersionUID = 1L;

    Skipped(String reason) {
      super(reason);
    }
  }
}
