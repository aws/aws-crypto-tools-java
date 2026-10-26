// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.function.Function;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;

/**
 * Builds and reads public materials from raw fields, without the public types' validation,
 * for library code that must handle any state (keyrings checking their input, the test adapter).
 * The public classes register these functions when they load.
 */
public final class MaterialsAccess {

  static volatile Function<MaterialsRules.Encryption, EncryptionMaterials> encryption;
  static volatile Function<EncryptionMaterials, MaterialsRules.Encryption> encryptionFields;
  static volatile Function<MaterialsRules.Decryption, DecryptionMaterials> decryption;
  static volatile Function<DecryptionMaterials, MaterialsRules.Decryption> decryptionFields;

  private MaterialsAccess() {}

  public static void registerEncryption(
    Function<MaterialsRules.Encryption, EncryptionMaterials> create,
    Function<EncryptionMaterials, MaterialsRules.Encryption> fields
  ) {
    encryption = create;
    encryptionFields = fields;
  }

  public static void registerDecryption(
    Function<MaterialsRules.Decryption, DecryptionMaterials> create,
    Function<DecryptionMaterials, MaterialsRules.Decryption> fields
  ) {
    decryption = create;
    decryptionFields = fields;
  }

  /** Materials holding exactly {@code fields}, valid or not. The materials take ownership of the secrets. */
  public static EncryptionMaterials encryption(MaterialsRules.Encryption fields) {
    load(EncryptionMaterials.class);
    return encryption.apply(fields);
  }

  public static MaterialsRules.Encryption fields(EncryptionMaterials materials) {
    return encryptionFields.apply(materials);
  }

  public static DecryptionMaterials decryption(MaterialsRules.Decryption fields) {
    load(DecryptionMaterials.class);
    return decryption.apply(fields);
  }

  public static MaterialsRules.Decryption fields(DecryptionMaterials materials) {
    return decryptionFields.apply(materials);
  }

  private static void load(Class<?> type) {
    try {
      Class.forName(type.getName(), true, type.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }
}
