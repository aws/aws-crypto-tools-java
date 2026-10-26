// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.Map;
import software.amazon.cryptography.keystore.BeaconKeyMaterials;
import software.amazon.cryptography.keystore.BranchKeyMaterials;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;

/**
 * Builds branch key and beacon key materials, which have no public constructors, for library code
 * (the key store, the test adapter). The public classes register their constructors when they load.
 * The materials take ownership of the secrets passed in.
 */
public final class KeyMaterialsAccess {

  /** Constructor of {@link BranchKeyMaterials}. */
  public interface BranchKeyFactory {
    BranchKeyMaterials create(String branchKeyIdentifier, String branchKeyVersion, EncryptionContext encryptionContext, SecretBytes branchKey);
  }

  /** Constructor of {@link BeaconKeyMaterials}; {@code beaconKey} may be null. */
  public interface BeaconKeyFactory {
    BeaconKeyMaterials create(
      String beaconKeyIdentifier,
      EncryptionContext encryptionContext,
      SecretBytes beaconKey,
      Map<String, SecretBytes> hmacKeys
    );
  }

  private static volatile BranchKeyFactory branchKey;
  private static volatile BeaconKeyFactory beaconKey;

  private KeyMaterialsAccess() {}

  public static void registerBranchKey(BranchKeyFactory factory) {
    branchKey = factory;
  }

  public static void registerBeaconKey(BeaconKeyFactory factory) {
    beaconKey = factory;
  }

  public static BranchKeyMaterials branchKey(
    String branchKeyIdentifier,
    String branchKeyVersion,
    EncryptionContext encryptionContext,
    SecretBytes key
  ) {
    load(BranchKeyMaterials.class);
    return branchKey.create(branchKeyIdentifier, branchKeyVersion, encryptionContext, key);
  }

  /** {@code key} may be null; an empty {@code hmacKeys} means none were derived. */
  public static BeaconKeyMaterials beaconKey(
    String beaconKeyIdentifier,
    EncryptionContext encryptionContext,
    SecretBytes key,
    Map<String, SecretBytes> hmacKeys
  ) {
    load(BeaconKeyMaterials.class);
    return beaconKey.create(beaconKeyIdentifier, encryptionContext, key, hmacKeys);
  }

  private static void load(Class<?> type) {
    try {
      Class.forName(type.getName(), true, type.getClassLoader());
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }
}
