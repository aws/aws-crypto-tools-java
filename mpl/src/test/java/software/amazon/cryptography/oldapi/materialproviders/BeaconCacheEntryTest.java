// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.WEST;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.get;
import static software.amazon.cryptography.oldapi.materialproviders.KeyStoreHarness.with;

import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.oldapi.keystore.model.CreateKeyInput;
import software.amazon.cryptography.oldapi.keystore.model.GetBeaconKeyInput;
import software.amazon.cryptography.oldapi.materialproviders.internal.CacheAdapter;
import software.amazon.cryptography.mpl.SecretBytes;
import software.amazon.cryptography.mpl.keystore.BeaconKeyMaterials;

// The beacon key cache entry a DB-ESDK builds with BeaconKeyMaterials.toHmacKeysOnly, against the one the Dafny DB-ESDK builds
// (SearchInfo.dfy getKeysCache): GetBeaconKey's materials with beaconKey := None and hmacKeys := Some(keyMap).
class BeaconCacheEntryTest {

  private final KeyStoreHarness harness = KeyStoreHarness.shared();

  BeaconCacheEntryTest() {
    harness.createTable(WEST);
  }

  @AfterEach
  void close() {
    harness.close();
  }

  @Test
  void theEntryMatchesTheDafnyDbEsdks() {
    KeyStoreHarness.Stores stores = KeyStoreHarness.stores(
      KeyStoreHarness.config(KeyStoreHarness.keyArn(harness.symmetricKey(WEST)), harness.kms(WEST), harness.ddb(WEST)).build()
    );
    String id = stores.nativeStore.CreateKey(CreateKeyInput.builder().build()).branchKeyIdentifier();
    Map<String, SecretBytes> derived = new LinkedHashMap<>();
    Map<String, ByteBuffer> derivedBuffers = new LinkedHashMap<>();
    for (int i = 0; i < 3; i++) {
      byte[] key = new byte[64];
      java.util.Arrays.fill(key, (byte) i);
      derived.put("beacon" + i, SecretBytes.copyOf(key));
      derivedBuffers.put("beacon" + i, ByteBuffer.wrap(key));
    }

    BeaconKeyMaterials nativeEntry = stores.nativeStore.impl().getBeaconKey(b -> b.branchKeyIdentifier(id)).beaconKeyMaterials().toHmacKeysOnly(derived);
    Object referenceOutput = ReferenceMpl.call(stores.referenceStore, "GetBeaconKey", GetBeaconKeyInput.builder().branchKeyIdentifier(id).build());
    Object referenceEntry = with(with(get(referenceOutput, "beaconKeyMaterials"), "beaconKey", null), "hmacKeys", derivedBuffers);
    assertEquals(ReferenceMpl.describe(referenceEntry), ReferenceMpl.describe(CacheAdapter.toOld(nativeEntry)));
  }
}
