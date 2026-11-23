// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.keystore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.KeyMaterialsAccess;

// BranchKeyMaterials and BeaconKeyMaterials built through the internal factories and the public builders.
class KeyMaterialsTest {

  private static final EncryptionContext CONTEXT = EncryptionContext.of("tenant", "a");

  @Test
  void branchKeyMaterials() {
    SecretBytes key = secret(1);
    BranchKeyMaterials materials = KeyMaterialsAccess.branchKey("id", "version", CONTEXT, key);
    assertEquals("id", materials.branchKeyId());
    assertEquals("version", materials.branchKeyVersion());
    assertSame(CONTEXT, materials.encryptionContext());
    assertSame(key, materials.branchKey());
    assertEquals("BranchKeyMaterials[id, version version, context keys [tenant]]", materials.toString());

    BranchKeyMaterials same = KeyMaterialsAccess.branchKey("id", "version", EncryptionContext.of("tenant", "a"), secret(1));
    assertEquals(materials, same);
    assertEquals(materials.hashCode(), same.hashCode());
    assertNotEquals(materials, KeyMaterialsAccess.branchKey("id2", "version", CONTEXT, secret(1)));
    assertNotEquals(materials, KeyMaterialsAccess.branchKey("id", "version2", CONTEXT, secret(1)));
    assertNotEquals(materials, KeyMaterialsAccess.branchKey("id", "version", EncryptionContext.empty(), secret(1)));
    assertNotEquals(materials, KeyMaterialsAccess.branchKey("id", "version", CONTEXT, secret(2)));
    assertNotEquals(materials, "id");

    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.branchKey(null, "v", CONTEXT, secret(1)));
    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.branchKey("id", null, CONTEXT, secret(1)));
    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.branchKey("id", "v", null, secret(1)));
    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.branchKey("id", "v", CONTEXT, null));
  }

  @Test
  void beaconKeyMaterials() {
    SecretBytes key = secret(1);
    Map<String, SecretBytes> hmacKeys = new HashMap<>();
    hmacKeys.put("beacon", secret(3));
    BeaconKeyMaterials materials = KeyMaterialsAccess.beaconKey("id", CONTEXT, key, hmacKeys);
    hmacKeys.clear();
    assertEquals("id", materials.beaconKeyIdentifier());
    assertSame(CONTEXT, materials.encryptionContext());
    assertSame(key, materials.beaconKey().get());
    assertEquals(Collections.singleton("beacon"), materials.hmacKeys().keySet());
    assertArrayEquals(new byte[] { 3, 3 }, materials.hmacKeys().get("beacon").toByteArray());
    assertThrows(UnsupportedOperationException.class, () -> materials.hmacKeys().clear());
    assertEquals("BeaconKeyMaterials[id, context keys [tenant]]", materials.toString());

    BeaconKeyMaterials same = KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.singletonMap("beacon", secret(3)));
    assertEquals(materials, same);
    assertEquals(materials.hashCode(), same.hashCode());
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id2", CONTEXT, secret(1), Collections.singletonMap("beacon", secret(3))));
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id", EncryptionContext.empty(), secret(1), Collections.singletonMap("beacon", secret(3))));
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(2), Collections.singletonMap("beacon", secret(3))));
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id", CONTEXT, null, Collections.singletonMap("beacon", secret(3))));
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.singletonMap("beacon", secret(4))));
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.singletonMap("other", secret(3))));
    assertNotEquals(materials, KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.emptyMap()));
    assertNotEquals(materials, "id");

    BeaconKeyMaterials keyless = KeyMaterialsAccess.beaconKey("id", CONTEXT, null, Collections.emptyMap());
    assertFalse(keyless.beaconKey().isPresent());
    assertEquals(keyless, KeyMaterialsAccess.beaconKey("id", CONTEXT, null, Collections.emptyMap()));
    assertNotEquals(keyless, KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.emptyMap()));

    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.beaconKey(null, CONTEXT, null, Collections.emptyMap()));
    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.beaconKey("id", null, null, Collections.emptyMap()));
    assertThrows(NullPointerException.class, () -> KeyMaterialsAccess.beaconKey("id", CONTEXT, null, null));
    assertThrows(
      NullPointerException.class,
      () -> KeyMaterialsAccess.beaconKey("id", CONTEXT, null, Collections.singletonMap("beacon", null))
    );
  }

  // The entry a beacon key cache holds: the derived keys, copied, and no beacon key.
  @Test
  void beaconKeyMaterialsWithHmacKeys() {
    BeaconKeyMaterials fetched = KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.<String, SecretBytes>emptyMap());
    Map<String, SecretBytes> derived = new LinkedHashMap<>();
    derived.put("b2", secret(3));
    derived.put("b1", secret(2));
    BeaconKeyMaterials cached = fetched.toHmacKeysOnly(derived);

    assertEquals(KeyMaterialsAccess.beaconKey("id", CONTEXT, null, derived), cached);
    assertFalse(cached.beaconKey().isPresent());
    assertEquals(Arrays.asList("b2", "b1"), Arrays.asList(cached.hmacKeys().keySet().toArray()));
    assertTrue(fetched.beaconKey().isPresent());
    assertTrue(fetched.hmacKeys().isEmpty());

    derived.get("b2").destroy();
    derived.put("b3", secret(4));
    assertArrayEquals(new byte[] { 3, 3 }, cached.hmacKeys().get("b2").toByteArray());
    assertFalse(cached.hmacKeys().containsKey("b3"));
    assertThrows(UnsupportedOperationException.class, () -> cached.hmacKeys().clear());

    assertEquals(KeyMaterialsAccess.beaconKey("id", CONTEXT, null, Collections.<String, SecretBytes>emptyMap()), fetched.toHmacKeysOnly(Collections.<String, SecretBytes>emptyMap()));
    assertThrows(NullPointerException.class, () -> fetched.toHmacKeysOnly(Collections.<String, SecretBytes>singletonMap("b", null)));
    assertThrows(NullPointerException.class, () -> fetched.toHmacKeysOnly(Collections.singletonMap((String) null, secret(1))));
  }

  // The builders a custom KeyStore uses: required members, and copies of the keys.
  @Test
  void branchKeyMaterialsBuilder() {
    SecretBytes key = secret(1);
    BranchKeyMaterials built = BranchKeyMaterials.builder().branchKeyId("id").branchKeyVersion("version").encryptionContext(CONTEXT).branchKey(key).build();
    assertEquals(KeyMaterialsAccess.branchKey("id", "version", CONTEXT, secret(1)), built);
    key.destroy();
    assertArrayEquals(new byte[] { 1, 1 }, built.branchKey().toByteArray());
    byte[] array = { 2, 2 };
    BranchKeyMaterials fromArray = BranchKeyMaterials.builder().branchKeyId("id").branchKeyVersion("version").encryptionContext(CONTEXT).branchKey(array).build();
    array[0] = 0;
    assertArrayEquals(new byte[] { 2, 2 }, fromArray.branchKey().toByteArray());
    for (String member : Arrays.asList("branchKeyId", "branchKeyVersion", "encryptionContext", "branchKey")) {
      BranchKeyMaterials.Builder missing = BranchKeyMaterials.builder().branchKeyId("id").branchKeyVersion("version").encryptionContext(CONTEXT).branchKey(secret(1));
      if (member.equals("branchKeyId")) missing.branchKeyId(null);
      if (member.equals("branchKeyVersion")) missing.branchKeyVersion(null);
      if (member.equals("encryptionContext")) missing.encryptionContext(null);
      if (member.equals("branchKey")) missing.branchKey((SecretBytes) null);
      assertEquals("Missing value for required field `" + member + "`", assertThrows(ValidationException.class, missing::build).getMessage());
    }
  }

  @Test
  void beaconKeyMaterialsBuilder() {
    SecretBytes key = secret(1);
    BeaconKeyMaterials built = BeaconKeyMaterials.builder().beaconKeyIdentifier("id").encryptionContext(CONTEXT).beaconKey(key).build();
    assertEquals(KeyMaterialsAccess.beaconKey("id", CONTEXT, secret(1), Collections.<String, SecretBytes>emptyMap()), built);
    key.destroy();
    assertArrayEquals(new byte[] { 1, 1 }, built.beaconKey().get().toByteArray());
    byte[] array = { 2, 2 };
    BeaconKeyMaterials fromArray = BeaconKeyMaterials.builder().beaconKeyIdentifier("id").encryptionContext(CONTEXT).beaconKey(array).build();
    array[0] = 0;
    assertArrayEquals(new byte[] { 2, 2 }, fromArray.beaconKey().get().toByteArray());
    assertEquals(
      "Missing value for required field `beaconKeyIdentifier`",
      assertThrows(ValidationException.class, () -> BeaconKeyMaterials.builder().encryptionContext(CONTEXT).beaconKey(secret(1)).build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `encryptionContext`",
      assertThrows(ValidationException.class, () -> BeaconKeyMaterials.builder().beaconKeyIdentifier("id").beaconKey(secret(1)).build()).getMessage()
    );
    assertEquals(
      "Missing value for required field `beaconKey`",
      assertThrows(ValidationException.class, () -> BeaconKeyMaterials.builder().beaconKeyIdentifier("id").encryptionContext(CONTEXT).beaconKey((byte[]) null).build()).getMessage()
    );
  }

  private static SecretBytes secret(int fill) {
    return SecretBytes.copyOf(new byte[] { (byte) fill, (byte) fill });
  }
}
