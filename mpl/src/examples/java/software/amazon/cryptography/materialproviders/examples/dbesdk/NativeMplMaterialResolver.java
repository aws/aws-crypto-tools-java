// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DbeCommitmentPolicy;
import software.amazon.cryptography.materialproviders.DecryptMaterialsRequest;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.GetEncryptionMaterialsRequest;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.cmm.RequiredEncryptionContextCryptographicMaterialsManager;

/**
 * Integration example: how the native DB-ESDK gets materials from the native MPL.
 * Replaces the test server's {@code NativeMaterialResolver} and {@code MplEcKeyDecoder}.
 *
 * <p>It returns the MPL's own {@link EncryptionMaterials} and {@link DecryptionMaterials} rather than copying them into
 * DB-ESDK records: the MPL types already carry the plaintext data key, the symmetric signing keys,
 * and the ECDSA keys as JCA keys, so the decoder and the duplicate records are not needed.
 * The caller owns the returned materials and destroys them when the item is done.
 *
 * <p>The DB-ESDK keeps encryption context values as {@code byte[]} and EDK provider ids as {@code byte[]},
 * as they are on the wire; the MPL uses {@code String}.
 * {@link EncryptionContext#fromUtf8} and {@link EncryptedDataKey.Builder#keyProviderIdUtf8} decode strictly, so bytes that are not UTF-8 fail
 * instead of turning into U+FFFD and silently changing the context.
 *
 * <p>Per the Dafny DB-ESDK's item encryptor (EncryptItem, DecryptItem) and StructuredEncryption (EncryptStructure, DecryptStructure):
 * the DBE commitment policy on every call, a suite id on every call (the configured one or the policy default),
 * {@code maxPlaintextLength}, and two Required Encryption Context CMMs per call, each with its keys in UTF-8 byte order:
 * the item encryptor's over every base context key, and around it StructuredEncryption's over the version-2
 * (SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT) entries, if there are any.
 * Every base and version-2 entry is therefore required, and the header stores none of them.
 */
public final class NativeMplMaterialResolver {

  private static final DbeCommitmentPolicy POLICY = DbeCommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT;

  private final CryptographicMaterialsManager cmm;

  private NativeMplMaterialResolver(CryptographicMaterialsManager cmm) {
    this.cmm = cmm;
  }

  /** For a table configured with a keyring: the DB-ESDK wraps it in the default materials manager once. */
  public static NativeMplMaterialResolver forKeyring(Keyring keyring) {
    return new NativeMplMaterialResolver(DefaultCryptographicMaterialsManager.create(keyring));
  }

  /** For a table configured with a materials manager. */
  public static NativeMplMaterialResolver forCmm(CryptographicMaterialsManager cmm) {
    return new NativeMplMaterialResolver(cmm);
  }

  /**
   * @param baseContext the item encryptor's context (table and key names, and in version 1 the key values); required, so not stored
   * @param v2Context the SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT entries and the legend; required, so not stored
   * @param configuredSuite the table's suite, or null for the policy default
   * @param maxPlaintextLength {@code 2 * encryptedFieldCount + totalEncryptedValueBytes}
   */
  public EncryptionMaterials forEncrypt(
    Map<String, byte[]> baseContext,
    Map<String, byte[]> v2Context,
    AlgorithmSuite configuredSuite,
    long maxPlaintextLength
  ) {
    GetEncryptionMaterialsRequest request = GetEncryptionMaterialsRequest
      .builder()
      .encryptionContext(EncryptionContext.fromUtf8(union(baseContext, v2Context)))
      .commitmentPolicy(POLICY)
      .algorithmSuiteId(configuredSuite != null ? configuredSuite : POLICY.defaultSuite())
      .maxPlaintextLength(maxPlaintextLength)
      .build();
    return cmmRequiring(baseContext, v2Context).getEncryptionMaterials(request).encryptionMaterials();
  }

  /**
   * @param headerSuite the suite named by the header's flavor byte
   * @param storedContext the context stored in the header
   * @param baseContext the context the item encryptor rebuilds from the item
   * @param v2Context the version-2 entries rebuilt from the item's plaintext SIGN_AND_INCLUDE fields
   */
  public DecryptionMaterials forDecrypt(
    AlgorithmSuite headerSuite,
    List<EncryptedDataKey> encryptedDataKeys,
    Map<String, byte[]> storedContext,
    Map<String, byte[]> baseContext,
    Map<String, byte[]> v2Context
  ) {
    DecryptMaterialsRequest request = DecryptMaterialsRequest
      .builder()
      .algorithmSuiteId(headerSuite)
      .commitmentPolicy(POLICY)
      .encryptedDataKeys(encryptedDataKeys)
      .encryptionContext(EncryptionContext.fromUtf8(storedContext))
      .reproducedEncryptionContext(EncryptionContext.fromUtf8(union(baseContext, v2Context)))
      .build();
    return cmmRequiring(baseContext, v2Context).decryptMaterials(request).decryptionMaterials();
  }

  /** The MPL context as the DB-ESDK keeps it, in the UTF-8 byte order the header serializes in. */
  public static Map<String, byte[]> toByteContext(Map<String, String> context) {
    Map<String, byte[]> bytes = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : EncryptionContext.copyOf(context).entrySet()) {
      bytes.put(entry.getKey(), entry.getValue().getBytes(StandardCharsets.UTF_8));
    }
    return bytes;
  }

  // The item encryptor always requires its base context keys (DynamoDbItemEncryptor EncryptItem, DecryptItem).
  // StructuredEncryption wraps that manager only when there are version-2 entries (EncryptStructure, DecryptStructure).
  private CryptographicMaterialsManager cmmRequiring(Map<String, byte[]> baseContext, Map<String, byte[]> v2Context) {
    CryptographicMaterialsManager itemEncryptor = requiring(cmm, baseContext);
    return v2Context.isEmpty() ? itemEncryptor : requiring(itemEncryptor, v2Context);
  }

  private static CryptographicMaterialsManager requiring(CryptographicMaterialsManager underlying, Map<String, byte[]> context) {
    // EncryptionContext iterates in UTF-8 byte order, the order Dafny passes the required keys in.
    List<String> requiredKeys = new ArrayList<>(EncryptionContext.fromUtf8(context).keySet());
    return RequiredEncryptionContextCryptographicMaterialsManager
      .builder()
      .underlyingCmm(underlying)
      .requiredEncryptionContextKeys(requiredKeys)
      .build();
  }

  // The two never share a key: a version-2 base context has only the table and key names,
  // and a version-1 item has no version-2 context.
  private static Map<String, byte[]> union(Map<String, byte[]> baseContext, Map<String, byte[]> v2Context) {
    Map<String, byte[]> union = new LinkedHashMap<>(baseContext);
    for (Map.Entry<String, byte[]> entry : v2Context.entrySet()) {
      if (union.put(entry.getKey(), entry.getValue()) != null) {
        throw new IllegalArgumentException("Encryption context overlaps with item encryptor encryption context: " + entry.getKey());
      }
    }
    return union;
  }
}
