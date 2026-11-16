// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EsdkAlgorithmSuite;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;
import software.amazon.cryptography.materialproviders.internal.primitives.Bytes;

//= spec/framework/structures.md#overview
//= type=implication
//# These structures define a group of related fields that MUST hold certain properties.
//# Wherever these structures are referenced in this specification,
//# implementations MUST ensure that all properties of a structure's fields are upheld.
/**
 * Validity and transition rules for materials, per Materials.dfy.
 *
 * <p>In Dafny these held by proof for materials the library produced; here they are checks.
 * They work on the raw fields so the same rules serve the public materials types
 * and inputs that cannot be built as public materials (an invalid state supplied through a test adapter).
 * An absent list and an empty list mean the same thing, as at the Dafny-based MPL's Java boundary.
 */
public final class MaterialsRules {

  /** Reserved encryption context key holding the base64 signature verification key. */
  public static final String EC_PUBLIC_KEY_FIELD = "aws-crypto-public-key";

  private MaterialsRules() {}

  /** Rejects an algorithm suite that is not one of the library's enums, whose rules the checks depend on. */
  public static <S extends AlgorithmSuite> S requireBuiltInSuite(S suite) {
    if (!(suite instanceof EsdkAlgorithmSuite) && !(suite instanceof DbeAlgorithmSuite)) {
      throw new ValidationException("Algorithm suite must be an EsdkAlgorithmSuite or a DbeAlgorithmSuite");
    }
    return suite;
  }

  /** The fields of encryption materials. Lists are never null; absent secrets are null. */
  public static final class Encryption {

    public final AlgorithmSuite suite;
    public final Map<String, String> encryptionContext;
    public final List<EncryptedDataKey> encryptedDataKeys;
    public final List<String> requiredEncryptionContextKeys;
    public final SecretBytes plaintextDataKey;
    public final SecretBytes signingKey;
    public final List<SecretBytes> symmetricSigningKeys;

    public Encryption(
      AlgorithmSuite suite,
      Map<String, String> encryptionContext,
      List<EncryptedDataKey> encryptedDataKeys,
      List<String> requiredEncryptionContextKeys,
      SecretBytes plaintextDataKey,
      SecretBytes signingKey,
      List<SecretBytes> symmetricSigningKeys
    ) {
      this.suite = suite;
      this.encryptionContext = encryptionContext;
      this.encryptedDataKeys = encryptedDataKeys;
      this.requiredEncryptionContextKeys = requiredEncryptionContextKeys;
      this.plaintextDataKey = plaintextDataKey;
      this.signingKey = signingKey;
      this.symmetricSigningKeys = symmetricSigningKeys;
    }
  }

  /** The fields of decryption materials. Lists are never null; absent values are null. */
  public static final class Decryption {

    public final AlgorithmSuite suite;
    public final Map<String, String> encryptionContext;
    public final List<String> requiredEncryptionContextKeys;
    public final SecretBytes plaintextDataKey;
    public final byte[] verificationKey;
    public final SecretBytes symmetricSigningKey;

    public Decryption(
      AlgorithmSuite suite,
      Map<String, String> encryptionContext,
      List<String> requiredEncryptionContextKeys,
      SecretBytes plaintextDataKey,
      byte[] verificationKey,
      SecretBytes symmetricSigningKey
    ) {
      this.suite = suite;
      this.encryptionContext = encryptionContext;
      this.requiredEncryptionContextKeys = requiredEncryptionContextKeys;
      this.plaintextDataKey = plaintextDataKey;
      this.verificationKey = verificationKey;
      this.symmetricSigningKey = symmetricSigningKey;
    }
  }

  /** InitializeEncryptionMaterials: checks in Dafny's order, then adds the base64 verification key for signing suites. */
  public static Map<String, String> initialEncryptionContext(
    AlgorithmSuite suite,
    Map<String, String> encryptionContext,
    List<String> requiredEncryptionContextKeys,
    SecretBytes signingKey,
    byte[] verificationKey
  ) {
    if (encryptionContext.containsKey(EC_PUBLIC_KEY_FIELD)) {
      throw new ValidationException("Encryption Context ");
    }
    if (!encryptionContext.keySet().containsAll(requiredEncryptionContextKeys)) {
      throw new ValidationException("Required encryption context keys do not exist in provided encryption context.");
    }
    // Two iffs, checked in Dafny's order: signing <=> both keys, then non-signing <=> neither key.
    boolean bothKeys = signingKey != null && verificationKey != null;
    boolean neitherKey = signingKey == null && verificationKey == null;
    if (suite.isSigning() != bothKeys) {
      throw new ValidationException("Missing signature key for signed suite.");
    }
    if (suite.isSigning() == neitherKey) {
      throw new ValidationException("Signature key not allowed for non-signed suites.");
    }
    if (!suite.isSigning()) {
      return encryptionContext;
    }
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# Adding the key `aws-crypto-public-key` SHOULD be done to a copy of the encryption context
    //# so that the caller's encryption context is not mutated.
    java.util.HashMap<String, String> withKey = new java.util.HashMap<>(encryptionContext);
    //= spec/framework/default-cmm.md#get-encryption-materials
    //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
    //# the default CMM MUST Add the key-value pair of
    //# key `aws-crypto-public-key`,
    //# value `base64-encoded public verification key`
    //# to the [encryption context](structures.md#encryption-context).
    //= spec/framework/structures.md#encryption-context-1
    //= type=implication
    //# The mapped value
    //# from the reserved key `aws-crypto-public-key` SHOULD be the signature
    //# verification key corresponding to the [signing key](#signing-key)
    //# stored on the [encryption material](#encryption-materials).
    withKey.put(EC_PUBLIC_KEY_FIELD, Base64.getEncoder().encodeToString(verificationKey));
    return withKey;
  }

  /** InitializeDecryptionMaterials: returns the decoded verification key, or null for a non-signing suite. */
  public static byte[] initialVerificationKey(
    AlgorithmSuite suite,
    Map<String, String> encryptionContext,
    List<String> requiredEncryptionContextKeys
  ) {
    if (!encryptionContext.keySet().containsAll(requiredEncryptionContextKeys)) {
      throw new ValidationException("Reproduced encryption context key did not exist in provided encryption context.");
    }
    // Dafny follows this with the converse check, "Verification key can not exist in non-signed
    // Algorithm Suites."; this iff already covers it, so that message is unreachable.
    //= spec/framework/default-cmm.md#decrypt-materials
    //# If this key is not present in the encryption context, the operation MUST fail
    //# without returning any decryption materials.
    //
    //= spec/framework/default-cmm.md#decrypt-materials
    //# If the algorithm suite does not contain a [signing algorithm](algorithm-suites.md#signature-algorithm),
    //# but the encryption context includes the reserved `aws-crypto-public-key` key,
    //# the operation MUST fail without returning any decryption materials.
    //= spec/framework/cmm-interface.md#decrypt-materials
    //# If the requested algorithm suite does not include a signing algorithm
    //# but the encryption context includes the reserved `aws-crypto-public-key` key, the operation SHOULD fail.
    //# Likewise, if the requested algorithm suite includes a signing algorithm
    //# but the encryption context does not include the reserved `aws-crypto-public-key` key, the operation SHOULD fail.
    if (suite.isSigning() != encryptionContext.containsKey(EC_PUBLIC_KEY_FIELD)) {
      throw new ValidationException("Encryption Context missing verification key.");
    }
    //= spec/framework/default-cmm.md#decrypt-materials
    //# If the algorithm suite contains a [signing algorithm](algorithm-suites.md#signature-algorithm),
    //# the default CMM MUST extract the verification key
    //# from the encryption context under the reserved `aws-crypto-public-key` key.
    String encoded = encryptionContext.get(EC_PUBLIC_KEY_FIELD);
    //= spec/framework/structures.md#encryption-context-2
    //= type=implication
    //# The mapped value
    //# from the reserved key `aws-crypto-public-key` SHOULD be the signature
    //# verification key stored on the [decryption materials](#decryption-materials).
    return encoded == null ? null : decodeBase64(encoded);
  }

  public static boolean isValid(Encryption m) {
    int encryptedDataKeyCount = m.encryptedDataKeys.size();
    return (
      //= spec/framework/structures.md#signing-key
      //# If the
      //# algorithm suite does not contain an asymmetric signing algorithm, the signing key
      //# MUST NOT be present.
      //
      //= spec/framework/structures.md#signing-key
      //= type=exception
      //= reason=Only the presence of the signing key is checked; its bytes are not checked against the suite's curve.
      //# The signing key MUST fit the specification described by the [asymmetric signature algorithm](algorithm-suites.md#asymmetric-signature-algorithm)
      //# included in this encryption material's [algorithm suite](#algorithm-suite).
      m.suite.isSigning() == (m.signingKey != null) &&
      //= spec/framework/structures.md#plaintext-data-key
      //# The plaintext data key MUST:
      //# - Fit the specification for the [key derivation algorithm](algorithm-
      //#   suites.md#key-derivation-algorithm) included in this decryption
      //#   material's [algorithm suite](#algorithm-suite).
      (m.plaintextDataKey == null || m.plaintextDataKey.length() == m.suite.dataKeyLength()) &&
      //= spec/framework/structures.md#encrypted-data-keys
      //# If the plaintext data key is not included in this set of encryption
      //# materials, this list MUST be empty.
      (m.plaintextDataKey != null || encryptedDataKeyCount == 0) &&
      //= spec/framework/structures.md#encryption-context-1
      //# If an [encryption material](#encryption-materials) contains a [signing key]
      //# (#signing-key), the [encryption context](#encryption-context) SHOULD
      //# include the reserved key `aws-crypto-public-key`.
      //
      //= spec/framework/structures.md#encryption-context-1
      //# If an [encryption
      //# material](#encryption-materials) does not contains a [signing key]
      //# (#signing-key), the [encryption context](#encryption-context) SHOULD
      //# NOT include the reserved key `aws-crypto-public-key`.
      m.suite.isSigning() == m.encryptionContext.containsKey(EC_PUBLIC_KEY_FIELD) &&
      //= spec/framework/structures.md#symmetric-signing-keys
      //# If the algorithm suite does contain a symmetric signing algorithm, this list MUST have length equal to the [encrypted data key list](#encrypted-data-keys).
      //
      //= spec/framework/structures.md#symmetric-signing-keys
      //# If the algorithm suite does not contain a symmetric signing algorithm, this list MUST NOT be included in the materials.
      (m.suite.isSymmetricSigning()
          // One symmetric signing key per encrypted data key; the list may be empty only before any are added.
          ? (m.symmetricSigningKeys.isEmpty()
              ? encryptedDataKeyCount == 0
              : m.symmetricSigningKeys.size() == encryptedDataKeyCount)
          : m.symmetricSigningKeys.isEmpty()) &&
      //= spec/framework/structures.md#required-encryption-context-keys
      //# Every key in Required Encryption Context Keys
      //# MUST be a key in the [encryption context](#encryption-context-1).
      m.encryptionContext.keySet().containsAll(m.requiredEncryptionContextKeys)
    );
  }

  /**
   * ValidEncryptionMaterialsTransition: both valid; nothing removed or changed;
   * the plaintext data key added or kept; encrypted data keys and symmetric signing keys only added.
   */
  public static boolean isValidTransition(Encryption previous, Encryption next) {
    if (!isValid(previous) || !isValid(next) || next.plaintextDataKey == null) {
      return false;
    }
    // Dafny also requires previous symmetric signing keys present unless there are no encrypted data keys;
    // isValid(previous) already guarantees that.
    boolean symmetricSigningKeysGrow =
      !previous.suite.isSymmetricSigning() ||
      (!next.symmetricSigningKeys.isEmpty() && isSubMultiset(secrets(previous.symmetricSigningKeys), secrets(next.symmetricSigningKeys)));
    return (
      previous.suite == next.suite &&
      previous.encryptionContext.equals(next.encryptionContext) &&
      previous.requiredEncryptionContextKeys.equals(next.requiredEncryptionContextKeys) &&
      sameSecret(previous.signingKey, next.signingKey) &&
      (previous.plaintextDataKey == null || sameSecret(previous.plaintextDataKey, next.plaintextDataKey)) &&
      isSubMultiset(edkBytes(previous.encryptedDataKeys), edkBytes(next.encryptedDataKeys)) &&
      symmetricSigningKeysGrow
    );
  }

  //= spec/framework/cmm-interface.md#get-encryption-materials
  //# The encryption materials returned MUST include the following:
  //
  //= spec/framework/cmm-interface.md#get-encryption-materials
  //# The CMM MUST ensure that the encryption materials returned are valid.
  //# - The encryption materials returned MUST follow the specification for [encryption-materials](structures.md#encryption-materials).
  //# - The value of the plaintext data key MUST be non-NULL.
  //# - The plaintext data key length MUST be equal to the [key derivation input length](algorithm-suites.md#key-derivation-input-length).
  //# - The encrypted data keys list MUST contain at least one encrypted data key.
  //# - If the algorithm suite contains a signing algorithm, the encryption materials returned MUST include the generated signing key.
  //# - For every key in [Required Encryption Context Keys](structures.md#required-encryption-context-keys)
  //#   there MUST be a matching key in the [Encryption Context](structures.md#encryption-context-1).
  /** EncryptionMaterialsHasPlaintextDataKey. */
  public static boolean isReadyForEncrypt(Encryption m) {
    return m.plaintextDataKey != null && !m.encryptedDataKeys.isEmpty() && isValid(m);
  }

  public static boolean isValid(Decryption m) {
    return (
      //= spec/framework/structures.md#plaintext-data-key-1
      //# The plaintext data key MUST:
      //# - Fit the specification for the [encryption algorithm](algorithm-
      //# suites.md#encryption-algorithm)  included in this decryption
      //# material's [algorithm suite](#algorithm-suite-1).
      (m.plaintextDataKey == null || m.plaintextDataKey.length() == m.suite.dataKeyLength()) &&
      //= spec/framework/structures.md#encryption-context-2
      //# If a [decryption materials](#decryption-materials) contains a [verification key]
      //# (#verification-key), the [encryption context](#encryption-context) SHOULD
      //# include the reserved key `aws-crypto-public-key`.
      //
      //= spec/framework/structures.md#encryption-context-2
      //# If a [decryption materials](#decryption-materials) does not contain a
      //# [verification key](#verification-key), the [encryption context]
      //# (#encryption-context) SHOULD NOT include the reserved key `aws-crypto-
      //# public-key`.
      m.suite.isSigning() == m.encryptionContext.containsKey(EC_PUBLIC_KEY_FIELD) &&
      //= spec/framework/structures.md#verification-key
      //= type=exception
      //= reason=Only the presence of the verification key is checked; its bytes are not checked against the suite's curve.
      //# The verification key MUST fit the specification for the [asymmetric signature algorithm](algorithm-suites.md#asymmetric-signature-algorithm)
      //# included in this decryption material's [algorithm suite](#algorithm-suite-1).
      m.suite.isSigning() == (m.verificationKey != null) &&
      //= spec/framework/structures.md#symmetric-signing-key
      //# If the algorithm suite does contain a symmetric signing algorithm,
      //# the symmetric signing key MUST also be included in the materials
      //# if and only if the materials also include a [plaintext data key](#plaintext-data-key-1).
      //
      //= spec/framework/structures.md#symmetric-signing-key
      //# If the algorithm suite does not contain a symmetric signing algorithm,
      //# the symmetric signing key MUST NOT be included in the materials.
      (m.suite.isSymmetricSigning()
          ? (m.plaintextDataKey != null) == (m.symmetricSigningKey != null)
          : m.symmetricSigningKey == null) &&
      //= spec/framework/structures.md#required-encryption-context-keys-1
      //# Every key in Required Encryption Context Keys
      //# MUST be a key in the [encryption context](#encryption-context-2).
      m.encryptionContext.keySet().containsAll(m.requiredEncryptionContextKeys)
    );
  }

  /** DecryptionMaterialsTransitionIsValid: {@code next} is {@code previous} with its plaintext data key added. */
  public static boolean isValidTransition(Decryption previous, Decryption next) {
    // Dafny also requires no symmetric signing key before; with no plaintext data key,
    // isValid(previous) already guarantees that.
    return (
      isValid(previous) &&
      isValid(next) &&
      previous.suite == next.suite &&
      previous.encryptionContext.equals(next.encryptionContext) &&
      previous.requiredEncryptionContextKeys.equals(next.requiredEncryptionContextKeys) &&
      Arrays.equals(previous.verificationKey, next.verificationKey) &&
      previous.plaintextDataKey == null &&
      next.plaintextDataKey != null
    );
  }

  //= spec/framework/cmm-interface.md#decrypt-materials
  //# The decryption materials returned MUST include the following:
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //# - All keys in this set MUST exist in the decryption materials encryption context.
  //
  //= spec/framework/cmm-interface.md#decrypt-materials
  //# The CMM MUST ensure that the decryption materials returned are valid.
  //# - The decryption materials returned MUST follow the specification for [decryption-materials](structures.md#decryption-materials).
  //# - The value of the plaintext data key MUST be non-NULL.
  /** DecryptionMaterialsWithPlaintextDataKey. */
  public static boolean isReadyForDecrypt(Decryption m) {
    return m.plaintextDataKey != null && isValid(m);
  }

  private static boolean sameSecret(SecretBytes a, SecretBytes b) {
    if (a == null || b == null) {
      return a == b;
    }
    return a.length() == b.length() && a.contentEquals(b);
  }

  private static List<byte[]> secrets(List<SecretBytes> values) {
    List<byte[]> copies = new ArrayList<>(values.size());
    for (SecretBytes value : values) {
      copies.add(value.toByteArray());
    }
    return copies;
  }

  // An encrypted data key as one byte string: each field length-prefixed, so distinct keys never collide.
  private static List<byte[]> edkBytes(List<EncryptedDataKey> values) {
    List<byte[]> keys = new ArrayList<>(values.size());
    for (EncryptedDataKey edk : values) {
      byte[] id = Utf8.encode(edk.keyProviderId());
      byte[] info = edk.keyProviderInfo();
      byte[] ciphertext = edk.ciphertext();
      keys.add(
        java.nio.ByteBuffer
          .allocate(12 + id.length + info.length + ciphertext.length)
          .putInt(id.length)
          .put(id)
          .putInt(info.length)
          .put(info)
          .putInt(ciphertext.length)
          .put(ciphertext)
          .array()
      );
    }
    return keys;
  }

  // Multiset inclusion; the arrays may hold secrets, so all of them are zeroed afterwards.
  private static boolean isSubMultiset(List<byte[]> smaller, List<byte[]> larger) {
    List<byte[]> remaining = new ArrayList<>(larger);
    try {
      for (byte[] element : smaller) {
        boolean found = false;
        for (int i = 0; i < remaining.size() && !found; i++) {
          if (Arrays.equals(element, remaining.get(i))) {
            remaining.remove(i);
            found = true;
          }
        }
        if (!found) {
          return false;
        }
      }
      return true;
    } finally {
      smaller.forEach(Bytes::zero);
      larger.forEach(Bytes::zero);
    }
  }

  /**
   * Decodes standard base64 as strictly as Dafny's Base64.Decode: padded to a multiple of 4,
   * padding only in the last block, and zero bits after the last encoded byte.
   * java.util.Base64 alone accepts missing padding and non-zero trailing bits.
   */
  static byte[] decodeBase64(String encoded) {
    if (!isCanonicalBase64(encoded)) {
      throw new ValidationException("The encoding is malformed");
    }
    return Base64.getDecoder().decode(encoded);
  }

  private static boolean isCanonicalBase64(String s) {
    int length = s.length();
    if (length % 4 != 0) {
      return false;
    }
    int padding = length == 0 ? 0 : s.endsWith("==") ? 2 : s.endsWith("=") ? 1 : 0;
    for (int i = 0; i < length - padding; i++) {
      if (sextet(s.charAt(i)) < 0) {
        return false;
      }
    }
    if (padding == 1) {
      return sextet(s.charAt(length - 2)) % 4 == 0;
    }
    if (padding == 2) {
      return sextet(s.charAt(length - 3)) % 16 == 0;
    }
    return true;
  }

  private static int sextet(char c) {
    if (c >= 'A' && c <= 'Z') {
      return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
      return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
      return c - '0' + 52;
    }
    return c == '+' ? 62 : c == '/' ? 63 : -1;
  }
}
