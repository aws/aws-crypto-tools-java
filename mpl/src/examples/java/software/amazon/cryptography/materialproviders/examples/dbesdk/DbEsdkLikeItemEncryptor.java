// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.examples.dbesdk;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;
import software.amazon.cryptography.materialproviders.DbeAlgorithmSuite;
import software.amazon.cryptography.materialproviders.CryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.EncryptionContext;
import software.amazon.cryptography.materialproviders.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.Keyring;
import software.amazon.cryptography.materialproviders.SecretBytes;

/**
 * STAND-IN for the AWS Database Encryption SDK item encryptor, written only so the examples run end to end.
 * Its item format is not the DB-ESDK's, and it is not fit for real data:
 * it has no key commitment, treats every attribute as a string, and skips most validation.
 *
 * <p>What it does with the MPL follows the Dafny DB-ESDK, through {@link NativeMplMaterialResolver}:
 * <ul>
 *   <li>DBE suites and the DBE commitment policy;</li>
 *   <li>one recipient tag per encrypted data key, an HMAC under that key's symmetric signing key;</li>
 *   <li>for signing suites, an ECDSA footer signature with the materials' JCA keys;</li>
 *   <li>Required Encryption Context CMMs per call over the base context keys and the SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT entries:
 *       the header stores none of those entries, and decrypt rebuilds them from the item.</li>
 * </ul>
 *
 * <p>An encrypted item is the plaintext item with ENCRYPT_AND_SIGN values replaced by base64 ciphertext,
 * plus {@value #HEADER} and {@value #FOOTER}.
 * As in the DB-ESDK, a table with any SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT attribute is version 2:
 * its key attributes must be SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT too, and its base context holds only the table and key names.
 * A version-1 table's key attributes are SIGN_ONLY, and its base context also holds the key values.
 * The header's first byte is the version; decrypt follows it.
 */
public final class DbEsdkLikeItemEncryptor {

  /** What happens to an attribute; the DB-ESDK's names. */
  public enum CryptoAction {
    ENCRYPT_AND_SIGN,
    SIGN_ONLY,
    SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT,
    DO_NOTHING,
  }

  /** The item failed authentication: a recipient tag, the signature, or a field's AES-GCM tag did not verify. */
  public static final class TamperedItemException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    TamperedItemException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static final String HEADER = "aws_dbe_head";
  public static final String FOOTER = "aws_dbe_foot";

  // Encryption context keys of the DB-ESDK.
  static final String TABLE_NAME = "aws-crypto-table-name";
  static final String PARTITION_NAME = "aws-crypto-partition-name";
  static final String SORT_NAME = "aws-crypto-sort-name";
  static final String ATTR_PREFIX = "aws-crypto-attr.";
  static final String LEGEND = "aws-crypto-legend";

  private static final byte[] STRING_TYPE_ID = { 0x00, 0x01 };
  private static final byte[] ITEM_KEY_INFO = "DbEsdkLikeItemEncryptor item key".getBytes(StandardCharsets.US_ASCII);
  private static final int MESSAGE_ID_LENGTH = 32;
  private static final int IV_LENGTH = 12;
  private static final int TAG_BITS = 128;
  private static final SecureRandom RANDOM = new SecureRandom();

  private final String logicalTableName;
  private final String partitionKeyName;
  private final String sortKeyName;
  private final Map<String, CryptoAction> actions;
  private final NativeMplMaterialResolver resolver;
  private final DbeAlgorithmSuite algorithmSuite;
  private final int version;

  private DbEsdkLikeItemEncryptor(Builder builder, NativeMplMaterialResolver resolver) {
    this.logicalTableName = builder.logicalTableName;
    this.partitionKeyName = builder.partitionKeyName;
    this.sortKeyName = builder.sortKeyName;
    this.actions = Collections.unmodifiableMap(new LinkedHashMap<>(builder.actions));
    this.resolver = resolver;
    this.algorithmSuite = builder.algorithmSuite;
    this.version = builder.version();
  }

  public static Builder builder() {
    return new Builder();
  }

  public Map<String, String> encryptItem(Map<String, String> item) {
    requireActions(item);
    EncryptionMaterials materials = resolver.forEncrypt(baseContext(item, version), v2Context(item, version), algorithmSuite, maxPlaintextLength(item));
    try {
      AlgorithmSuite suite = materials.algorithmSuite();
      byte[] messageId = random(MESSAGE_ID_LENGTH);
      // The header stores the context minus the required keys; the footer authenticates all of it.
      Map<String, String> stored = new LinkedHashMap<>(materials.encryptionContext());
      stored.keySet().removeAll(materials.requiredEncryptionContextKeys());
      byte[] header = writeHeader(version, suite, messageId, NativeMplMaterialResolver.toByteContext(stored), materials.encryptedDataKeys());
      Map<String, String> encrypted = new TreeMap<>();
      byte[] itemKey = itemKey(suite, materials.plaintextDataKey().get(), messageId);
      try {
        for (Map.Entry<String, String> attribute : item.entrySet()) {
          String value = attribute.getValue();
          if (actions.get(attribute.getKey()) == CryptoAction.ENCRYPT_AND_SIGN) {
            value = Base64.getEncoder().encodeToString(encryptField(itemKey, attribute.getKey(), value));
          }
          encrypted.put(attribute.getKey(), value);
        }
      } finally {
        Arrays.fill(itemKey, (byte) 0);
      }
      byte[] signed = canonical(header, encrypted);
      ByteArrayOutputStream footer = new ByteArrayOutputStream();
      for (SecretBytes symmetricSigningKey : materials.symmetricSigningKeys()) {
        byte[] tag = hmac(suite.symmetricSignatureHmacAlgorithm().get(), symmetricSigningKey, signed);
        footer.write(tag, 0, tag.length);
      }
      if (suite.isSigning()) {
        byte[] signature = sign(suite, materials, signed, footer.toByteArray());
        footer.write(signature, 0, signature.length);
      }
      encrypted.put(HEADER, Base64.getEncoder().encodeToString(header));
      encrypted.put(FOOTER, Base64.getEncoder().encodeToString(footer.toByteArray()));
      return encrypted;
    } finally {
      materials.destroy();
    }
  }

  /**
   * @throws TamperedItemException if the item does not authenticate
   * @throws software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException if no keyring can decrypt a data key,
   *   as when a key or SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT value changed after encryption
   */
  public Map<String, String> decryptItem(Map<String, String> encryptedItem) {
    byte[] header = Base64.getDecoder().decode(required(encryptedItem, HEADER));
    byte[] footer = Base64.getDecoder().decode(required(encryptedItem, FOOTER));
    ParsedHeader parsed = readHeader(header);
    Map<String, String> attributes = new TreeMap<>(encryptedItem);
    attributes.remove(HEADER);
    attributes.remove(FOOTER);
    requireActions(attributes);
    DecryptionMaterials materials = resolver.forDecrypt(
      parsed.algorithmSuite(),
      parsed.encryptedDataKeys(),
      NativeMplMaterialResolver.toByteContext(parsed.storedEncryptionContext()),
      baseContext(attributes, parsed.version),
      v2Context(attributes, parsed.version)
    );
    try {
      AlgorithmSuite suite = materials.algorithmSuite();
      byte[] signed = canonical(header, attributes);
      verifyFooter(suite, materials, parsed.encryptedDataKeys().size(), signed, footer);
      Map<String, String> decrypted = new TreeMap<>();
      byte[] itemKey = itemKey(suite, materials.plaintextDataKey().get(), parsed.messageId);
      try {
        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
          String value = attribute.getValue();
          if (actions.get(attribute.getKey()) == CryptoAction.ENCRYPT_AND_SIGN) {
            value = decryptField(itemKey, attribute.getKey(), Base64.getDecoder().decode(value));
          }
          decrypted.put(attribute.getKey(), value);
        }
      } finally {
        Arrays.fill(itemKey, (byte) 0);
      }
      return decrypted;
    } finally {
      materials.destroy();
    }
  }

  /** What the header of an encrypted item holds; the DB-ESDK returns the same as {@code ParsedHeader}. */
  public static ParsedHeader parseHeader(Map<String, String> encryptedItem) {
    return readHeader(Base64.getDecoder().decode(required(encryptedItem, HEADER)));
  }

  /** The header fields an example inspects. */
  public static final class ParsedHeader {

    private final int version;
    private final DbeAlgorithmSuite algorithmSuite;
    private final byte[] messageId;
    private final EncryptionContext storedEncryptionContext;
    private final List<EncryptedDataKey> encryptedDataKeys;

    ParsedHeader(int version, DbeAlgorithmSuite algorithmSuite, byte[] messageId, EncryptionContext storedEncryptionContext, List<EncryptedDataKey> edks) {
      this.version = version;
      this.algorithmSuite = algorithmSuite;
      this.messageId = messageId;
      this.storedEncryptionContext = storedEncryptionContext;
      this.encryptedDataKeys = Collections.unmodifiableList(edks);
    }

    public DbeAlgorithmSuite algorithmSuite() {
      return algorithmSuite;
    }

    /** The encryption context minus the required keys. */
    public EncryptionContext storedEncryptionContext() {
      return storedEncryptionContext;
    }

    public List<EncryptedDataKey> encryptedDataKeys() {
      return encryptedDataKeys;
    }
  }

  // The primary key as the DDB-key branch key id supplier sees it, per ConvertContextForSelector:
  // the partition name is required, the sort name optional.
  static Map<String, String> ddbKey(EncryptionContext context) {
    Map<String, String> key = new LinkedHashMap<>();
    String partitionName = context.get(PARTITION_NAME);
    if (partitionName == null) {
      throw new IllegalArgumentException("Invalid encryption context: Missing partition name");
    }
    key.put(partitionName, keyValue(context, partitionName));
    String sortName = context.get(SORT_NAME);
    if (sortName != null) {
      key.put(sortName, keyValue(context, sortName));
    }
    return key;
  }

  private static String keyValue(EncryptionContext context, String attributeName) {
    String encoded = context.get(ATTR_PREFIX + attributeName);
    if (encoded == null) {
      throw new IllegalArgumentException("Invalid encryption context: Missing value of " + attributeName);
    }
    // A version-2 context (it has a legend) holds string values as they are; version 1 holds Base64(typeId ++ value).
    if (context.containsKey(LEGEND)) {
      return encoded;
    }
    byte[] typed = Base64.getDecoder().decode(encoded);
    return new String(typed, STRING_TYPE_ID.length, typed.length - STRING_TYPE_ID.length, StandardCharsets.UTF_8);
  }

  private void requireActions(Map<String, String> item) {
    for (String name : item.keySet()) {
      if (!actions.containsKey(name)) {
        throw new IllegalArgumentException("No crypto action configured for attribute " + name);
      }
    }
  }

  // Table and key names, and the key values as Base Context Value Version 1: UTF8(Base64(typeId ++ value)).
  // Version 2 has only the names; its key values are version-2 entries instead.
  private Map<String, byte[]> baseContext(Map<String, String> item, int itemVersion) {
    Map<String, byte[]> context = new LinkedHashMap<>();
    context.put(TABLE_NAME, utf8(logicalTableName));
    context.put(PARTITION_NAME, utf8(partitionKeyName));
    if (itemVersion == 1) {
      context.put(ATTR_PREFIX + partitionKeyName, typedValue(required(item, partitionKeyName)));
    }
    if (sortKeyName != null) {
      context.put(SORT_NAME, utf8(sortKeyName));
      if (itemVersion == 1) {
        context.put(ATTR_PREFIX + sortKeyName, typedValue(required(item, sortKeyName)));
      }
    }
    return context;
  }

  // One aws-crypto-attr.<name> entry per SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT attribute, and the legend:
  // one type character per entry, in UTF-8 byte order of the entry keys.
  private Map<String, byte[]> v2Context(Map<String, String> item, int itemVersion) {
    if (itemVersion == 1) {
      return Collections.emptyMap();
    }
    Map<String, String> included = new LinkedHashMap<>();
    for (Map.Entry<String, String> attribute : item.entrySet()) {
      if (actions.get(attribute.getKey()) == CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT) {
        included.put(ATTR_PREFIX + attribute.getKey(), attribute.getValue());
      }
    }
    if (included.isEmpty()) {
      return Collections.emptyMap();
    }
    Map<String, byte[]> context = NativeMplMaterialResolver.toByteContext(included);
    char[] legend = new char[context.size()];
    Arrays.fill(legend, 'S');
    context.put(LEGEND, utf8(new String(legend)));
    return context;
  }

  // As EncryptStructure: 2 * number of encrypted fields + their total size.
  private long maxPlaintextLength(Map<String, String> item) {
    long length = 0;
    for (Map.Entry<String, String> attribute : item.entrySet()) {
      if (actions.get(attribute.getKey()) == CryptoAction.ENCRYPT_AND_SIGN) {
        length += 2 + utf8(attribute.getValue()).length;
      }
    }
    return length;
  }

  private static byte[] itemKey(AlgorithmSuite suite, SecretBytes plaintextDataKey, byte[] messageId) {
    byte[] dataKey = plaintextDataKey.toByteArray();
    try {
      return Hkdf.derive(suite.keyDerivation().hmacAlgorithm().get(), messageId, dataKey, ITEM_KEY_INFO, suite.dataKeyLength());
    } finally {
      Arrays.fill(dataKey, (byte) 0);
    }
  }

  private static byte[] encryptField(byte[] itemKey, String name, String value) {
    byte[] iv = random(IV_LENGTH);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(itemKey, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      cipher.updateAAD(utf8(name));
      byte[] ciphertext = cipher.doFinal(utf8(value));
      return ByteBuffer.allocate(IV_LENGTH + ciphertext.length).put(iv).put(ciphertext).array();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String decryptField(byte[] itemKey, String name, byte[] stored) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(itemKey, "AES"), new GCMParameterSpec(TAG_BITS, stored, 0, IV_LENGTH));
      cipher.updateAAD(utf8(name));
      return new String(cipher.doFinal(stored, IV_LENGTH, stored.length - IV_LENGTH), StandardCharsets.UTF_8);
    } catch (AEADBadTagException e) {
      throw new TamperedItemException("Field " + name + " does not decrypt", e);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  // The header, then every authenticated attribute in name order.
  private byte[] canonical(byte[] header, Map<String, String> attributes) {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(bytes)) {
      out.write(header);
      for (Map.Entry<String, String> attribute : new TreeMap<>(attributes).entrySet()) {
        if (actions.get(attribute.getKey()) != CryptoAction.DO_NOTHING) {
          writeField(out, utf8(attribute.getKey()));
          writeField(out, utf8(attribute.getValue()));
        }
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return bytes.toByteArray();
  }

  private static byte[] sign(AlgorithmSuite suite, EncryptionMaterials materials, byte[] signed, byte[] tags) {
    try {
      Signature signature = Signature.getInstance(suite.signature().get().jcaAlgorithm());
      signature.initSign(materials.signingPrivateKey().get());
      signature.update(signed);
      signature.update(tags);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  // At least one recipient tag must verify under the symmetric signing key of the data key that was decrypted.
  private static void verifyFooter(AlgorithmSuite suite, DecryptionMaterials materials, int edkCount, byte[] signed, byte[] footer) {
    String hmacAlgorithm = suite.symmetricSignatureHmacAlgorithm().get();
    byte[] expected = hmac(hmacAlgorithm, materials.symmetricSigningKey().get(), signed);
    int tagsLength = edkCount * expected.length;
    if (footer.length < tagsLength) {
      throw new TamperedItemException("Footer is too short", null);
    }
    boolean matched = false;
    for (int i = 0; i < edkCount; i++) {
      matched |= MessageDigest.isEqual(expected, Arrays.copyOfRange(footer, i * expected.length, (i + 1) * expected.length));
    }
    if (!matched) {
      throw new TamperedItemException("No recipient tag matches", null);
    }
    if (suite.isSigning()) {
      try {
        Signature signature = Signature.getInstance(suite.signature().get().jcaAlgorithm());
        signature.initVerify(materials.verificationPublicKey().get());
        signature.update(signed);
        signature.update(footer, 0, tagsLength);
        if (!signature.verify(Arrays.copyOfRange(footer, tagsLength, footer.length))) {
          throw new TamperedItemException("Signature does not verify", null);
        }
      } catch (GeneralSecurityException e) {
        throw new TamperedItemException("Signature does not verify", e);
      }
    }
  }

  private static byte[] hmac(String algorithm, SecretBytes key, byte[] message) {
    try {
      Mac mac = Mac.getInstance(algorithm);
      mac.init(key.toSecretKey(algorithm));
      return mac.doFinal(message);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  // Version (1) || suite id (2) || message id (32) || stored context || EDKs.
  // Context: u16 count, then u16-length-prefixed key and value per entry, in UTF-8 byte order of the keys.
  // EDKs: u8 count, then u16-length-prefixed provider id, provider info, and ciphertext per key.
  private static byte[] writeHeader(int version, AlgorithmSuite suite, byte[] messageId, Map<String, byte[]> stored, List<EncryptedDataKey> edks) {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (DataOutputStream out = new DataOutputStream(bytes)) {
      out.writeByte(version);
      out.write(suite.binaryId());
      out.write(messageId);
      out.writeShort(stored.size());
      for (Map.Entry<String, byte[]> entry : stored.entrySet()) {
        writeShortField(out, utf8(entry.getKey()));
        writeShortField(out, entry.getValue());
      }
      out.writeByte(edks.size());
      for (EncryptedDataKey edk : edks) {
        writeShortField(out, edk.keyProviderIdUtf8());
        writeShortField(out, edk.keyProviderInfo());
        writeShortField(out, edk.ciphertext());
      }
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return bytes.toByteArray();
  }

  private static ParsedHeader readHeader(byte[] header) {
    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(header))) {
      int version = in.readUnsignedByte();
      byte[] suiteId = new byte[2];
      in.readFully(suiteId);
      byte[] messageId = new byte[MESSAGE_ID_LENGTH];
      in.readFully(messageId);
      Map<String, byte[]> stored = new LinkedHashMap<>();
      for (int i = in.readUnsignedShort(); i > 0; i--) {
        stored.put(strictUtf8(readShortField(in)), readShortField(in));
      }
      List<EncryptedDataKey> edks = new ArrayList<>();
      for (int i = in.readUnsignedByte(); i > 0; i--) {
        edks.add(EncryptedDataKey.builder()
            .keyProviderIdUtf8(readShortField(in))
            .keyProviderInfo(readShortField(in))
            .ciphertext(readShortField(in))
            .build());
      }
      return new ParsedHeader(
        version,
        DbeAlgorithmSuite.fromBinaryId(suiteId),
        messageId,
        EncryptionContext.fromUtf8(stored),
        edks
      );
    } catch (IOException e) {
      throw new TamperedItemException("Header is truncated", e);
    }
  }

  // EncryptionContext.fromUtf8 decodes the values; the keys are decoded as strictly here,
  // so bytes that are not UTF-8 fail instead of becoming U+FFFD (and two keys one).
  private static String strictUtf8(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
    } catch (CharacterCodingException e) {
      throw new TamperedItemException("Header key is not UTF-8", e);
    }
  }

  private static void writeField(DataOutputStream out, byte[] value) throws IOException {
    out.writeInt(value.length);
    out.write(value);
  }

  private static void writeShortField(DataOutputStream out, byte[] value) throws IOException {
    out.writeShort(value.length);
    out.write(value);
  }

  private static byte[] readShortField(DataInputStream in) throws IOException {
    byte[] value = new byte[in.readUnsignedShort()];
    in.readFully(value);
    return value;
  }

  private static byte[] typedValue(String value) {
    byte[] bytes = utf8(value);
    byte[] typed = ByteBuffer.allocate(STRING_TYPE_ID.length + bytes.length).put(STRING_TYPE_ID).put(bytes).array();
    return utf8(Base64.getEncoder().encodeToString(typed));
  }

  private static String required(Map<String, String> item, String name) {
    String value = item.get(name);
    if (value == null) {
      throw new IllegalArgumentException("Item has no attribute " + name);
    }
    return value;
  }

  private static byte[] utf8(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] random(int length) {
    byte[] bytes = new byte[length];
    RANDOM.nextBytes(bytes);
    return bytes;
  }

  /** Not thread-safe. Requires a table name, a partition key name, actions, and exactly one of a keyring and a CMM. */
  public static final class Builder {

    private String logicalTableName;
    private String partitionKeyName;
    private String sortKeyName;
    private Map<String, CryptoAction> actions = new LinkedHashMap<>();
    private Keyring keyring;
    private CryptographicMaterialsManager cmm;
    private DbeAlgorithmSuite algorithmSuite;

    private Builder() {}

    public Builder logicalTableName(String logicalTableName) {
      this.logicalTableName = logicalTableName;
      return this;
    }

    public Builder partitionKeyName(String partitionKeyName) {
      this.partitionKeyName = partitionKeyName;
      return this;
    }

    public Builder sortKeyName(String sortKeyName) {
      this.sortKeyName = sortKeyName;
      return this;
    }

    public Builder attributeActionsOnEncrypt(Map<String, CryptoAction> actions) {
      this.actions = new LinkedHashMap<>(actions);
      return this;
    }

    public Builder keyring(Keyring keyring) {
      this.keyring = keyring;
      return this;
    }

    public Builder cmm(CryptographicMaterialsManager cmm) {
      this.cmm = cmm;
      return this;
    }

    /** Default: the DBE commitment policy's default, which signs with ECDSA P-384. */
    public Builder algorithmSuite(DbeAlgorithmSuite algorithmSuite) {
      this.algorithmSuite = algorithmSuite;
      return this;
    }

    public DbEsdkLikeItemEncryptor build() {
      Objects.requireNonNull(logicalTableName, "logicalTableName");
      Objects.requireNonNull(partitionKeyName, "partitionKeyName");
      if ((keyring == null) == (cmm == null)) {
        throw new IllegalArgumentException("Configure exactly one of keyring and cmm");
      }
      requireKeyAction(partitionKeyName, "Partition");
      if (sortKeyName != null) {
        requireKeyAction(sortKeyName, "Sort");
      }
      NativeMplMaterialResolver resolver = keyring != null
        ? NativeMplMaterialResolver.forKeyring(keyring)
        : NativeMplMaterialResolver.forCmm(cmm);
      return new DbEsdkLikeItemEncryptor(this, resolver);
    }

    private int version() {
      return actions.containsValue(CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT) ? 2 : 1;
    }

    private void requireKeyAction(String keyName, String which) {
      CryptoAction required = version() == 2 ? CryptoAction.SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT : CryptoAction.SIGN_ONLY;
      if (actions.get(keyName) != required) {
        throw new IllegalArgumentException(which + " key attribute action MUST be " + required);
      }
    }
  }
}
