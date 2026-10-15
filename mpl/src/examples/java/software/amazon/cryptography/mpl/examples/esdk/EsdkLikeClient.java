// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.mpl.examples.esdk;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.cryptography.mpl.CryptographicMaterialsManager;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.Keyring;
import software.amazon.cryptography.mpl.cmm.DefaultCryptographicMaterialsManager;
import software.amazon.cryptography.mpl.examples.esdk.integration.CmmHandler;
import software.amazon.cryptography.mpl.examples.esdk.integration.CommitmentPolicy;
import software.amazon.cryptography.mpl.examples.esdk.integration.CryptoAlgorithm;
import software.amazon.cryptography.mpl.examples.esdk.integration.DecryptionMaterialsHandler;
import software.amazon.cryptography.mpl.examples.esdk.integration.EncryptionMaterialsHandler;
import software.amazon.cryptography.mpl.examples.esdk.integration.KeyBlob;

/**
 * STAND-IN for {@code com.amazonaws.encryptionsdk.AwsCrypto} until the ESDK integrates the native MPL.
 * Not the ESDK message format and not for real data.
 *
 * <p>It calls the MPL the way {@code AwsCrypto} and {@code CMMHandler} would (through the classes in {@code integration})
 * and protects a payload with the materials: one AES-GCM frame under an HKDF-derived key, a key commitment for committing
 * suites, the encrypted data keys and stored context in a header, and an ECDSA signature for signing suites.
 * The method names match {@code AwsCrypto} so the customer examples read like ESDK code.
 */
public final class EsdkLikeClient {

  private static final SecureRandom RANDOM = new SecureRandom();

  private final CommitmentPolicy commitmentPolicy;
  private final CryptoAlgorithm encryptionAlgorithm;

  private EsdkLikeClient(Builder builder) {
    this.commitmentPolicy = builder.commitmentPolicy;
    this.encryptionAlgorithm = builder.encryptionAlgorithm;
  }

  public static Builder builder() {
    return new Builder();
  }

  /** {@code AwsCrypto.encryptData(IKeyring, ...)}: wraps the keyring in a default materials manager per call, as ESDK 3.x does. */
  public byte[] encryptData(Keyring keyring, byte[] plaintext, Map<String, String> encryptionContext) {
    return encryptData(DefaultCryptographicMaterialsManager.of(keyring), plaintext, encryptionContext);
  }

  public byte[] encryptData(CryptographicMaterialsManager cmm, byte[] plaintext, Map<String, String> encryptionContext) {
    EncryptionMaterialsHandler materials = new CmmHandler(cmm)
      .getMaterialsForEncrypt(encryptionContext, encryptionAlgorithm, commitmentPolicy, plaintext.length);
    try {
      return encrypt(materials, plaintext);
    } finally {
      materials.destroy();
    }
  }

  private byte[] encrypt(EncryptionMaterialsHandler materials, byte[] plaintext) {
    // The built-in managers check their results; a customer's manager might return incomplete materials.
    if (!materials.isReadyForEncrypt()) {
      throw new AwsCryptoException("No encrypted data keys in materials result");
    }
    CryptoAlgorithm algorithm = materials.getAlgorithm();
    if (encryptionAlgorithm != null && algorithm != encryptionAlgorithm) {
      throw new AwsCryptoException("Materials manager ignored requested algorithm " + encryptionAlgorithm + "; selected " + algorithm);
    }
    if (!commitmentPolicy.algorithmAllowedForEncrypt(algorithm)) {
      throw new AwsCryptoException("Configuration conflict. Cannot encrypt due to CommitmentPolicy " + commitmentPolicy);
    }
    // Required keys are authenticated but not stored, as in the ESDK's EncryptionHandler.
    Map<String, String> context = materials.getEncryptionContext();
    List<String> requiredKeys = materials.getRequiredEncryptionContextKeys();
    byte[] messageId = random(algorithm.getMessageIdLength());
    MessageKeys keys = MessageKeys.derive(algorithm, materials.getCleartextDataKey(), messageId);

    Writer header = new Writer();
    header.u8(algorithm.getMessageFormatVersion());
    header.u16(algorithm.getValue());
    header.raw(messageId);
    header.context(only(context, requiredKeys, false));
    List<KeyBlob> keyBlobs = materials.getEncryptedDataKeys();
    header.u16(keyBlobs.size());
    for (KeyBlob keyBlob : keyBlobs) {
      header.bytes(keyBlob.getProviderId().getBytes(StandardCharsets.UTF_8));
      header.bytes(keyBlob.getProviderInformation());
      header.bytes(keyBlob.getEncryptedDataKey());
    }
    if (keys.commitment != null) {
      header.raw(keys.commitment);
    }
    byte[] headerBytes = header.toByteArray();

    byte[] iv = random(algorithm.getNonceLen());
    byte[] ciphertext = gcm(Cipher.ENCRYPT_MODE, keys.encryption, iv, algorithm, aad(headerBytes, context, requiredKeys), plaintext);
    Writer message = new Writer();
    message.raw(headerBytes);
    message.raw(iv);
    message.bytes(ciphertext);
    PrivateKey signingKey = materials.getTrailingSignatureKey();
    if (signingKey != null) {
      byte[] signed = message.toByteArray();
      message.bytes(sign(algorithm, signingKey, signed));
    }
    return message.toByteArray();
  }

  /**
   * {@code AwsCrypto.decryptData(IKeyring, ciphertext, encryptionContext)}.
   *
   * @param reproducedEncryptionContext context the caller expects; it must agree with the message and must hold
   *   every key the encrypting materials manager required
   */
  public Decrypted decryptData(Keyring keyring, byte[] message, Map<String, String> reproducedEncryptionContext) {
    return decryptData(DefaultCryptographicMaterialsManager.of(keyring), message, reproducedEncryptionContext);
  }

  public Decrypted decryptData(Keyring keyring, byte[] message) {
    return decryptData(keyring, message, Collections.<String, String>emptyMap());
  }

  public Decrypted decryptData(CryptographicMaterialsManager cmm, byte[] message, Map<String, String> reproducedEncryptionContext) {
    Reader in = new Reader(message);
    byte version = in.u8();
    short id = (short) in.u16();
    CryptoAlgorithm algorithm = CryptoAlgorithm.deserialize(version, id);
    if (algorithm == null) {
      throw new AwsCryptoException("Unknown algorithm " + id);
    }
    if (!commitmentPolicy.algorithmAllowedForDecrypt(algorithm)) {
      throw new AwsCryptoException("Configuration conflict. Cannot decrypt due to CommitmentPolicy " + commitmentPolicy);
    }
    byte[] messageId = in.raw(algorithm.getMessageIdLength());
    Map<String, String> storedContext = in.context();
    int count = in.u16();
    List<KeyBlob> keyBlobs = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      keyBlobs.add(new KeyBlob(new String(in.bytes(), StandardCharsets.UTF_8), in.bytes(), in.bytes()));
    }
    byte[] storedCommitment = algorithm.isCommitting() ? in.raw(algorithm.getCommitmentLength()) : null;
    byte[] headerBytes = Arrays.copyOf(message, in.position());
    byte[] iv = in.raw(algorithm.getNonceLen());
    byte[] ciphertext = in.bytes();

    DecryptionMaterialsHandler materials = new CmmHandler(cmm)
      .decryptMaterials(algorithm, storedContext, keyBlobs, reproducedEncryptionContext, commitmentPolicy);
    try {
      return decrypt(materials, algorithm, message, messageId, storedCommitment, headerBytes, iv, ciphertext, in);
    } finally {
      materials.destroy();
    }
  }

  private static Decrypted decrypt(
    DecryptionMaterialsHandler materials,
    CryptoAlgorithm algorithm,
    byte[] message,
    byte[] messageId,
    byte[] storedCommitment,
    byte[] headerBytes,
    byte[] iv,
    byte[] ciphertext,
    Reader in
  ) {
    // ESDK 3.x rejects such materials when the data key's algorithm name does not match the message's suite.
    if (!materials.isReadyForDecrypt() || materials.getAlgorithm() != algorithm) {
      throw new AwsCryptoException("Materials manager returned materials for " + materials.getAlgorithm() + ", message uses " + algorithm);
    }
    int signedLength = in.position();
    PublicKey verificationKey = materials.getTrailingSignatureKey();
    if (algorithm.getTrailingSignatureLength() > 0) {
      verify(algorithm, verificationKey, Arrays.copyOf(message, signedLength), in.bytes());
    } else if (verificationKey != null) {
      throw new AwsCryptoException("Unexpected trailing signature key in context");
    }
    MessageKeys keys = MessageKeys.derive(algorithm, materials.getDataKey(), messageId);
    if (storedCommitment != null && !MessageDigest.isEqual(storedCommitment, keys.commitment)) {
      throw new AwsCryptoException("Key commitment validation failed");
    }
    Map<String, String> context = materials.getEncryptionContext();
    byte[] aad = aad(headerBytes, context, materials.getRequiredEncryptionContextKeys());
    return new Decrypted(gcm(Cipher.DECRYPT_MODE, keys.encryption, iv, algorithm, aad, ciphertext), context);
  }

  /** The header, then the required (authenticate-only) pairs. */
  private static byte[] aad(byte[] header, Map<String, String> context, List<String> requiredKeys) {
    Writer aad = new Writer();
    aad.raw(header);
    aad.context(only(context, requiredKeys, true));
    return aad.toByteArray();
  }

  private static EncryptionContext only(Map<String, String> context, List<String> requiredKeys, boolean required) {
    EncryptionContext result = EncryptionContext.empty();
    for (Map.Entry<String, String> entry : context.entrySet()) {
      if (requiredKeys.contains(entry.getKey()) == required) {
        result = result.with(entry.getKey(), entry.getValue());
      }
    }
    return result;
  }

  private static byte[] gcm(int mode, SecretKey key, byte[] iv, CryptoAlgorithm algorithm, byte[] aad, byte[] input) {
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(mode, key, new GCMParameterSpec(algorithm.getTagLen() * 8, iv));
      cipher.updateAAD(aad);
      return cipher.doFinal(input);
    } catch (GeneralSecurityException e) {
      throw new AwsCryptoException("AES-GCM failed", e);
    }
  }

  private static byte[] sign(CryptoAlgorithm algorithm, PrivateKey key, byte[] data) {
    try {
      Signature signature = Signature.getInstance(algorithm.getTrailingSignatureAlgo());
      signature.initSign(key, RANDOM);
      signature.update(data);
      return signature.sign();
    } catch (GeneralSecurityException e) {
      throw new AwsCryptoException("Signing failed", e);
    }
  }

  private static void verify(CryptoAlgorithm algorithm, PublicKey key, byte[] data, byte[] signatureBytes) {
    try {
      Signature signature = Signature.getInstance(algorithm.getTrailingSignatureAlgo());
      signature.initVerify(key);
      signature.update(data);
      if (!signature.verify(signatureBytes)) {
        throw new AwsCryptoException("Bad trailing signature");
      }
    } catch (GeneralSecurityException e) {
      throw new AwsCryptoException("Bad trailing signature", e);
    }
  }

  private static byte[] random(int length) {
    byte[] bytes = new byte[length];
    RANDOM.nextBytes(bytes);
    return bytes;
  }

  /** The plaintext and the encryption context it was bound to, as {@code CryptoResult} returns them. */
  public static final class Decrypted {

    private final byte[] plaintext;
    private final Map<String, String> encryptionContext;

    Decrypted(byte[] plaintext, Map<String, String> encryptionContext) {
      this.plaintext = plaintext;
      this.encryptionContext = encryptionContext;
    }

    public byte[] getResult() {
      return plaintext.clone();
    }

    public Map<String, String> getEncryptionContext() {
      return encryptionContext;
    }
  }

  /** Stand-in for {@code AwsCryptoException}: failures of the message layer. MPL exceptions pass through unchanged. */
  public static final class AwsCryptoException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    AwsCryptoException(String message) {
      super(message);
    }

    AwsCryptoException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  public static final class Builder {

    private CommitmentPolicy commitmentPolicy = CommitmentPolicy.RequireEncryptRequireDecrypt;
    private CryptoAlgorithm encryptionAlgorithm;

    private Builder() {}

    public Builder withCommitmentPolicy(CommitmentPolicy commitmentPolicy) {
      this.commitmentPolicy = commitmentPolicy;
      return this;
    }

    public Builder withEncryptionAlgorithm(CryptoAlgorithm encryptionAlgorithm) {
      this.encryptionAlgorithm = encryptionAlgorithm;
      return this;
    }

    public EsdkLikeClient build() {
      return new EsdkLikeClient(this);
    }
  }

  /** The message encryption key and, for committing suites, the commitment, both derived from the data key. */
  private static final class MessageKeys {

    final SecretKey encryption;
    final byte[] commitment;

    private MessageKeys(SecretKey encryption, byte[] commitment) {
      this.encryption = encryption;
      this.commitment = commitment;
    }

    static MessageKeys derive(CryptoAlgorithm algorithm, SecretKey dataKey, byte[] messageId) {
      String mac = algorithm.getKdfMacAlgo();
      if (mac == null) {
        return new MessageKeys(new SecretKeySpec(dataKey.getEncoded(), "AES"), null);
      }
      byte[] salt = algorithm.isCommitting() ? messageId : new byte[0];
      byte[] info = ByteBuffer.allocate(2 + messageId.length).putShort(algorithm.getValue()).put(messageId).array();
      byte[] key = hkdf(mac, salt, dataKey.getEncoded(), info, algorithm.getKeyLength());
      byte[] commitment = algorithm.isCommitting()
        ? hkdf(
          algorithm.algorithmSuite().commitmentHmacAlgorithm().get(),
          salt,
          dataKey.getEncoded(),
          "COMMITKEY".getBytes(StandardCharsets.US_ASCII),
          algorithm.getCommitmentLength()
        )
        : null;
      return new MessageKeys(new SecretKeySpec(key, "AES"), commitment);
    }

    // RFC 5869 with one expand block, enough for keys up to the hash length.
    private static byte[] hkdf(String macAlgorithm, byte[] salt, byte[] ikm, byte[] info, int length) {
      try {
        Mac mac = Mac.getInstance(macAlgorithm);
        mac.init(new SecretKeySpec(salt.length == 0 ? new byte[mac.getMacLength()] : salt, macAlgorithm));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, macAlgorithm));
        mac.update(info);
        mac.update((byte) 1);
        return Arrays.copyOf(mac.doFinal(), length);
      } catch (GeneralSecurityException e) {
        throw new AwsCryptoException("HKDF failed", e);
      }
    }
  }

  private static final class Writer {

    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private final DataOutputStream out = new DataOutputStream(bytes);

    void u8(int value) {
      write(() -> out.writeByte(value));
    }

    void u16(int value) {
      write(() -> out.writeShort(value));
    }

    void raw(byte[] value) {
      write(() -> out.write(value));
    }

    void bytes(byte[] value) {
      u16(value.length);
      raw(value);
    }

    // EncryptionContext iterates in UTF-8 byte order, so equal contexts serialize equally.
    void context(EncryptionContext context) {
      u16(context.size());
      for (Map.Entry<String, String> entry : context.entrySet()) {
        bytes(entry.getKey().getBytes(StandardCharsets.UTF_8));
        bytes(entry.getValue().getBytes(StandardCharsets.UTF_8));
      }
    }

    byte[] toByteArray() {
      return bytes.toByteArray();
    }

    private void write(IoAction action) {
      try {
        action.run();
      } catch (IOException e) {
        throw new UncheckedIOException(e);
      }
    }
  }

  @FunctionalInterface
  private interface IoAction {
    void run() throws IOException;
  }

  private static final class Reader {

    private final ByteBuffer in;

    Reader(byte[] message) {
      this.in = ByteBuffer.wrap(message);
    }

    int position() {
      return in.position();
    }

    byte u8() {
      return in.get();
    }

    int u16() {
      return in.getShort() & 0xFFFF;
    }

    byte[] raw(int length) {
      byte[] value = new byte[length];
      in.get(value);
      return value;
    }

    byte[] bytes() {
      return raw(u16());
    }

    Map<String, String> context() {
      EncryptionContext context = EncryptionContext.empty();
      int count = u16();
      for (int i = 0; i < count; i++) {
        context = context.with(new String(bytes(), StandardCharsets.UTF_8), new String(bytes(), StandardCharsets.UTF_8));
      }
      return context;
    }
  }
}
