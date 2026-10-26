// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import software.amazon.cryptography.materialproviders.SecretBytes;
import software.amazon.cryptography.materialproviders.exceptions.ValidationException;

/** PEM reading and writing for RSA and ECDH keys, through BouncyCastle's PemReader and PemWriter. */
public final class Pem {

  private Pem() {}

  /**
   * The DER content of the first PEM object.
   * The bytes are decoded with the platform charset, as the Dafny-based MPL decoded them.
   * Input with no PEM header throws NullPointerException: readPemObject returns null,
   * and the Dafny-based MPL reported that NullPointerException as the failure.
   */
  static byte[] content(byte[] pem) throws IOException {
    PemObject object = new PemReader(new InputStreamReader(new ByteArrayInputStream(pem))).readPemObject();
    return object.getContent();
  }

  /**
   * The PEM the keyrings take for a public key: its {@link Key#getEncoded()} (X.509 SubjectPublicKeyInfo) as a {@code PUBLIC KEY}.
   *
   * @throws ValidationException if the key has no encoding
   */
  public static byte[] publicKey(PublicKey key, String name) {
    return encode("PUBLIC KEY", encoded(key, name));
  }

  /**
   * The PEM the keyrings take for a private key: its {@link Key#getEncoded()} (PKCS #8) as a {@code PRIVATE KEY}.
   * The caller owns the result.
   *
   * @throws ValidationException if the key has no encoding, for example a key held in a hardware module
   */
  public static SecretBytes privateKey(PrivateKey key, String name) {
    // The Base64 text also passes through a String, which cannot be cleared; SecretBytes documents such copies.
    byte[] der = encoded(key, name);
    byte[] pem = encode("PRIVATE KEY", der);
    try {
      return SecretBytes.copyOf(pem);
    } finally {
      Bytes.zero(der);
      Bytes.zero(pem);
    }
  }

  /**
   * The key's encoding.
   *
   * @throws ValidationException if the key has none
   */
  public static byte[] encoded(Key key, String name) {
    byte[] encoded = key.getEncoded();
    if (encoded == null) {
      throw new ValidationException(name + " has no encoded form");
    }
    return encoded;
  }

  /** {@code der} as a PEM object of {@code type}, as UTF-8 bytes. Lines end with the platform line separator. */
  static byte[] encode(String type, byte[] der) {
    StringWriter text = new StringWriter();
    try (PemWriter writer = new PemWriter(text)) {
      writer.writeObject(new PemObject(type, der));
    } catch (IOException e) {
      throw new IllegalStateException("writing PEM to a StringWriter failed", e);
    }
    return text.toString().getBytes(StandardCharsets.UTF_8);
  }
}
