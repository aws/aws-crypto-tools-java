// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders.internal.primitives;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.materialproviders.AlgorithmSuite;

// The provider picks the signature's length; the differential tests cannot choose it, so a scripted Signature does.
class EcdsaFixedLengthTest {

  private static final ECPrivateKey KEY = (ECPrivateKey) EcKeys.privateKey(AlgorithmSuite.Signature.ECDSA_P256, new byte[] { 5 });
  private static final BigInteger N = KEY.getParams().getOrder();
  private static final byte[] DIGEST = { 1, 2, 3 };

  // Both r and s have their top bit set, so the DER is 72 bytes; n - s is shorter, which makes it 71.
  @Test
  void aLongSignatureIsShortenedByNegatingS() throws Exception {
    BigInteger r = BigInteger.ONE.shiftLeft(255).add(BigInteger.valueOf(7));
    BigInteger s = N.subtract(BigInteger.ONE.shiftLeft(254));
    ScriptedSignature signer = new ScriptedSignature(der(r, s));
    assertEquals(72, der(r, s).length);
    byte[] signature = Ecdsa.fixedLengthSignature(signer, DIGEST, KEY, 71);
    assertArrayEquals(der(r, BigInteger.ONE.shiftLeft(254)), signature);
    assertEquals(71, signature.length);
    assertEquals(1, signer.signCalls);
    assertArrayEquals(DIGEST, signer.updates.toByteArray());
  }

  // Negating s does not fix a short r, so the signer signs again, with the digest again.
  @Test
  void aSignatureNegationCannotFixIsReplaced() throws Exception {
    byte[] tooShort = der(BigInteger.valueOf(3), BigInteger.ONE.shiftLeft(250));
    byte[] right = der(BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE), BigInteger.ONE.shiftLeft(254));
    ScriptedSignature signer = new ScriptedSignature(tooShort, right);
    assertEquals(71, right.length);
    assertArrayEquals(right, Ecdsa.fixedLengthSignature(signer, DIGEST, KEY, 71));
    assertEquals(2, signer.signCalls);
    byte[] twice = Arrays.copyOf(DIGEST, 2 * DIGEST.length);
    System.arraycopy(DIGEST, 0, twice, DIGEST.length, DIGEST.length);
    assertArrayEquals(twice, signer.updates.toByteArray());
  }

  @Test
  void aSignatureOfTheRightLengthIsKept() throws Exception {
    byte[] right = der(BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE), BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE));
    assertEquals(72, right.length);
    ScriptedSignature signer = new ScriptedSignature(right);
    assertArrayEquals(right, Ecdsa.fixedLengthSignature(signer, DIGEST, KEY, 72));
    assertEquals(1, signer.signCalls);
  }

  private static byte[] der(BigInteger r, BigInteger s) throws IOException {
    return new DERSequence(new ASN1Encodable[] { new ASN1Integer(r), new ASN1Integer(s) }).getEncoded();
  }

  /** Returns the given signatures in order and records what it was asked to sign. */
  private static final class ScriptedSignature extends Signature {

    private final Deque<byte[]> signatures;
    private final ByteArrayOutputStream updates = new ByteArrayOutputStream();
    private int signCalls;

    ScriptedSignature(byte[]... signatures) throws Exception {
      super("scripted");
      this.signatures = new ArrayDeque<>(Arrays.asList(signatures));
      initSign(KEY);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) {}

    @Override
    protected void engineInitVerify(PublicKey publicKey) {
      throw new UnsupportedOperationException();
    }

    @Override
    protected void engineUpdate(byte b) {
      updates.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
      updates.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      signCalls++;
      return signatures.removeFirst();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
      throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
      throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
      throw new UnsupportedOperationException();
    }
  }
}
