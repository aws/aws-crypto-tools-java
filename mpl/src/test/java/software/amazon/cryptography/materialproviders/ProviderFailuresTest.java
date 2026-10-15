// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.primitives.AtomicPrimitives;
import software.amazon.cryptography.primitives.model.CryptoConfig;
import software.amazon.cryptography.primitives.model.ECDSASignInput;
import software.amazon.cryptography.primitives.model.ECDSASignatureAlgorithm;
import software.amazon.cryptography.primitives.model.ECDSAVerifyInput;
import software.amazon.cryptography.primitives.model.GenerateECDSASignatureKeyInput;
import software.amazon.cryptography.primitives.model.GenerateECDSASignatureKeyOutput;

// ECDSA uses the installed providers for "EC" and "NONEwithECDSA". SunEC accepts every key these tests build,
// so its failure branches are reached by replacing SunEC (and BouncyCastle, which the reference installs)
// with a provider that defers to SunEC except where it fails on purpose. The JCA falls back to the next
// provider when one fails, so the failing provider must be the only one.
// It is named SunEC because SunEC's own key classes look up "EC" parameters from the provider of that name.
// Both libraries share java.security.Security, so the reference sees the same providers.
// No ECDH operation runs while the providers are replaced: the reference would install BouncyCastle again.
class ProviderFailuresTest {

  private static final Provider SUN_EC = Security.getProvider("SunEC");
  private static volatile String failing = "";

  private final AtomicPrimitives primitives = AtomicPrimitives
    .builder()
    .CryptoConfig(CryptoConfig.builder().build())
    .build();
  private final Object reference = ReferenceMpl.atomicPrimitives();

  @Test
  void providerFailuresSurfaceAsTheDafnyBasedMplReportedThem() throws Exception {
    Inputs in = new Inputs();
    withOnlyProvider(new FailingProvider(), () -> {
      failing = "generatePrivate";
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.OpaqueError: generatePrivate [obj java.security.spec.InvalidKeySpecException]",
        assertSameOutcome("ECDSASign", in.sign, () -> primitives.ECDSASign(in.sign))
      );
      failing = "generatePublic";
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.OpaqueError: generatePublic [obj java.security.spec.InvalidKeySpecException]",
        assertSameOutcome("ECDSAVerify", in.verify, () -> primitives.ECDSAVerify(in.verify))
      );
      failing = "initSign";
      String initSign = assertSameOutcome("ECDSASign", in.sign, () -> primitives.ECDSASign(in.sign));
      assertTrue(
        initSign.startsWith(
          "throws software.amazon.cryptography.primitives.model.AwsCryptographicPrimitivesError: " +
          "Signature Cipher does not support provided key.Signature Signature object: NONEwithECDSA<not initialized>Key "
        ),
        initSign
      );
      failing = "initVerify";
      String initVerify = assertSameOutcome("ECDSAVerify", in.verify, () -> primitives.ECDSAVerify(in.verify));
      assertTrue(
        initVerify.startsWith(
          "throws software.amazon.cryptography.primitives.model.AwsCryptographicPrimitivesError: " +
          "Signature does not support provided key.Signature Signature object: NONEwithECDSA<not initialized>Key Sun EC public key"
        ),
        initVerify
      );
      failing = "sign";
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.OpaqueError: sign [obj java.security.SignatureException]",
        assertSameOutcome("ECDSASign", in.sign, () -> primitives.ECDSASign(in.sign))
      );
      failing = "";
      assertEquals("true", assertSameOutcome("ECDSAVerify", in.verify, () -> primitives.ECDSAVerify(in.verify)));
    });
  }

  // A JVM without SunEC, for example one limited to a FIPS provider without these algorithms.
  @Test
  void missingEcProvidersSurfaceAsTheDafnyBasedMplReportedThem() throws Exception {
    Inputs in = new Inputs();
    GenerateECDSASignatureKeyInput generate = GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P384).build();
    withOnlyProvider(null, () -> {
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.AwsCryptographicPrimitivesError: " +
        "Requested Signature Algorithm is not supported. Requested NONEwithECDSA.",
        assertSameOutcome("ECDSASign", in.sign, () -> primitives.ECDSASign(in.sign))
      );
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.OpaqueError: EC AlgorithmParameters not available [obj java.security.NoSuchAlgorithmException]",
        assertSameOutcome("ECDSAVerify", in.verify, () -> primitives.ECDSAVerify(in.verify))
      );
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.OpaqueError: EC KeyPairGenerator not available [obj java.security.NoSuchAlgorithmException]",
        assertSameOutcome("GenerateECDSASignatureKey", generate, () -> primitives.GenerateECDSASignatureKey(generate))
      );
    });
    // The curve is looked up before the signing key is read, so even an empty key fails for the missing curve.
    ECDSASignInput emptyKey = in.sign.toBuilder().signingKey(ByteBuffer.allocate(0)).build();
    withOnlyProvider(new SignatureOnlyProvider(), () ->
      assertEquals(
        "throws software.amazon.cryptography.primitives.model.OpaqueError: EC AlgorithmParameters not available [obj java.security.NoSuchAlgorithmException]",
        assertSameOutcome("ECDSASign", emptyKey, () -> primitives.ECDSASign(emptyKey))
      )
    );
  }

  /** A P-256 key pair from the default providers, and inputs that use it. */
  private final class Inputs {

    final ECDSASignInput sign;
    final ECDSAVerifyInput verify;

    Inputs() {
      GenerateECDSASignatureKeyOutput keys = primitives.GenerateECDSASignatureKey(
        GenerateECDSASignatureKeyInput.builder().signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P256).build()
      );
      sign = ECDSASignInput
        .builder()
        .signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P256)
        .signingKey(keys.signingKey())
        .message(ByteBuffer.wrap(new byte[] { 1 }))
        .build();
      verify = ECDSAVerifyInput
        .builder()
        .signatureAlgorithm(ECDSASignatureAlgorithm.ECDSA_P256)
        .verificationKey(keys.verificationKey())
        .message(sign.message())
        .signature(primitives.ECDSASign(sign))
        .build();
    }
  }

  // Runs body with SunEC and BouncyCastle uninstalled and {@code replacement}, if any, installed first; then restores the list.
  private static void withOnlyProvider(Provider replacement, ThrowingRunnable body) throws Exception {
    Provider[] installed = Security.getProviders();
    Security.removeProvider("SunEC");
    Security.removeProvider("BC");
    if (replacement != null) {
      Security.insertProviderAt(replacement, 1);
    }
    try {
      body.run();
    } finally {
      failing = "";
      if (replacement != null) {
        Security.removeProvider(replacement.getName());
      }
      for (int i = 0; i < installed.length; i++) {
        if (Security.getProvider(installed[i].getName()) == null) {
          Security.insertProviderAt(installed[i], i + 1);
        }
      }
    }
    assertEquals(java.util.Arrays.asList(installed), java.util.Arrays.asList(Security.getProviders()));
  }

  private interface ThrowingRunnable {
    void run() throws Exception;
  }

  // Identity hash codes in messages (from a key's Object.toString) differ between calls.
  private String assertSameOutcome(String operation, Object input, Supplier<Object> nativeCall) {
    String expected = ReferenceMpl.outcome(() -> ReferenceMpl.call(reference, operation, input));
    String actual = ReferenceMpl.outcome(nativeCall);
    assertEquals(expected.replaceAll("@[0-9a-f]+", "@"), actual.replaceAll("@[0-9a-f]+", "@"), operation);
    return actual;
  }

  /** SunEC's "EC" parameters, which the key factory and signature need alongside them. */
  public static final class SunEcParameters extends AlgorithmParametersSpi {

    private final AlgorithmParameters sunEc;

    public SunEcParameters() throws NoSuchAlgorithmException {
      sunEc = AlgorithmParameters.getInstance("EC", SUN_EC);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
      sunEc.init(paramSpec);
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
      sunEc.init(params);
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
      sunEc.init(params, format);
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
      return sunEc.getParameterSpec(paramSpec);
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
      return sunEc.getEncoded();
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
      return sunEc.getEncoded(format);
    }

    @Override
    protected String engineToString() {
      return sunEc.toString();
    }
  }

  /** Stands in for SunEC. Offers "EC" key factories and "NONEwithECDSA" signatures that defer to SunEC except for the step named by {@link #failing}. */
  public static final class FailingProvider extends Provider {

    private static final long serialVersionUID = 1L;

    FailingProvider() {
      super("SunEC", 1.0, "SunEC that fails on request");
      put("AlgorithmParameters.EC", SunEcParameters.class.getName());
      put("KeyFactory.EC", FailingKeyFactory.class.getName());
      put("Signature.NONEwithECDSA", FailingSignature.class.getName());
    }
  }

  /** Offers SunEC's "NONEwithECDSA" signatures and nothing else. */
  public static final class SignatureOnlyProvider extends Provider {

    private static final long serialVersionUID = 1L;

    SignatureOnlyProvider() {
      super("AsymmetricPrimitivesSignatureOnly", 1.0, "NONEwithECDSA only");
      put("Signature.NONEwithECDSA", FailingSignature.class.getName());
    }
  }

  public static final class FailingKeyFactory extends KeyFactorySpi {

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
      fail("generatePublic", new InvalidKeySpecException("generatePublic"));
      return sunEc().generatePublic(keySpec);
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
      fail("generatePrivate", new InvalidKeySpecException("generatePrivate"));
      return sunEc().generatePrivate(keySpec);
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
      return sunEc().getKeySpec(key, keySpec);
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
      return sunEc().translateKey(key);
    }

    private static KeyFactory sunEc() {
      try {
        return KeyFactory.getInstance("EC", SUN_EC);
      } catch (NoSuchAlgorithmException e) {
        throw new IllegalStateException(e);
      }
    }
  }

  public static final class FailingSignature extends SignatureSpi {

    private final Signature sunEc;

    public FailingSignature() throws NoSuchAlgorithmException {
      sunEc = Signature.getInstance("NONEwithECDSA", SUN_EC);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      fail("initVerify", new InvalidKeyException("initVerify"));
      sunEc.initVerify(publicKey);
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      fail("initSign", new InvalidKeyException("initSign"));
      sunEc.initSign(privateKey);
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
      sunEc.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
      sunEc.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      fail("sign", new SignatureException("sign"));
      return sunEc.sign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      return sunEc.verify(sigBytes);
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

  private static <E extends Exception> void fail(String step, E exception) throws E {
    if (failing.equals(step)) {
      throw exception;
    }
  }
}
