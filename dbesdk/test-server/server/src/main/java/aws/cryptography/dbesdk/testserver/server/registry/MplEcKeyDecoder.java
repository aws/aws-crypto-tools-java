package aws.cryptography.dbesdk.testserver.server.registry;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

/**
 * Decodes the Material Providers Library's ECDSA P-384 key encoding into JCE
 * keys the native footer signs and verifies with. The MPL encodes a private key
 * as the signed big-endian scalar and a public key as a SEC-1 compressed point,
 * so a native signer resolving materials from an MPL CMM must reverse both.
 */
final class MplEcKeyDecoder {

    private static final int PREFIX_EVEN_Y = 2;
    private static final int PREFIX_ODD_Y = 3;

    private MplEcKeyDecoder() {}

    static PrivateKey decodePrivateKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance("EC")
                .generatePrivate(new ECPrivateKeySpec(new BigInteger(encoded), p384Params()));
        } catch (Exception e) {
            throw new IllegalStateException("Could not decode MPL EC private key", e);
        }
    }

    static PublicKey decodePublicKey(byte[] encoded) {
        try {
            ECParameterSpec params = p384Params();
            return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(decompressPoint(encoded, params), params));
        } catch (Exception e) {
            throw new IllegalStateException("Could not decode MPL EC public key", e);
        }
    }

    private static ECPoint decompressPoint(byte[] encoded, ECParameterSpec params) {
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, encoded.length));
        BigInteger yParity = switch (encoded[0]) {
            case PREFIX_EVEN_Y -> BigInteger.ZERO;
            case PREFIX_ODD_Y -> BigInteger.ONE;
            default -> throw new IllegalStateException("Invalid compressed point prefix");
        };
        BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
        BigInteger a = params.getCurve().getA();
        BigInteger b = params.getCurve().getB();
        // y^2 = x^3 + a*x + b (mod p); the square root is closed-form because P-384's p ≡ 3 (mod 4).
        BigInteger ySquared = x.modPow(BigInteger.valueOf(3), p).add(a.multiply(x).mod(p)).add(b).mod(p);
        BigInteger beta = ySquared.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        BigInteger y = beta.mod(BigInteger.TWO).equals(yParity) ? beta : p.subtract(beta);
        return new ECPoint(x, y);
    }

    private static ECParameterSpec p384Params() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp384r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new IllegalStateException("secp384r1 parameters unavailable", e);
        }
    }
}
