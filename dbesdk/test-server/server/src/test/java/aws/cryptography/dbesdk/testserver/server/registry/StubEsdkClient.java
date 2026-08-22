package aws.cryptography.dbesdk.testserver.server.registry;

import aws.cryptography.dbesdk.testserver.server.error.DbesdkClientException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

/**
 * A trivial {@link DbesdkClient} stand-in used by the registry property tests,
 * which assert only on object identity ({@code register} stores an instance and
 * {@code resolve} returns the very same instance). The crypto methods are never
 * called by those tests, so they throw to make any accidental call obvious.
 *
 * <p>Error-mapping and handler property tests use the richer, controllable fake
 * {@code aws.cryptography.dbesdk.testserver.server.handler.ControllableEsdkClient}.
 */
final class StubEsdkClient implements DbesdkClient {

    @Override
    public byte[] encrypt(byte[] plaintext, Map<String, String> encryptionContext,
                          String algorithmSuiteId, Long frameLength) {
        throw new UnsupportedOperationException("StubEsdkClient does not encrypt");
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, Map<String, String> encryptionContext) {
        throw new UnsupportedOperationException("StubEsdkClient does not decrypt");
    }

    @Override
    public void encryptStream(InputStream plaintext, OutputStream ciphertext,
                              Map<String, String> encryptionContext,
                              String algorithmSuiteId, Long frameLength) throws DbesdkClientException {
        throw new UnsupportedOperationException("StubEsdkClient does not stream");
    }

    @Override
    public void decryptStream(InputStream ciphertext, OutputStream plaintext,
                              Map<String, String> encryptionContext) throws DbesdkClientException {
        throw new UnsupportedOperationException("StubEsdkClient does not stream");
    }

    @Override
    public boolean isStreamingCapable() {
        return true;
    }
}
