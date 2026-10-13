package aws.cryptography.dbesdk.testserver.server.config;

import java.nio.ByteBuffer;
import software.amazon.cryptography.dbesdk.dynamodbencryption.BeaconKeyRetriever;
import software.amazon.cryptography.keystore.KeyStore;
import software.amazon.cryptography.keystore.model.GetBeaconKeyInput;

/**
 * Bridges the MPL key store's {@code GetBeaconKey} (which reads the branch key from DynamoDB
 * and unwraps it with KMS) to the native {@link BeaconKeyRetriever} seam. This is the MPL
 * boundary for searchable encryption: the native library stays MPL-free and this adapter,
 * in the integration layer, supplies the raw beacon key.
 */
final class MplBeaconKeyRetriever implements BeaconKeyRetriever {

    private final KeyStore keyStore;

    MplBeaconKeyRetriever(KeyStore keyStore) {
        this.keyStore = keyStore;
    }

    @Override
    public byte[] getBeaconKey(String keyId) {
        ByteBuffer beaconKey = keyStore
            .GetBeaconKey(GetBeaconKeyInput.builder().branchKeyIdentifier(keyId).build())
            .beaconKeyMaterials()
            .beaconKey();
        byte[] out = new byte[beaconKey.remaining()];
        beaconKey.duplicate().get(out);
        return out;
    }
}
