package software.amazon.cryptography.dbesdk.dynamodbencryption;

/**
 * Signals an invalid beacon configuration or input — a beacon length or partition
 * outside the supported range, or a failure computing the beacon HMAC (Beacon
 * behavior spec §2–§4).
 */
public class BeaconException extends RuntimeException {

    public BeaconException(String message) {
        super(message);
    }
}
