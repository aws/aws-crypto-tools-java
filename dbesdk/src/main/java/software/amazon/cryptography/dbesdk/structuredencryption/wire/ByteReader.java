package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import java.util.Arrays;
import software.amazon.cryptography.dbesdk.structuredencryption.StructuredEncryptionException;

/**
 * Sequential big-endian reader over a header byte array. Every read that would
 * run past the end fails with the same message the Dafny deserializer uses, so
 * a truncated header is rejected rather than throwing an index exception.
 */
public final class ByteReader {

    private final byte[] data;
    private int position;

    public ByteReader(byte[] data) {
        this.data = data;
    }

    public int remaining() {
        return data.length - position;
    }

    public int readByte() {
        require(1);
        return data[position++] & 0xFF;
    }

    public int readUint16() {
        require(2);
        int value = ((data[position] & 0xFF) << 8) | (data[position + 1] & 0xFF);
        position += 2;
        return value;
    }

    public byte[] readBytes(int length) {
        require(length);
        byte[] out = Arrays.copyOfRange(data, position, position + length);
        position += length;
        return out;
    }

    private void require(int count) {
        if (count < 0 || remaining() < count) {
            throw new StructuredEncryptionException("Unexpected end of header data.");
        }
    }
}
