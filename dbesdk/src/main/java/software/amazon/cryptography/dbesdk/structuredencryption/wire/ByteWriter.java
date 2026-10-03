package software.amazon.cryptography.dbesdk.structuredencryption.wire;

import java.io.ByteArrayOutputStream;

/** Accumulates big-endian wire fields into a byte array. */
public final class ByteWriter {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public ByteWriter writeByte(int value) {
        out.write(value & 0xFF);
        return this;
    }

    public ByteWriter writeUint16(int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
        return this;
    }

    public ByteWriter writeUint64(long value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.write((int) (value >>> shift) & 0xFF);
        }
        return this;
    }

    public ByteWriter writeBytes(byte[] bytes) {
        out.write(bytes, 0, bytes.length);
        return this;
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }
}
