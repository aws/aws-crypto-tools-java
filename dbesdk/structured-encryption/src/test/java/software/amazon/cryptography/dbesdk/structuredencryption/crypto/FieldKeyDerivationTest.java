package software.amazon.cryptography.dbesdk.structuredencryption.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.dbesdk.structuredencryption.crypto.FieldKeyDerivation.FieldKey;

class FieldKeyDerivationTest {

    private record Vector(String rootKeyHex, int offset, String fieldKeyHex) {}

    // The 40 golden vectors from test/Crypt.dfy TestFieldKey: (32-byte root key,
    // offset) -> 44-byte FieldKey (32-byte cipher key ++ 12-byte nonce), one
    // block of 8 offsets per root key.
    private static final List<Vector> VECTORS = List.of(
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 0, "4d17ac4f80763c4f5c1523ca2322b89918d5ad8b728aea9e052b177e41570f7be7ff404ace5e9b22aa1e8968"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 1, "18fcefe222b4d2a414c908f35c2e09153068198ad2b33fd0921596e5b02e7c1a48b2c6e720dc75167db54f46"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 2, "ec387607afb264f56ba44abd037c469fdfff9d5861a976a4261083e6dfa48d883b6c85c440003ed094a1eee7"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 3, "7124e0a5e057d168d17c76be6d61efff694048b301786d7952f463b509d2a542fe5cdf045f096f99ec3dca5b"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 4, "56e053ebe6f7a937b9fec2847e82b3a9c5daa20d49d9e6eb7951595e68a0bb826277d52685464da6cf8271d8"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 5, "8aacffc78d68c3350f510883394edfb1caaf21ddf363485dc4f6bcb4aef7a4dfaf8a0a0b9f647accc39db0f6"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 6, "7fb8a9f5b5e8c838523944fe7da143ef0dab663df66ef22c0cec7653b541115dfda3a55fae43c4a27459909d"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000000", 7, "edfa5a6c99e14d131753163c2b890b135b8a6d4e310884d7d365a0670ef46686ef44b77c1c5a945797f17dd5"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 0, "c6a8b4e10a23bac8e13ae2d4edc0311509a5ce01b4d2357f8b1e667eeef77066cb9a2c4481d66ad1ede3d50f"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 1, "d54d4fe8e8295a523644dd49698f637a30f0c1e868c47a2a38e0e756ca0fcdee8e5aa355796debbb8fcb898b"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 2, "254489ab5be234d848f4fb21cba3ea27962c50363c9924054fffe34bd4f87d641fdb793224ccbf3e6ca9fa60"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 3, "b600f98e1c868209de7d563362ab8131bc8d0a5b58bf2590a8309889a94ee505515a02692824f7e32a31142f"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 4, "0af797f151dca40bd6db2cf69d5f3fdb98f34a3efe5f4af778cb3f8b942b507bd6eca848dd8e4b62e9d2db42"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 5, "9207c0c3dacd1b015d92689b78ba0bd49a1547f670d20097cc94cd35e569af02597a187f2ff7402f92149a19"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 6, "ca14fb5a292ec5f76669a04811532d3ed0d09421bdce95d629b0d3259b35888cf17e28e1ed4c1c136b4e5866"),
        new Vector("0000000000000000000000000000000000000000000000000000000000000001", 7, "da1188242ab66975027f11e49ecca9e7e23aaf1215855c263460a24f7d000cab89600be8ad6781d226190bed"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0, "0c7e451b952b793d95c66bef5df16a7e42cd70bca33d5f9e01651751b4dbff0e4f9524335caef55a68d55f2a"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1, "de3cdd84c99d3f6c011469433b2c24994e1836f2c923ee1fab47c3bedca95c1dd0fc547887cf9948efe1ffb6"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 2, "a088b21f062333d7a588da26ae30e11239949abd30b8a971621f2d664e5f2406212a4d51a04e63d314de54c3"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 3, "dc3448317b6d74b6dd662a9270fe808ab1dd7faf0f009e6e5e9f3aaac969d947d81e5bbc933819b8d6f2d76e"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 4, "87c5acfda18b650896588cd1f67e8f69cab31aed59df54b49c0748f4646e4789153bccb33b96ed760e9dfd44"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 5, "392d11b7e0884a5e42ef50f408cd79cbb0b96f792d67025527fd0ff0cfacad33c4dcead6021b34e4d0d1a3a2"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 6, "6092ee61588d3b1013b82c05ea7a894cdb9649d2fa8695f731c946aa75c47c4db0996bff661f8a796533c348"),
        new Vector("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 7, "d0270cfa0da88692a057c39b39644970786367da64008206e51a799af19f65db5b1531d01c52216431c451e5"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 0, "772cb513bc2bebfed36dfa3c22dec2c5cb09466dd1b5275cd1f2713339b32e9c7993c521808a0bd6faa4cb4f"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1, "e93a3a5dd1633af15027c2ec078fc536ddf295110dfa5053592842a8c1f1010ad15c2462d0371ff27d98e99b"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 2, "66f92041859c2000b8ff492629ae1ef875666c360fcfadeefe11e9f9f257887c4d1289c43ac1a442ec14a426"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 3, "02dd4a565fcc6d308ce3f9a2818c8426c3476b2fb6ea66f1c4688c313b061177a6c69a2663122e4c5f3895dd"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 4, "010a7cd17c89ac7668ba45332bdd956e388113f1ee9d01f387c5574ffdd86ade24b0430300d4009b0802335f"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 5, "aecfa53a5f05f6b3b5185584573d527790c8d3504d5a0deb2af3d58c35164d58f232704851f7c9f357dcfb5b"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 6, "3482b90bb7ddbed3d2b1f270ea648043539d7d6797861ec12c3d0797a07d31ecf3b160aab844008934823436"),
        new Vector("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 7, "5c82960fb8370644b7fb7fd41f090e0098f52130379381ed4c21379fa65884e6e1367326c067856388b57589"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 0, "d7d8c2e84dd5f56663b98501bf702a04f32451e62a1c30177d89bbf51beadd1090718c72ba120f7f20cf1e97"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 1, "fadae5fa4f62e4cbec50d3b4572166fbccc114cb800ed066a4632e966fa18f1189a1fb7cd20ad1c93f29531d"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 2, "14db82fab8f6f8e49a8061cf1689172b5bd37508560a8e9d42c21c507657a64a47545b155304c73198847429"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 3, "4d83002cf87da3f9670999c707ee4ed8483c297390eb5abb989ea8cb514f4bf27e43bf1f92e6b76c3045080e"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 4, "06fbc86f1e9716f218823710ef51b4558476a1cff4e5d706baac5ad14de544eb7e94197677f99cb46e12d63c"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 5, "12ede6750d1f02e0aca4b159f4b7aac9fca85355ac7f21e39f44b37e4157dea6f76b9fd44aa7fe540256522b"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 6, "7bfd555c3be12c57402b5db97cbfd897aefec952c3ba878642e5b22005cf1074ce854d210ac3c48c5fd0fbe2"),
        new Vector("59d9a5166a507f3cf0dfd60809a8b387b409d0b0c935abbfe08833fa9ffc1ecc", 7, "20847d5de204cb578f3012940fa9876ddb3386ae9719cf9adcbdd611385011b2e7d5375fb6d3fd5ea77ba461"));

    @Test
    void matchesDafnyFieldKeyVectors() {
        HexFormat hex = HexFormat.of();
        for (Vector vector : VECTORS) {
            FieldKey fieldKey = FieldKeyDerivation.fieldKey(hex.parseHex(vector.rootKeyHex()), vector.offset());
            byte[] actual = new byte[fieldKey.cipherKey().length + fieldKey.nonce().length];
            System.arraycopy(fieldKey.cipherKey(), 0, actual, 0, fieldKey.cipherKey().length);
            System.arraycopy(fieldKey.nonce(), 0, actual, fieldKey.cipherKey().length, fieldKey.nonce().length);
            assertArrayEquals(
                hex.parseHex(vector.fieldKeyHex()), actual,
                () -> "rootKey=" + vector.rootKeyHex() + " offset=" + vector.offset());
        }
    }

    /**
     * The Field Root Key has no standalone golden vector (test/Crypt.dfy feeds
     * the root key directly). The one non-obvious byte-level input to its HKDF
     * is the info string, so pin that: the label bytes and their order, ahead of
     * the message id.
     */
    @Test
    void deriveKeyInfoIsLabelThenMessageId() {
        byte[] messageId = {0x01, 0x02, 0x03, 0x04};
        byte[] expected = {
            0x41, 0x57, 0x53, 0x5f, 0x44, 0x42, 0x45, 0x5f, // "AWS_DBE_"
            0x44, 0x45, 0x52, 0x49, 0x56, 0x45, 0x5f, 0x4b, 0x45, 0x59, // "DERIVE_KEY"
            0x01, 0x02, 0x03, 0x04
        };

        assertArrayEquals(expected, FieldKeyDerivation.deriveKeyInfo(messageId));
    }
}
