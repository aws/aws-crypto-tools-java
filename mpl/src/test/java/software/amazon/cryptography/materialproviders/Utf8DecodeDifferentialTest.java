// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.Test;
import software.amazon.cryptography.mpl.EncryptedDataKey;
import software.amazon.cryptography.mpl.EncryptionContext;
import software.amazon.cryptography.mpl.exceptions.ValidationException;

// EncryptionContext.fromUtf8 and EncryptedDataKey.ofUtf8 accept exactly the bytes the reference's UTF8.Decode accepts,
// and decode them to the same string. The Dafny DB-ESDK decodes header contexts and provider ids with UTF8.Decode.
class Utf8DecodeDifferentialTest {

  @Test
  void everyOneAndTwoByteSequence() throws Exception {
    Decoder reference = new Decoder();
    for (int first = 0; first < 256; first++) {
      assertSame(reference, new byte[] { (byte) first });
      for (int second = 0; second < 256; second++) {
        assertSame(reference, new byte[] { (byte) first, (byte) second });
      }
    }
  }

  @Test
  void edgesOfThreeAndFourByteSequences() throws Exception {
    Decoder reference = new Decoder();
    List<byte[]> cases = new ArrayList<>();
    // Overlong forms, encoded surrogates, the largest code points, and just past them; truncations of each.
    int[][] sequences = {
      { 0xE0, 0x80, 0x80 }, { 0xE0, 0x9F, 0xBF }, { 0xE0, 0xA0, 0x80 }, { 0xED, 0x9F, 0xBF }, { 0xED, 0xA0, 0x80 },
      { 0xED, 0xBF, 0xBF }, { 0xEE, 0x80, 0x80 }, { 0xEF, 0xBF, 0xBF }, { 0xEF, 0xBB, 0xBF }, { 0xEF, 0xBF, 0xBD },
      { 0xF0, 0x80, 0x80, 0x80 }, { 0xF0, 0x8F, 0xBF, 0xBF }, { 0xF0, 0x90, 0x80, 0x80 }, { 0xF0, 0x9F, 0x98, 0x80 },
      { 0xF4, 0x8F, 0xBF, 0xBF }, { 0xF4, 0x90, 0x80, 0x80 }, { 0xF5, 0x80, 0x80, 0x80 }, { 0xF8, 0x88, 0x80, 0x80, 0x80 },
      { 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80 },
    };
    for (int[] sequence : sequences) {
      for (int length = 1; length <= sequence.length; length++) {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++) {
          bytes[i] = (byte) sequence[i];
        }
        cases.add(bytes);
      }
    }
    // Random 3- and 4-byte sequences with lead bytes from E0 to F7, where most of the rules apply.
    Random random = new Random(7);
    for (int i = 0; i < 20000; i++) {
      byte[] bytes = new byte[3 + random.nextInt(2)];
      bytes[0] = (byte) (0xE0 + random.nextInt(0x18));
      for (int j = 1; j < bytes.length; j++) {
        bytes[j] = (byte) (0x70 + random.nextInt(0x60));
      }
      cases.add(bytes);
    }
    for (byte[] bytes : cases) {
      assertSame(reference, bytes);
    }
    assertTrue(reference.accepted > 0 && reference.rejected > 0, reference.accepted + " accepted, " + reference.rejected + " rejected");
  }

  private static void assertSame(Decoder reference, byte[] bytes) throws Exception {
    String expected = reference.decode(bytes);
    String context = ReferenceMpl.describe(java.nio.ByteBuffer.wrap(bytes));
    assertEquals(expected, nativeDecode(() -> EncryptionContext.fromUtf8(Collections.singletonMap("k", bytes)).get("k")), context);
    assertEquals(expected, nativeDecode(() -> EncryptedDataKey.ofUtf8(bytes, new byte[0], new byte[0]).keyProviderId()), context);
  }

  // The decoded string, or null when the bytes are rejected.
  private static String nativeDecode(java.util.function.Supplier<String> decode) {
    try {
      return decode.get();
    } catch (ValidationException e) {
      return null;
    }
  }

  /** The reference's {@code UTF8.Decode}: the decoded string, or null on failure. */
  private static final class Decoder {

    private final Method fromBytes;
    private final Method decode;
    private final Method verbatimString;
    int accepted;
    int rejected;

    Decoder() throws Exception {
      ClassLoader loader = ReferenceMpl.loader();
      Class<?> sequence = loader.loadClass("dafny.DafnySequence");
      fromBytes = sequence.getMethod("fromBytes", byte[].class);
      decode = loader.loadClass("UTF8.__default").getMethod("Decode", sequence);
      // Through the public DafnySequence: the runtime class of a decoded value is not public.
      verbatimString = sequence.getMethod("verbatimString");
    }

    String decode(byte[] bytes) throws Exception {
      Object result = decode.invoke(null, fromBytes.invoke(null, (Object) bytes));
      if (!(Boolean) result.getClass().getMethod("is_Success").invoke(result)) {
        rejected++;
        return null;
      }
      accepted++;
      Object value = result.getClass().getMethod("dtor_value").invoke(result);
      return (String) verbatimString.invoke(value);
    }
  }
}
