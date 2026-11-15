package aws.cryptography.canary;

import java.util.Map;

/** Code that the CI gates must reject: each method has a gap that one gate checks. */
public final class Limits {

  private Limits() {}

  /** Whether {@code count} keys fit under {@code max}; a {@code max} of zero or less means no limit. */
  public static boolean withinLimit(int count, int max) {
    // No test passes a max of zero or less, so this branch is never taken.
    if (max <= 0) {
      return true;
    }
    // No test passes count == max, so changing <= to < survives.
    return count <= max;
  }

  /** No test calls this. */
  public static int twice(int x) {
    return x * 2;
  }

  /** Serializes an encryption context; only the empty case is written. */
  public static byte[] serialize(Map<String, String> context) {
    //= spec/framework/structures.md#serialization
    //# If the encryption context is empty, its serialization MUST be
    //# an empty byte sequence.
    if (context.isEmpty()) {
      return new byte[0];
    }
    //= spec/framework/structures.md#serialization
    //# This sentence is not in the specification.
    throw new UnsupportedOperationException("not written");
  }

  /** Error Prone rejects this: the exception is created and dropped. */
  public static void check(int x) {
    if (x < 0) {
      new IllegalArgumentException("negative");
    }
  }
}
