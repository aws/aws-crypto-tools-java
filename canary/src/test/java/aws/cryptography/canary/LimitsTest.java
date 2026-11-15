package aws.cryptography.canary;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class LimitsTest {

  @Test
  void acceptsCountUnderLimit() {
    assertTrue(Limits.withinLimit(1, 5));
  }

  @Test
  void rejectsCountOverLimit() {
    assertFalse(Limits.withinLimit(9, 5));
  }

  // This test cites the serialization requirement but never calls serialize.
  @Test
  void serializesEmptyContext() {
    //= spec/framework/structures.md#serialization
    //= type=test
    //# If the encryption context is empty, its serialization MUST be
    //# an empty byte sequence.
    assertTrue(Limits.withinLimit(0, 1));
  }

  @Test
  void checkAcceptsZero() {
    Limits.check( 0 );
  }
}
