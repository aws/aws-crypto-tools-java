// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.cryptography.materialproviders.KeyringTests.Outcomes;
import software.amazon.cryptography.materialproviders.KeyringTests.Pair;
import software.amazon.cryptography.materialproviders.fakeaws.FakeAws;
import software.amazon.cryptography.materialproviders.fakeaws.RecordedRequest;
import software.amazon.cryptography.materialproviders.model.DecryptionMaterials;
import software.amazon.cryptography.materialproviders.model.EncryptedDataKey;
import software.amazon.cryptography.materialproviders.model.EncryptionMaterials;
import software.amazon.cryptography.materialproviders.model.GetClientInput;

/**
 * Shared pieces of the KMS keyring differential tests: both sides talk to one {@link FakeAws},
 * and each comparison checks the outcome and the KMS requests each side sent.
 */
final class KmsKeyringTests {

  static final String REGION = "us-west-2";
  static final String OTHER_REGION = "eu-west-1";

  private KmsKeyringTests() {}

  /** Runs one operation on each side and asserts the same outcome and the same KMS requests. */
  static String assertSame(FakeAws aws, Outcomes outcomes, String operation, Supplier<Object> reference, Supplier<Object> nativeCall, String context) {
    return assertSame(aws, outcomes, operation, reference, nativeCall, context, new String[0]);
  }

  /** As {@link #assertSame}, ignoring request fields that legitimately differ, such as a random data key. */
  static String assertSame(
    FakeAws aws,
    Outcomes outcomes,
    String operation,
    Supplier<Object> reference,
    Supplier<Object> nativeCall,
    String context,
    String... ignoredFields
  ) {
    aws.clearRequests();
    String expected = normalized(ReferenceMpl.outcome(reference));
    String actual = normalized(ReferenceMpl.outcome(nativeCall));
    assertEquals(expected, actual, context);
    assertEquals(
      RecordedRequest.describe(aws.requests(ReferenceAws.REFERENCE), ignoredFields),
      RecordedRequest.describe(aws.requests(ReferenceAws.NATIVE), ignoredFields),
      "KMS requests: " + context
    );
    aws.clearRequests();
    return outcomes.record(operation, actual);
  }

  static String assertSameEncrypt(FakeAws aws, Outcomes outcomes, Pair keyrings, EncryptionMaterials materials, String context) {
    boolean dataKeyGiven = materials.plaintextDataKey() != null;
    return assertSame(
      aws,
      outcomes,
      "OnEncrypt",
      () -> maskedKms(keyrings.referenceEncrypt(materials), dataKeyGiven),
      () -> maskedKms(keyrings.nativeEncrypt(materials), dataKeyGiven),
      context + " " + ReferenceMpl.describe(materials),
      // A generated data key differs between the sides, and later keyrings encrypt it.
      dataKeyGiven ? new String[0] : new String[] { "Plaintext" }
    );
  }

  static String assertSameDecrypt(
    FakeAws aws,
    Outcomes outcomes,
    Pair keyrings,
    DecryptionMaterials materials,
    List<EncryptedDataKey> edks,
    String context
  ) {
    Object input = KeyringTests.decryptInput(materials, edks);
    return assertSame(
      aws,
      outcomes,
      "OnDecrypt",
      () -> ReferenceMpl.call(keyrings.referenceKeyring, "OnDecrypt", input),
      () -> keyrings.nativeKeyring.OnDecrypt(KeyringTests.decryptInput(materials, edks)),
      context + " " + ReferenceMpl.describe(input)
    );
  }

  /** The AWS SDK puts the response's request id in its messages; the two sides' requests have different ids. */
  static String normalized(String outcome) {
    return outcome.replaceAll("Request ID: [^,)]*", "Request ID: <id>");
  }

  /**
   * Encryption output with the random parts replaced by their lengths: each KMS ciphertext,
   * a generated data key, and the symmetric signing keys. The provider info (a key ARN) is shown as text.
   */
  static String maskedKms(EncryptionMaterials materials, boolean dataKeyGiven) {
    List<String> edks = new ArrayList<>();
    for (EncryptedDataKey edk : materials.encryptedDataKeys()) {
      edks.add(
        edk.keyProviderId() + " info " + new String(KeyringTests.array(edk.keyProviderInfo()), StandardCharsets.UTF_8) +
        " ciphertext " + edk.ciphertext().remaining()
      );
    }
    List<Integer> symmetric = new ArrayList<>();
    if (materials.symmetricSigningKeys() != null) {
      for (ByteBuffer key : materials.symmetricSigningKeys()) {
        symmetric.add(key.remaining());
      }
    }
    EncryptionMaterials rest = materials
      .toBuilder()
      .encryptedDataKeys(Collections.emptyList())
      .symmetricSigningKeys(null)
      .plaintextDataKey(dataKeyGiven ? materials.plaintextDataKey() : null)
      .build();
    return (
      ReferenceMpl.describe(rest) + " data key " + (materials.plaintextDataKey() == null ? "none" : KeyringTests.array(materials.plaintextDataKey()).length) +
      " edks " + edks + " symmetric signing keys " + (materials.symmetricSigningKeys() == null ? "null" : symmetric)
    );
  }

  /**
   * A client supplier for both sides: fake KMS clients per Region, created on first use; {@code ""} gets a {@link #REGION} client.
   * Each side's calls are recorded separately, see {@link Supplied#calls}.
   */
  static Supplied supplier(FakeAws aws) {
    java.util.Map<String, KmsClient> clients = new java.util.HashMap<>();
    return new Supplied(input -> clients.computeIfAbsent(input.region(), region -> ReferenceAws.kms(aws, region.isEmpty() ? REGION : region)));
  }

  /** An old-interface supplier that the reference side gets as its own implementation of the same behavior. */
  static final class Supplied implements IClientSupplier, ReferenceMpl.Paired {

    private final java.util.function.Function<GetClientInput, KmsClient> behavior;
    private final List<String> nativeCalls = new ArrayList<>();
    private final List<String> referenceCalls = new ArrayList<>();
    private final Object reference;

    Supplied(java.util.function.Function<GetClientInput, KmsClient> behavior) {
      this.behavior = behavior;
      this.reference = ReferenceMpl.customer("materialproviders.IClientSupplier", referenceCalls, argument -> behavior.apply((GetClientInput) argument));
    }

    @Override
    public KmsClient GetClient(GetClientInput input) {
      nativeCalls.add("GetClient " + ReferenceMpl.describe(input));
      return behavior.apply(input);
    }

    @Override
    public Object reference() {
      return reference;
    }

    /** Asserts that both sides asked for the same clients, in the same order, and forgets the calls. */
    void assertSameCalls(String context) {
      assertEquals(referenceCalls, nativeCalls, "GetClient calls: " + context);
      nativeCalls.clear();
      referenceCalls.clear();
    }
  }
}
