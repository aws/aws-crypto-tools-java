package software.amazon.cryptography.dbesdk.examples;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.dbencryptionsdk.structuredencryption.StructuredEncryptionException;

public final class ManipulationUtils {

  private ManipulationUtils() {}

  public static class ManipulationException extends RuntimeException {

    public ManipulationException(String msg) {
      super(msg);
    }

    public ManipulationException(Throwable throwable) {
      super(throwable);
    }

    public ManipulationException(String msg, Throwable throwable) {
      super(msg, throwable);
    }
  }

  // Assert a manipulated encrypted attribute fails the authentication (signature) check.
  public static void assertManipulationProof(
    final DynamoDbItemEncryptor itemEncryptor,
    final Map<String, AttributeValue> manipulated,
    final String attributeName
  ) {
    boolean manipulationProof = false;
    try {
      itemEncryptor.decryptItem(manipulated);
    } catch (StructuredEncryptionException ex) {
      manipulationProof = true;
    }
    if (!manipulationProof) {
      throw new ManipulationException(
        String.format(
          "Attribute Named %s was supposedly manipulated but did not fail Authorization Check!",
          attributeName
        )
      );
    }
  }

  // Assert a manipulated key attribute fails specifically because it is bound into the encryption
  // context. Every keyring attempt fails, surfacing as InvalidCiphertextException directly from
  // KMS. Anything else is the wrong failure.
  public static void assertProtectedByEncryptionContext(
    final DynamoDbItemEncryptor itemEncryptor,
    final Map<String, AttributeValue> manipulated,
    final String attributeName
  ) {
    boolean manipulationProof = false;
    final String exceptionMsg = String.format(
      "Attribute Named %s was supposedly manipulated but did not fail Encryption Context" +
      " Check! (Or at least it did not fail it as expected!)",
      attributeName
    );
    try {
      itemEncryptor.decryptItem(manipulated);
    } catch (InvalidCiphertextException ex) {
      manipulationProof = true;
    }
    if (!manipulationProof) {
      throw new ManipulationException(exceptionMsg);
    }
  }

  // Assert a manipulated DO_NOTHING attribute still decrypts: it is neither signed nor encrypted,
  // so changing it must not fail the authentication check.
  public static void assertNotManipulationProof(
    final DynamoDbItemEncryptor itemEncryptor,
    final Map<String, AttributeValue> manipulated,
    final String attributeName
  ) {
    try {
      itemEncryptor.decryptItem(manipulated);
    } catch (StructuredEncryptionException ex) {
      throw new ManipulationException(
        String.format(
          "Attribute Named %s was supposedly manipulated and is NOT SIGNED " +
          "but it failed Authorization Check!%n" +
          "\tAttribute Value: %s",
          attributeName,
          manipulated.get(attributeName)
        ),
        ex
      );
    }
  }

  public static Map<String, AttributeValue> manipulateByteAttribute(
    final Map<String, AttributeValue> item,
    final String attributeName
  ) throws IOException {
    final Map<String, AttributeValue> manipulated = new HashMap<>(item);
    final ByteArrayOutputStream concatStream = new ByteArrayOutputStream();
    concatStream.write(item.get(attributeName).b().asByteArray());
    concatStream.write(
      SdkBytes
        .fromString("Manipulation!", Charset.defaultCharset())
        .asByteArray()
    );
    manipulated.put(
      attributeName,
      AttributeValue.fromB(SdkBytes.fromByteArray(concatStream.toByteArray()))
    );
    return manipulated;
  }

  public static Map<String, AttributeValue> manipulateStringAttribute(
    final Map<String, AttributeValue> item,
    final String attributeName
  ) {
    final Map<String, AttributeValue> manipulated = new HashMap<>(item);
    final String concatString = item.get(attributeName).s() + "Manipulation!";
    manipulated.put(attributeName, AttributeValue.fromS(concatString));
    return manipulated;
  }

  public static Map<String, AttributeValue> manipulateNumberAttribute(
    final Map<String, AttributeValue> item,
    final String attributeName
  ) {
    final Map<String, AttributeValue> manipulated = new HashMap<>(item);
    final int manipulatedInt =
      Integer.parseInt(item.get(attributeName).n()) + 1;
    manipulated.put(
      attributeName,
      AttributeValue.fromN(Integer.toString(manipulatedInt))
    );
    return manipulated;
  }
}
