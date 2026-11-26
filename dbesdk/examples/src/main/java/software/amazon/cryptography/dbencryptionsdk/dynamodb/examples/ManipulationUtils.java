package software.amazon.cryptography.dbencryptionsdk.dynamodb.examples;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.ServiceException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.exceptions.VerificationFailedException;
import software.amazon.cryptography.dbencryptionsdk.dynamodb.itemencryptor.DynamoDbItemEncryptor;
import software.amazon.cryptography.materialproviders.exceptions.Service;

/**
 * Helpers that the enhanced client examples use to show what each attribute action protects. Each
 * manipulate method returns a copy of an encrypted item with one attribute changed, and each assert
 * method decrypts that copy and checks that it fails, or still succeeds, in the expected way.
 */
public final class ManipulationUtils {

  private ManipulationUtils() {}

  public static class ManipulationException extends RuntimeException {

    public ManipulationException(String message) {
      super(message);
    }

    public ManipulationException(String message, Throwable throwable) {
      super(message, throwable);
    }
  }

  // Assert a manipulated encrypted attribute fails the authentication (signature) check.
  public static void assertManipulationProof(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> manipulated,
    String attributeName
  ) {
    try {
      itemEncryptor.decryptItem(manipulated);
    } catch (VerificationFailedException exception) {
      return;
    }
    throw new ManipulationException(
      String.format(
        "Attribute Named %s was supposedly manipulated but did not fail Authorization Check!",
        attributeName
      )
    );
  }

  // Assert a manipulated key attribute fails specifically because it is bound into the encryption
  // context. The key attribute values are part of the encryption context that AWS KMS checks when
  // it decrypts the data key, so AWS KMS rejects the request with InvalidCiphertextException. The
  // DB-ESDK reports an AWS KMS error as a ServiceException that keeps AWS KMS's error code, so the
  // check matches on awsErrorCode(). Any other failure is the wrong failure.
  public static void assertProtectedByEncryptionContext(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> manipulated,
    String attributeName
  ) {
    try {
      itemEncryptor.decryptItem(manipulated);
    } catch (ServiceException exception) {
      if (
        exception.service() == Service.KMS &&
        "InvalidCiphertextException".equals(exception.awsErrorCode())
      ) {
        return;
      }
      throw new ManipulationException(
        String.format(
          "Attribute Named %s was supposedly manipulated but failed for a reason other than" +
          " the Encryption Context Check!",
          attributeName
        ),
        exception
      );
    }
    throw new ManipulationException(
      String.format(
        "Attribute Named %s was supposedly manipulated but did not fail Encryption Context" +
        " Check! (Or at least it did not fail it as expected!)",
        attributeName
      )
    );
  }

  // Assert a manipulated DO_NOTHING attribute still decrypts: it is neither signed nor encrypted,
  // so changing it must not fail the authentication check.
  public static void assertNotManipulationProof(
    DynamoDbItemEncryptor itemEncryptor,
    Map<String, AttributeValue> manipulated,
    String attributeName
  ) {
    try {
      itemEncryptor.decryptItem(manipulated);
    } catch (VerificationFailedException exception) {
      throw new ManipulationException(
        String.format(
          "Attribute Named %s was supposedly manipulated and is NOT SIGNED " +
          "but it failed Authorization Check!%n" +
          "\tAttribute Value: %s",
          attributeName,
          manipulated.get(attributeName)
        ),
        exception
      );
    }
  }

  public static Map<String, AttributeValue> manipulateByteAttribute(
    Map<String, AttributeValue> item,
    String attributeName
  ) {
    Map<String, AttributeValue> manipulated = new HashMap<>(item);
    ByteArrayOutputStream concatStream = new ByteArrayOutputStream();
    concatStream.writeBytes(item.get(attributeName).b().asByteArray());
    concatStream.writeBytes("Manipulation!".getBytes(StandardCharsets.UTF_8));
    manipulated.put(
      attributeName,
      AttributeValue.fromB(SdkBytes.fromByteArray(concatStream.toByteArray()))
    );
    return manipulated;
  }

  public static Map<String, AttributeValue> manipulateStringAttribute(
    Map<String, AttributeValue> item,
    String attributeName
  ) {
    Map<String, AttributeValue> manipulated = new HashMap<>(item);
    String concatString = item.get(attributeName).s() + "Manipulation!";
    manipulated.put(attributeName, AttributeValue.fromS(concatString));
    return manipulated;
  }

  public static Map<String, AttributeValue> manipulateNumberAttribute(
    Map<String, AttributeValue> item,
    String attributeName
  ) {
    Map<String, AttributeValue> manipulated = new HashMap<>(item);
    int manipulatedInt = Integer.parseInt(item.get(attributeName).n()) + 1;
    manipulated.put(
      attributeName,
      AttributeValue.fromN(Integer.toString(manipulatedInt))
    );
    return manipulated;
  }
}
