package software.amazon.cryptography.build;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class ApiSurfaceTest {

  // Every class in Fixtures, nested builders included, as the task would load them.
  private static List<Class<?>> fixtureClasses() {
    List<Class<?>> classes = new ArrayList<>();
    List<Class<?>> todo = new ArrayList<>(Arrays.asList(Fixtures.class.getDeclaredClasses()));
    while (!todo.isEmpty()) {
      Class<?> next = todo.remove(0);
      classes.add(next);
      todo.addAll(Arrays.asList(next.getDeclaredClasses()));
    }
    return classes;
  }

  private static ApiSurface.Api api(String id) {
    return ApiSurface.discover("mpl", fixtureClasses()).apis.stream()
        .filter(a -> a.id.equals(id))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no api " + id));
  }

  // "kind id option [overloads]", one line per way.
  private static List<String> ways(String apiId) {
    return api(apiId).ways.stream()
        .map(w -> w.kind + " " + w.id + " " + w.option + " " + w.overloads)
        .collect(Collectors.toList());
  }

  @Test
  void findsOnlyKeyringsCmmsAndTheClient() {
    List<String> ids =
        ApiSurface.discover("mpl", fixtureClasses()).apis.stream()
            .map(a -> a.id + " " + a.group + " " + a.name)
            .collect(Collectors.toList());
    assertEquals(
        Arrays.asList(
            "encrypt-input Client Encrypt input",
            "esdk-client Client ESDK client",
            "fake-cmm CMMs Fake CMM",
            "fake-keyring Keyrings Fake keyring"),
        ids);
  }

  @Test
  void groupsOverloadsAndFindsBuilderSetters() {
    assertEquals(
        Arrays.asList(
            "constructor builder null []",
            "constructor fromKeyName null [String]",
            "setter grantTokens grantTokens [Collection, String...]",
            "setter keyName keyName [String]",
            "setter wrappingKey wrappingKey [String, byte[]]"),
        ways("fake-keyring"));
  }

  @Test
  void findsPublicConstructors() {
    assertEquals(Collections.singletonList("constructor new null [Keyring]"), ways("fake-cmm"));
  }

  @Test
  void findsClientOperationsAndTheirInputs() {
    assertEquals(
        Arrays.asList(
            "constructor builder null []",
            "setter maxEncryptedDataKeys maxEncryptedDataKeys [int]",
            "method encrypt null [EncryptInput]"),
        ways("esdk-client"));
    assertEquals(
        Arrays.asList("constructor builder null []", "setter plaintext plaintext [byte[]]"),
        ways("encrypt-input"));
  }

  @Test
  void listsEveryOverloadInTheSignature() {
    ApiSurface.Way grantTokens =
        api("fake-keyring").ways.stream().filter(w -> w.id.equals("grantTokens")).findFirst().get();
    assertEquals(
        "public Fixtures.FakeKeyring.Builder grantTokens(Collection<String>)\n"
            + "public Fixtures.FakeKeyring.Builder grantTokens(String...)",
        grantTokens.signature);
  }

  @Test
  void writesAnEmptySurfaceForALibraryWithNoApis() {
    assertEquals(
        "{\n  \"schema\": 1,\n  \"language\": \"java\",\n  \"library\": \"esdk\",\n  \"apis\": []\n}\n",
        ApiSurface.toJson(ApiSurface.discover("esdk", Collections.emptyList())));
  }
}
