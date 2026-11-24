package software.amazon.cryptography.build;

import com.google.gson.GsonBuilder;
import java.lang.reflect.Constructor;
import java.lang.reflect.Executable;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Type;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Finds every public way to build or call a library's keyrings, CMMs, and ESDK client.
 *
 * <p>Overloads of one name are one way. The way's overloads list holds one label per overload
 * that takes parameters: the parameters' simple type names, such as {@code String} or {@code
 * byte[]}.
 */
public final class ApiSurface {

  /** Classes that implement an interface with this simple name are keyrings. */
  static final String KEYRING_INTERFACE = "Keyring";

  /** Classes that implement an interface with this simple name are CMMs. */
  static final String CMM_INTERFACE = "CryptographicMaterialsManager";

  /** A class with this simple name is the ESDK client. */
  static final String CLIENT_CLASS = "EsdkClient";

  static final String KEYRINGS = "Keyrings";
  static final String CMMS = "CMMs";
  static final String CLIENT = "Client";

  /** Words written in capitals in an API's display name. */
  private static final Set<String> ACRONYMS =
      new HashSet<>(Arrays.asList("aes", "aws", "cmm", "ecdh", "esdk", "kms", "mrk", "rsa"));

  private static final Pattern PACKAGE_PREFIX = Pattern.compile("(?<![\\w$])(?:[a-z][\\w]*\\.)+");

  private ApiSurface() {}

  static final class Surface {
    final int schema = 1;
    final String language = "java";
    final String library;
    final List<Api> apis;

    Surface(String library, List<Api> apis) {
      this.library = library;
      this.apis = apis;
    }
  }

  static final class Api {
    final String id;
    final String group;
    final String name;
    final String type;
    final List<Way> ways;

    Api(String id, String group, String name, String type, List<Way> ways) {
      this.id = id;
      this.group = group;
      this.name = name;
      this.type = type;
      this.ways = ways;
    }
  }

  static final class Way {
    final String id;
    final String option;
    final String kind;
    final String signature;
    final List<String> overloads;

    Way(String id, String option, String kind, String signature, List<String> overloads) {
      this.id = id;
      this.option = option;
      this.kind = kind;
      this.signature = signature;
      this.overloads = overloads;
    }
  }

  static Surface discover(String library, List<Class<?>> classes) {
    Map<String, Api> apis = new TreeMap<>();
    for (Class<?> type : classes) {
      if (!isPublicConcreteClass(type)) {
        continue;
      }
      Set<String> interfaces = interfaceNames(type);
      if (interfaces.contains(KEYRING_INTERFACE)) {
        add(apis, buildable(type, KEYRINGS));
      } else if (interfaces.contains(CMM_INTERFACE)) {
        add(apis, buildable(type, CMMS));
      } else if (type.getSimpleName().equals(CLIENT_CLASS)) {
        Api client = buildable(type, CLIENT);
        client.ways.addAll(operations(type));
        add(apis, client);
        // An operation's input, such as EncryptInput, is its own API when it has a builder.
        for (Method operation : operationMethods(type)) {
          for (Class<?> input : operation.getParameterTypes()) {
            if (builderOf(input) != null) {
              add(apis, buildable(input, CLIENT));
            }
          }
        }
      }
    }
    return new Surface(library, new ArrayList<>(apis.values()));
  }

  static String toJson(Surface surface) {
    return new GsonBuilder()
            .setPrettyPrinting()
            .serializeNulls()
            .disableHtmlEscaping()
            .create()
            .toJson(surface)
        + "\n";
  }

  private static void add(Map<String, Api> apis, Api api) {
    apis.putIfAbsent(api.id, api);
  }

  private static Api buildable(Class<?> type, String group) {
    List<Way> ways = new ArrayList<>();
    ways.addAll(constructors(type));
    Class<?> builder = builderOf(type);
    if (builder != null) {
      ways.addAll(setters(builder));
    }
    return new Api(id(type), group, name(type), type.getCanonicalName(), ways);
  }

  /** Public constructors, and public static methods that return the type or its builder. */
  private static List<Way> constructors(Class<?> type) {
    List<Way> ways = new ArrayList<>();
    if (type.getConstructors().length > 0) {
      ways.add(way("new", null, "constructor", Arrays.asList(type.getConstructors())));
    }
    Class<?> builder = builderOf(type);
    List<Method> factories =
        Arrays.stream(type.getMethods())
            .filter(m -> Modifier.isStatic(m.getModifiers()))
            .filter(m -> m.getReturnType() == type || m.getReturnType() == builder)
            .collect(Collectors.toList());
    ways.addAll(byName(factories, "constructor", false));
    return ways;
  }

  /** Public builder methods that return the builder. */
  private static List<Way> setters(Class<?> builder) {
    List<Method> setters =
        Arrays.stream(builder.getMethods())
            .filter(m -> !Modifier.isStatic(m.getModifiers()))
            .filter(m -> m.getReturnType() == builder)
            .collect(Collectors.toList());
    return byName(setters, "setter", true);
  }

  private static List<Way> operations(Class<?> client) {
    return byName(operationMethods(client), "method", false);
  }

  // Methods with no parameters, such as getters and close(), are not operations.
  private static List<Method> operationMethods(Class<?> client) {
    return Arrays.stream(client.getMethods())
        .filter(m -> m.getDeclaringClass() == client)
        .filter(m -> !Modifier.isStatic(m.getModifiers()))
        .filter(m -> m.getParameterCount() > 0)
        .collect(Collectors.toList());
  }

  private static List<Way> byName(List<Method> methods, String kind, boolean isOption) {
    Map<String, List<Executable>> byName = new TreeMap<>();
    for (Method m : methods) {
      if (!m.isBridge() && !m.isSynthetic()) {
        byName.computeIfAbsent(m.getName(), k -> new ArrayList<>()).add(m);
      }
    }
    List<Way> ways = new ArrayList<>();
    byName.forEach((name, overloads) -> ways.add(way(name, isOption ? name : null, kind, overloads)));
    return ways;
  }

  private static Way way(String id, String option, String kind, List<? extends Executable> overloads) {
    List<Executable> sorted = new ArrayList<>(overloads);
    sorted.sort(Comparator.comparing(ApiSurface::parameterLabel));
    String signature = sorted.stream().map(ApiSurface::signature).collect(Collectors.joining("\n"));
    List<String> labels =
        sorted.stream()
            .filter(e -> e.getParameterCount() > 0)
            .map(ApiSurface::parameterLabel)
            .distinct()
            .collect(Collectors.toList());
    return new Way(id, option, kind, signature, labels);
  }

  /** The nested public class named Builder, or null. */
  private static Class<?> builderOf(Class<?> type) {
    for (Class<?> nested : type.getClasses()) {
      if (nested.getSimpleName().equals("Builder") && nested.getDeclaringClass() == type) {
        return nested;
      }
    }
    return null;
  }

  private static boolean isPublicConcreteClass(Class<?> type) {
    int mods = type.getModifiers();
    return Modifier.isPublic(mods)
        && !Modifier.isAbstract(mods)
        && !type.isInterface()
        && !type.isAnonymousClass()
        && !type.isLocalClass()
        && !type.isSynthetic();
  }

  private static Set<String> interfaceNames(Class<?> type) {
    Set<String> names = new HashSet<>();
    Deque<Class<?>> todo = new ArrayDeque<>();
    for (Class<?> c = type; c != null; c = c.getSuperclass()) {
      todo.addAll(Arrays.asList(c.getInterfaces()));
    }
    while (!todo.isEmpty()) {
      Class<?> next = todo.pop();
      if (names.add(next.getSimpleName())) {
        todo.addAll(Arrays.asList(next.getInterfaces()));
      }
    }
    return names;
  }

  // AwsKmsKeyring -> aws-kms-keyring, RawAESKeyring -> raw-aes-keyring.
  static String id(Class<?> type) {
    return type.getSimpleName()
        .replaceAll("([a-z0-9])([A-Z])", "$1-$2")
        .replaceAll("([A-Z])([A-Z][a-z])", "$1-$2")
        .toLowerCase(Locale.ROOT);
  }

  // aws-kms-keyring -> AWS KMS keyring.
  static String name(Class<?> type) {
    String[] words = id(type).split("-");
    for (int i = 0; i < words.length; i++) {
      if (ACRONYMS.contains(words[i])) {
        words[i] = words[i].toUpperCase(Locale.ROOT);
      } else if (i == 0) {
        words[i] = Character.toUpperCase(words[i].charAt(0)) + words[i].substring(1);
      }
    }
    return String.join(" ", words);
  }

  private static String parameterLabel(Executable e) {
    Class<?>[] params = e.getParameterTypes();
    List<String> names = new ArrayList<>();
    for (int i = 0; i < params.length; i++) {
      String name = params[i].getSimpleName();
      if (e.isVarArgs() && i == params.length - 1) {
        name = name.substring(0, name.length() - "[]".length()) + "...";
      }
      names.add(name);
    }
    return String.join(", ", names);
  }

  // For example "public Builder grantTokens(Collection<String>)".
  private static String signature(Executable e) {
    StringBuilder s = new StringBuilder("public ");
    if (Modifier.isStatic(e.getModifiers())) {
      s.append("static ");
    }
    if (e instanceof Method) {
      s.append(typeName(((Method) e).getGenericReturnType())).append(' ').append(e.getName());
    } else {
      s.append(((Constructor<?>) e).getDeclaringClass().getSimpleName());
    }
    Type[] params = e.getGenericParameterTypes();
    List<String> names = new ArrayList<>();
    for (int i = 0; i < params.length; i++) {
      String name = typeName(params[i]);
      if (e.isVarArgs() && i == params.length - 1) {
        name = name.substring(0, name.length() - "[]".length()) + "...";
      }
      names.add(name);
    }
    return s.append('(').append(String.join(", ", names)).append(')').toString();
  }

  // java.util.List<java.lang.String> -> List<String>, a.b.Outer$Builder -> Outer.Builder.
  private static String typeName(Type type) {
    return PACKAGE_PREFIX.matcher(type.getTypeName()).replaceAll("").replace('$', '.');
  }
}
