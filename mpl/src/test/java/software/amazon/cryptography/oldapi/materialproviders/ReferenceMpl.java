// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.oldapi.materialproviders;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * The published Dafny-based MPL, loaded in an isolated class loader, as a differential-test oracle.
 *
 * <p>It declares the same class names as this module and the old-API copy, so it is reached only by reflection.
 * {@link #toReference} and {@link #fromReference} rebuild a model value on the other side, mapping
 * {@code software.amazon.cryptography.oldapi.X} to {@code software.amazon.cryptography.X}; {@link #describe}
 * renders a value from either side as one comparable string.
 */
final class ReferenceMpl {

  private static final String JAR_PREFIX = "aws-cryptographic-material-providers-";
  private static final String MODEL_ROOT = "software.amazon.cryptography.";
  private static final String OLD_API_ROOT = MODEL_ROOT + "oldapi.";
  private static final String SDK_ROOT = "software.amazon.awssdk.";

  private static File jar;
  private static URLClassLoader loader;

  private ReferenceMpl() {}

  static synchronized File jar() {
    initialize();
    return jar;
  }

  static synchronized ClassLoader loader() {
    initialize();
    return loader;
  }

  private static void initialize() {
    if (loader != null) {
      return;
    }
    List<URL> urls = new ArrayList<>();
    for (String path : System.getProperty("mpl.reference.classpath").split(File.pathSeparator)) {
      File file = new File(path);
      try {
        urls.add(file.toURI().toURL());
      } catch (MalformedURLException e) {
        throw new IllegalStateException(e);
      }
      if (file.getName().startsWith(JAR_PREFIX)) {
        jar = file;
      }
    }
    Objects.requireNonNull(jar, "reference MPL jar is not on mpl.reference.classpath");
    // A null parent keeps this module's classes, some of which share the reference's names, out of the lookup.
    loader = new URLClassLoader(urls.toArray(new URL[0]), null);
  }

  /** Rebuilds a model value in the reference class loader; a value already there stays as is. */
  static Object toReference(Object value) {
    return rebuild(value, loader());
  }

  /** Rebuilds a reference model value as the test adapter's model value of the same class name under {@code oldapi}. */
  static Object fromReference(Object value) {
    return rebuild(value, ReferenceMpl.class.getClassLoader());
  }

  private static Object rebuild(Object value, ClassLoader target) {
    if (value == null || isShared(value)) {
      return value;
    }
    if (target == loader() && value.getClass().getClassLoader() == loader()) {
      return value;
    }
    if (value instanceof List) {
      List<Object> converted = new ArrayList<>();
      for (Object element : (List<?>) value) {
        converted.add(rebuild(element, target));
      }
      return converted;
    }
    if (value instanceof Map) {
      Map<Object, Object> converted = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
        converted.put(rebuild(entry.getKey(), target), rebuild(entry.getValue(), target));
      }
      return converted;
    }
    Class<?> type = value.getClass();
    // Each side has its own copy of the AWS SDK; its enums, such as KMS's EncryptionAlgorithmSpec, map by name.
    if (type.isEnum() && type.getName().startsWith(SDK_ROOT)) {
      return enumConstant(load(type.getName(), target), ((Enum<?>) value).name());
    }
    Class<?> targetType = load(targetName(type, target), target);
    if (type.isEnum()) {
      return enumConstant(targetType, ((Enum<?>) value).name());
    }
    Object builder = invoke(null, targetType, "builder");
    // A collection's builder appends the list's description to the message; set the list afterwards so it is not appended twice.
    boolean collection = type.getSimpleName().equals("CollectionOfErrors");
    Object list = null;
    for (Method accessor : accessors(type)) {
      Object field = invokeMethod(accessor, value);
      if (collection && accessor.getName().equals("list")) {
        list = rebuild(field, target);
      } else if (field != null) {
        invoke(builder, accessor.getName(), rebuild(field, target));
      }
    }
    Object built = invoke(builder, "build");
    if (collection) {
      setField(built, "list", list);
    }
    return built;
  }

  /** A canonical rendering of a model value from either class loader. */
  static String describe(Object value) {
    if (value == null) {
      return "null";
    }
    if (value instanceof ByteBuffer) {
      // Bytes [0, limit), plus every property in which the buffer differs from a freshly wrapped array.
      ByteBuffer buffer = (ByteBuffer) value;
      StringBuilder hex = new StringBuilder("0x");
      for (int i = 0; i < buffer.limit(); i++) {
        hex.append(String.format("%02x", buffer.get(i)));
      }
      if (buffer.position() != 0) {
        hex.append(" position=").append(buffer.position());
      }
      if (buffer.capacity() != buffer.limit()) {
        hex.append(" capacity=").append(buffer.capacity());
      }
      if (buffer.hasArray() && buffer.arrayOffset() != 0) {
        hex.append(" arrayOffset=").append(buffer.arrayOffset());
      }
      if (buffer.isReadOnly()) {
        hex.append(" readOnly");
      }
      if (buffer.isDirect()) {
        hex.append(" direct");
      }
      return hex.toString();
    }
    if (value instanceof String) {
      return '"' + (String) value + '"';
    }
    if (value instanceof Number || value instanceof Boolean) {
      return value.toString();
    }
    if (value instanceof Enum) {
      return ((Enum<?>) value).name();
    }
    if (value instanceof List) {
      List<String> elements = new ArrayList<>();
      for (Object element : (List<?>) value) {
        elements.add(describe(element));
      }
      return elements.toString();
    }
    if (value instanceof Map) {
      Map<String, String> entries = new TreeMap<>();
      for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
        entries.put(describe(entry.getKey()), describe(entry.getValue()));
      }
      return entries.toString();
    }
    Map<String, String> fields = new TreeMap<>();
    for (Method accessor : accessors(value.getClass())) {
      fields.put(accessor.getName(), describe(invokeMethod(accessor, value)));
    }
    return value.getClass().getSimpleName() + fields;
  }

  // Only the old-API copy maps to the reference, so a main class that shares a reference name is not rebuilt as it.
  private static String targetName(Class<?> type, ClassLoader target) {
    String name = type.getName();
    if (target == loader()) {
      if (name.startsWith(OLD_API_ROOT)) {
        return MODEL_ROOT + name.substring(OLD_API_ROOT.length());
      }
    } else if (type.getClassLoader() == loader() && name.startsWith(MODEL_ROOT)) {
      return OLD_API_ROOT + name.substring(MODEL_ROOT.length());
    }
    throw new IllegalArgumentException("cannot rebuild " + name);
  }

  /** The class name with the {@code oldapi} segment dropped, as the reference names it. */
  static String apiName(Class<?> type) {
    String name = type.getName();
    return name.startsWith(OLD_API_ROOT) ? MODEL_ROOT + name.substring(OLD_API_ROOT.length()) : name;
  }

  private static boolean isShared(Object value) {
    return (
      (value instanceof Throwable && (value.getClass().getName().startsWith("java.") || value.getClass().getName().startsWith("javax."))) ||
      value instanceof ByteBuffer ||
      value instanceof String ||
      value instanceof Number ||
      value instanceof Boolean
    );
  }

  // Model accessors: public, non-static, no parameters, and not the builder plumbing.
  private static List<Method> accessors(Class<?> type) {
    List<Method> accessors = new ArrayList<>();
    for (Method method : type.getDeclaredMethods()) {
      int modifiers = method.getModifiers();
      if (
        Modifier.isPublic(modifiers) &&
        !Modifier.isStatic(modifiers) &&
        method.getParameterCount() == 0 &&
        method.getReturnType() != void.class &&
        !method.getName().equals("toBuilder")
      ) {
        accessors.add(method);
      }
    }
    return accessors;
  }

  private static Class<?> load(String name, ClassLoader classLoader) {
    try {
      return Class.forName(name, true, classLoader);
    } catch (ClassNotFoundException e) {
      throw new IllegalStateException(e);
    }
  }

  @SuppressWarnings({ "unchecked", "rawtypes" })
  private static Object enumConstant(Class<?> type, String name) {
    return Enum.valueOf((Class) type, name);
  }

  private static Object invoke(Object target, String method, Object... args) {
    return invoke(target, target.getClass(), method, args);
  }

  // Finds a public method by name and arity. Model classes do not overload by parameter type.
  private static Object invoke(Object target, Class<?> type, String name, Object... args) {
    for (Method method : type.getMethods()) {
      if (method.getName().equals(name) && method.getParameterCount() == args.length) {
        method.setAccessible(true);
        return invokeMethod(method, target, args);
      }
    }
    throw new IllegalArgumentException("no method " + name + "/" + args.length + " on " + type.getName());
  }

  private static Object invokeMethod(Method method, Object target, Object... args) {
    try {
      method.setAccessible(true);
      return method.invoke(target, args);
    } catch (InvocationTargetException e) {
      throw new ReflectiveFailure(e.getCause());
    } catch (IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void setField(Object target, String name, Object value) {
    try {
      java.lang.reflect.Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Carries an exception thrown by a reflective call. */
  private static final class ReflectiveFailure extends RuntimeException {

    private static final long serialVersionUID = 1L;

    ReflectiveFailure(Throwable cause) {
      super(cause);
    }
  }
}
