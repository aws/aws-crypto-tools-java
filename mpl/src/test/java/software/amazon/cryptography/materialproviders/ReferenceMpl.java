// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package software.amazon.cryptography.materialproviders;

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
 * <p>Both MPLs declare the same class names, so reference objects are reached only by reflection.
 * {@link #toReference} rebuilds a native model object in the reference class loader through its builder;
 * {@link #describe} renders a model object from either side as a canonical string.
 *
 * <p>Values from the bootstrap class loader (ByteBuffer, String, boxed numbers) pass between the sides as is.
 */
final class ReferenceMpl {

  private static final String JAR_PREFIX = "aws-cryptographic-material-providers-";
  private static final String MODEL_ROOT = "software.amazon.cryptography.";

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
    // A null parent keeps this module's classes, which share the reference's names, out of the lookup.
    loader = new URLClassLoader(urls.toArray(new URL[0]), null);
  }

  /**
   * Rebuilds a native model value in the reference class loader.
   * A value already in the reference class loader stays as is.
   */
  static Object toReference(Object value) {
    return rebuild(value, loader());
  }

  /** Rebuilds a reference model value as the native model value of the same class name. */
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
    if (!type.getName().startsWith(MODEL_ROOT)) {
      throw new IllegalArgumentException("cannot rebuild " + type.getName());
    }
    Class<?> targetType = load(type.getName(), target);
    if (type.isEnum()) {
      return enumConstant(targetType, ((Enum<?>) value).name());
    }
    Object builder = invoke(null, targetType, "builder");
    for (Method accessor : accessors(type)) {
      Object field = invokeMethod(accessor, value);
      if (field != null) {
        invoke(builder, accessor.getName(), rebuild(field, target));
      }
    }
    return invoke(builder, "build");
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

  /** Carries an exception thrown by the reference MPL out of a reflective call. */
  private static final class ReflectiveFailure extends RuntimeException {

    private static final long serialVersionUID = 1L;

    ReflectiveFailure(Throwable cause) {
      super(cause);
    }
  }
}
