package software.amazon.cryptography.build;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.gradle.api.DefaultTask;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.OutputFile;
import org.gradle.api.tasks.TaskAction;

/** Loads a library's compiled classes and writes its surface.json. */
public abstract class ApiSurfaceTask extends DefaultTask {

  @Input
  public abstract Property<String> getLibrary();

  /** The library's own classes. Only these are searched for APIs. */
  @Classpath
  public abstract ConfigurableFileCollection getClassesDirs();

  /** Everything the library's classes need to load, such as the AWS SDK. */
  @Classpath
  public abstract ConfigurableFileCollection getClasspath();

  @OutputFile
  public abstract RegularFileProperty getOutputFile();

  @TaskAction
  public void write() throws IOException, ClassNotFoundException {
    List<URL> urls = new ArrayList<>();
    for (File file : getClasspath().plus(getClassesDirs())) {
      urls.add(toUrl(file));
    }
    ApiSurface.Surface surface;
    try (URLClassLoader loader =
        new URLClassLoader(urls.toArray(new URL[0]), ClassLoader.getPlatformClassLoader())) {
      List<Class<?>> classes = new ArrayList<>();
      for (String name : classNames()) {
        classes.add(Class.forName(name, false, loader));
      }
      surface = ApiSurface.discover(getLibrary().get(), classes);
    }
    Path out = getOutputFile().get().getAsFile().toPath();
    Files.createDirectories(out.getParent());
    Files.write(out, ApiSurface.toJson(surface).getBytes(StandardCharsets.UTF_8));
  }

  private List<String> classNames() throws IOException {
    List<String> names = new ArrayList<>();
    for (File dir : getClassesDirs()) {
      // A library with no main sources has no classes directory.
      if (!dir.isDirectory()) {
        continue;
      }
      Path root = dir.toPath();
      try (Stream<Path> files = Files.walk(root)) {
        names.addAll(
            files
                .map(root::relativize)
                .map(Path::toString)
                .filter(p -> p.endsWith(".class"))
                .filter(p -> !p.endsWith("module-info.class") && !p.endsWith("package-info.class"))
                .map(p -> p.substring(0, p.length() - ".class".length()).replace(File.separatorChar, '.'))
                .collect(Collectors.toList()));
      }
    }
    return names;
  }

  private static URL toUrl(File file) {
    try {
      return file.toURI().toURL();
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }
}
