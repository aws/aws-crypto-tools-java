package software.amazon.cryptography.materialproviders.testing;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import org.jacoco.agent.rt.IAgent;
import org.jacoco.agent.rt.RT;
import org.junit.platform.engine.TestExecutionResult;
import org.junit.platform.engine.support.descriptor.MethodSource;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.TestIdentifier;
import org.junit.platform.launcher.TestPlan;

/**
 * Writes the JaCoCo coverage of each test to its own file, for CI's per-test coverage job.
 *
 * <p>The JUnit Platform loads this class through META-INF/services. It does nothing unless
 * PER_TEST_COVERAGE_DIR is set. Then, after each test, it takes the JaCoCo agent's counters and
 * zeroes them, writes them to {@code <dir>/java/tests/<file>.local.exec}, and appends one line to
 * {@code <dir>/tests.jsonl}. That is the layout that aws-crypto-tools-commons' per_test_coverage.py
 * reads. The counters belong to the whole JVM, so this only works while one test runs at a time.
 */
public final class PerTestCoverageListener implements TestExecutionListener {

  private static final String DIRECTORY_VARIABLE = "PER_TEST_COVERAGE_DIR";

  private final String run = UUID.randomUUID().toString().substring(0, 8);
  private Path directory;
  private IAgent agent;
  private int nextFile;

  @Override
  public void testPlanExecutionStarted(TestPlan plan) {
    String value = System.getenv(DIRECTORY_VARIABLE);
    if (value == null || value.isEmpty()) {
      return;
    }
    try {
      agent = RT.getAgent();
    } catch (IllegalStateException | NoClassDefFoundError e) {
      throw new IllegalStateException(
          DIRECTORY_VARIABLE + " is set but the JaCoCo agent is not running", e);
    }
    directory = Paths.get(value);
    // What ran before the first test (class loading, static setup) is not charged to it.
    agent.getExecutionData(true);
  }

  @Override
  public synchronized void executionSkipped(TestIdentifier test, String reason) {
    if (directory != null && test.isTest()) {
      record(test, "skipped", "");
    }
  }

  @Override
  public synchronized void executionFinished(TestIdentifier test, TestExecutionResult result) {
    if (directory == null || !test.isTest()) {
      return;
    }
    String file = run + "-" + nextFile++;
    Path tests = directory.resolve("java").resolve("tests");
    try {
      Files.createDirectories(tests);
      try (OutputStream out = Files.newOutputStream(tests.resolve(file + ".local.exec"))) {
        out.write(agent.getExecutionData(true));
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    String status;
    switch (result.getStatus()) {
      case SUCCESSFUL:
        status = "passed";
        break;
      case ABORTED:
        status = "skipped";
        break;
      default:
        status = "failed";
    }
    record(test, status, file);
  }

  private void record(TestIdentifier test, String status, String file) {
    String className =
        test.getSource()
            .filter(MethodSource.class::isInstance)
            .map(s -> ((MethodSource) s).getClassName())
            .orElse("");
    String line =
        "{\"test\": "
            + quote(className + "#" + test.getDisplayName())
            + ", \"junit_id\": "
            + quote(test.getUniqueId())
            + ", \"source\": \"local\", \"status\": "
            + quote(status)
            + ", \"file\": "
            + quote(file)
            + "}\n";
    try (Writer out =
        Files.newBufferedWriter(
            directory.resolve("tests.jsonl"),
            StandardCharsets.UTF_8,
            StandardOpenOption.CREATE,
            StandardOpenOption.APPEND)) {
      out.write(line);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static String quote(String text) {
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (c == '"' || c == '\\') {
        out.append('\\').append(c);
      } else if (c < 0x20) {
        out.append(String.format("\\u%04x", (int) c));
      } else {
        out.append(c);
      }
    }
    return out.append('"').toString();
  }
}
