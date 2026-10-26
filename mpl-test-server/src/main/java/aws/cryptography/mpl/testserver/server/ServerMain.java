package aws.cryptography.mpl.testserver.server;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import software.amazon.cryptography.materialproviders.exceptions.MaterialProvidersException;

/**
 * rpcv2Cbor HTTP Language_Server for the MPL TestServer, backed by the native Java MPL. Binds loopback
 * only: unwrapped data keys cross this connection.
 *
 * <p>Error contract: a {@link MaterialProvidersException} (every failure the library raises on purpose)
 * is an MPLClientError carrying the library's message. Any other exception is a GenericServerError: either
 * the harness sent something the server cannot handle, or the library failed in a way it does not
 * declare, which is a bug a test should see as such rather than as an MPL rejection.
 */
public final class ServerMain {

  private static final String SERVICE = "MPLTestServer";
  private static final String PROTOCOL = "rpc-v2-cbor";
  private static final String CONTENT_TYPE = "application/cbor";
  private static final int DEFAULT_PORT = 8106;

  private final Operations operations = new Operations();

  private ServerMain() {}

  public static void main(String[] args) throws IOException, InterruptedException {
    int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
    start(port);
    System.out.println("MPL TestServer (java-native) listening on http://127.0.0.1:" + port);
    Thread.currentThread().join();
  }

  /** Starts a server on {@code port} (0 for any free port); the caller stops it. */
  static HttpServer start(int port) throws IOException {
    ServerMain server = new ServerMain();
    HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
    http.createContext("/", server::handle);
    // Daemon workers: stopping the HttpServer then leaves nothing that keeps the JVM alive.
    ExecutorService executor = Executors.newFixedThreadPool(
      8,
      runnable -> {
        Thread thread = new Thread(runnable, "mpl-test-server");
        thread.setDaemon(true);
        return thread;
      }
    );
    http.setExecutor(executor);
    http.start();
    return http;
  }

  private void handle(HttpExchange exchange) throws IOException {
    try {
      byte[] body = readBody(exchange.getRequestBody());
      try {
        String operation = route(exchange.getRequestURI().getPath());
        requireHeaders(exchange);
        ObjectNode response = operations.dispatch(operation, Cbor.decode(body));
        write(exchange, 200, Cbor.encode(response));
      } catch (RuntimeException | Error e) {
        writeError(exchange, classify(e));
        if (e instanceof VirtualMachineError) {
          throw (VirtualMachineError) e;
        }
      }
    } finally {
      exchange.close();
    }
  }

  /** The modeled error for a failure; see the class comment. */
  static ModeledError classify(Throwable failure) {
    if (failure instanceof ModeledError) {
      return (ModeledError) failure;
    }
    if (failure instanceof MaterialProvidersException) {
      return ModeledError.mpl(failure.getMessage() == null ? failure.toString() : failure.getMessage());
    }
    return ModeledError.generic("unexpected server error: " + failure);
  }

  private static String route(String path) {
    String[] parts = path.split("/");
    if (parts.length != 5 || !parts[0].isEmpty() || !"service".equals(parts[1]) || !"operation".equals(parts[3])) {
      throw ModeledError.generic("unexpected path: " + path);
    }
    if (!SERVICE.equals(parts[2])) {
      throw ModeledError.generic("unknown service: " + parts[2] + "; expected " + SERVICE);
    }
    return parts[4];
  }

  private static void requireHeaders(HttpExchange exchange) {
    if (!"POST".equals(exchange.getRequestMethod())) {
      throw ModeledError.generic("unexpected method: " + exchange.getRequestMethod() + "; expected POST");
    }
    if (!PROTOCOL.equals(exchange.getRequestHeaders().getFirst("smithy-protocol"))) {
      throw ModeledError.generic("missing or invalid smithy-protocol header; expected " + PROTOCOL);
    }
    if (!CONTENT_TYPE.equals(exchange.getRequestHeaders().getFirst("Content-Type"))) {
      throw ModeledError.generic("missing or invalid content-type; expected " + CONTENT_TYPE);
    }
  }

  private static byte[] readBody(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int n;
    while ((n = in.read(buffer)) != -1) {
      out.write(buffer, 0, n);
    }
    return out.toByteArray();
  }

  private static void write(HttpExchange exchange, int status, byte[] body) throws IOException {
    exchange.getResponseHeaders().set("smithy-protocol", PROTOCOL);
    exchange.getResponseHeaders().set("Content-Type", CONTENT_TYPE);
    exchange.sendResponseHeaders(status, body.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(body);
    }
  }

  private static void writeError(HttpExchange exchange, ModeledError error) throws IOException {
    ObjectNode body = Cbor.object();
    body.put("__type", error.typeId());
    body.put("message", error.getMessage() == null ? "" : error.getMessage());
    write(exchange, 400, Cbor.encode(body));
  }
}
