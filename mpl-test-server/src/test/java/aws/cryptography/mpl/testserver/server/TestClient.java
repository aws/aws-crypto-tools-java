package aws.cryptography.mpl.testserver.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.URL;

/** A raw rpcv2Cbor client, so the tests control every header and byte the server sees. */
final class TestClient {

  static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());

  /** An HTTP status and decoded CBOR body. */
  static final class Reply {

    final int status;
    final JsonNode body;

    Reply(int status, JsonNode body) {
      this.status = status;
      this.body = body;
    }

    String errorType() {
      return body.path("__type").asText(null);
    }

    String message() {
      return body.path("message").asText(null);
    }
  }

  private final int port;

  TestClient(int port) {
    this.port = port;
  }

  static ObjectNode object() {
    return CBOR.createObjectNode();
  }

  Reply call(String operation, ObjectNode request) {
    return post("/service/MPLTestServer/operation/" + operation, "rpc-v2-cbor", "application/cbor", encode(request));
  }

  /** Calls {@code operation}, requiring success. */
  JsonNode ok(String operation, ObjectNode request) {
    Reply reply = call(operation, request);
    if (reply.status != 200) {
      throw new AssertionError(operation + " failed: " + reply.status + " " + reply.body);
    }
    return reply.body;
  }

  Reply post(String path, String protocol, String contentType, byte[] body) {
    try {
      HttpURLConnection connection = (HttpURLConnection) new URL("http://127.0.0.1:" + port + path).openConnection();
      connection.setRequestMethod("POST");
      connection.setDoOutput(true);
      if (protocol != null) {
        connection.setRequestProperty("smithy-protocol", protocol);
      }
      if (contentType != null) {
        connection.setRequestProperty("Content-Type", contentType);
      }
      try (OutputStream out = connection.getOutputStream()) {
        out.write(body);
      }
      int status = connection.getResponseCode();
      InputStream in = status == 200 ? connection.getInputStream() : connection.getErrorStream();
      return new Reply(status, CBOR.readTree(readAll(in)));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static byte[] encode(ObjectNode request) {
    try {
      return CBOR.writeValueAsBytes(request);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int n;
    while ((n = in.read(buffer)) != -1) {
      out.write(buffer, 0, n);
    }
    return out.toByteArray();
  }
}
