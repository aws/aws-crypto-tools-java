# MPL TestServer: native Java Language_Server

An rpcv2Cbor HTTP server for the cross-language MPL TestServer (aws-crypto-tools-commons,
`mpl/test-server/model/mpl-test-server.smithy`). Every operation delegates to the public API of the
native Java MPL in `../mpl`, which this build includes, so the server always runs this working tree's library.

- `POST /service/MPLTestServer/operation/{Operation}`, headers `smithy-protocol: rpc-v2-cbor` and
  `Content-Type: application/cbor`; errors are HTTP 400 with `{__type, message}`.
- A `MaterialProvidersException` is an `MPLClientError` with the library's message. Anything else
  (bad request, bad handle, an undeclared library exception) is a `GenericServerError`.
- Per-server configuration: `server-config.json`, `feature-config.json`, `bug-config.json`.

```bash
JAVA_HOME=<jdk 21+> ./gradlew build                  # server tests (Java 8 bytecode)
JAVA_HOME=<jdk 21+> ./gradlew runServer --args=8106  # what the orchestrator runs
```
