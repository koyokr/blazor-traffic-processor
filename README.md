# BlazorTrafficProcessor (BTP)
A Burp Suite extension for inspecting and editing Blazor Server/BlazorPack messages over native WebSockets.

This fork does not rewrite SignalR negotiation or downgrade WebSockets to Long Polling. In Burp's Proxy WebSockets history, select a binary `/_blazor` message and open the `BTP` editor tab to view its JSON representation. Edits made in an editable/intercept context are serialized back to BlazorPack with corrected length prefixes.

The top-level `BTP` suite tab contains project settings; inspection and editing take place in the message editor tabs.

## Build

Run `./gradlew clean build`. The loadable extension is written to `build/libs/BlazorTrafficProcessor-1.1.1.jar`.

Builds use the current host JDK without downloading or pinning a Java toolchain. Kotlin and Java compilation target Java 21 bytecode and JDK APIs, for Burp Suite with Montoya API 2026.7 support on Java 21 or later. The included Gradle Wrapper 9.7.0 (bin) handles the build tool; no global Gradle or Kotlin installation is required.

Production sources are in `src/main/kotlin`, compiled with Kotlin/JVM 2.4.21 using Kotlin DSL build/settings scripts. The JAR bundles the Kotlin standard library and runtime dependencies; Montoya API is provided by Burp. The entry point remains `com.gdssecurity.BlazorTrafficProcessor`, and installation still uses Burp's **Java** extension type.

Tests in `src/test/kotlin` cover the codec, framing, binary analysis and the HTTP and WebSocket editors. A separate smoke test loads the packaged JAR with an isolated class loader and initializes the extension against Montoya test doubles.

## Usage

### Installing the extension in Burp

Load the built JAR as a Java extension from Burp's Extensions settings. Remove the original BTP 1.0 extension first because it rewrites SignalR negotiation independently.

### Using the Extension
* Native WebSocket negotiation is left untouched.
* A `BTP` tab appears on structurally valid BlazorPack messages under Proxy WebSockets history and WebSocket interception.
  * Opening the tab converts BlazorPack to formatted JSON. The WebSocket BTP editor displays and edits Unicode text (including Korean, Chinese, and Japanese) independently of Burp’s raw binary display; edited strings are encoded as UTF-8 in BlazorPack. Undo/redo is available from the context menu and Ctrl/Cmd+Z, Ctrl/Cmd+Shift+Z or Ctrl/Cmd+Y; history resets when another message is loaded.
  * Binary arguments retain their editable `BinaryBytes` hex and, when binary analysis is enabled, include a derived `BinaryAnalysis`. For `JS.RenderBatch`, the analysis extracts component edits, reference frames, disposed IDs, and the UTF-8 string table.
  * Editing the JSON serializes it back to BlazorPack when Burp applies the message.
  * In read-only Proxy WebSockets history, consecutive binary rows from the same WebSocket and direction are reassembled when one length-prefixed BlazorPack message spans multiple transport chunks. Intercepted fragments remain unmodified and are never merged on the wire.
* The top-level `BTP` tab provides three settings. Click **Apply** to save them with the Burp project, then reopen messages to apply the changes:
  * **Analyze binary payloads** (default: on): additionally interpret binary data as UTF-8 text or structured RenderBatch data. Turning this off skips analysis entirely while retaining editable `BinaryHeader` and `BinaryBytes`.
  * **Reassemble fragmented WebSocket messages** (default: on): reconstruct split BlazorPack payloads for read-only history previews. Turning this off skips history lookup for incomplete messages; complete messages still decode normally.
  * **Additional endpoint paths**: exact, case-sensitive paths, one per line (for example `/app/hub`). Queries are excluded from matching. No hosts or wildcards. `/_blazor` and paths ending in `/_blazor` remain enabled. This applies to both WebSocket and HTTP editors.
* The former manual conversion tool and its “Send body to BTP tab” menu have been removed.

BTP does not analyze all traffic in a background listener. Burp editor callbacks first filter paths, then validate eligible payloads; JSON and binary analysis are produced when a message is displayed. Incomplete read-only WebSocket messages can trigger a filtered history lookup and bounded reassembly (32 chunks, 8 MiB). The history lookup itself is not bounded by those limits, so large histories may still be expensive. WebSocket editors do not require target scope; the existing HTTP editors continue to require in-scope URLs.

## JSON representation and compatibility

The codec follows the [SignalR MessagePack schema](https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#messagepack-msgpack-encoding). It accepts both five-field legacy invocations and six-field invocations with a proper `StreamIds` array, as supported by [ASP.NET Core's shared protocol worker](https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/common/Protocols.MessagePack/src/Protocol/MessagePackHubProtocolWorker.cs).

For example:

```json
[
  {
    "MessageType": 1,
    "Headers": 0,
    "Target": "Echo",
    "Arguments": [null, "null", "[1,2]", [1, 2]],
    "StreamIds": ["stream-1"]
  }
]
```

JSON `null` is MessagePack nil; the string `"null"` remains a string. Strings containing JSON or NUL characters are preserved as strings. JSON arrays represent MessagePack arrays. This corrects the older editor's ambiguous string coercions; update saved JSON snippets that used strings as nil or arrays as JSON-encoded strings.

Empty headers display as `0`; nonempty headers display as an object of string keys and string values. Binary values use `BinaryHeader` and `BinaryBytes`; the byte count must match the hex length. `BinaryAnalysis` is derived and ignored during serialization. An object with both `BinaryHeader` and `BinaryBytes` is always a binary value and may contain no keys other than `BinaryAnalysis`. Maps that would be ambiguous as JSON objects (non-string or duplicate keys, both binary wrapper keys, or a sole `MapEntries` key) display as `{"MapEntries": [[key, value], ...]}`.

Ping and StreamItem now include their required array headers. Close writes its error once. Ack (8) and Sequence (9) use `SequenceId` as a 64-bit integer. Completion distinguishes error, void and value results and rejects invalid result kinds or inconsistent fields. Non-invocation messages requiring an invocation ID reject missing or empty IDs. Unknown message types, MessagePack extensions and non-finite values are not editable.

HTTP requests and WebSocket messages retain their original bytes when unchanged, read-only, undecodable or unsuccessfully edited. When a payload is edited, messages whose values are unchanged keep their original frame bytes; edited messages are re-encoded, so a float32 inside one becomes float64. Floats always display with a decimal point or exponent and stay floats. HTTP responses are read-only previews. Reassembly is available only in read-only WebSocket history; it never replaces a transport chunk on the wire.

## Implementation and limits

The immutable `HubMessage` sealed model is separate from JSON and MessagePack conversion. `BlazorHelper` has no Burp dependency and returns Kotlin `Result` values; a failed conversion never returns a partial message list or partially serialized payload.

Frame processing uses offsets into the original byte array. VarInt decoding tracks consumed bytes directly, supports at most five bytes, and checks the 2 GB numeric limit. Structural validation checks nesting, declared lengths, field types/counts and trailing data before exposing messages. The WebSocket editor reuses the immediately preceding decode result only when message identity, payload bytes and the reassembly setting still match. Modification checks cache their result until the document changes. Reassembly groups and sorts history once per connection, checks neighboring chunk lengths before loading bytes, and loads chunks on demand. Neighboring chunk bytes retained per candidate window are bounded to less than 16 MiB; each assembled candidate remains limited to 8 MiB. Reassembly inspects a growing buffer and copies only a successful result.

Editor resource limits are 8 MiB per frame, 32 MiB per transport payload, 100,000 messages per payload, 100,000 MessagePack values per frame and 64 nesting levels. JSON conversion has corresponding value/depth limits and a 32 Mi-character text limit. Oversized input is rejected; it is not truncated or sent.

Run `./gradlew clean build` for protocol fixtures, malformed-input cases, HTTP/WebSocket preservation tests and the isolated-JAR loading check. A real Burp GUI loading check remains a separate manual step.

Copyright 2023 Aon plc
