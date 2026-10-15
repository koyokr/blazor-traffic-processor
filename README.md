# BlazorTrafficProcessor Native WebSocket (BTP)
A Burp Suite extension for inspecting and editing Blazor Server/BlazorPack messages over native WebSockets.

This fork does not rewrite SignalR negotiation or downgrade WebSockets to Long Polling. In Burp's Proxy WebSockets history, select a binary `/_blazor` message and open the `BTP` editor tab to view its JSON representation. Edits made in an editable/intercept context are serialized back to BlazorPack with corrected length prefixes.

The standalone `BTP` suite tab remains available for ad-hoc BlazorPack/JSON conversion.

## Build

Run `./gradlew clean test jar`. The loadable extension is written to `build/libs/BlazorTrafficProcessor-1.1-native-ws.jar`.

Requires JDK 25 to build. The classes target Java 21, so they load in Burp Suite with Montoya API 2026.7 support running on Java 21 or later. The included Gradle Wrapper handles the build tool; no global Gradle or Kotlin installation is required.

Production sources are in `src/main/kotlin`, compiled with Kotlin/JVM 2.3.21. The JAR bundles the Kotlin standard library and runtime dependencies; Montoya API is provided by Burp. The entry point remains `com.gdssecurity.BlazorTrafficProcessor`, and installation still uses Burp's **Java** extension type.

Tests in `src/test/kotlin` cover the codec, framing, binary analysis and the HTTP and WebSocket editors. A separate smoke test loads the packaged JAR with an isolated class loader and initializes the extension against Montoya test doubles.

## Usage

### Installing the extension in Burp

Load the built JAR as a Java extension from Burp's Extensions settings. Remove the original BTP 1.0 extension first because it rewrites SignalR negotiation independently.

### Using the Extension
* Native WebSocket negotiation is left untouched.
* A `BTP` tab appears on structurally valid BlazorPack messages under Proxy WebSockets history and WebSocket interception.
  * Opening the tab converts BlazorPack to formatted JSON.
  * Binary arguments retain their editable `BinaryBytes` hex and include a derived `BinaryAnalysis`. For `JS.RenderBatch`, the analysis extracts component edits, reference frames, disposed IDs, and the UTF-8 string table.
  * Editing the JSON serializes it back to BlazorPack when Burp applies the message.
  * In read-only Proxy WebSockets history, consecutive binary rows from the same WebSocket and direction are reassembled when one length-prefixed BlazorPack message spans multiple transport chunks. Intercepted fragments remain unmodified and are never merged on the wire.
* The "BTP" Burpsuite tab, which allows for ad-hoc conversions of Blazor->JSON and JSON->Blazor
  * The left-hand editor is for your input (JSON or raw Blazor)
  * The right-hand editor is for the results of the conversion
  * A drop-down menu on the bottom of the window lets you select "Blazor->JSON" or "JSON->Blazor"
  * The Serialize/Deserialize button at the top is how you trigger the conversion
* The standalone tab and existing HTTP body context-menu conversion remain available.

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

Frame processing uses offsets into the original byte array. VarInt decoding tracks consumed bytes directly, supports at most five bytes, and checks the 2 GB numeric limit. Structural validation checks nesting, declared lengths, field types/counts and trailing data before exposing messages. Reassembly inspects a growing buffer and copies only a successful result.

Editor resource limits are 8 MiB per frame, 32 MiB per transport payload, 100,000 messages per payload, 100,000 MessagePack values per frame and 64 nesting levels. JSON conversion has corresponding value/depth limits and a 32 Mi-character text limit. Oversized input is rejected; it is not truncated or sent.

Run `./gradlew clean test jar` for protocol fixtures, malformed-input cases, HTTP/WebSocket preservation tests and the isolated-JAR loading check. A real Burp GUI loading check remains a separate manual step.

Copyright 2023 Aon plc
