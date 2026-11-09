package com.gdssecurity.editors

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.ui.Selection
import burp.api.montoya.core.Range
import burp.api.montoya.ui.contextmenu.WebSocketMessage
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.websocket.Direction
import org.json.JSONArray
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.util.HexFormat
import javax.swing.JScrollPane
import javax.swing.text.JTextComponent
import com.gdssecurity.helpers.BlazorHelper
import com.gdssecurity.settings.BTPSettings

/** Montoya doubles exercise the editor locally; no browser or network connection is created. */
class BTPWebSocketMessageEditorTest {
    private val wire = HexFormat.of().parseHex("0b950180c0a44563686f9107")
    private val first = wire.copyOfRange(0, 5)
    private val second = wire.copyOfRange(5, wire.size)
    private var previousFactory: MontoyaObjectFactory? = null
    private lateinit var textArea: JTextComponent
    private val contents get() = textArea.text
    private val editable get() = textArea.isEditable
    private val settings = BTPSettings()
    private var historyLookups = 0
    private var history = listOf<ProxyWebSocketMessage>()

    @BeforeEach
    fun installByteArrayFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory::class.java) { method, args ->
            if (method.name == "selection") return@stub stub(Selection::class.java) { selectedMethod, _ ->
                when (selectedMethod.name) {
                    "contents" -> args[0]
                    "offsets" -> stub(Range::class.java) { rangeMethod, _ ->
                        when (rangeMethod.name) {
                            "startIndexInclusive" -> args[1]
                            "endIndexExclusive" -> args[2]
                            else -> error(rangeMethod)
                        }
                    }
                    else -> error(selectedMethod)
                }
            }
            check(method.name == "byteArray")
            bytes(when (val value = args[0]) {
                is String -> value.toByteArray(Charsets.ISO_8859_1)
                is ByteArray -> value
                else -> error("Unexpected byteArray overload")
            })
        }
    }

    @AfterEach
    fun restoreByteArrayFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    @Test
    fun displaysJsonAndReturnsUnmodifiedPayload() {
        val editor = editor(EditorMode.DEFAULT)
        val message = message(wire, 1)
        assertTrue(editor.isEnabledFor(message))
        editor.setMessage(message)
        assertEquals("Echo", JSONArray(contents).getJSONObject(0).getString("Target"))
        assertArrayEquals(wire, editor.getMessage().bytes)
        assertTrue(editable)
        assertFalse(editor.isModified())
        assertNull(editor.selectedData())
    }

    @Test
    fun rejectsStaleDecodedCacheWhenTheSameMessagePayloadChanges() {
        val payload = wire.clone()
        val selected = message(payload, 1)
        val editor = editor(EditorMode.DEFAULT)
        assertTrue(editor.isEnabledFor(selected))
        payload[payload.lastIndex] = 8
        editor.setMessage(selected)
        assertEquals(8, JSONArray(contents).getJSONObject(0).getJSONArray("Arguments").getInt(0))
        assertArrayEquals(payload, editor.getMessage().bytes)
    }

    @Test
    fun cachedDecodedMessageUsesTheLatestAnalysisSetting() {
        val payload = BlazorHelper().packJson("""[{MessageType:1,Headers:0,Target:Echo,Arguments:[{BinaryHeader:3,BinaryBytes:'616263'}]}]""").getOrThrow()
        val selected = message(payload, 1)
        val editor = editor(EditorMode.DEFAULT)
        assertTrue(editor.isEnabledFor(selected))
        settings.save(false, true, "")
        editor.setMessage(selected)
        assertFalse(contents.contains("BinaryAnalysis"))
        assertArrayEquals(payload, editor.getMessage().bytes)
    }

    @Test
    fun reassemblyChecksCumulativeSizesBeforeReadingAndLoadsOnlyNeededChunks() {
        val selected = message(first, 2)
        val tooLarge = message(byteArrayOf(), 1, declaredLength = 8 * 1024 * 1024,
            onRead = { fail<Unit>("A neighbor exceeding the remaining byte budget must not be read") })
        val unused = message(byteArrayOf(0), 4,
            onRead = { fail<Unit>("A row after successful reassembly must not be read") })
        history = listOf(tooLarge, selected, message(second, 3), unused)
        val editor = editor(EditorMode.READ_ONLY)
        assertTrue(editor.isEnabledFor(selected))
        editor.setMessage(selected)
        assertTrue(contents.contains("Echo"))
        assertEquals(1, historyLookups)
        assertArrayEquals(first, editor.getMessage().bytes)
    }

    @Test
    fun reassemblyAccepts32ChunksButDoesNotCrossTheChunkLimit() {
        val payload = BlazorHelper().packJson("""[{MessageType:1,Headers:0,Target:Echo,Arguments:["${"x".repeat(200)}"]}]""").getOrThrow()
        for (count in listOf(32, 33)) {
            history = (0 until count).map { index ->
                val end = if (index == count - 1) payload.size else index + 1
                message(payload.copyOfRange(index, end), index + 1)
            }
            val editor = editor(EditorMode.READ_ONLY)
            val selected = history[15]
            assertEquals(count == 32, editor.isEnabledFor(selected))
            if (count == 32) {
                editor.setMessage(selected)
                assertTrue(contents.contains("x".repeat(200)))
                assertArrayEquals(selected.payload().bytes, editor.getMessage().bytes)
            }
        }
    }

    @Test
    fun rejectsOversizedSelectedPayloadBeforeReadingBytesOrHistory() {
        val selected = message(byteArrayOf(), 1, declaredLength = 32 * 1024 * 1024 + 1,
            onRead = { fail<Unit>("Oversized transport bytes must not be read") })
        val editor = editor(EditorMode.READ_ONLY)
        assertFalse(editor.isEnabledFor(selected))
        editor.setMessage(selected)
        assertEquals("Unable to decode BlazorPack payload.", contents)
        assertEquals(0, historyLookups)
    }

    @Test
    fun unidentifiedMatchingRowsMustAllReassembleToTheSameBytes() {
        val selected = message(second, 2)
        val unidentified = stub(WebSocketMessage::class.java) { method, args -> method.invoke(selected, *args) }
        history = listOf(message(first, 1), selected, message(first, 3), message(second, 4))
        val editor = editor(EditorMode.READ_ONLY)
        assertTrue(editor.isEnabledFor(unidentified))
        editor.setMessage(unidentified)
        assertTrue(contents.contains("Echo"))
        assertEquals(1, historyLookups)
    }

    @Test
    fun disabledReassemblySkipsHistoryIncludingAPreviouslyCachedResult() {
        val selected = message(second, 2)
        history = listOf(message(first, 1), selected)
        val editor = editor(EditorMode.READ_ONLY)
        assertTrue(editor.isEnabledFor(selected))
        assertEquals(1, historyLookups)
        settings.save(true, false, "")
        editor.setMessage(selected)
        assertEquals("Unable to decode BlazorPack payload.", contents)
        assertFalse(editor.isEnabledFor(selected))
        assertEquals(1, historyLookups)
        assertTrue(editor.isEnabledFor(message(wire, 3)))
        settings.save(true, true, "")
        assertTrue(editor.isEnabledFor(selected))
        editor.setMessage(selected)
        assertTrue(contents.contains("Echo"))
        assertEquals(2, historyLookups)
    }

    @Test
    fun customPathsApplyToExistingEditorsAndUnrelatedPathsSkipHistory() {
        val editor = editor(EditorMode.READ_ONLY)
        assertFalse(editor.isEnabledFor(message(second, 1, path = "/app/hub?id=1")))
        assertEquals(0, historyLookups)
        settings.save(true, true, "/app/hub")
        assertTrue(editor.isEnabledFor(message(wire, 1, path = "/app/hub?id=1")))
        assertTrue(editor.isEnabledFor(message(wire, 1, path = "/nested/_blazor?id=1")))
        assertFalse(editor.isEnabledFor(message(wire, 1, path = "/app/hub/other")))
        assertEquals(0, historyLookups)
    }

    @Test
    fun disablingAnalysisKeepsBinaryHexAndDoesNotChangeTheWire() {
        val payload = BlazorHelper().packJson("""[{MessageType:1,Headers:0,Target:Echo,Arguments:[{BinaryHeader:3,BinaryBytes:'616263'}]}]""").getOrThrow()
        val editor = editor(EditorMode.DEFAULT)
        val selected = message(payload, 1)
        editor.setMessage(selected)
        assertTrue(contents.contains("BinaryAnalysis"))
        settings.save(false, true, "")
        editor.setMessage(selected)
        assertFalse(contents.contains("BinaryAnalysis"))
        assertTrue(contents.contains("616263"))
        edit(contents + " ")
        assertArrayEquals(payload, editor.getMessage().bytes)
    }

    @Test
    fun displaysAndEditsCjkWithoutLoss() {
        val codec = BlazorHelper()
        val original = "한글 中文 日本語 𠮷 😀"
        val wire = codec.packJson("""[{"MessageType":1,"Headers":0,"Target":"Echo","Arguments":["$original"]}]""").getOrThrow()
        val editor = editor(EditorMode.DEFAULT)
        editor.setMessage(message(wire, 1))
        assertEquals(original, JSONArray(contents).getJSONObject(0).getJSONArray("Arguments").getString(0))
        assertArrayEquals(wire, editor.getMessage().bytes)
        val changed = "수정된 한글 漢字 かな 𠮷 😀"
        edit(contents.replace(original, changed))
        assertTrue(editor.isModified())
        assertEquals(changed, JSONArray(codec.unpackJson(editor.getMessage().bytes).getOrThrow())
            .getJSONObject(0).getJSONArray("Arguments").getString(0))
    }

    @Test
    fun selectsCjkAsUtf8WithByteOffsets() {
        val editor = editor(EditorMode.DEFAULT)
        edit("한글 앞 中文𠮷 뒤")
        textArea.select(5, 9)
        val selection = editor.selectedData()!!
        assertArrayEquals("中文𠮷".toByteArray(Charsets.UTF_8), selection.contents().bytes)
        assertEquals("한글 앞 ".toByteArray(Charsets.UTF_8).size, selection.offsets().startIndexInclusive())
        assertEquals("한글 앞 中文𠮷".toByteArray(Charsets.UTF_8).size, selection.offsets().endIndexExclusive())
    }

    @Test
    fun reassemblesCjkSplitInsideUtf8CharacterWithoutChangingTheChunk() {
        val text = "한글 中文 日本語"
        val payload = BlazorHelper().packJson("""[{"MessageType":1,"Headers":0,"Target":"Echo","Arguments":["$text"]}]""").getOrThrow()
        val split = payload.indexOf(0xed.toByte()) + 1 // First byte of 한.
        assertTrue(split > 0)
        val chunk = payload.copyOfRange(split, payload.size)
        val selected = message(chunk, 2)
        history = listOf(selected, message(payload.copyOfRange(0, split), 1))
        val editor = editor(EditorMode.READ_ONLY)
        assertTrue(editor.isEnabledFor(selected))
        editor.setMessage(selected)
        assertTrue(contents.contains(text))
        assertFalse(editable)
        assertFalse(editor.isModified())
        assertArrayEquals(chunk, editor.getMessage().bytes)
        textArea.document.insertString(textArea.document.length, " ", null)
        assertFalse(editor.isModified())
        assertArrayEquals(chunk, editor.getMessage().bytes)
    }

    @Test
    fun serializesEditsAndKeepsOriginalWhenJsonIsInvalid() {
        val editor = editor(EditorMode.DEFAULT)
        editor.setMessage(message(wire, 1))
        edit("[{MessageType:1,Headers:0,Target:Echo,Arguments:[8]}]")
        assertTrue(editor.isModified())
        assertArrayEquals(HexFormat.of().parseHex("0b950180c0a44563686f9108"), editor.getMessage().bytes)
        edit("invalid json")
        assertArrayEquals(wire, editor.getMessage().bytes)
        edit("[{MessageType:1}]")
        assertArrayEquals(wire, editor.getMessage().bytes)
    }

    @Test
    fun identifiesTheSelectedHistoryRowAndRejectsAmbiguousPayloadMatches() {
        val selected = message(second, 2)
        history = listOf(message(first, 1), selected, message(second, 3, socket = 11))
        assertTrue(editor(EditorMode.READ_ONLY).isEnabledFor(selected))
        // Without a history id, the same bytes in connection 11 cannot be reassembled, so the match is ambiguous.
        val unidentified = stub(WebSocketMessage::class.java) { method, args -> method.invoke(selected, *args) }
        assertFalse(editor(EditorMode.READ_ONLY).isEnabledFor(unidentified))
    }

    @Test
    fun reassemblyFromAnEarlierLookupIsNotReusedAfterAnotherMessage() {
        val selected = message(second, 2)
        history = listOf(message(first, 1), selected)
        val editor = editor(EditorMode.READ_ONLY)
        assertTrue(editor.isEnabledFor(selected))
        history = listOf(selected)
        assertTrue(editor.isEnabledFor(message(wire, 3)))
        editor.setMessage(selected)
        assertEquals("Unable to decode BlazorPack payload.", contents)
    }

    @Test
    fun doesNotJoinDifferentConnectionsDirectionsOrUpgradePaths() {
        val selected = message(second, 2)
        val editor = editor(EditorMode.READ_ONLY)
        for (unrelated in listOf(
            message(first, 1, socket = 11),
            message(first, 1, direction = Direction.CLIENT_TO_SERVER),
            message(first, 1, path = "/_blazor?id=other"),
        )) {
            history = listOf(unrelated, selected)
            assertFalse(editor.isEnabledFor(selected))
        }
        assertFalse(editor.isEnabledFor(message(wire, 1, path = "/other")))
    }

    @Test
    fun clearsSelectionAndResetsEditability() {
        val editor = editor(EditorMode.DEFAULT)
        editor.setMessage(message(wire, 1))
        editor.setMessage(null)
        assertEquals(0, contents.length)
        assertEquals(0, editor.getMessage().length())
        assertFalse(editor.isEnabledFor(null))
        assertFalse(editable)
    }

    @Test
    fun doesNotReassembleEditableTransportChunks() {
        val selected = message(second, 2)
        history = listOf(message(first, 1), selected)
        val editor = editor(EditorMode.DEFAULT)
        assertFalse(editor.isEnabledFor(selected))
        editor.setMessage(selected)
        textArea.document.insertString(textArea.document.length, " ", null)
        assertFalse(editable)
        assertFalse(editor.isModified())
        assertArrayEquals(second, editor.getMessage().bytes)
    }

    @Test
    fun readOnlyCompleteMessagesCannotBeRewritten() {
        val editor = editor(EditorMode.READ_ONLY)
        editor.setMessage(message(wire, 1))
        edit("[{MessageType:6}]")
        assertFalse(editable)
        assertFalse(editor.isModified())
        assertArrayEquals(wire, editor.getMessage().bytes)
    }

    private fun edit(json: String) {
        textArea.text = json
    }

    private fun editor(mode: EditorMode) = BTPWebSocketMessageEditor(apiStub(MontoyaApi::class.java), mode, settings).also {
        textArea = (it.uiComponent() as JScrollPane).viewport.view as JTextComponent
    }

    private fun <T> apiStub(type: Class<T>): T = stub(type) { method, args ->
        when (method.name) {
            "applyThemeToComponent", "currentEditorFont" -> null
            "logToError" -> null
            "webSocketHistory" -> { historyLookups++; history.filter((args[0] as ProxyWebSocketHistoryFilter)::matches) }
            else -> if (method.returnType.isInterface) apiStub(method.returnType) else error("Unexpected API call: $method")
        }
    }

    private fun message(
        payload: ByteArray,
        id: Int,
        socket: Int = 10,
        path: String = "/_blazor?id=synthetic",
        direction: Direction = Direction.SERVER_TO_CLIENT,
        declaredLength: Int = payload.size,
        onRead: () -> Unit = {},
    ): ProxyWebSocketMessage {
        val service = stub(HttpService::class.java) { method, _ ->
            when (method.name) {
                "host" -> "example.test"
                "port" -> 443
                "secure" -> true
                else -> error(method)
            }
        }
        val request = stub(HttpRequest::class.java) { method, _ ->
            when (method.name) {
                "path" -> path
                "pathWithoutQuery" -> path.substringBefore('?')
                "httpService" -> service
                else -> error(method)
            }
        }
        return stub(ProxyWebSocketMessage::class.java) { method, _ ->
            when (method.name) {
                "payload" -> bytes(payload, declaredLength, onRead)
                "id" -> id
                "webSocketId" -> socket
                "upgradeRequest" -> request
                "direction" -> direction
                else -> error(method)
            }
        }
    }

    private fun bytes(value: ByteArray, declaredLength: Int = value.size, onRead: () -> Unit = {}): BurpByteArray = stub(BurpByteArray::class.java) { method, _ ->
        when (method.name) {
            "getBytes" -> { onRead(); value.clone() }
            "length" -> declaredLength
            "copy" -> bytes(value.clone())
            "toString" -> value.toString(Charsets.UTF_8)
            else -> error(method)
        }
    }

    private fun <T> stub(type: Class<T>, handler: (Method, Array<out Any?>) -> Any?): T =
        type.cast(Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            handler(method, args ?: emptyArray())
        })
}
