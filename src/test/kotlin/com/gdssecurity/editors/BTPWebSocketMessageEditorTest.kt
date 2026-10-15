package com.gdssecurity.editors

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.proxy.ProxyWebSocketHistoryFilter
import burp.api.montoya.proxy.ProxyWebSocketMessage
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
import java.util.Optional

/** Montoya doubles exercise the editor locally; no browser or network connection is created. */
class BTPWebSocketMessageEditorTest {
    private val wire = HexFormat.of().parseHex("0b950180c0a44563686f9107")
    private val first = wire.copyOfRange(0, 5)
    private val second = wire.copyOfRange(5, wire.size)
    private var previousFactory: MontoyaObjectFactory? = null
    private var contents = bytes(byteArrayOf())
    private var modified = false
    private var editable = false
    private var history = listOf<ProxyWebSocketMessage>()

    @BeforeEach
    fun installByteArrayFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory::class.java) { method, args ->
            check(method.name == "byteArray")
            bytes(when (val value = args[0]) {
                is String -> value.toByteArray()
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
        assertEquals("Echo", JSONArray(contents.toString()).getJSONObject(0).getString("Target"))
        assertArrayEquals(wire, editor.getMessage().bytes)
        assertTrue(editable)
        assertFalse(editor.isModified())
        assertNull(editor.selectedData())
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
    fun reassembledDisplayIsReadOnlyAndReturnsTheOriginalChunk() {
        val selected = message(second, 2)
        history = listOf(selected, message(first, 1))
        val editor = editor(EditorMode.READ_ONLY)
        assertTrue(editor.isEnabledFor(selected))
        editor.setMessage(selected)
        assertEquals("Echo", JSONArray(contents.toString()).getJSONObject(0).getString("Target"))
        assertFalse(editable)
        modified = true
        assertFalse(editor.isModified())
        assertArrayEquals(second, editor.getMessage().bytes)
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
        assertEquals("Unable to decode BlazorPack payload.", contents.toString())
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
        assertEquals(0, contents.length())
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
        modified = true
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
        contents = bytes(json.toByteArray())
        modified = true
    }

    private fun editor(mode: EditorMode) = BTPWebSocketMessageEditor(apiStub(MontoyaApi::class.java), mode)

    private fun <T> apiStub(type: Class<T>): T = stub(type) { method, args ->
        when (method.name) {
            "getContents" -> contents
            "setContents" -> { contents = args[0] as BurpByteArray; modified = false; null }
            "isModified" -> modified
            "setEditable" -> { editable = args[0] as Boolean; null }
            "selection" -> Optional.empty<Any>()
            "logToError" -> null
            "webSocketHistory" -> history.filter((args[0] as ProxyWebSocketHistoryFilter)::matches)
            else -> if (method.returnType.isInterface) apiStub(method.returnType) else error("Unexpected API call: $method")
        }
    }

    private fun message(
        payload: ByteArray,
        id: Int,
        socket: Int = 10,
        path: String = "/_blazor?id=synthetic",
        direction: Direction = Direction.SERVER_TO_CLIENT,
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
                "payload" -> bytes(payload)
                "id" -> id
                "webSocketId" -> socket
                "upgradeRequest" -> request
                "direction" -> direction
                else -> error(method)
            }
        }
    }

    private fun bytes(value: ByteArray): BurpByteArray = stub(BurpByteArray::class.java) { method, _ ->
        when (method.name) {
            "getBytes" -> value.clone()
            "length" -> value.size
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
