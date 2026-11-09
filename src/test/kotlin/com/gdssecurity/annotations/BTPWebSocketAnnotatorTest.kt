package com.gdssecurity.annotations

import burp.api.montoya.core.Annotations
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.internal.MontoyaObjectFactory
import burp.api.montoya.internal.ObjectFactoryLocator
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.MessageReceivedAction
import burp.api.montoya.proxy.MessageToBeSentAction
import burp.api.montoya.proxy.Proxy
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage
import burp.api.montoya.proxy.websocket.InterceptedTextMessage
import burp.api.montoya.proxy.websocket.ProxyMessageHandler
import burp.api.montoya.proxy.websocket.ProxyWebSocket
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreation
import burp.api.montoya.proxy.websocket.ProxyWebSocketCreationHandler
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction
import burp.api.montoya.websocket.Direction
import com.gdssecurity.annotations.BlazorWire.attribute
import com.gdssecurity.annotations.BlazorWire.diff
import com.gdssecurity.annotations.BlazorWire.dispatchEvent
import com.gdssecurity.annotations.BlazorWire.element
import com.gdssecurity.annotations.BlazorWire.handler
import com.gdssecurity.annotations.BlazorWire.invocation
import com.gdssecurity.annotations.BlazorWire.renderBatch
import com.gdssecurity.annotations.BlazorWire.send
import com.gdssecurity.annotations.BlazorWire.text
import com.gdssecurity.helpers.RenderEdit
import com.gdssecurity.settings.BTPSettings
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.lang.reflect.Method
import java.lang.reflect.Proxy as JdkProxy

/** Montoya doubles: no Burp, browser or network is involved. */
class BTPWebSocketAnnotatorTest {
    private var previousFactory: MontoyaObjectFactory? = null
    private val events = mutableListOf<String>()
    private val errors = mutableListOf<String>()
    private var creationHandler: ProxyWebSocketCreationHandler? = null
    private val settings = BTPSettings()
    private val proxy = stub(Proxy::class.java) { method, args ->
        check(method.name == "registerWebSocketCreationHandler")
        creationHandler = args[0] as ProxyWebSocketCreationHandler
        events += "register creation hook"
        registration("creation hook")
    }
    private val logging = stub(Logging::class.java) { method, args ->
        check(method.name == "logToError")
        errors += args[0] as String
        null
    }
    private val annotator = BTPWebSocketAnnotator(proxy, settings, logging).also {
        it.update(settings.current)
        settings.addListener(it::update)
    }

    private class Sent<A>(val action: A, val payload: Any, val notes: Notes)
    private class Notes(var value: String?, val failing: Boolean = false)

    @BeforeEach
    fun installActionFactory() {
        previousFactory = ObjectFactoryLocator.FACTORY
        ObjectFactoryLocator.FACTORY = stub(MontoyaObjectFactory::class.java) { method, args ->
            when (method.name) {
                "continueWithFinalProxyBinaryMessage" -> stub(BinaryMessageToBeSentAction::class.java) { m, _ ->
                    if (m.name == "action") MessageToBeSentAction.CONTINUE else args[0]
                }
                "continueWithFinalProxyTextMessage" -> stub(TextMessageToBeSentAction::class.java) { m, _ ->
                    if (m.name == "action") MessageToBeSentAction.CONTINUE else args[0]
                }
                "followUserRulesInitialProxyBinaryMessage" -> stub(BinaryMessageReceivedAction::class.java) { m, _ ->
                    if (m.name == "action") MessageReceivedAction.CONTINUE else args[0]
                }
                "followUserRulesInitialProxyTextMessage" -> stub(TextMessageReceivedAction::class.java) { m, _ ->
                    if (m.name == "action") MessageReceivedAction.CONTINUE else args[0]
                }
                else -> error("Unexpected factory call: $method")
            }
        }
    }

    @AfterEach
    fun restoreFactory() {
        ObjectFactoryLocator.FACTORY = previousFactory
    }

    @Test
    fun annotatesBlazorSocketsWithoutChangingAnyPayload() {
        val socket = open("/_blazor")!!
        val wire = send(invocation("JS.AttachComponent", 1, "app"))

        val sent = binary(socket, Direction.SERVER_TO_CLIENT, wire)
        val receivedNotes = Notes("")
        val received = socket.handleBinaryMessageReceived(binaryMessage(Direction.SERVER_TO_CLIENT, wire, receivedNotes))
        val handshake = text(socket, Direction.CLIENT_TO_SERVER, "{\"protocol\":\"blazorpack\",\"version\":1}\u001e")

        assertEquals("""S>C SESSION attach component 1 to "app"""", sent.notes.value)
        assertSame(sent.payload, sent.action.payload())
        assertArrayEquals(wire, sent.action.payload().bytes)
        assertEquals(MessageToBeSentAction.CONTINUE, sent.action.action())
        assertArrayEquals(wire, received.payload().bytes)
        assertEquals("", receivedNotes.value)
        assertEquals("C>S SESSION handshake blazorpack v1", handshake.notes.value)
        assertSame(handshake.payload, handshake.action.payload())
    }

    @Test
    fun keepsExistingNotesWhileStillFollowingTheConversation() {
        val socket = open("/app/_blazor")!!
        binary(socket, Direction.SERVER_TO_CLIENT, send(invocation("JS.AttachComponent", 1, "app")))

        val rendered = binary(socket, Direction.SERVER_TO_CLIENT, send(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)),
            frames = listOf(element("button", 4), attribute("id", "save"), handler("onclick", 2), text("Save")))),
            Notes("tester note"))
        val clicked = binary(socket, Direction.CLIENT_TO_SERVER, send(dispatchEvent("1", 2, "click", "{}")))

        assertEquals("tester note", rendered.notes.value)
        assertEquals("""C>S UI click listener=button#save "Save" (handler 2, call 1)""", clicked.notes.value)
    }

    @Test
    fun watchesOnlySocketsOnConfiguredEndpoints() {
        assertNull(open("/chat"))
        assertNull(open("/_blazor/extra"))
        assertNotNull(open("/_blazor"))

        settings.save(true, true, "/hub", true)

        assertNotNull(open("/hub"))
    }

    @Test
    fun turningAnnotationsOffReleasesEverySocketUntilTurnedBackOn() {
        val socket = open("/_blazor")!!

        settings.save(true, true, "", false)
        val afterOff = binary(socket, Direction.SERVER_TO_CLIENT, send(invocation("JS.AttachComponent", 1, "app")))
        settings.save(true, true, "", true)

        assertEquals(listOf("register creation hook", "register socket handler", "deregister creation hook",
            "deregister socket handler", "register creation hook"), events)
        assertEquals("", afterOff.notes.value)
        assertSame(afterOff.payload, afterOff.action.payload())
    }

    @Test
    fun closedSocketsAreReleasedAndUnloadDeregistersEverything() {
        val closed = open("/_blazor")!!
        val open = open("/_blazor")!!

        closed.onClose()
        val afterClose = binary(closed, Direction.SERVER_TO_CLIENT, send(invocation("JS.AttachComponent", 1, "app")))
        annotator.close()
        annotator.close()

        assertEquals("", afterClose.notes.value)
        assertEquals(1, events.count { it == "deregister creation hook" })
        assertEquals(1, events.count { it == "deregister socket handler" })
        assertEquals("", binary(open, Direction.SERVER_TO_CLIENT, send(invocation("JS.AttachComponent", 1, "app"))).notes.value)
    }

    @Test
    fun aFailingAnnotationNeverBlocksTrafficAndOnlyStopsThatSocket() {
        val failing = open("/_blazor")!!
        val healthy = open("/_blazor")!!
        val wire = send(invocation("JS.AttachComponent", 1, "app"))

        val first = binary(failing, Direction.SERVER_TO_CLIENT, wire, Notes("", failing = true))
        val second = binary(failing, Direction.SERVER_TO_CLIENT, wire)
        val other = binary(healthy, Direction.SERVER_TO_CLIENT, wire)

        assertSame(first.payload, first.action.payload())
        assertEquals(MessageToBeSentAction.CONTINUE, first.action.action())
        assertEquals(1, errors.size)
        assertEquals("", second.notes.value)
        assertEquals("""S>C SESSION attach component 1 to "app"""", other.notes.value)
    }

    private fun open(path: String): ProxyMessageHandler? {
        var registered: ProxyMessageHandler? = null
        val request = stub(HttpRequest::class.java) { method, _ ->
            check(method.name == "pathWithoutQuery")
            path
        }
        val webSocket = stub(ProxyWebSocket::class.java) { method, args ->
            check(method.name == "registerProxyMessageHandler")
            registered = args[0] as ProxyMessageHandler
            events += "register socket handler"
            registration("socket handler")
        }
        creationHandler!!.handleWebSocketCreation(stub(ProxyWebSocketCreation::class.java) { method, _ ->
            when (method.name) {
                "upgradeRequest" -> request
                "proxyWebSocket" -> webSocket
                else -> error(method)
            }
        })
        return registered
    }

    private fun binary(socket: ProxyMessageHandler, direction: Direction, payload: ByteArray,
                       notes: Notes = Notes("")): Sent<BinaryMessageToBeSentAction> {
        val message = binaryMessage(direction, payload, notes)
        return Sent(socket.handleBinaryMessageToBeSent(message), message.payload(), notes)
    }

    private fun text(socket: ProxyMessageHandler, direction: Direction, payload: String): Sent<TextMessageToBeSentAction> {
        val notes = Notes("")
        val message = stub(InterceptedTextMessage::class.java) { method, _ ->
            when (method.name) {
                "payload" -> payload
                "direction" -> direction
                "annotations" -> annotations(notes)
                else -> error(method)
            }
        }
        return Sent(socket.handleTextMessageToBeSent(message), payload, notes)
    }

    private fun binaryMessage(direction: Direction, payload: ByteArray, notes: Notes): InterceptedBinaryMessage {
        val bytes = stub(BurpByteArray::class.java) { method, _ ->
            when (method.name) {
                "getBytes" -> payload.clone()
                "length" -> payload.size
                else -> error(method)
            }
        }
        return stub(InterceptedBinaryMessage::class.java) { method, _ ->
            when (method.name) {
                "payload" -> bytes
                "direction" -> direction
                "annotations" -> annotations(notes)
                else -> error(method)
            }
        }
    }

    private fun annotations(notes: Notes) = stub(Annotations::class.java) { method, args ->
        when (method.name) {
            "notes" -> notes.value
            "hasNotes" -> !notes.value.isNullOrEmpty()
            "setNotes" -> {
                if (notes.failing) throw IllegalStateException("synthetic annotation failure")
                notes.value = args[0] as String
                null
            }
            else -> error(method)
        }
    }

    private fun registration(name: String) = stub(Registration::class.java) { method, _ ->
        check(method.name == "deregister")
        events += "deregister $name"
        null
    }

    private fun <T> stub(type: Class<T>, handler: (Method, Array<out Any?>) -> Any?): T =
        type.cast(JdkProxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            if (method.name == "toString") type.simpleName else handler(method, args ?: emptyArray())
        })
}
