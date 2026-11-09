package com.gdssecurity.annotations

import com.gdssecurity.annotations.BlazorWire.attribute
import com.gdssecurity.annotations.BlazorWire.diff
import com.gdssecurity.annotations.BlazorWire.dispatchEvent
import com.gdssecurity.annotations.BlazorWire.element
import com.gdssecurity.annotations.BlazorWire.frame
import com.gdssecurity.annotations.BlazorWire.handler
import com.gdssecurity.annotations.BlazorWire.invocation
import com.gdssecurity.annotations.BlazorWire.renderBatch
import com.gdssecurity.annotations.BlazorWire.send
import com.gdssecurity.annotations.BlazorWire.text
import com.gdssecurity.helpers.RenderEdit
import com.gdssecurity.helpers.RenderFrame
import com.gdssecurity.messages.HubMessage
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.ThrowingSupplier
import java.time.Duration

class CircuitConversationTest {
    private val conversation = CircuitConversation()

    private val loginForm = listOf(
        element("form", 12),
        handler("onsubmit", 1),
        element("input", 5),
        attribute("id", "TID"),
        attribute("type", "text"),
        attribute("placeholder", "아이디"),
        handler("onchange", 3),
        element("button", 5),
        attribute("disabled", ""),
        handler("onclick", 2),
        element("span", 2),
        text("확인 코드 보내기"),
    )
    private val idInput = """input#TID[type=text][placeholder="아이디"]"""

    private fun client(vararg messages: HubMessage) = conversation.annotate(Flow.CLIENT_TO_SERVER, send(*messages))
    private fun server(vararg messages: HubMessage) = conversation.annotate(Flow.SERVER_TO_CLIENT, send(*messages))

    private fun renderLoginForm() {
        server(invocation("JS.AttachComponent", 1, "app"))
        server(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm))
    }

    @Test
    fun namesTheListenerAfterAReRenderMovesItToANewHandler() {
        assertEquals("""S>C SESSION attach component 1 to "app"""", server(invocation("JS.AttachComponent", 1, "app")))
        assertEquals("""S>C RENDER patch batch 2: +form +$idInput +button "확인 코드 보내기" disabled(last-render)""",
            server(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)))
        assertEquals("C>S NOISE OnRenderCompleted 2", client(invocation("OnRenderCompleted", 2, null)))
        assertEquals("S>C RENDER patch batch 3: no visible change", server(renderBatch(3,
            diff(1, RenderEdit.StepIn(0), RenderEdit.SetAttribute(0, 0), RenderEdit.StepOut),
            frames = listOf(handler("onchange", 43)), disposedHandlers = listOf(3))))

        assertEquals("""C>S UI change listener=$idInput value="synthetic-user" (handler 43, call 5)""",
            client(dispatchEvent("5", 43, "change", """{"value":"synthetic-user"}""",
                """{"componentId":1,"fieldValue":"synthetic-user"}""")))
        assertEquals("""S>C RESULT dotnet completed ok (call 5) for change listener=$idInput""",
            server(invocation("JS.EndInvokeDotNet", "5", true, "null")))
        assertEquals("""C>S UI change listener=unknown value="stale" (handler 3, call 6)""",
            client(dispatchEvent("6", 3, "change", """{"value":"stale"}""")))
    }

    @Test
    fun describesClicksOnControlsTheLastRenderDisabled() {
        renderLoginForm()

        assertEquals("""C>S UI click listener=button "확인 코드 보내기" disabled(last-render) (handler 2, call 7)""",
            client(dispatchEvent("7", 2, "click", """{"detail":1,"screenX":10,"type":"click"}""")))
        assertEquals("""C>S UI submit listener=form (handler 1, call 8)""", client(dispatchEvent("8", 1, "submit", "{}")))
        assertEquals("""C>S UI click listener=button "확인 코드 보내기" disabled(last-render) (handler 2)""",
            client(invocation("DispatchBrowserEvent", """{"browserRendererId":0,"eventHandlerId":2,"eventArgsType":"mouse"}""",
                """{"type":"click","detail":1}""")))
    }

    @Test
    fun flagsServerRequestedEvalAndCorrelatesItsResult() {
        assertEquals("""S>C JS! eval requested "alert(document.domain)" (async 6)""",
            server(invocation("JS.BeginInvokeJS", 6, "eval", """["alert(document.domain)"]""", 0, 0)))
        assertEquals("C>S RESULT js completed ok (async 6) for eval result=[6,true,null]",
            client(invocation("EndInvokeJSFromDotNet", 6, true, "[6,true,null]")))
        assertEquals("""S>C JS Blazor._internal.domWrapper.focusBySelector ["h1"] (async 5)""",
            server(invocation("JS.BeginInvokeJS", 5, "Blazor._internal.domWrapper.focusBySelector", """["h1"]""", 0, 0)))
    }

    @Test
    fun describesApplicationCallsAndTheirFailures() {
        assertEquals("""C>S CALL Synthetic.App::Lookup ["q",2] (call 9)""",
            client(invocation("BeginInvokeDotNetFromJS", "9", "Synthetic.App", "Lookup", 0, """["q",2]""")))
        assertEquals("""S>C RESULT dotnet completed failed (call 9) for Synthetic.App::Lookup error="There was an exception invoking 'Lookup'"""",
            server(invocation("JS.EndInvokeDotNet", "9", false, "There was an exception invoking 'Lookup'")))
        assertEquals("""C>S CALL obj3.Refresh [] (call 10)""",
            client(invocation("BeginInvokeDotNetFromJS", "10", null, "Refresh", 3, "[]")))
    }

    @Test
    fun labelsSessionSetupAndProtocolNoise() {
        assertEquals("C>S SESSION handshake blazorpack v1",
            conversation.annotate(Flow.CLIENT_TO_SERVER, "{\"protocol\":\"blazorpack\",\"version\":1}\u001e".toByteArray()))
        assertEquals("S>C SESSION handshake accepted | NOISE ping",
            conversation.annotate(Flow.SERVER_TO_CLIENT, "{}\u001e".toByteArray() + frame(HubMessage.Ping)))
        assertEquals("C>S SESSION StartCircuit https://app.example.test/login", client(invocation("StartCircuit",
            "https://app.example.test/", "https://app.example.test/login", "[]", "synthetic-state", id = "0")))
        assertEquals("S>C RESULT hub completed ok (invocation 0) for StartCircuit result=\"synthetic-circuit\"",
            server(BlazorWire.completion("0", "synthetic-circuit")))
        assertEquals("C>S UI navigate https://app.example.test/next (intercepted link)",
            client(invocation("OnLocationChanged", "https://app.example.test/next", null, true)))
        assertEquals("S>C ERROR JS.Error \"synthetic failure\"", server(invocation("JS.Error", "synthetic failure")))
        assertEquals("S>C UNKNOWN JS.Custom [1]", server(invocation("JS.Custom", 1)))
    }

    @Test
    fun summarizesEveryHubMessageInOneWebSocketMessageInWireOrder() {
        server(invocation("JS.AttachComponent", 1, "app"))

        assertEquals("""S>C RENDER patch batch 2: +a "Home" text "Welcome" | JS! eval requested "init()" (async 4)""", server(
            renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0), RenderEdit.PrependFrame(1, 3)),
                frames = listOf(element("a", 3), attribute("href", "/"), text("Home"), text("Welcome"))),
            invocation("JS.BeginInvokeJS", 4, "eval", """["init()"]""", 0, 0),
        ))
    }

    @Test
    fun marksFramesThatSpanWebSocketMessagesAsPartialUntilComplete() {
        server(invocation("JS.AttachComponent", 1, "app"))
        val wire = frame(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm))

        assertEquals("S>C PARTIAL frame 100/${wire.size - 2} B", conversation.annotate(Flow.SERVER_TO_CLIENT, wire.copyOfRange(0, 102)))
        assertEquals("""S>C RENDER patch batch 2: +form +$idInput +button "확인 코드 보내기" disabled(last-render)""",
            conversation.annotate(Flow.SERVER_TO_CLIENT, wire.copyOfRange(102, wire.size)))
    }

    @Test
    fun keepsEvalVisibleWhenTheNoteIsTruncated() {
        val calls = List(30) { invocation("JS.BeginInvokeJS", 100 + it, "Synthetic.interop.log", "[\"${"x".repeat(80)}\"]", 0, 0) }

        val note = server(*(calls + invocation("JS.BeginInvokeJS", 7, "eval", """["alert(1)"]""", 0, 0)).toTypedArray())!!

        assertTrue(note.contains("""JS! eval requested "alert(1)" (async 7)"""), note)
        assertTrue(note.codePointCount(0, note.length) <= 400, note)
        assertTrue(note.startsWith("S>C JS Synthetic.interop.log"), note)
        assertTrue(note.endsWith(" more"), note)
    }

    @Test
    fun escapesControlDelimiterAndBidiCharactersInAttackerControlledText() {
        server(invocation("JS.AttachComponent", 1, "app"))
        server(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = listOf(
            element("input", 3), attribute("id", "a‮b|c d"), handler("onchange", 5))))

        assertEquals("""C>S UI change listener=input#a\u{202E}b\|c\u{20}d value="1\"\n2 \| S>C JS! eval\u{200B}" (handler 5, call 1)""",
            client(dispatchEvent("1", 5, "change", """{"value":"1\"\n2 | S>C JS! eval​"}""")))
    }

    @Test
    fun boundsLongValuesAndForgetsTheOldestPendingCalls() {
        val note = client(invocation("BeginInvokeDotNetFromJS", "1", "Synthetic.App", "Save", 0, "[\"${"가".repeat(500)}\"]"))!!
        repeat(300) { client(invocation("BeginInvokeDotNetFromJS", "${it + 2}", "Synthetic.App", "Ping", 0, "[]")) }

        assertEquals("""C>S CALL Synthetic.App::Save ["${"가".repeat(58)}… (call 1)""", note)
        assertEquals("S>C RESULT dotnet completed ok (call 1)", server(invocation("JS.EndInvokeDotNet", "1", true, "null")))
        assertEquals("S>C RESULT dotnet completed ok (call 301) for Synthetic.App::Ping",
            server(invocation("JS.EndInvokeDotNet", "301", true, "null")))
    }

    @Test
    fun forgetsLabelsAfterAMalformedFrameOrAFailedRender() {
        renderLoginForm()
        assertEquals("""S>C ERROR malformed frame "invalid frame length 0" (element labels reset)""",
            conversation.annotate(Flow.SERVER_TO_CLIENT, byteArrayOf(0, 1, 2)))
        assertEquals("C>S UI click listener=unknown (handler 2, call 1)", client(dispatchEvent("1", 2, "click", "{}")))

        val fresh = CircuitConversation()
        fresh.annotate(Flow.SERVER_TO_CLIENT, send(invocation("JS.AttachComponent", 1, "app")))
        fresh.annotate(Flow.SERVER_TO_CLIENT, send(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)))
        assertEquals("""C>S ERROR browser failed to apply batch 2 "TypeError: synthetic" (element labels reset)""",
            fresh.annotate(Flow.CLIENT_TO_SERVER, send(invocation("OnRenderCompleted", 2, "TypeError: synthetic"))))
        assertEquals("C>S UI click listener=unknown (handler 2, call 2)",
            fresh.annotate(Flow.CLIENT_TO_SERVER, send(dispatchEvent("2", 2, "click", "{}"))))
    }

    @Test
    fun resetsLabelsWhenOneBatchReusesASubtreeBeyondTheNodeBudget() {
        renderLoginForm()
        val subtree = listOf(element("div", 3_001)) + List(3_000) { element("div", 1) }
        val insertions = List(3_000) { RenderEdit.PrependFrame(0, 0) }.toTypedArray()

        val note = assertTimeoutPreemptively(Duration.ofSeconds(5), ThrowingSupplier {
            server(renderBatch(3, diff(1, *insertions), frames = subtree))
        })

        assertEquals("S>C RENDER patch batch 3: tree exceeds the node budget (element labels reset)", note)
        assertEquals("C>S UI click listener=unknown (handler 2, call 1)", client(dispatchEvent("1", 2, "click", "{}")))
    }

    @Test
    fun resetsLabelsWhenDescribingAnUnsyncedComponentExceedsTheNodeBudget() {
        renderLoginForm()
        val subtree = listOf(element("div", 1_001)) + List(1_000) { element("div", 1) }
        val insertions = List(100) { RenderEdit.PrependFrame(0, 0) }.toTypedArray()

        assertEquals("S>C RENDER patch batch 3: tree exceeds the node budget (element labels reset) unsynced components 9",
            server(renderBatch(3, diff(9, *insertions), frames = subtree)))
        assertEquals("C>S UI click listener=unknown (handler 2, call 1)", client(dispatchEvent("1", 2, "click", "{}")))
    }

    @Test
    fun notesRetransmittedBatchesAndFlagsServerPushedScripts() {
        renderLoginForm()

        assertEquals("S>C NOISE render batch 2 retransmitted (already applied)",
            server(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)))
        assertEquals("""S>C RENDER! patch batch 3: markup "<script>steal()</script>"""",
            server(renderBatch(3, diff(1, RenderEdit.PrependFrame(1, 0)), frames = listOf(RenderFrame.Markup("<script>steal()</script>")))))
    }

    @Test
    fun flagsScriptsInsertedInsideOtherElementsOrAsInlineHandlers() {
        server(invocation("JS.AttachComponent", 1, "app"))

        assertEquals("""S>C RENDER! patch batch 2: set div onclick="alert(1)"""",
            server(renderBatch(2, diff(1, RenderEdit.PrependFrame(0, 0)),
                frames = listOf(element("div", 2), attribute("onclick", "alert(1)")))))
        assertEquals("""S>C RENDER! patch batch 3: +button "Go steal()" +script "steal()"""",
            server(renderBatch(3, diff(1, RenderEdit.PrependFrame(1, 0)),
                frames = listOf(element("button", 4), text("Go "), element("script", 2), text("steal()")))))
        assertEquals("""S>C RENDER! patch batch 4: +a "Home steal()" markup "<script>steal()</script>"""",
            server(renderBatch(4, diff(1, RenderEdit.PrependFrame(2, 0)),
                frames = listOf(element("a", 3), text("Home "), RenderFrame.Markup("<script>steal()</script>")))))
    }
}
