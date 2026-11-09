package com.gdssecurity.annotations

import com.gdssecurity.annotations.BlazorWire.attribute
import com.gdssecurity.annotations.BlazorWire.diff
import com.gdssecurity.annotations.BlazorWire.element
import com.gdssecurity.annotations.BlazorWire.handler
import com.gdssecurity.annotations.BlazorWire.id
import com.gdssecurity.annotations.BlazorWire.text
import com.gdssecurity.helpers.ComponentDiff
import com.gdssecurity.helpers.RenderBatch
import com.gdssecurity.helpers.RenderEdit
import com.gdssecurity.helpers.RenderFrame
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class RenderTreeMirrorTest {
    private val mirror = RenderTreeMirror().apply { attachRoot(1) }
    private val idInput = ElementLabel("input", "TID", null, "text", "아이디", null, false)
    private val smsButton = ElementLabel("button", null, null, null, null, "확인 코드 보내기", true)

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

    private fun apply(batchId: Long, vararg diffs: ComponentDiff, frames: List<RenderFrame> = emptyList(),
                      disposedComponents: List<Int> = emptyList(), disposedHandlers: List<Long> = emptyList()) =
        mirror.apply(batchId, RenderBatch(diffs.toList(), frames, disposedComponents, disposedHandlers.map(::id), emptyList()))

    private fun label(handlerId: Long) = mirror.element(id(handlerId))

    @Test
    fun labelsListenersFromTheirAttributesAndNestedText() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)

        assertEquals(idInput, label(3))
        assertEquals(smsButton, label(2))
        assertEquals(ElementLabel("form", null, null, null, null, null, false), label(1))
        assertNull(label(4))
    }

    @Test
    fun followsAHandlerRebindingThroughAStandaloneSetAttribute() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)

        apply(3, diff(1, RenderEdit.StepIn(0), RenderEdit.SetAttribute(0, 0), RenderEdit.StepOut),
            frames = listOf(handler("onchange", 43)), disposedHandlers = listOf(3))

        assertEquals(idInput, label(43))
        assertNull(label(3))
    }

    @Test
    fun disposingTheReplacedHandlerLaterKeepsTheReplacement() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)
        apply(3, diff(1, RenderEdit.StepIn(0), RenderEdit.SetAttribute(0, 0), RenderEdit.StepOut),
            frames = listOf(handler("onchange", 43)))

        apply(4, disposedHandlers = listOf(3))

        assertEquals(idInput, label(43))
        assertNull(label(3))
    }

    @Test
    fun disposesHandlersOnlyAfterApplyingTheBatchEdits() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0), RenderEdit.PrependFrame(1, 3)), frames = listOf(
            element("button", 3), handler("onclick", 7), text("bound and disposed in one batch"),
            element("button", 3), handler("onclick", 6), text("kept"),
        ), disposedHandlers = listOf(7))

        assertNull(label(7))
        assertEquals("kept", label(6)?.text)
    }

    @Test
    fun disposingAComponentDropsItsListeners() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), diff(5, RenderEdit.PrependFrame(0, 2)), frames = listOf(
            element("div", 2), RenderFrame.Component(1, 5),
            element("a", 3), handler("onclick", 8), text("child"),
        ))
        assertEquals("child", label(8)?.text)

        apply(3, disposedComponents = listOf(5))

        assertNull(label(8))
    }

    @Test
    fun appliesPermutationsFromTheOriginalSiblingPositions() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0), RenderEdit.PrependFrame(1, 3), RenderEdit.PrependFrame(2, 6)),
            frames = listOf(
                element("button", 3), handler("onclick", 11), text("A"),
                element("button", 3), handler("onclick", 12), text("B"),
                element("button", 3), handler("onclick", 13), text("C"),
            ))

        apply(3, diff(1, RenderEdit.PermutationListEntry(0, 2), RenderEdit.PermutationListEntry(2, 0),
            RenderEdit.PermutationListEnd, RenderEdit.SetAttribute(0, 0), RenderEdit.SetAttribute(2, 1)),
            frames = listOf(handler("onclick", 21), handler("onclick", 23)))

        assertEquals("C", label(21)?.text)
        assertEquals("A", label(23)?.text)
        assertEquals("B", label(12)?.text)
        assertNull(label(11))
        assertNull(label(13))
    }

    @Test
    fun flattensRegionsAndCountsMarkupAndComponentsAsOneSlot() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0), RenderEdit.PrependFrame(2, 7), RenderEdit.PrependFrame(3, 8),
            RenderEdit.PrependFrame(4, 10)), frames = listOf(
                RenderFrame.Region(7),
                element("button", 3), handler("onclick", 31), text("first"),
                element("button", 3), handler("onclick", 32), text("second"),
                RenderFrame.Markup("<b>x</b><i>y</i>"),
                RenderFrame.Component(2, 9),
                attribute("Title", "parameter, not a DOM attribute"),
                element("button", 3), handler("onclick", 34), text("last"),
            ))

        apply(3, diff(1, RenderEdit.SetAttribute(1, 0), RenderEdit.SetAttribute(4, 1)),
            frames = listOf(attribute("id", "second"), attribute("id", "after-markup-and-component")))

        assertEquals("second", label(32)?.id)
        assertEquals("after-markup-and-component", label(34)?.id)
        assertNull(label(31)?.id)
    }

    @Test
    fun readsTextRenderedByAChildComponentInsideTheListener() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), diff(5, RenderEdit.PrependFrame(0, 4)), frames = listOf(
            element("button", 4), handler("onclick", 51), RenderFrame.Component(2, 5), attribute("Label", "ignored"),
            text("저장"),
        ))

        assertEquals("저장", label(51)?.text)
    }

    @Test
    fun neverLabelsComponentsFirstSeenMidStream() {
        val outcome = apply(2, diff(9, RenderEdit.PrependFrame(0, 0)),
            frames = listOf(element("button", 3), handler("onclick", 61), text("Delete")))

        assertNull(label(61))
        assertEquals(BatchOutcome.Applied(listOf(RenderChange.Unsynchronized(9),
            RenderChange.Inserted(ElementLabel("button", null, null, null, null, "Delete", false)))), outcome)
    }

    @Test
    fun dropsAComponentAfterAnEditTheBrowserWouldReject() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = loginForm)

        val outcome = apply(3, diff(1, RenderEdit.RemoveFrame(5)))
        apply(4, diff(1, RenderEdit.PrependFrame(0, 0)), frames = listOf(element("button", 2), handler("onclick", 2)))

        assertEquals(BatchOutcome.Applied(listOf(RenderChange.Unsynchronized(1))), outcome)
        assertNull(label(2))
        assertNull(label(3))
    }

    @Test
    fun rejectsReferenceCapturesWhereBrowserRendererWould() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = listOf(
            element("button", 3), handler("onclick", 81), RenderFrame.ElementReferenceCapture("capture"),
        ))
        assertNotNull(label(81))

        mirror.attachRoot(2)
        apply(3, diff(2, RenderEdit.PrependFrame(0, 1), RenderEdit.PrependFrame(1, 0)),
            frames = listOf(RenderFrame.ComponentReferenceCapture, element("a", 2), handler("onclick", 82)))
        mirror.attachRoot(3)
        apply(4, diff(3, RenderEdit.PrependFrame(0, 1), RenderEdit.PrependFrame(1, 0)),
            frames = listOf(RenderFrame.ElementReferenceCapture("root"), element("a", 2), handler("onclick", 83)))

        assertNull(label(82))
        assertNull(label(83))
    }

    @Test
    fun skipsComponentParametersAndRenderModeFramesInsideAComponentSubtree() {
        apply(2, diff(1, RenderEdit.PrependFrame(0, 0)), frames = listOf(
            element("div", 6), handler("onclick", 91),
            RenderFrame.Component(4, 6), attribute("Value", "x"), RenderFrame.ComponentReferenceCapture,
            RenderFrame.ComponentRenderMode,
        ))

        assertEquals("div", label(91)?.tag)
    }

    @Test
    fun ignoresRetransmittedBatchesAndDropsEverythingAfterAGap() {
        val first = RenderBatch(listOf(diff(1, RenderEdit.PrependFrame(0, 0))),
            listOf(element("button", 2), handler("onclick", 71)), emptyList(), emptyList(), emptyList())
        mirror.apply(2, first)

        assertEquals(BatchOutcome.Retransmitted, mirror.apply(2, first))
        assertEquals("button", label(71)?.tag)

        apply(4)
        assertNull(label(71))
    }

    @Test
    fun dropsAllLabelsWhenTheTreeExceedsTheNodeBudget() {
        val small = RenderTreeMirror(maxNodes = 5).apply { attachRoot(1) }
        val frames = List(10) { listOf(element("button", 2), handler("onclick", 100L + it)) }.flatten()
        val edits = List(10) { RenderEdit.PrependFrame(it, it * 2) }

        val outcome = small.apply(2, RenderBatch(listOf(ComponentDiff(1, edits)), frames, emptyList(), emptyList(), emptyList()))

        assertTrue((outcome as BatchOutcome.Applied).changes.contains(RenderChange.Overflow))
        assertNull(small.element(id(100)))
    }
}
