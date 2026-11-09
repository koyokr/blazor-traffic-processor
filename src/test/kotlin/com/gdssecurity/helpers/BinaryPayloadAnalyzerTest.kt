package com.gdssecurity.helpers

import org.json.JSONArray
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class BinaryPayloadAnalyzerTest {
    @Test
    fun exposesPrintableUtf8WithoutChangingTheBytes() {
        val bytes = """{"authenticated":true}""".toByteArray()

        val analysis = BinaryPayloadAnalyzer.analyze(bytes, "JS.ReceiveByteArray")

        assertEquals(bytes.size, analysis.getInt("Length"))
        assertEquals("Binary", analysis.getString("Format"))
        assertEquals("""{"authenticated":true}""", analysis.getString("Utf8Text"))
        assertFalse(analysis.has("RenderBatch"))
    }

    @Test
    fun extractsRenderBatchFramesAndStringTable() {
        val analysis = BinaryPayloadAnalyzer.analyze(renderBatchWithTextFrame("한글 中文 日本語 𠮷 😀"), "JS.RenderBatch")
        val renderBatch = analysis.getJSONObject("RenderBatch")
        val frame = renderBatch.getJSONArray("ReferenceFrames").getJSONObject(0)

        assertEquals("BlazorRenderBatch", analysis.getString("Format"))
        assertEquals(1, renderBatch.getInt("StringTableCount"))
        assertEquals("한글 中文 日本語 𠮷 😀", renderBatch.getJSONArray("Strings").getString(0))
        assertEquals("Text", frame.getString("Type"))
        assertEquals("한글 中文 日本語 𠮷 😀", frame.getString("TextContent"))
    }

    @Test
    fun reportsMalformedRenderBatchWithoutThrowing() {
        val analysis = BinaryPayloadAnalyzer.analyze(ByteArray(40), "JS.RenderBatch")

        assertEquals("BlazorRenderBatch", analysis.getString("Format"))
        assertTrue(analysis.has("RenderBatchDecodeError"))
        assertFalse(analysis.has("RenderBatch"))
    }

    @Test
    fun namesEditsAndSelectsTheirFieldsByAspNetCoreEditType() {
        val bytes = RenderBatchWriter.batch(
            ComponentDiff(3, listOf(
                RenderEdit.PrependFrame(0, 1),
                RenderEdit.SetAttribute(1, 2),
                RenderEdit.RemoveAttribute(2, "disabled"),
                RenderEdit.PermutationListEntry(3, 0),
                RenderEdit.PermutationListEnd,
                RenderEdit.StepOut,
            )),
            frames = listOf(RenderFrame.Text("a"), RenderFrame.Text("b"), RenderFrame.Text("c")),
        )

        val edits = BinaryPayloadAnalyzer.analyze(bytes, "JS.RenderBatch").getJSONObject("RenderBatch")
            .getJSONArray("UpdatedComponents").getJSONObject(0).getJSONArray("Edits")

        assertEquals(JSONArray("""[{"Type":"PrependFrame","SiblingIndex":0,"ReferenceFrameIndex":1},""" +
            """{"Type":"SetAttribute","SiblingIndex":1,"ReferenceFrameIndex":2},""" +
            """{"Type":"RemoveAttribute","SiblingIndex":2,"AttributeName":"disabled"},""" +
            """{"Type":"PermutationListEntry","SiblingIndex":3,"MoveToSiblingIndex":0},""" +
            """{"Type":"PermutationListEnd"},{"Type":"StepOut"}]""").toList(), edits.toList())
    }

    @Test
    fun rendersNullAttributeValuesAsJsonNullAndHandlerIdsAsUnsigned() {
        val bytes = RenderBatchWriter.batch(frames = listOf(
            RenderFrame.Attribute("disabled", null, null),
            RenderFrame.Attribute("disabled", "", null),
            RenderFrame.Attribute("onclick", null, EventHandlerId(ULong.MAX_VALUE)),
        ))

        val frames = BinaryPayloadAnalyzer.analyze(bytes, "JS.RenderBatch").getJSONObject("RenderBatch")
            .getJSONArray("ReferenceFrames")

        assertTrue(frames.getJSONObject(0).isNull("AttributeValue"))
        assertEquals("", frames.getJSONObject(1).getString("AttributeValue"))
        assertEquals("0", frames.getJSONObject(1).getString("EventHandlerId"))
        assertEquals("18446744073709551615", frames.getJSONObject(2).getString("EventHandlerId"))
    }

    private fun renderBatchWithTextFrame(text: String): ByteArray {
        val textBytes = text.toByteArray()
        val batch = ByteArrayOutputStream()
        fun int32(value: Int) = batch.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array())

        val updatedComponentsOffset = batch.size()
        int32(0)
        val referenceFramesOffset = batch.size()
        listOf(1, 2, 0, 0, 0, 0).forEach(::int32)
        val disposedComponentIdsOffset = batch.size()
        int32(0)
        val disposedEventHandlerIdsOffset = batch.size()
        int32(0)
        val stringOffset = batch.size()
        batch.writeBytes(VarIntHelper.encodeVarInt(textBytes.size))
        batch.writeBytes(textBytes)
        val stringTableOffset = batch.size()
        int32(stringOffset)

        listOf(updatedComponentsOffset, referenceFramesOffset, disposedComponentIdsOffset,
            disposedEventHandlerIdsOffset, stringTableOffset).forEach(::int32)
        return batch.toByteArray()
    }
}
