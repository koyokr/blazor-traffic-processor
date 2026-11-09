package com.gdssecurity.helpers

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

class RenderBatchTest {
    @Test
    fun decodesEveryEditAndFrameTypeTheWayAspNetCoreWritesThem() {
        val frames = listOf(
            RenderFrame.Element(4, "button"),
            RenderFrame.Attribute("onclick", null, EventHandlerId(ULong.MAX_VALUE)),
            RenderFrame.Attribute("disabled", "", null),
            RenderFrame.Text("한글 😀"),
            RenderFrame.Component(3, 7),
            RenderFrame.ComponentReferenceCapture,
            RenderFrame.ComponentRenderMode,
            RenderFrame.Region(2),
            RenderFrame.ElementReferenceCapture("capture-1"),
            RenderFrame.Markup("<b>bold</b>"),
            RenderFrame.NamedEvent,
            RenderFrame.Unknown(42, listOf(1, 2, 3, 4)),
        )
        val edits = listOf(
            RenderEdit.PrependFrame(0, 0),
            RenderEdit.RemoveFrame(1),
            RenderEdit.SetAttribute(2, 1),
            RenderEdit.RemoveAttribute(3, "disabled"),
            RenderEdit.UpdateText(4, 3),
            RenderEdit.StepIn(5),
            RenderEdit.StepOut,
            RenderEdit.UpdateMarkup(6, 9),
            RenderEdit.PermutationListEntry(7, 8),
            RenderEdit.PermutationListEnd,
            RenderEdit.Unknown(99, 9),
        )
        val written = RenderBatch(listOf(ComponentDiff(3, edits), ComponentDiff(4, emptyList())), frames,
            listOf(5, 6), listOf(EventHandlerId(12u)), emptyList())

        val decoded = RenderBatch.decode(RenderBatchWriter.write(written))

        assertEquals(written, decoded.copy(strings = emptyList()))
    }

    @Test
    fun keepsNullStringsDistinctFromEmptyStrings() {
        val decoded = RenderBatch.decode(RenderBatchWriter.batch(
            ComponentDiff(1, listOf(RenderEdit.RemoveAttribute(0, null))),
            frames = listOf(RenderFrame.Attribute("disabled", "", null), RenderFrame.Attribute("disabled", null, null),
                RenderFrame.Text(""), RenderFrame.Text(null)),
        ))

        assertEquals(listOf(RenderFrame.Attribute("disabled", "", null), RenderFrame.Attribute("disabled", null, null),
            RenderFrame.Text(""), RenderFrame.Text(null)), decoded.referenceFrames)
        assertEquals(RenderEdit.RemoveAttribute(0, null), decoded.updatedComponents.single().edits.single())
    }

    @Test
    fun repeatedStringOffsetsShareOneDecodedString() {
        val text = "x".repeat(1_000)
        val decoded = RenderBatch.decode(rawBatchWithStringTable(VarIntHelper.encodeVarInt(text.length) + text.toByteArray(),
            List(20_000) { 0 }))

        assertEquals(20_000, decoded.strings.size)
        assertTrue(decoded.strings.all { it === decoded.strings[0] })
        assertEquals(text, decoded.strings[0])
    }

    @Test
    fun rejectsStringTablesWhoseEntriesOverlapBeyondThePayloadSize() {
        val data = ByteArray(2_000) { 0x7f }
        val error = assertThrows(IllegalArgumentException::class.java) {
            RenderBatch.decode(rawBatchWithStringTable(data, List(1_500) { it }))
        }
        assertEquals("Render-batch strings exceed the payload size.", error.message)
    }

    @Test
    fun rejectsDiffTablesThatReuseOneDiffBeyondThePayloadSize() {
        val batch = ByteArrayOutputStream()
        fun int32(value: Int) = batch.writeBytes(le(value))
        int32(1)
        int32(100)
        repeat(100) { listOf(2, 0, 0, -1).forEach(::int32) }
        val updated = batch.size()
        int32(1_000)
        repeat(1_000) { int32(0) }
        val references = batch.size()
        repeat(3) { int32(0) }
        listOf(updated, references, references + 4, references + 8, references + 12).forEach(::int32)

        val error = assertThrows(IllegalArgumentException::class.java) { RenderBatch.decode(batch.toByteArray()) }
        assertEquals("Render-batch edits exceed the payload size.", error.message)
    }

    private fun rawBatchWithStringTable(stringData: ByteArray, offsets: List<Int>): ByteArray {
        val batch = ByteArrayOutputStream()
        val updated = batch.size()
        repeat(4) { batch.writeBytes(le(0)) }
        val strings = batch.size()
        batch.writeBytes(stringData)
        val table = batch.size()
        offsets.forEach { batch.writeBytes(le(strings + it)) }
        listOf(updated, updated + 4, updated + 8, updated + 12, table).forEach { batch.writeBytes(le(it)) }
        return batch.toByteArray()
    }

    private fun le(value: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
}
