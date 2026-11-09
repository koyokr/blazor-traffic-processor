package com.gdssecurity.helpers

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Test port of aspnetcore src/Components/Shared/src/RenderBatchWriter.cs: UTF-8 string table, the same
 * deduplication rules, and literal wire codes from RenderTreeEditType / RenderTreeFrameType. [RenderBatch.strings]
 * is ignored; the writer builds its own table.
 */
class RenderBatchWriter private constructor() {
    private val output = ByteArrayOutputStream()
    private val strings = mutableListOf<String>()
    private val deduplicated = HashMap<String, Int>()

    private fun write(batch: RenderBatch): ByteArray {
        val updatedComponents = writeDiffs(batch.updatedComponents)
        val referenceFrames = position()
        int32(batch.referenceFrames.size)
        batch.referenceFrames.forEach(::writeFrame)
        val disposedComponents = position()
        int32(batch.disposedComponentIds.size)
        batch.disposedComponentIds.forEach(::int32)
        val disposedHandlers = position()
        int32(batch.disposedEventHandlerIds.size)
        batch.disposedEventHandlerIds.forEach { int64(it.value.toLong()) }
        val stringTable = writeStringTable()
        listOf(updatedComponents, referenceFrames, disposedComponents, disposedHandlers, stringTable).forEach(::int32)
        return output.toByteArray()
    }

    private fun writeDiffs(diffs: List<ComponentDiff>): Int {
        val locations = diffs.map { diff ->
            position().also {
                int32(diff.componentId)
                int32(diff.edits.size)
                diff.edits.forEach(::writeEdit)
            }
        }
        return position().also {
            int32(diffs.size)
            locations.forEach(::int32)
        }
    }

    private fun writeEdit(edit: RenderEdit) {
        val (type, sibling, referenceOrMove) = when (edit) {
            is RenderEdit.PrependFrame -> Triple(1, edit.siblingIndex, edit.frameIndex)
            is RenderEdit.RemoveFrame -> Triple(2, edit.siblingIndex, 0)
            is RenderEdit.SetAttribute -> Triple(3, edit.siblingIndex, edit.frameIndex)
            is RenderEdit.RemoveAttribute -> Triple(4, edit.siblingIndex, 0)
            is RenderEdit.UpdateText -> Triple(5, edit.siblingIndex, edit.frameIndex)
            is RenderEdit.StepIn -> Triple(6, edit.siblingIndex, 0)
            RenderEdit.StepOut -> Triple(7, 0, 0)
            is RenderEdit.UpdateMarkup -> Triple(8, edit.siblingIndex, edit.frameIndex)
            is RenderEdit.PermutationListEntry -> Triple(9, edit.siblingIndex, edit.moveToSiblingIndex)
            RenderEdit.PermutationListEnd -> Triple(10, 0, 0)
            is RenderEdit.Unknown -> Triple(edit.type, edit.siblingIndex, 0)
        }
        int32(type)
        int32(sibling)
        int32(referenceOrMove)
        int32(stringIndex((edit as? RenderEdit.RemoveAttribute)?.name, deduplicate = true))
    }

    private fun writeFrame(frame: RenderFrame) {
        val fields = IntArray(4)
        var handler = 0L
        val type = when (frame) {
            is RenderFrame.Element -> 1.also {
                fields[0] = frame.subtreeLength
                fields[1] = stringIndex(frame.name, deduplicate = true)
            }
            is RenderFrame.Text -> 2.also { fields[0] = stringIndex(frame.text, deduplicate = frame.text.isNullOrBlank()) }
            is RenderFrame.Attribute -> 3.also {
                fields[0] = stringIndex(frame.name, deduplicate = true)
                fields[1] = stringIndex(frame.value, deduplicate = frame.value.isNullOrEmpty())
                handler = frame.eventHandlerId?.value?.toLong() ?: 0L
            }
            is RenderFrame.Component -> 4.also {
                fields[0] = frame.subtreeLength
                fields[1] = frame.componentId
            }
            is RenderFrame.Region -> 5.also { fields[0] = frame.subtreeLength }
            is RenderFrame.ElementReferenceCapture -> 6.also { fields[0] = stringIndex(frame.captureId, deduplicate = false) }
            RenderFrame.ComponentReferenceCapture -> 7
            is RenderFrame.Markup -> 8.also { fields[0] = stringIndex(frame.markup, deduplicate = false) }
            RenderFrame.ComponentRenderMode -> 9
            RenderFrame.NamedEvent -> 10
            is RenderFrame.Unknown -> frame.type.also { frame.fields.forEachIndexed { i, value -> fields[i] = value } }
        }
        int32(type)
        if (frame is RenderFrame.Attribute) {
            int32(fields[0])
            int32(fields[1])
            int64(handler)
        } else {
            fields.forEach(::int32)
        }
    }

    private fun stringIndex(value: String?, deduplicate: Boolean): Int {
        if (value == null) return -1
        if (deduplicate) deduplicated[value]?.let { return it }
        val index = strings.size
        strings += value
        if (deduplicate) deduplicated[value] = index
        return index
    }

    private fun writeStringTable(): Int {
        val locations = strings.map { value ->
            position().also {
                val utf8 = value.toByteArray(Charsets.UTF_8)
                output.writeBytes(VarIntHelper.encodeVarInt(utf8.size))
                output.writeBytes(utf8)
            }
        }
        return position().also { locations.forEach(::int32) }
    }

    private fun position() = output.size()
    private fun int32(value: Int) = output.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array())
    private fun int64(value: Long) = output.writeBytes(ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array())

    companion object {
        fun write(batch: RenderBatch): ByteArray = RenderBatchWriter().write(batch)

        fun batch(
            vararg diffs: ComponentDiff,
            frames: List<RenderFrame> = emptyList(),
            disposedComponentIds: List<Int> = emptyList(),
            disposedEventHandlerIds: List<Long> = emptyList(),
        ): ByteArray = write(RenderBatch(diffs.toList(), frames, disposedComponentIds,
            disposedEventHandlerIds.map { EventHandlerId(it.toULong()) }, emptyList()))
    }
}
