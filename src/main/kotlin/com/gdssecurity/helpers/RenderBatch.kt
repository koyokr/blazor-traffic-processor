/*
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.helpers

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/** Blazor's unsigned 64-bit event handler ID; zero on the wire means "no handler". */
@JvmInline
value class EventHandlerId(val value: ULong) {
    override fun toString(): String = value.toString()

    companion object {
        fun parse(text: String): EventHandlerId? = text.toULongOrNull()?.takeIf { it != 0uL }?.let(::EventHandlerId)
    }
}

/**
 * The out-of-process render batch written by aspnetcore's RenderBatchWriter (UTF-8 string table).
 * String fields are null where the wire holds string index -1, which Blazor uses to tell a false boolean
 * attribute (null) from a true one ("").
 */
data class RenderBatch(
    val updatedComponents: List<ComponentDiff>,
    val referenceFrames: List<RenderFrame>,
    val disposedComponentIds: List<Int>,
    val disposedEventHandlerIds: List<EventHandlerId>,
    val strings: List<String>,
) {
    companion object {
        /** @throws IllegalArgumentException when the bytes are not a well-formed batch within the size budgets. */
        fun decode(bytes: ByteArray): RenderBatch = Decoder(bytes).decode()
    }
}

data class ComponentDiff(val componentId: Int, val edits: List<RenderEdit>)

sealed interface RenderEdit {
    data class PrependFrame(val siblingIndex: Int, val frameIndex: Int) : RenderEdit
    data class RemoveFrame(val siblingIndex: Int) : RenderEdit
    data class SetAttribute(val siblingIndex: Int, val frameIndex: Int) : RenderEdit
    data class RemoveAttribute(val siblingIndex: Int, val name: String?) : RenderEdit
    data class UpdateText(val siblingIndex: Int, val frameIndex: Int) : RenderEdit
    data class StepIn(val siblingIndex: Int) : RenderEdit
    data object StepOut : RenderEdit
    data class UpdateMarkup(val siblingIndex: Int, val frameIndex: Int) : RenderEdit
    data class PermutationListEntry(val siblingIndex: Int, val moveToSiblingIndex: Int) : RenderEdit
    data object PermutationListEnd : RenderEdit
    data class Unknown(val type: Int, val siblingIndex: Int) : RenderEdit
}

sealed interface RenderFrame {
    data class Element(val subtreeLength: Int, val name: String?) : RenderFrame
    data class Text(val text: String?) : RenderFrame
    data class Attribute(val name: String?, val value: String?, val eventHandlerId: EventHandlerId?) : RenderFrame
    data class Component(val subtreeLength: Int, val componentId: Int) : RenderFrame
    data class Region(val subtreeLength: Int) : RenderFrame
    data class ElementReferenceCapture(val captureId: String?) : RenderFrame
    data object ComponentReferenceCapture : RenderFrame
    data class Markup(val markup: String?) : RenderFrame
    data object ComponentRenderMode : RenderFrame
    data object NamedEvent : RenderFrame
    data class Unknown(val type: Int, val fields: List<Int>) : RenderFrame
}

/**
 * Every section is bounded by the payload: entries are fixed-size, and the aggregate budgets reject batches whose
 * table entries reuse or overlap the same bytes, which RenderBatchWriter never produces.
 */
private class Decoder(private val bytes: ByteArray) {
    private val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    private lateinit var strings: List<String>
    private var editBudget = 0

    fun decode(): RenderBatch {
        require(bytes.size >= FOOTER_SIZE + 16) { "Payload is too short for a render batch." }
        val footer = bytes.size - FOOTER_SIZE
        val updated = int32(footer)
        val references = int32(footer + 4)
        val disposedComponents = int32(footer + 8)
        val disposedHandlers = int32(footer + 12)
        val table = int32(footer + 16)
        var previous = 0
        for (offset in intArrayOf(updated, references, disposedComponents, disposedHandlers, table)) {
            require(offset in previous..footer) { "Invalid render-batch section offsets." }
            previous = offset
        }
        strings = stringTable(table, footer)
        editBudget = updated / EDIT_SIZE
        return RenderBatch(
            updatedComponents = entries(updated, references, 4, "updated components") { entry ->
                val diffOffset = int32(entry)
                require(diffOffset in 0..updated - 8) { "Invalid component diff range." }
                ComponentDiff(int32(diffOffset), edits(diffOffset + 4, updated))
            },
            referenceFrames = entries(references, disposedComponents, FRAME_SIZE, "reference frames", ::frame),
            disposedComponentIds = entries(disposedComponents, disposedHandlers, 4, "disposed component IDs", ::int32),
            disposedEventHandlerIds = entries(disposedHandlers, table, 8, "disposed event handler IDs") {
                EventHandlerId(uint64(it))
            },
            strings = strings,
        )
    }

    private fun edits(offset: Int, sectionEnd: Int): List<RenderEdit> {
        val count = count(offset, sectionEnd, EDIT_SIZE, "render edits")
        editBudget -= count
        require(editBudget >= 0) { "Render-batch edits exceed the payload size." }
        return List(count) { index -> edit(offset + 4 + index * EDIT_SIZE) }
    }

    private fun edit(entry: Int): RenderEdit {
        val sibling = int32(entry + 4)
        return when (val type = int32(entry)) {
            1 -> RenderEdit.PrependFrame(sibling, int32(entry + 8))
            2 -> RenderEdit.RemoveFrame(sibling)
            3 -> RenderEdit.SetAttribute(sibling, int32(entry + 8))
            4 -> RenderEdit.RemoveAttribute(sibling, string(int32(entry + 12)))
            5 -> RenderEdit.UpdateText(sibling, int32(entry + 8))
            6 -> RenderEdit.StepIn(sibling)
            7 -> RenderEdit.StepOut
            8 -> RenderEdit.UpdateMarkup(sibling, int32(entry + 8))
            9 -> RenderEdit.PermutationListEntry(sibling, int32(entry + 8))
            10 -> RenderEdit.PermutationListEnd
            else -> RenderEdit.Unknown(type, sibling)
        }
    }

    private fun frame(entry: Int): RenderFrame = when (val type = int32(entry)) {
        1 -> RenderFrame.Element(int32(entry + 4), string(int32(entry + 8)))
        2 -> RenderFrame.Text(string(int32(entry + 4)))
        3 -> RenderFrame.Attribute(
            string(int32(entry + 4)),
            string(int32(entry + 8)),
            uint64(entry + 12).takeIf { it != 0uL }?.let(::EventHandlerId),
        )
        4 -> RenderFrame.Component(int32(entry + 4), int32(entry + 8))
        5 -> RenderFrame.Region(int32(entry + 4))
        6 -> RenderFrame.ElementReferenceCapture(string(int32(entry + 4)))
        7 -> RenderFrame.ComponentReferenceCapture
        8 -> RenderFrame.Markup(string(int32(entry + 4)))
        9 -> RenderFrame.ComponentRenderMode
        10 -> RenderFrame.NamedEvent
        else -> RenderFrame.Unknown(type, List(4) { int32(entry + 4 + it * 4) })
    }

    private fun stringTable(tableOffset: Int, footerOffset: Int): List<String> {
        val tableBytes = footerOffset - tableOffset
        require(tableBytes % 4 == 0) { "Invalid render-batch string table." }
        val count = tableBytes / 4
        require(count <= MAX_STRING_TABLE_ENTRIES) { "Render-batch string table is unreasonably large." }
        val byOffset = HashMap<Int, String>()
        var budget = bytes.size
        return List(count) { index ->
            val stringOffset = int32(tableOffset + index * 4)
            require(stringOffset in 0 until tableOffset) { "Invalid render-batch string offset." }
            byOffset.getOrPut(stringOffset) {
                val length = VarIntHelper.decode(bytes, stringOffset, tableOffset)
                val start = stringOffset + length.bytesRead
                require(length.value <= tableOffset - start) { "Invalid render-batch string range." }
                budget -= length.value
                require(budget >= 0) { "Render-batch strings exceed the payload size." }
                String(bytes, start, length.value, StandardCharsets.UTF_8)
            }
        }
    }

    private fun string(index: Int): String? {
        if (index == -1) return null
        require(index in strings.indices) { "Invalid render-batch string index." }
        return strings[index]
    }

    private inline fun <T> entries(offset: Int, sectionEnd: Int, size: Int, label: String, read: (Int) -> T): List<T> {
        val count = count(offset, sectionEnd, size, label)
        return List(count) { read(offset + 4 + it * size) }
    }

    private fun count(offset: Int, sectionEnd: Int, entrySize: Int, label: String): Int {
        require(offset in 0..sectionEnd - 4) { "Invalid $label range." }
        val count = int32(offset)
        require(count in 0..(sectionEnd - offset - 4) / entrySize) { "Invalid $label count." }
        return count
    }

    private fun int32(offset: Int): Int {
        require(offset in 0..bytes.size - 4) { "Unexpected end of binary payload." }
        return buffer.getInt(offset)
    }

    private fun uint64(offset: Int): ULong {
        require(offset in 0..bytes.size - 8) { "Unexpected end of binary payload." }
        return buffer.getLong(offset).toULong()
    }

    private companion object {
        const val FOOTER_SIZE = 20
        const val FRAME_SIZE = 20
        const val EDIT_SIZE = 16
        const val MAX_STRING_TABLE_ENTRIES = 100_000
    }
}
