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

import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Produces bounded, read-only hints for MessagePack binary arguments. */
object BinaryPayloadAnalyzer {
    private const val MAX_OUTPUT_ITEMS = 512
    private const val MAX_TEXT_CHARS = 4_096
    private const val MIN_PRINTABLE_RUN = 4

    fun analyze(bytes: ByteArray, target: String?): JSONObject {
        val analysis = JSONObject().put("Length", bytes.size).put("Format", detectFileFormat(bytes))
        val utf8 = decodePrintableUtf8(bytes)
        if (utf8 != null) {
            analysis.put("Utf8Text", truncate(utf8))
            if (utf8.length > MAX_TEXT_CHARS) analysis.put("Utf8TextTruncated", true)
        } else {
            val strings = extractPrintableAscii(bytes)
            if (!strings.isEmpty) analysis.put("PrintableStrings", strings)
        }
        if (target == "JS.RenderBatch") {
            try {
                analysis.put("Format", "BlazorRenderBatch")
                analysis.put("RenderBatch", renderBatchJson(RenderBatch.decode(bytes)))
            } catch (exception: IllegalArgumentException) {
                analysis.put("RenderBatchDecodeError", exception.message)
            }
        }
        return analysis
    }

    private fun renderBatchJson(batch: RenderBatch): JSONObject = JSONObject()
        .put("UpdatedComponents", limited(batch.updatedComponents) { _, diff ->
            JSONObject().put("ComponentId", diff.componentId).put("Edits", limited(diff.edits) { _, edit -> editJson(edit) })
        })
        .put("ReferenceFrames", limited(batch.referenceFrames, ::frameJson))
        .put("DisposedComponentIds", JSONArray(batch.disposedComponentIds.take(MAX_OUTPUT_ITEMS)))
        .put("DisposedEventHandlerIds", JSONArray(batch.disposedEventHandlerIds.take(MAX_OUTPUT_ITEMS).map { it.toString() }))
        .put("StringTableCount", batch.strings.size)
        .put("Strings", JSONArray(batch.strings.take(MAX_OUTPUT_ITEMS).map(::truncate)))
        .apply { if (batch.strings.size > MAX_OUTPUT_ITEMS) put("StringsTruncated", true) }

    private fun <T> limited(items: List<T>, json: (Int, T) -> JSONObject): JSONArray = JSONArray().apply {
        items.take(MAX_OUTPUT_ITEMS).forEachIndexed { index, item -> put(json(index, item)) }
        if (items.size > MAX_OUTPUT_ITEMS) put(JSONObject().put("Truncated", true).put("TotalCount", items.size))
    }

    private fun editJson(edit: RenderEdit): JSONObject {
        val json = JSONObject().put("Type", edit.javaClass.simpleName)
        fun at(siblingIndex: Int) = json.put("SiblingIndex", siblingIndex)
        when (edit) {
            is RenderEdit.PrependFrame -> at(edit.siblingIndex).put("ReferenceFrameIndex", edit.frameIndex)
            is RenderEdit.RemoveFrame -> at(edit.siblingIndex)
            is RenderEdit.SetAttribute -> at(edit.siblingIndex).put("ReferenceFrameIndex", edit.frameIndex)
            is RenderEdit.RemoveAttribute -> at(edit.siblingIndex).put("AttributeName", text(edit.name))
            is RenderEdit.UpdateText -> at(edit.siblingIndex).put("ReferenceFrameIndex", edit.frameIndex)
            is RenderEdit.StepIn -> at(edit.siblingIndex)
            RenderEdit.StepOut, RenderEdit.PermutationListEnd -> Unit
            is RenderEdit.UpdateMarkup -> at(edit.siblingIndex).put("ReferenceFrameIndex", edit.frameIndex)
            is RenderEdit.PermutationListEntry -> at(edit.siblingIndex).put("MoveToSiblingIndex", edit.moveToSiblingIndex)
            is RenderEdit.Unknown -> json.put("Type", "Unknown(${edit.type})").put("SiblingIndex", edit.siblingIndex)
        }
        return json
    }

    private fun frameJson(index: Int, frame: RenderFrame): JSONObject {
        val json = JSONObject().put("Index", index).put("Type", frame.javaClass.simpleName)
        when (frame) {
            is RenderFrame.Element -> json.put("SubtreeLength", frame.subtreeLength).put("ElementName", text(frame.name))
            is RenderFrame.Text -> json.put("TextContent", text(frame.text))
            is RenderFrame.Attribute -> json.put("AttributeName", text(frame.name)).put("AttributeValue", text(frame.value))
                .put("EventHandlerId", frame.eventHandlerId?.toString() ?: "0")
            is RenderFrame.Component -> json.put("SubtreeLength", frame.subtreeLength).put("ComponentId", frame.componentId)
            is RenderFrame.Region -> json.put("SubtreeLength", frame.subtreeLength)
            is RenderFrame.ElementReferenceCapture -> json.put("CaptureId", text(frame.captureId))
            is RenderFrame.Markup -> json.put("MarkupContent", text(frame.markup))
            RenderFrame.ComponentReferenceCapture, RenderFrame.ComponentRenderMode, RenderFrame.NamedEvent -> Unit
            is RenderFrame.Unknown -> {
                json.put("Type", "Unknown(${frame.type})")
                frame.fields.forEachIndexed { field, value -> json.put("Field${field + 1}", value) }
            }
        }
        return json
    }

    private fun text(value: String?): Any = value?.let(::truncate) ?: JSONObject.NULL

    private fun detectFileFormat(bytes: ByteArray): String = when {
        startsWith(bytes, byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte())) -> "PNG"
        startsWith(bytes, byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0xff.toByte())) -> "JPEG"
        startsWith(bytes, "GIF8".toByteArray(StandardCharsets.US_ASCII)) -> "GIF"
        startsWith(bytes, "%PDF-".toByteArray(StandardCharsets.US_ASCII)) -> "PDF"
        startsWith(bytes, byteArrayOf('P'.code.toByte(), 'K'.code.toByte(), 3, 4)) -> "ZIP"
        startsWith(bytes, byteArrayOf(0x1f, 0x8b.toByte())) -> "GZIP"
        else -> "Binary"
    }

    private fun startsWith(value: ByteArray, prefix: ByteArray): Boolean =
        value.size >= prefix.size && prefix.indices.all { value[it] == prefix[it] }

    private fun decodePrintableUtf8(bytes: ByteArray): String? {
        try {
            val value = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString()
            if (value.isEmpty()) return value
            val printable = value.codePoints().filter {
                !Character.isISOControl(it) || it == '\r'.code || it == '\n'.code || it == '\t'.code
            }.count()
            return if (printable * 100 >= value.codePointCount(0, value.length) * 85L) value else null
        } catch (_: CharacterCodingException) {
            return null
        }
    }

    private fun extractPrintableAscii(bytes: ByteArray): JSONArray {
        val strings = JSONArray()
        val current = StringBuilder()
        for (value in bytes) {
            val unsigned = value.toInt() and 0xff
            if (unsigned in 0x20..0x7e) current.append(unsigned.toChar()) else addPrintableRun(strings, current)
            if (strings.length() >= MAX_OUTPUT_ITEMS) break
        }
        addPrintableRun(strings, current)
        return strings
    }

    private fun addPrintableRun(strings: JSONArray, current: StringBuilder) {
        if (current.length >= MIN_PRINTABLE_RUN && strings.length() < MAX_OUTPUT_ITEMS) {
            strings.put(truncate(current.toString()))
        }
        current.setLength(0)
    }

    private fun truncate(value: String): String = value.take(MAX_TEXT_CHARS)
}
