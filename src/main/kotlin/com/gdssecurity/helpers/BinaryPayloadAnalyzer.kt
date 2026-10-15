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
import java.nio.ByteOrder
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/** Produces bounded, read-only hints for MessagePack binary arguments. */
object BinaryPayloadAnalyzer {
    private const val RENDER_BATCH_FOOTER_SIZE = 20
    private const val REFERENCE_FRAME_SIZE = 20
    private const val EDIT_SIZE = 16
    private const val MAX_OUTPUT_ITEMS = 512
    private const val MAX_STRING_TABLE_ENTRIES = 100_000
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
                analysis.put("RenderBatch", decodeRenderBatch(bytes))
            } catch (exception: IllegalArgumentException) {
                analysis.put("RenderBatchDecodeError", exception.message)
            }
        }
        return analysis
    }

    private fun decodeRenderBatch(bytes: ByteArray): JSONObject {
        require(bytes.size >= RENDER_BATCH_FOOTER_SIZE + 16) { "Payload is too short for a render batch." }
        val footer = bytes.size - RENDER_BATCH_FOOTER_SIZE
        val updated = readInt32(bytes, footer)
        val references = readInt32(bytes, footer + 4)
        val disposedComponents = readInt32(bytes, footer + 8)
        val disposedHandlers = readInt32(bytes, footer + 12)
        val table = readInt32(bytes, footer + 16)
        requireOrderedOffsets(footer, updated, references, disposedComponents, disposedHandlers, table)
        val strings = readStringTable(bytes, table, footer)
        return JSONObject()
            .put("UpdatedComponents", readUpdatedComponents(bytes, updated, references, strings))
            .put("ReferenceFrames", readReferenceFrames(bytes, references, disposedComponents, strings))
            .put("DisposedComponentIds", readInt32Array(bytes, disposedComponents, disposedHandlers))
            .put("DisposedEventHandlerIds", readUInt64Array(bytes, disposedHandlers, table))
            .put("StringTableCount", strings.size)
            .put("Strings", limitedStrings(strings))
            .apply { if (strings.size > MAX_OUTPUT_ITEMS) put("StringsTruncated", true) }
    }

    private fun readUpdatedComponents(bytes: ByteArray, offset: Int, sectionEnd: Int, strings: List<String>): JSONArray {
        val count = readCount(bytes, offset, sectionEnd, 4, "updated components")
        val components = JSONArray()
        repeat(minOf(count, MAX_OUTPUT_ITEMS)) { index ->
            val diffOffset = readInt32(bytes, offset + 4 + index * 4)
            requireRange(diffOffset, 8, offset, "component diff")
            components.put(JSONObject().put("ComponentId", readInt32(bytes, diffOffset))
                .put("Edits", readEdits(bytes, diffOffset + 4, offset, strings)))
        }
        if (count > MAX_OUTPUT_ITEMS) components.put(JSONObject().put("Truncated", true).put("TotalCount", count))
        return components
    }

    private fun readEdits(bytes: ByteArray, offset: Int, sectionEnd: Int, strings: List<String>): JSONArray {
        val count = readCount(bytes, offset, sectionEnd, EDIT_SIZE, "render edits")
        val edits = JSONArray()
        repeat(minOf(count, MAX_OUTPUT_ITEMS)) { index ->
            val entry = offset + 4 + index * EDIT_SIZE
            val type = readInt32(bytes, entry)
            val edit = JSONObject().put("Type", editTypeName(type)).put("SiblingIndex", readInt32(bytes, entry + 4))
            when (type) {
                0, 2, 4, 7 -> edit.put("ReferenceFrameIndex", readInt32(bytes, entry + 8))
                3 -> edit.put("AttributeName", stringAt(strings, readInt32(bytes, entry + 12)))
                8 -> edit.put("MoveToSiblingIndex", readInt32(bytes, entry + 8))
            }
            edits.put(edit)
        }
        if (count > MAX_OUTPUT_ITEMS) edits.put(JSONObject().put("Truncated", true).put("TotalCount", count))
        return edits
    }

    private fun readReferenceFrames(bytes: ByteArray, offset: Int, sectionEnd: Int, strings: List<String>): JSONArray {
        val count = readCount(bytes, offset, sectionEnd, REFERENCE_FRAME_SIZE, "reference frames")
        val frames = JSONArray()
        repeat(minOf(count, MAX_OUTPUT_ITEMS)) { index ->
            val entry = offset + 4 + index * REFERENCE_FRAME_SIZE
            val type = readInt32(bytes, entry)
            val frame = JSONObject().put("Index", index).put("Type", frameTypeName(type))
            when (type) {
                1 -> {
                    frame.put("SubtreeLength", readInt32(bytes, entry + 4))
                    frame.put("ElementName", stringAt(strings, readInt32(bytes, entry + 8)))
                }
                2 -> frame.put("TextContent", stringAt(strings, readInt32(bytes, entry + 4)))
                3 -> {
                    frame.put("AttributeName", stringAt(strings, readInt32(bytes, entry + 4)))
                    frame.put("AttributeValue", stringAt(strings, readInt32(bytes, entry + 8)))
                    frame.put("EventHandlerId", readUInt64(bytes, entry + 12))
                }
                4 -> {
                    frame.put("SubtreeLength", readInt32(bytes, entry + 4))
                    frame.put("ComponentId", readInt32(bytes, entry + 8))
                }
                5 -> frame.put("SubtreeLength", readInt32(bytes, entry + 4))
                6 -> frame.put("CaptureId", stringAt(strings, readInt32(bytes, entry + 4)))
                8 -> frame.put("MarkupContent", stringAt(strings, readInt32(bytes, entry + 4)))
                else -> {
                    frame.put("Field1", readInt32(bytes, entry + 4))
                    frame.put("Field2", readInt32(bytes, entry + 8))
                    frame.put("Field3", readInt32(bytes, entry + 12))
                    frame.put("Field4", readInt32(bytes, entry + 16))
                }
            }
            frames.put(frame)
        }
        if (count > MAX_OUTPUT_ITEMS) frames.put(JSONObject().put("Truncated", true).put("TotalCount", count))
        return frames
    }

    private fun readInt32Array(bytes: ByteArray, offset: Int, sectionEnd: Int): JSONArray {
        val count = readCount(bytes, offset, sectionEnd, 4, "disposed component IDs")
        return JSONArray().apply {
            repeat(minOf(count, MAX_OUTPUT_ITEMS)) { put(readInt32(bytes, offset + 4 + it * 4)) }
        }
    }

    private fun readUInt64Array(bytes: ByteArray, offset: Int, sectionEnd: Int): JSONArray {
        val count = readCount(bytes, offset, sectionEnd, 8, "disposed event handler IDs")
        return JSONArray().apply {
            repeat(minOf(count, MAX_OUTPUT_ITEMS)) { put(readUInt64(bytes, offset + 4 + it * 8)) }
        }
    }

    private fun readStringTable(bytes: ByteArray, tableOffset: Int, footerOffset: Int): List<String> {
        val tableBytes = footerOffset - tableOffset
        require(tableBytes >= 0 && tableBytes % 4 == 0) { "Invalid render-batch string table." }
        val count = tableBytes / 4
        require(count <= MAX_STRING_TABLE_ENTRIES) { "Render-batch string table is unreasonably large." }
        return List(count) { index ->
            val stringOffset = readInt32(bytes, tableOffset + index * 4)
            require(stringOffset >= 0 && stringOffset < tableOffset) { "Invalid render-batch string offset." }
            val length = readVarInt(bytes, stringOffset, tableOffset)
            val valueOffset = stringOffset + length.bytesRead
            requireRange(valueOffset, length.value, tableOffset, "render-batch string")
            String(bytes, valueOffset, length.value, StandardCharsets.UTF_8)
        }
    }

    private fun limitedStrings(strings: List<String>): JSONArray = JSONArray().apply {
        repeat(minOf(strings.size, MAX_OUTPUT_ITEMS)) { put(truncate(strings[it])) }
    }

    private fun readCount(bytes: ByteArray, offset: Int, sectionEnd: Int, entrySize: Int, label: String): Int {
        requireRange(offset, 4, sectionEnd, label)
        val count = readInt32(bytes, offset)
        require(count >= 0 && count <= (sectionEnd - offset - 4) / entrySize) { "Invalid $label count." }
        return count
    }

    private fun requireOrderedOffsets(footerOffset: Int, vararg offsets: Int) {
        var previous = 0
        for (offset in offsets) {
            require(offset >= previous && offset <= footerOffset) { "Invalid render-batch section offsets." }
            previous = offset
        }
    }

    private fun requireRange(offset: Int, length: Int, exclusiveEnd: Int, label: String) {
        require(offset >= 0 && length >= 0 && offset <= exclusiveEnd && length <= exclusiveEnd - offset) {
            "Invalid $label range."
        }
    }

    private fun readInt32(bytes: ByteArray, offset: Int): Int {
        require(offset >= 0 && offset <= bytes.size - 4) { "Unexpected end of binary payload." }
        return ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).int
    }

    private fun readUInt64(bytes: ByteArray, offset: Int): String {
        require(offset >= 0 && offset <= bytes.size - 8) { "Unexpected end of binary payload." }
        return java.lang.Long.toUnsignedString(ByteBuffer.wrap(bytes, offset, 8).order(ByteOrder.LITTLE_ENDIAN).long)
    }

    private fun readVarInt(bytes: ByteArray, offset: Int, exclusiveEnd: Int): VarInt {
        var value = 0
        var shift = 0
        for (index in 0 until 4) {
            if (offset + index >= exclusiveEnd) break
            val current = bytes[offset + index].toInt() and 0xff
            value = value or ((current and 0x7f) shl shift)
            if (current and 0x80 == 0) return VarInt(value, index + 1)
            shift += 7
        }
        throw IllegalArgumentException("Invalid render-batch string length.")
    }

    private fun stringAt(strings: List<String>, index: Int): String {
        if (index == -1) return JSONObject.NULL.toString()
        require(index in strings.indices) { "Invalid render-batch string index." }
        return truncate(strings[index])
    }

    private fun frameTypeName(type: Int): String = when (type) {
        1 -> "Element"
        2 -> "Text"
        3 -> "Attribute"
        4 -> "Component"
        5 -> "Region"
        6 -> "ElementReferenceCapture"
        7 -> "ComponentReferenceCapture"
        8 -> "Markup"
        9 -> "ComponentRenderMode"
        10 -> "NamedEvent"
        else -> "Unknown($type)"
    }

    private fun editTypeName(type: Int): String = when (type) {
        0 -> "PrependFrame"
        1 -> "RemoveFrame"
        2 -> "SetAttribute"
        3 -> "RemoveAttribute"
        4 -> "UpdateText"
        5 -> "StepIn"
        6 -> "StepOut"
        7 -> "UpdateMarkup"
        8 -> "PermutationListEntry"
        9 -> "PermutationListEnd"
        else -> "Unknown($type)"
    }

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

    private data class VarInt(val value: Int, val bytesRead: Int)
}
