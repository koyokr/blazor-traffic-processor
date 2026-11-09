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
package com.gdssecurity.annotations

import com.gdssecurity.helpers.BlazorFrames
import com.gdssecurity.helpers.VarIntHelper
import com.gdssecurity.messages.HubCodec
import com.gdssecurity.messages.HubMessage
import java.io.ByteArrayOutputStream

/**
 * One direction of a SignalR connection: the JSON handshake record, then length-prefixed BlazorPack frames that may
 * span WebSocket messages. Completed frames are emitted as they are found; only an incomplete tail is retained.
 */
class HubFrameStream {
    sealed interface Event {
        data class Handshake(val json: String) : Event
        data class Message(val message: HubMessage) : Event
        data class Malformed(val reason: String) : Event
    }

    /** [expected] is null until the length prefix itself is complete. */
    data class Pending(val received: Int, val expected: Int?)

    private enum class Mode { START, HANDSHAKE, FRAMES }

    private var mode = Mode.START
    private val tail = Tail()

    fun accept(bytes: ByteArray, sink: (Event) -> Unit): Pending? {
        var offset = 0
        while (tail.size() > 0 && offset < bytes.size) {
            val take = minOf(bytes.size - offset, bytesToCompleteTail(bytes, offset))
            tail.write(bytes, offset, take)
            offset += take
            val consumed = parse(tail.bytes(), 0, tail.size(), sink) ?: return null
            if (consumed == tail.size()) tail.reset()
        }
        if (tail.size() == 0 && offset < bytes.size) {
            val consumed = parse(bytes, offset, bytes.size, sink) ?: return null
            tail.write(bytes, consumed, bytes.size - consumed)
        }
        return pending()
    }

    /**
     * Returns the offset of the first byte of an incomplete handshake or frame, or null once framing is lost; the
     * rest of that WebSocket message is then dropped and parsing resumes at the next message.
     */
    private fun parse(data: ByteArray, from: Int, to: Int, sink: (Event) -> Unit): Int? {
        var offset = from
        if (mode == Mode.START && offset < to) mode = if (data[offset] == '{'.code.toByte()) Mode.HANDSHAKE else Mode.FRAMES
        if (mode == Mode.HANDSHAKE) {
            val end = separatorIndex(data, offset, to)
            if (end == null) {
                if (to - offset <= MAX_HANDSHAKE_BYTES) return offset
                return malformed(sink, "handshake has no record separator")
            }
            sink(Event.Handshake(String(data, offset, end - offset, Charsets.UTF_8)))
            mode = Mode.FRAMES
            offset = end + 1
        }
        while (offset < to) {
            if (prefixIncomplete(data, offset, to)) return offset
            val prefix = runCatching { VarIntHelper.decode(data, offset, to) }.getOrNull()
                ?: return malformed(sink, "invalid length prefix")
            if (prefix.value !in 1..BlazorFrames.MAX_FRAME_BYTES) return malformed(sink, "invalid frame length ${prefix.value}")
            val start = offset + prefix.bytesRead
            if (prefix.value > to - start) return offset
            sink(runCatching { Event.Message(HubCodec.decode(data, start, prefix.value)) }
                .getOrElse { Event.Malformed(it.message ?: "undecodable frame") })
            offset = start + prefix.value
        }
        return offset
    }

    private fun malformed(sink: (Event) -> Unit, reason: String): Int? {
        sink(Event.Malformed(reason))
        mode = Mode.FRAMES
        tail.reset()
        return null
    }

    private fun separatorIndex(data: ByteArray, from: Int, to: Int): Int? =
        (from until minOf(to, from + MAX_HANDSHAKE_BYTES + 1)).firstOrNull { data[it] == RECORD_SEPARATOR }

    private fun bytesToCompleteTail(bytes: ByteArray, offset: Int): Int = when (mode) {
        Mode.START, Mode.HANDSHAKE -> separatorIndex(bytes, offset, bytes.size)?.let { it - offset + 1 } ?: (bytes.size - offset)
        Mode.FRAMES -> if (prefixIncomplete(tail.bytes(), 0, tail.size())) 1 else {
            val prefix = VarIntHelper.decode(tail.bytes(), 0, tail.size())
            prefix.bytesRead + prefix.value - tail.size()
        }
    }

    private fun pending(): Pending? {
        if (tail.size() == 0) return null
        if (mode != Mode.FRAMES || prefixIncomplete(tail.bytes(), 0, tail.size())) return Pending(tail.size(), null)
        val prefix = VarIntHelper.decode(tail.bytes(), 0, tail.size())
        return Pending(tail.size() - prefix.bytesRead, prefix.value)
    }

    private fun prefixIncomplete(data: ByteArray, offset: Int, to: Int): Boolean =
        to - offset < MAX_PREFIX_BYTES && (offset until to).all { data[it].toInt() and 0x80 != 0 }

    private class Tail : ByteArrayOutputStream() {
        fun bytes(): ByteArray = buf
    }

    private companion object {
        const val RECORD_SEPARATOR: Byte = 0x1e
        const val MAX_HANDSHAKE_BYTES = 4_096
        const val MAX_PREFIX_BYTES = 5
    }
}
