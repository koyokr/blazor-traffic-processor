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

import com.gdssecurity.messages.HubCodec
import java.io.ByteArrayOutputStream

/** Uses the same schema and framing rules as decoding, without producing JSON or binary analysis. */
object BlazorFrameValidator {
    fun isBlazorPack(payload: ByteArray?): Boolean =
        payload != null && isBlazorPack(payload, payload.size)

    private fun isBlazorPack(payload: ByteArray, end: Int): Boolean {
        if (end == 0) return false
        return runCatching {
            BlazorFrames.forEach(payload, end) { offset, length -> HubCodec.decode(payload, offset, length) }
        }.isSuccess
    }

    /** Reassembles history for display only; callers retain the original transport message. */
    fun reassembleContaining(
        chunks: List<ByteArray?>?,
        selectedIndex: Int,
        maxChunks: Int,
        maxBytes: Int,
    ): ByteArray? {
        if (chunks == null || selectedIndex !in chunks.indices || maxChunks < 2 || maxBytes <= 0) return null
        val selected = chunks[selectedIndex]
        if (selected == null || selected.isEmpty() || isBlazorPack(selected)) return null
        val firstStart = maxOf(0, selectedIndex - maxChunks + 1)
        for (start in selectedIndex downTo firstStart) {
            val candidate = ReassemblyBuffer()
            // Subtraction avoids overflowing start + maxChunks.
            val endExclusive = start + minOf(maxChunks, chunks.size - start)
            for (end in start until endExclusive) {
                val chunk = chunks[end]
                if (chunk == null || chunk.isEmpty() || chunk.size > maxBytes - candidate.size()) break
                candidate.writeBytes(chunk)
                if (end >= selectedIndex && end > start && candidate.isComplete()) return candidate.toByteArray()
            }
        }
        return null
    }

    /** Inspect the backing buffer; copy only once, when a complete candidate is returned. */
    private class ReassemblyBuffer : ByteArrayOutputStream() {
        fun isComplete(): Boolean = isBlazorPack(buf, count)
    }
}
