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

import org.msgpack.core.MessagePack
import org.msgpack.value.ValueType

/** Offset-based parsing: no copies of a frame or the remainder of the transport payload. */
internal object BlazorFrames {
    const val MAX_FRAME_BYTES = 8 * 1024 * 1024
    const val MAX_PAYLOAD_BYTES = 32 * 1024 * 1024
    const val MAX_VALUES = 100_000
    const val MAX_DEPTH = 64

    inline fun forEach(bytes: ByteArray, end: Int = bytes.size, action: (Int, Int) -> Unit) {
        require(end in 0..bytes.size) { "Invalid payload boundary." }
        require(end <= MAX_PAYLOAD_BYTES) { "Transport payload exceeds the editor size limit." }
        var offset = 0
        var messages = 0
        while (offset < end) {
            require(++messages <= MAX_VALUES) { "Too many Hub messages." }
            val prefix = VarIntHelper.decode(bytes, offset, end)
            val start = offset + prefix.bytesRead
            require(prefix.value in 1..MAX_FRAME_BYTES) { "Frame length must be between 1 and $MAX_FRAME_BYTES bytes." }
            require(prefix.value <= end - start) { "Truncated frame body." }
            action(start, prefix.value)
            offset = start + prefix.value
        }
    }

    /** Bound nesting and declared sizes before MessagePack allocates a value tree. */
    fun checkStructure(bytes: ByteArray, offset: Int, length: Int) {
        MessagePack.newDefaultUnpacker(bytes, offset, length).use { unpacker ->
            var values = 0
            fun scan(depth: Int) {
                require(depth <= MAX_DEPTH && ++values <= MAX_VALUES) { "MessagePack structure exceeds editor limits." }
                when (unpacker.nextFormat.valueType) {
                    ValueType.ARRAY -> {
                        val count = unpacker.unpackArrayHeader()
                        require(count >= 0 && count <= length - unpacker.totalReadBytes &&
                            count <= MAX_VALUES - values) { "Invalid MessagePack array length." }
                        repeat(count) { scan(depth + 1) }
                    }
                    ValueType.MAP -> {
                        val count = unpacker.unpackMapHeader()
                        require(count >= 0 && count <= (length - unpacker.totalReadBytes) / 2 &&
                            count <= (MAX_VALUES - values) / 2) { "Invalid MessagePack map length." }
                        repeat(count) { scan(depth + 1); scan(depth + 1) }
                    }
                    else -> unpacker.skipValue()
                }
            }
            scan(0)
            require(!unpacker.hasNext()) { "Trailing data inside a frame." }
        }
    }
}
