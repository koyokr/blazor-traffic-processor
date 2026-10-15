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

/** SignalR lengths are at most five bytes and cannot exceed Int.MAX_VALUE. */
object VarIntHelper {
    data class Decoded(val value: Int, val bytesRead: Int)

    fun decode(data: ByteArray, offset: Int = 0, end: Int = data.size): Decoded {
        require(offset >= 0 && offset < end && end <= data.size) { "Missing length prefix." }
        var value = 0
        for (index in 0 until 5) {
            require(index < end - offset) { "Truncated length prefix." }
            val byte = data[offset + index].toInt() and 0xff
            require(index < 4 || byte <= 7) { "Length prefix exceeds 2 GB." }
            value = value or ((byte and 0x7f) shl (index * 7))
            if (byte and 0x80 == 0) return Decoded(value, index + 1)
        }
        error("Invalid length prefix.")
    }

    fun encodeVarInt(value: Int): ByteArray {
        require(value >= 0) { "Length must not be negative." }
        val size = maxOf(1, (32 - Integer.numberOfLeadingZeros(value) + 6) / 7)
        var remaining = value
        return ByteArray(size) { index ->
            val byte = remaining and 0x7f
            remaining = remaining ushr 7
            (byte or if (index < size - 1) 0x80 else 0).toByte()
        }
    }
}
