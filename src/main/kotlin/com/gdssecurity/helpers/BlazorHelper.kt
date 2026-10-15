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
import com.gdssecurity.messages.HubMessage
import org.json.JSONArray
import org.msgpack.core.MessagePack
import java.io.ByteArrayOutputStream

/** Conversion is independent of Burp and returns either a complete result or a failure. */
class BlazorHelper {
    /**
     * A message whose canonical encoding equals that of the same-position message in [original] keeps the original
     * frame bytes (e.g. float32). Comparing encodings, not Value equality, keeps -0.0, map order and duplicates distinct.
     */
    fun pack(messages: JSONArray, original: ByteArray? = null): Result<ByteArray> = runCatching {
        require(messages.length() <= BlazorFrames.MAX_VALUES) { "Too many Hub messages." }
        val originals = original?.let { bytes ->
            runCatching {
                buildList {
                    BlazorFrames.forEach(bytes) { offset, length ->
                        add(encode(HubCodec.decode(bytes, offset, length)) to bytes.copyOfRange(offset, offset + length))
                    }
                }
            }.getOrNull()
        }.orEmpty()
        ByteArrayOutputStream().apply {
            repeat(messages.length()) { index ->
                val encoded = encode(HubCodec.fromJson(messages.getJSONObject(index)))
                val bytes = originals.getOrNull(index)?.takeIf { it.first.contentEquals(encoded) }?.second ?: encoded
                require(bytes.size in 1..BlazorFrames.MAX_FRAME_BYTES) { "Message exceeds the frame size limit." }
                // Enforce the same resource limits on edited and received frames.
                BlazorFrames.checkStructure(bytes, 0, bytes.size)
                val prefix = VarIntHelper.encodeVarInt(bytes.size)
                require(bytes.size + prefix.size <= BlazorFrames.MAX_PAYLOAD_BYTES - size()) {
                    "Encoded payload exceeds the editor size limit."
                }
                writeBytes(prefix)
                writeBytes(bytes)
            }
        }.toByteArray()
    }

    private fun encode(message: HubMessage): ByteArray = MessagePack.newDefaultBufferPacker().use { packer ->
        packer.packValue(HubCodec.toWire(message))
        packer.toByteArray()
    }

    fun unpack(bytes: ByteArray): Result<List<HubMessage>> = runCatching {
        buildList {
            BlazorFrames.forEach(bytes) { offset, length -> add(HubCodec.decode(bytes, offset, length)) }
        }
    }

    fun toJson(messages: List<HubMessage>): JSONArray =
        JSONArray().apply { messages.forEach { put(HubCodec.toJson(it)) } }

    fun packJson(text: String, original: ByteArray? = null): Result<ByteArray> = runCatching {
        require(text.length <= BlazorFrames.MAX_FRAME_BYTES * 4) { "JSON text exceeds the editor size limit." }
        pack(JSONArray(text), original).getOrThrow()
    }

    fun unpackJson(bytes: ByteArray, indent: Int = 3): Result<String> =
        unpack(bytes).mapCatching { toJson(it).toString(indent) }

    /** HTTP header boundaries are byte offsets, not offsets into a decoded Unicode string. */
    fun getBodyOffset(bytes: ByteArray): Int {
        for (index in 0 until bytes.size - 3) {
            if (bytes[index] == 13.toByte() && bytes[index + 1] == 10.toByte() &&
                bytes[index + 2] == 13.toByte() && bytes[index + 3] == 10.toByte()) return index + 4
        }
        return 0
    }
}
