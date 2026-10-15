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

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import java.util.HexFormat

class BlazorFramesTest {
    private val codec = BlazorHelper()
    private val hex = HexFormat.of()

    @ParameterizedTest
    @ValueSource(ints = [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, Int.MAX_VALUE])
    fun varIntRoundTrips(value: Int) {
        val encoded = VarIntHelper.encodeVarInt(value)
        assertEquals(VarIntHelper.Decoded(value, encoded.size), VarIntHelper.decode(encoded))
        val padded = byteArrayOf(99) + encoded + byteArrayOf(98)
        assertEquals(VarIntHelper.Decoded(value, encoded.size), VarIntHelper.decode(padded, 1, padded.size - 1))
    }

    @Test
    fun tracksConsumedBytesForNonCanonicalPrefixes() {
        // ASP.NET accepts this two-byte representation of 2.
        val wire = hex.parseHex("82009106029106")
        val messages = codec.unpack(wire).getOrThrow()
        assertEquals(2, messages.size)
        assertEquals(VarIntHelper.Decoded(2, 2), VarIntHelper.decode(wire))
        assertTrue(BlazorFrameValidator.isBlazorPack(wire))
        assertThrows(IllegalArgumentException::class.java) { VarIntHelper.encodeVarInt(-1) }
    }

    @ParameterizedTest
    @ValueSource(strings = ["80", "8080", "8080808080", "ffffffff08", "ffffffff7f",
        "00", "079106", "ff", "0106", "0491060291"])
    fun invalidOrIncompleteFramesFailWithoutPartialMessages(wireHex: String) {
        val wire = hex.parseHex(wireHex)
        assertTrue(codec.unpack(wire).isFailure)
        assertFalse(BlazorFrameValidator.isBlazorPack(wire))
        assertTrue(codec.unpack(hex.parseHex("029106") + wire).isFailure)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "9107", "920600", "910600", "930580c0",
        "940380a13100", "940380a13104", "950380a1310200", "940380a13103", "950380a131012a",
        "950180c0a178c0", "950480c0a17890", "95018101a178c0a17890",
        "960180c0a178909101", "9307c0a178", "9108",
        "950180c0a17891dd7fffffff", "950180c0a17891df7fffffff", "950180c0a17891c6ffffffff"
    ])
    fun rejectsWrongShapesTypesTrailingValuesAndOversizedNestedLengths(bodyHex: String) {
        val wire = frame(hex.parseHex(bodyHex))
        assertTrue(codec.unpack(wire).isFailure)
        assertFalse(BlazorFrameValidator.isBlazorPack(wire))
    }

    @Test
    fun boundsNestingValueCountsAndFrameSize() {
        val nested = hex.parseHex("950180c0a17891") + ByteArray(65) { 0x91.toByte() } + byteArrayOf(0)
        assertFalse(BlazorFrameValidator.isBlazorPack(frame(nested)))
        val wide = hex.parseHex("950180c0a178dd000186a1") + ByteArray(100_001)
        assertFalse(BlazorFrameValidator.isBlazorPack(frame(wide)))
        assertFalse(BlazorFrameValidator.isBlazorPack(
            VarIntHelper.encodeVarInt(BlazorFrames.MAX_FRAME_BYTES + 1) + byteArrayOf(0)))
        assertFalse(BlazorFrameValidator.isBlazorPack(null))
        assertFalse(BlazorFrameValidator.isBlazorPack(byteArrayOf()))
    }

    @Test
    fun readsManyFramesFromOffsetsAndDoesNotReadPastThePayloadBoundary() {
        val ping = hex.parseHex("029106")
        val wire = ByteArray(ping.size * 10_000) { ping[it % ping.size] }
        assertEquals(10_000, codec.unpack(wire).getOrThrow().size)
        assertTrue(BlazorFrameValidator.isBlazorPack(wire))
        var seen = 0
        BlazorFrames.forEach(wire, ping.size) { offset, length ->
            assertEquals(1, offset)
            assertEquals(2, length)
            seen++
        }
        assertEquals(1, seen)
    }

    @Test
    fun reassemblyChecksLimitsWithoutIntegerOverflow() {
        val wire = frame(hex.parseHex("950180c0a44563686f9107"))
        val chunks = listOf(wire.copyOfRange(0, 5), wire.copyOfRange(5, wire.size))
        assertArrayEquals(wire, BlazorFrameValidator.reassembleContaining(chunks, 1, Int.MAX_VALUE, Int.MAX_VALUE))
        assertNull(BlazorFrameValidator.reassembleContaining(chunks, 1, 2, wire.size - 1))
        assertNull(BlazorFrameValidator.reassembleContaining(listOf(chunks[0], null), 0, 2, 100))
    }

    @Test
    fun httpHeaderOffsetsAreMeasuredInBytes() {
        val headers = "POST / HTTP/1.1\r\nX-Note: 한글\r\n\r\n".toByteArray()
        assertEquals(headers.size, codec.getBodyOffset(headers + byteArrayOf(1, 2)))
        assertEquals(0, codec.getBodyOffset(byteArrayOf()))
        assertEquals(0, codec.getBodyOffset("no separator".toByteArray()))
    }

    private fun frame(bytes: ByteArray): ByteArray = VarIntHelper.encodeVarInt(bytes.size) + bytes

    @Test
    fun limitsTheTotalMessageCount() {
        val ping = hex.parseHex("029106")
        val wire = ByteArray(ping.size * (BlazorFrames.MAX_VALUES + 1)) { ping[it % ping.size] }
        assertTrue(codec.unpack(wire).isFailure)
        assertFalse(BlazorFrameValidator.isBlazorPack(wire))
    }
}
