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

import com.gdssecurity.messages.HubMessage
import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import org.junit.jupiter.params.provider.ValueSource
import org.msgpack.core.MessagePack
import java.util.HexFormat

/** Synthetic wire fixtures follow the SignalR Hub Protocol, including legacy five-field invocations. */
class BlazorHelperTest {
    private val codec = BlazorHelper()
    private val hex = HexFormat.of()

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = [
        "0b950180c0a44563686f9107 | {MessageType:1,Headers:0,Target:Echo,Arguments:[7]}",
        "07940280a131a178 | {MessageType:2,Headers:0,InvocationId:'1',Item:x}",
        "06940280a131c3 | {MessageType:2,Headers:0,InvocationId:'1',Item:true}",
        "0a940280a131a46e756c6c | {MessageType:2,Headers:0,InvocationId:'1',Item:'null'}",
        "06940380a13102 | {MessageType:3,Headers:0,InvocationId:'1',ResultKind:2}",
        "07950380a131032a | {MessageType:3,Headers:0,InvocationId:'1',ResultKind:3,Result:42}",
        "07950380a13103c3 | {MessageType:3,Headers:0,InvocationId:'1',ResultKind:3,Result:true}",
        "07950380a13103c0 | {MessageType:3,Headers:0,InvocationId:'1',ResultKind:3,Result:null}",
        "0b950380a13103a46e756c6c | {MessageType:3,Headers:0,InvocationId:'1',ResultKind:3,Result:'null'}",
        "08950380a13101a178 | {MessageType:3,Headers:0,InvocationId:'1',ResultKind:1,Result:x}",
        "0c950480a131a44563686f9107 | {MessageType:4,Headers:0,InvocationId:'1',Target:Echo,Arguments:[7]}",
        "05930580a131 | {MessageType:5,Headers:0,InvocationId:'1'}",
        "029106 | {MessageType:6}",
        "049307c0c3 | {MessageType:7,Error:null,AllowReconnect:true}",
        "039207c0 | {MessageType:7,Error:null}",
        "049207a178 | {MessageType:7,Error:x}",
        "03920801 | {MessageType:8,SequenceId:1}",
        "0b9209cf7fffffffffffffff | {MessageType:9,SequenceId:9223372036854775807}",
    ])
    fun roundTripsProtocolFixtures(wireHex: String, json: String) {
        val wire = hex.parseHex(wireHex)
        val expected = JSONArray().put(JSONObject(json))
        val decoded = codec.toJson(codec.unpack(wire).getOrThrow())
        assertTrue(expected.similar(decoded), decoded.toString())
        assertArrayEquals(wire, codec.pack(expected).getOrThrow())
        assertArrayEquals(wire, codec.pack(decoded).getOrThrow())
        assertTrue(BlazorFrameValidator.isBlazorPack(wire))
    }

    @Test
    fun binaryArgumentsRetainBytesAndDerivedAnalysisIsIgnoredWhenPacking() {
        val binary = ByteArray(300) { it.toByte() }
        val body = MessagePack.newDefaultBufferPacker().use {
            it.packArrayHeader(5).packInt(1).packMapHeader(0).packNil()
                .packString("Echo").packArrayHeader(5)
                .packNil().packBoolean(true).packInt(42).packString("한글")
                .packBinaryHeader(binary.size).writePayload(binary)
            it.toByteArray()
        }
        val wire = frame(body)
        val decoded = codec.toJson(codec.unpack(wire).getOrThrow())
        val argument = decoded.getJSONObject(0).getJSONArray("Arguments").getJSONObject(4)
        assertEquals(hex.withUpperCase().formatHex(binary), argument.getString("BinaryBytes"))
        assertEquals(binary.size, argument.getJSONObject("BinaryAnalysis").getInt("Length"))
        argument.put("BinaryAnalysis", JSONObject().put("ignored", true))
        assertArrayEquals(wire, codec.pack(decoded).getOrThrow())
    }

    @Test
    fun mapsThatAreAmbiguousAsJsonObjectsRoundTripAsEntries() {
        val body = MessagePack.newDefaultBufferPacker().use {
            it.packArrayHeader(5).packInt(1)
                .packMapHeader(2).packString("BinaryHeader").packString("h").packString("BinaryBytes").packString("b")
                .packNil().packString("Echo").packArrayHeader(6)
                .packMapHeader(3).packString("BinaryHeader").packInt(2).packString("BinaryBytes").packString("ABCD")
                .packString("role").packString("admin")
                .packMapHeader(1).packInt(1).packString("a")
                .packMapHeader(2).packString("k").packInt(1).packString("k").packInt(2)
                .packMapHeader(1).packString("MapEntries").packArrayHeader(0)
                .packMapHeader(0)
                .packMapHeader(1).packString("BinaryAnalysis").packInt(1)
            it.toByteArray()
        }
        val wire = frame(body)
        val decoded = codec.toJson(codec.unpack(wire).getOrThrow())
        assertEquals(setOf("MapEntries"), decoded.getJSONObject(0).getJSONObject("Headers").keySet())
        val arguments = decoded.getJSONObject(0).getJSONArray("Arguments")
        repeat(4) { assertEquals(setOf("MapEntries"), arguments.getJSONObject(it).keySet()) }
        assertTrue(arguments.getJSONObject(4).isEmpty)
        assertEquals(1, arguments.getJSONObject(5).getInt("BinaryAnalysis"))
        assertEquals("""[["BinaryHeader",2],["BinaryBytes","ABCD"],["role","admin"]]""",
            arguments.getJSONObject(0).getJSONArray("MapEntries").toString())
        assertArrayEquals(wire, codec.pack(decoded).getOrThrow())
    }

    @Test
    fun floatsStayFloatsAndUneditedMessagesKeepTheirOriginalBytes() {
        val body = MessagePack.newDefaultBufferPacker().use {
            it.packArrayHeader(5).packInt(1).packMapHeader(0).packNil().packString("Echo").packArrayHeader(2)
                .packFloat(1.5f).packDouble(1.0)
            it.toByteArray()
        }
        val wire = frame(body) + hex.parseHex("0b950180c0a44563686f9107")
        val text = codec.unpackJson(wire).getOrThrow()
        assertArrayEquals(wire, codec.packJson(text, wire).getOrThrow())

        val edited = JSONArray(text).apply { getJSONObject(1).put("Arguments", JSONArray().put(8)) }
        val packed = codec.pack(edited, wire).getOrThrow()
        assertArrayEquals(frame(body) + hex.parseHex("0b950180c0a44563686f9108"), packed)

        val tree = codec.toJson(codec.unpack(wire).getOrThrow())
        assertTrue(JSONArray(text).similar(tree))
        assertArrayEquals(wire, codec.pack(tree, wire).getOrThrow())

        // Without the original, 1.0 is still a float (widened to float64), not the integer 1.
        val arguments = (codec.unpack(codec.packJson(text).getOrThrow()).getOrThrow()[0] as HubMessage.Invocation).arguments
        assertTrue(arguments.all { it.isFloatValue })
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = [
        "{MapEntries:[[k,1],[k,1]]} | {MapEntries:[[k,1],[k,2]]}",
        "{MapEntries:[[a,1],[b,2]]} | {MapEntries:[[b,2],[a,1]]}",
        "0.0 | -0.0",
    ])
    fun editsThatValueEqualityConsidersEqualAreStillWritten(original: String, edited: String) {
        fun payload(argument: String) = JSONArray("[{MessageType:1,Headers:0,Target:Echo,Arguments:[$argument]}]")
        val wire = codec.pack(payload(original)).getOrThrow()
        val packed = codec.pack(payload(edited), wire).getOrThrow()
        assertFalse(wire.contentEquals(packed))
        assertArrayEquals(codec.pack(payload(edited)).getOrThrow(), packed)
    }

    @Test
    fun acceptsMixedCaseAndEmptyHexButRejectsMalformedOrMismatchedBinary() {
        val binary = JSONObject().put("BinaryHeader", 2).put("BinaryBytes", "abCD")
        val json = JSONArray().put(JSONObject().put("MessageType", 1).put("Headers", 0)
            .put("Target", "Echo").put("Arguments", JSONArray().put(binary)))
        for (value in listOf("abCD", "")) {
            binary.put("BinaryHeader", value.length / 2).put("BinaryBytes", value)
            val decoded = codec.toJson(codec.unpack(codec.pack(json).getOrThrow()).getOrThrow())
            assertEquals(value.uppercase(), decoded.getJSONObject(0).getJSONArray("Arguments")
                .getJSONObject(0).getString("BinaryBytes"))
        }
        for (value in listOf("a", "GG", "ab cd", "AABB")) {
            binary.put("BinaryBytes", value)
            assertTrue(codec.pack(json).isFailure)
        }
    }

    @Test
    fun retainsHeadersStreamsAndPayloadTypesWithoutStringCoercion() {
        val json = JSONArray("""[{"MessageType":1,"Headers":{"trace":"local"},"InvocationId":"1",
            "Target":"Echo","Arguments":[null,"null","[1,2]","a\u0000b",[1,2],{"x":true},4294967296],
            "StreamIds":["가","2"]}]""")
        val packed = codec.pack(json).getOrThrow()
        val decoded = codec.toJson(codec.unpack(packed).getOrThrow())
        assertTrue(json.similar(decoded), decoded.toString())
        assertTrue(BlazorFrameValidator.isBlazorPack(packed))
        assertArrayEquals(packed, codec.pack(decoded).getOrThrow())
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "{MessageType:1}", "{MessageType:99}", "{MessageType:'6'}",
        "{MessageType:4,Headers:0,Target:Echo,Arguments:[]}",
        "{MessageType:2,Headers:0,InvocationId:'',Item:1}",
        "{MessageType:5,Headers:0}",
        "{MessageType:3,Headers:0,InvocationId:'1',ResultKind:0}",
        "{MessageType:3,Headers:0,InvocationId:'1',ResultKind:4}",
        "{MessageType:3,Headers:0,InvocationId:'1',ResultKind:2,Result:null}",
        "{MessageType:3,Headers:0,InvocationId:'1',ResultKind:1,Result:42}",
        "{MessageType:3,Headers:0,InvocationId:'1',ResultKind:3}",
        "{MessageType:1,Headers:1,Target:Echo,Arguments:[]}",
        "{MessageType:1,Headers:{x:1},Target:Echo,Arguments:[]}",
        "{MessageType:1,Headers:0,Target:Echo,Arguments:[],StreamIds:[1]}",
        "{MessageType:7,AllowReconnect:'true'}",
        "{MessageType:8}", "{MessageType:9,SequenceId:'1'}", "{MessageType:9,SequenceId:1.5}",
        "{MessageType:1,Headers:0,Target:Echo,Arguments:[{BinaryHeader:0,BinaryBytes:'',role:admin}]}",
        "{MessageType:1,Headers:0,Target:Echo,Arguments:[{MapEntries:[[1]]}]}",
    ])
    fun invalidJsonReturnsFailureWithoutPartialOutput(json: String) {
        assertTrue(codec.pack(JSONArray().put(JSONObject("{MessageType:6}")).put(JSONObject(json))).isFailure)
    }

    @Test
    fun decodedModelsDoNotShareMutableJsonOrInputBytes() {
        val bytes = hex.parseHex("0b950180c0a44563686f9107")
        val messages = codec.unpack(bytes).getOrThrow()
        assertInstanceOf(HubMessage.Invocation::class.java, messages.single())
        bytes.fill(0)
        codec.toJson(messages).getJSONObject(0).put("Target", "Changed")
        assertEquals("Echo", codec.toJson(messages).getJSONObject(0).getString("Target"))
        assertTrue(codec.unpack(hex.parseHex("02910680")).isFailure)
        assertTrue(codec.unpack(byteArrayOf()).getOrThrow().isEmpty())
        assertArrayEquals(byteArrayOf(), codec.pack(JSONArray()).getOrThrow())
        assertTrue(codec.packJson("invalid json").isFailure)
    }

    private fun frame(bytes: ByteArray): ByteArray = VarIntHelper.encodeVarInt(bytes.size) + bytes

    @Test
    fun rejectsExcessiveJsonNestingWithoutReturningAPartialPayload() {
        var nested: Any = 1
        repeat(BlazorFrames.MAX_DEPTH + 1) { nested = JSONArray().put(nested) }
        val json = JSONObject().put("MessageType", 1).put("Headers", 0)
            .put("Target", "Echo").put("Arguments", JSONArray().put(nested))
        assertTrue(codec.pack(JSONArray().put(json)).isFailure)
    }

    @Test
    fun closeWithoutAnErrorProducesExactlyOneNilField() {
        assertArrayEquals(hex.parseHex("039207c0"), codec.packJson("[{MessageType:7}]").getOrThrow())
    }
}
