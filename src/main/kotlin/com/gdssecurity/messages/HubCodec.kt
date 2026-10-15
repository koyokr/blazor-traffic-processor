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

package com.gdssecurity.messages

import com.gdssecurity.helpers.BinaryPayloadAnalyzer
import com.gdssecurity.helpers.BlazorFrames
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONString
import org.msgpack.core.MessagePack
import org.msgpack.value.*
import java.math.BigDecimal
import java.math.BigInteger
import java.util.HexFormat

/** One schema for decoded frames and edited JSON; never constructs a partially valid message. */
internal object HubCodec {
    private val hex = HexFormat.of().withUpperCase()

    fun decode(bytes: ByteArray, offset: Int, length: Int): HubMessage {
        BlazorFrames.checkStructure(bytes, offset, length)
        return MessagePack.newDefaultUnpacker(bytes, offset, length).use {
            fromWire(it.unpackValue().asArrayValue())
        }
    }

    private fun fromWire(fields: ImmutableArrayValue): HubMessage {
        require(fields.size() > 0) { "Hub message must contain a type." }
        val type = fields[0].asIntegerValue().asInt()
        fun count(vararg expected: Int) = require(fields.size() in expected) { "Invalid field count for message type $type." }
        fun headers(): ImmutableMapValue = fields[1].immutableValue().asMapValue().also { map ->
            require(map.map().all { (key, value) -> key.isStringValue && value.isStringValue }) {
                "Headers must contain string keys and values."
            }
            require(map.map().size == map.size()) { "Duplicate header keys." }
        }
        fun id(): String = fields[2].asStringValue().asString().also {
            require(it.isNotEmpty()) { "InvocationId must not be empty." }
        }
        return when (type) {
            1, 4 -> {
                count(5, 6)
                val header = headers()
                val invocationId = if (fields[2].isNilValue) null else fields[2].asStringValue().asString()
                require(type == 1 || !invocationId.isNullOrEmpty()) { "StreamInvocation requires InvocationId." }
                val target = fields[3].asStringValue().asString()
                require(target.isNotEmpty()) { "Target must not be empty." }
                val args = fields[4].immutableValue().asArrayValue()
                val streams = if (fields.size() == 6) fields[5].immutableValue().asArrayValue().also {
                    require(it.all { value -> value.isStringValue && value.asStringValue().asString().isNotEmpty() }) {
                        "StreamIds must contain nonempty strings."
                    }
                } else null
                HubMessage.Invocation(header, invocationId, target, args, streams, streaming = type == 4)
            }
            2 -> {
                count(4)
                HubMessage.StreamItem(headers(), id(), fields[3].immutableValue())
            }
            3 -> {
                count(4, 5)
                val header = headers()
                val invocationId = id()
                val result = when (fields[3].asIntegerValue().asInt()) {
                    1 -> { count(5); CompletionResult.Error(fields[4].asStringValue().asString()) }
                    2 -> { count(4); CompletionResult.Void }
                    3 -> { count(5); CompletionResult.Value(fields[4].immutableValue()) }
                    else -> throw IllegalArgumentException("ResultKind must be 1, 2 or 3.")
                }
                HubMessage.Completion(header, invocationId, result)
            }
            5 -> {
                count(3)
                HubMessage.CancelInvocation(headers(), id())
            }
            6 -> { count(1); HubMessage.Ping }
            7 -> {
                count(2, 3)
                val error = if (fields[1].isNilValue) null else fields[1].asStringValue().asString()
                val reconnect = if (fields.size() == 3) fields[2].asBooleanValue().boolean else null
                HubMessage.Close(error, reconnect)
            }
            8, 9 -> {
                count(2)
                val sequenceId = fields[1].asIntegerValue().asLong()
                if (type == 8) HubMessage.Ack(sequenceId) else HubMessage.Sequence(sequenceId)
            }
            else -> throw IllegalArgumentException("Unsupported Hub message type: $type.")
        }
    }

    fun toWire(message: HubMessage): ImmutableArrayValue {
        val values: List<Value> = when (message) {
            is HubMessage.Invocation -> buildList {
                add(ValueFactory.newInteger(if (message.streaming) 4 else 1))
                add(message.headers)
                add(message.invocationId.wireString())
                add(ValueFactory.newString(message.target))
                add(message.arguments)
                message.streamIds?.let(::add)
            }
            is HubMessage.StreamItem -> listOf(ValueFactory.newInteger(2), message.headers,
                ValueFactory.newString(message.invocationId), message.item)
            is HubMessage.Completion -> buildList {
                add(ValueFactory.newInteger(3))
                add(message.headers)
                add(ValueFactory.newString(message.invocationId))
                when (val result = message.result) {
                    is CompletionResult.Error -> { add(ValueFactory.newInteger(1)); add(ValueFactory.newString(result.message)) }
                    CompletionResult.Void -> add(ValueFactory.newInteger(2))
                    is CompletionResult.Value -> { add(ValueFactory.newInteger(3)); add(result.value) }
                }
            }
            is HubMessage.CancelInvocation -> listOf(ValueFactory.newInteger(5), message.headers,
                ValueFactory.newString(message.invocationId))
            HubMessage.Ping -> listOf(ValueFactory.newInteger(6))
            is HubMessage.Close -> buildList {
                add(ValueFactory.newInteger(7))
                add(message.error.wireString())
                message.allowReconnect?.let { add(ValueFactory.newBoolean(it)) }
            }
            is HubMessage.Ack -> listOf(ValueFactory.newInteger(8), ValueFactory.newInteger(message.sequenceId))
            is HubMessage.Sequence -> listOf(ValueFactory.newInteger(9), ValueFactory.newInteger(message.sequenceId))
        }
        return ValueFactory.newArray(values)
    }

    fun fromJson(json: JSONObject): HubMessage {
        val budget = JsonBudget()
        fun integer(key: String): Int = (json.get(key) as? Int)
            ?: throw IllegalArgumentException("$key must be an integer.")
        fun string(key: String): String = (json.get(key) as? String)
            ?: throw IllegalArgumentException("$key must be a string.")
        fun optionalString(key: String): Value =
            if (!json.has(key) || json.isNull(key)) ValueFactory.newNil() else ValueFactory.newString(string(key))
        fun headers(): Value = when (val value = json.get("Headers")) {
            0 -> ValueFactory.newMap(emptyMap<Value, Value>())
            is JSONObject -> budget.value(value)
            else -> throw IllegalArgumentException("Headers must be 0 or an object of strings.")
        }
        val type = integer("MessageType")
        val fields = buildList<Value> {
            add(ValueFactory.newInteger(type))
            when (type) {
                1, 4 -> {
                    add(headers())
                    add(optionalString("InvocationId"))
                    add(ValueFactory.newString(string("Target")))
                    add(budget.value(json.getJSONArray("Arguments")))
                    if (json.has("StreamIds")) add(budget.value(json.getJSONArray("StreamIds")))
                }
                2 -> {
                    add(headers())
                    add(ValueFactory.newString(string("InvocationId")))
                    add(budget.value(json.get("Item")))
                }
                3 -> {
                    add(headers())
                    add(ValueFactory.newString(string("InvocationId")))
                    val kind = integer("ResultKind")
                    require(kind in 1..3) { "ResultKind must be 1, 2 or 3." }
                    add(ValueFactory.newInteger(kind))
                    if (kind == 2) require(!json.has("Result")) { "Void completion must not contain Result." }
                    else add(budget.value(json.get("Result")))
                }
                5 -> { add(headers()); add(ValueFactory.newString(string("InvocationId"))) }
                6 -> Unit
                7 -> {
                    add(optionalString("Error"))
                    if (json.has("AllowReconnect")) {
                        val reconnect = json.get("AllowReconnect") as? Boolean
                            ?: throw IllegalArgumentException("AllowReconnect must be a boolean.")
                        add(ValueFactory.newBoolean(reconnect))
                    }
                }
                8, 9 -> {
                    val sequenceId = json.get("SequenceId")
                    require(sequenceId is Int || sequenceId is Long) { "SequenceId must be a 64-bit integer." }
                    add(ValueFactory.newInteger((sequenceId as Number).toLong()))
                }
                else -> throw IllegalArgumentException("Unsupported Hub message type: $type.")
            }
        }
        return fromWire(ValueFactory.newArray(fields))
    }

    fun toJson(message: HubMessage): JSONObject {
        fun base(type: Int, headers: ImmutableMapValue, id: String?): JSONObject =
            JSONObject().put("MessageType", type)
                .put("Headers", if (headers.size() == 0) 0 else jsonValue(headers))
                .apply { if (id != null) put("InvocationId", id) }
        return when (message) {
            is HubMessage.Invocation -> base(if (message.streaming) 4 else 1, message.headers, message.invocationId)
                .put("Target", message.target).put("Arguments", jsonValue(message.arguments, message.target))
                .apply { message.streamIds?.let { put("StreamIds", jsonValue(it)) } }
            is HubMessage.StreamItem -> base(2, message.headers, message.invocationId).put("Item", jsonValue(message.item))
            is HubMessage.Completion -> base(3, message.headers, message.invocationId).apply {
                when (val result = message.result) {
                    is CompletionResult.Error -> { put("ResultKind", 1); put("Result", result.message) }
                    CompletionResult.Void -> put("ResultKind", 2)
                    is CompletionResult.Value -> { put("ResultKind", 3); put("Result", jsonValue(result.value)) }
                }
            }
            is HubMessage.CancelInvocation -> base(5, message.headers, message.invocationId)
            HubMessage.Ping -> JSONObject().put("MessageType", 6)
            is HubMessage.Close -> JSONObject().put("MessageType", 7).put("Error", message.error ?: JSONObject.NULL)
                .apply { message.allowReconnect?.let { put("AllowReconnect", it) } }
            is HubMessage.Ack -> JSONObject().put("MessageType", 8).put("SequenceId", message.sequenceId)
            is HubMessage.Sequence -> JSONObject().put("MessageType", 9).put("SequenceId", message.sequenceId)
        }
    }

    private const val MAP_ENTRIES = "MapEntries"
    private val BINARY_KEYS = setOf("BinaryHeader", "BinaryBytes", "BinaryAnalysis")
    private fun isBinaryWrapper(keys: Set<String>) = "BinaryHeader" in keys && "BinaryBytes" in keys

    /** Always written with a decimal point or exponent, so 1.0 is not read back as the integer 1. */
    private class JsonFloat(private val value: Double) : Number(), JSONString {
        override fun toJSONString() = value.toString()
        override fun toString() = value.toString()
        override fun toDouble() = value
        override fun toFloat() = value.toFloat()
        override fun toLong() = value.toLong()
        override fun toInt() = value.toInt()
        override fun toShort() = value.toInt().toShort()
        override fun toByte() = value.toInt().toByte()
    }

    private fun String?.wireString(): ImmutableValue = this?.let(ValueFactory::newString) ?: ValueFactory.newNil()

    private class JsonBudget {
        private var count = 0
        fun value(input: Any, depth: Int = 0): ImmutableValue {
            require(++count <= BlazorFrames.MAX_VALUES && depth <= BlazorFrames.MAX_DEPTH) { "JSON structure exceeds editor limits." }
            return when (input) {
                JSONObject.NULL -> ValueFactory.newNil()
                is Boolean -> ValueFactory.newBoolean(input)
                is String -> {
                    require(input.length <= BlazorFrames.MAX_FRAME_BYTES) { "String exceeds editor limits." }
                    ValueFactory.newString(input)
                }
                is Byte, is Short, is Int, is Long -> ValueFactory.newInteger((input as Number).toLong())
                is BigInteger -> ValueFactory.newInteger(input)
                is Float, is Double, is BigDecimal, is JsonFloat -> ValueFactory.newFloat(
                    input.toDouble().also { require(it.isFinite()) { "Float must be finite." } }
                )
                is JSONArray -> {
                    require(input.length() <= BlazorFrames.MAX_VALUES - count) { "JSON array exceeds editor limits." }
                    ValueFactory.newArray(List(input.length()) { value(input.get(it), depth + 1) })
                }
                is JSONObject -> {
                    if (input.keySet() == setOf(MAP_ENTRIES)) {
                        val entries = input.get(MAP_ENTRIES) as? JSONArray
                            ?: throw IllegalArgumentException("$MAP_ENTRIES must be an array of [key, value] pairs.")
                        require(entries.length() <= (BlazorFrames.MAX_VALUES - count) / 2) { "JSON object exceeds editor limits." }
                        ValueFactory.newMap(*(0 until entries.length()).flatMap {
                            val pair = entries.get(it) as? JSONArray
                            require(pair != null && pair.length() == 2) { "$MAP_ENTRIES must be an array of [key, value] pairs." }
                            listOf(value(pair.get(0), depth + 1), value(pair.get(1), depth + 1))
                        }.toTypedArray())
                    } else if (isBinaryWrapper(input.keySet())) {
                        require(input.keySet().all { it in BINARY_KEYS }) {
                            "Objects with BinaryHeader and BinaryBytes are binary values; use $MAP_ENTRIES for other keys."
                        }
                        val text = input.get("BinaryBytes") as? String
                            ?: throw IllegalArgumentException("BinaryBytes must be a hex string.")
                        require(text.length / 2 <= BlazorFrames.MAX_FRAME_BYTES) { "Binary value exceeds editor limits." }
                        val bytes = hex.parseHex(text)
                        require(input.get("BinaryHeader") == bytes.size) { "BinaryHeader must match the byte length." }
                        ValueFactory.newBinary(bytes)
                    } else {
                        require(input.length() <= (BlazorFrames.MAX_VALUES - count) / 2) { "JSON object exceeds editor limits." }
                        ValueFactory.newMap(input.keySet().associate {
                            value(it, depth + 1) to value(input.get(it), depth + 1)
                        })
                    }
                }
                else -> throw IllegalArgumentException("Unsupported JSON value type: " + input.javaClass.simpleName)
            }
        }
    }

    private fun jsonValue(value: Value, target: String? = null): Any = when (value.valueType) {
        ValueType.NIL -> JSONObject.NULL
        ValueType.BOOLEAN -> value.asBooleanValue().boolean
        ValueType.INTEGER -> value.asIntegerValue().asBigInteger()
        ValueType.FLOAT -> value.asFloatValue().toDouble().let { number ->
            require(number.isFinite()) { "Non-finite floats cannot be represented in JSON." }
            JsonFloat(number)
        }
        ValueType.STRING -> value.asStringValue().asString()
        ValueType.BINARY -> value.asBinaryValue().asByteArray().let {
            JSONObject().put("BinaryHeader", it.size).put("BinaryBytes", hex.formatHex(it))
                .put("BinaryAnalysis", BinaryPayloadAnalyzer.analyze(it, target))
        }
        ValueType.ARRAY -> JSONArray().apply { value.asArrayValue().forEach { put(jsonValue(it, target)) } }
        ValueType.MAP -> {
            val map = value.asMapValue()
            // Keep plain objects unambiguous; any other map is written as ordered key/value pairs.
            val pairs = map.keyValueArray
            val keys = (pairs.indices step 2).mapNotNull { pairs[it].takeIf(Value::isStringValue)?.asStringValue()?.asString() }
            val names = keys.toSet()
            if (keys.size == map.size() && names.size == keys.size && !isBinaryWrapper(names) && names != setOf(MAP_ENTRIES)) {
                JSONObject().apply { keys.forEachIndexed { i, key -> put(key, jsonValue(pairs[2 * i + 1], target)) } }
            } else {
                JSONObject().put(MAP_ENTRIES, JSONArray().apply {
                    for (index in pairs.indices step 2) {
                        put(JSONArray().put(jsonValue(pairs[index], target)).put(jsonValue(pairs[index + 1], target)))
                    }
                })
            }
        }
        else -> throw IllegalArgumentException("Unsupported MessagePack value type: " + value.valueType)
    }
}
