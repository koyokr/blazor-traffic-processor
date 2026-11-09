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

import com.gdssecurity.helpers.EventHandlerId
import com.gdssecurity.helpers.RenderBatch
import com.gdssecurity.messages.CompletionResult
import com.gdssecurity.messages.HubMessage
import org.json.JSONArray
import org.json.JSONObject
import org.msgpack.value.ImmutableArrayValue
import org.msgpack.value.Value

enum class Flow(val arrow: String) {
    CLIENT_TO_SERVER("C>S"),
    SERVER_TO_CLIENT("S>C"),
}

enum class Kind { SESSION, UI, CALL, RESULT, RENDER, JS, DATA, NOISE, PARTIAL, ERROR, UNKNOWN }

data class Summary(val kind: Kind, val text: String, val alert: Boolean = false) {
    override fun toString() = "$kind${if (alert) "!" else ""} $text"
}

/**
 * Reduces one socket's Hub traffic, both directions, to one-line notes. Not thread-safe; the caller serializes calls.
 * Correlation IDs live in separate namespaces: Hub invocation IDs, .NET call IDs and JS async handles.
 */
class CircuitConversation(private val tree: RenderTreeMirror = RenderTreeMirror()) {
    private val streams = Flow.entries.associateWith { HubFrameStream() }
    private val hubCalls = Recent<Pair<Flow, String>, String>()
    private val dotNetCalls = Recent<String, String>()
    private val jsCalls = Recent<Long, String>()

    private val targets: Map<Pair<Flow, String>, (Args) -> Summary> = buildMap {
        fun client(target: String, summary: (Args) -> Summary) = put(Flow.CLIENT_TO_SERVER to target, summary)
        fun server(target: String, summary: (Args) -> Summary) = put(Flow.SERVER_TO_CLIENT to target, summary)
        client("StartCircuit") { Summary(Kind.SESSION, "StartCircuit ${token(it.string(1) ?: "?", URI_LIMIT)}") }
        client("ConnectCircuit") { Summary(Kind.SESSION, "ConnectCircuit (reconnect to an existing circuit)") }
        client("ResumeCircuit") { Summary(Kind.SESSION, "ResumeCircuit") }
        client("PauseCircuit") { Summary(Kind.SESSION, "PauseCircuit") }
        client("UpdateRootComponents", ::updateRootComponents)
        client("BeginInvokeDotNetFromJS", ::beginInvokeDotNet)
        client("DispatchBrowserEvent") { dispatchEvent(null, it.string(0), it.string(1)) }
        client("EndInvokeJSFromDotNet", ::endInvokeJs)
        client("OnRenderCompleted", ::renderCompleted)
        client("OnLocationChanged") {
            Summary(Kind.UI, "navigate ${token(it.string(0) ?: "?", URI_LIMIT)}${if (it.bool(2) == true) " (intercepted link)" else ""}")
        }
        client("OnLocationChanging") {
            Summary(Kind.UI, "navigating ${token(it.string(1) ?: "?", URI_LIMIT)} (call ${it.long(0)})")
        }
        client("ReceiveByteArray") { Summary(Kind.DATA, "byte array ${it.long(0)} (${it.binary(1)?.size ?: 0} bytes)") }
        client("ReceiveJSDataChunk") {
            Summary(Kind.DATA, "stream ${it.long(0)} chunk ${it.long(1)} (${it.binary(2)?.size ?: 0} bytes)")
        }
        client("SendDotNetStreamToJS") { Summary(Kind.DATA, "request stream ${it.long(0)}") }
        server("JS.RenderBatch", ::renderBatch)
        server("JS.BeginInvokeJS", ::beginInvokeJs)
        server("JS.EndInvokeDotNet", ::endInvokeDotNet)
        server("JS.AttachComponent") { args ->
            args.long(0)?.toInt()?.let(tree::attachRoot)
            Summary(Kind.SESSION, "attach component ${args.long(0)} to ${quote(args.string(1) ?: "?", VALUE_LIMIT)}")
        }
        server("JS.EndUpdateRootComponents") { Summary(Kind.NOISE, "EndUpdateRootComponents ${it.long(0)}") }
        server("JS.Error") { Summary(Kind.ERROR, "JS.Error ${quote(it.string(0) ?: it.json(0), ERROR_LIMIT)}") }
        server("JS.ReceiveByteArray") { Summary(Kind.DATA, "byte array ${it.long(0)} (${it.binary(1)?.size ?: 0} bytes)") }
        server("JS.BeginTransmitStream") { Summary(Kind.DATA, "stream ${it.long(0)} begins") }
        server("JS.SavePersistedState") { Summary(Kind.SESSION, "SavePersistedState") }
        server("JS.RequestPause") { Summary(Kind.SESSION, "RequestPause") }
        server("JS.EndLocationChanging") {
            Summary(Kind.RESULT, "navigation ${if (it.bool(1) == true) "allowed" else "cancelled"} (call ${it.long(0)})")
        }
    }

    /** The note for one WebSocket message, or null when it completes nothing and leaves nothing pending. */
    fun annotate(flow: Flow, payload: ByteArray): String? {
        val summaries = mutableListOf<Summary>()
        var alerts = 0
        var omitted = 0
        val pending = streams.getValue(flow).accept(payload) { event ->
            val summary = observe(flow, event)
            if (summary.alert) alerts++
            if (summaries.size < MAX_SUMMARIES || summary.alert && alerts <= MAX_SUMMARIES) summaries += summary else omitted++
        }
        pending?.let { summaries += Summary(Kind.PARTIAL, "frame ${progress(it)}") }
        return if (summaries.isEmpty()) null else formatNote(flow, summaries, omitted)
    }

    private fun observe(flow: Flow, event: HubFrameStream.Event): Summary = when (event) {
        is HubFrameStream.Event.Handshake -> handshake(flow, event.json)
        is HubFrameStream.Event.Malformed -> {
            tree.invalidate()
            Summary(Kind.ERROR, "malformed frame ${quote(event.reason, ERROR_LIMIT)} (element labels reset)")
        }
        is HubFrameStream.Event.Message -> message(flow, event.message)
    }

    private fun message(flow: Flow, message: HubMessage): Summary = when (message) {
        is HubMessage.Invocation -> {
            message.invocationId?.let { hubCalls[flow to it] = message.target }
            targets[flow to message.target]?.invoke(Args(message.arguments))
                ?: Summary(Kind.UNKNOWN, "${token(message.target, VALUE_LIMIT)} ${raw(Args(message.arguments).json(), VALUE_LIMIT)}")
        }
        is HubMessage.Completion -> completion(flow, message)
        is HubMessage.StreamItem -> Summary(Kind.DATA, "stream item (invocation ${token(message.invocationId, VALUE_LIMIT)})")
        is HubMessage.CancelInvocation -> Summary(Kind.NOISE, "cancel invocation ${token(message.invocationId, VALUE_LIMIT)}")
        HubMessage.Ping -> Summary(Kind.NOISE, "ping")
        is HubMessage.Close -> message.error?.let { Summary(Kind.ERROR, "close ${quote(it, ERROR_LIMIT)}") }
            ?: Summary(Kind.SESSION, "close${if (message.allowReconnect == true) " (reconnect allowed)" else ""}")
        is HubMessage.Ack -> Summary(Kind.NOISE, "ack ${message.sequenceId}")
        is HubMessage.Sequence -> Summary(Kind.NOISE, "sequence ${message.sequenceId}")
    }

    private fun handshake(flow: Flow, json: String): Summary {
        val record = runCatching { JSONObject(json) }.getOrNull()
            ?: return Summary(Kind.ERROR, "handshake is not JSON ${quote(json, VALUE_LIMIT)}")
        record.optString("error").ifEmpty { null }?.let { return Summary(Kind.ERROR, "handshake rejected ${quote(it, ERROR_LIMIT)}") }
        return if (flow == Flow.CLIENT_TO_SERVER) {
            Summary(Kind.SESSION, "handshake ${token(record.optString("protocol", "?"), VALUE_LIMIT)} v${record.opt("version")}")
        } else {
            Summary(Kind.SESSION, "handshake accepted")
        }
    }

    private fun completion(flow: Flow, message: HubMessage.Completion): Summary {
        val target = hubCalls.remove(flow.opposite() to message.invocationId)
        val id = "(invocation ${token(message.invocationId, VALUE_LIMIT)})"
        val subject = target?.let { " for ${token(it, VALUE_LIMIT)}" }.orEmpty()
        return when (val result = message.result) {
            is CompletionResult.Error -> Summary(Kind.RESULT, "hub completed failed $id$subject error=${quote(result.message, ERROR_LIMIT)}")
            CompletionResult.Void -> Summary(Kind.RESULT, "hub completed ok $id$subject")
            is CompletionResult.Value -> Summary(Kind.RESULT, "hub completed ok $id$subject result=${raw(result.value.toJson(), VALUE_LIMIT)}")
        }
    }

    private fun updateRootComponents(args: Args): Summary {
        val operations = jsonObject(args.string(0))?.optJSONArray("operations")
        val types = operations?.let { list -> (0 until minOf(list.length(), 8)).map { list.optJSONObject(it)?.optString("type") ?: "?" } }
        return Summary(Kind.SESSION, "UpdateRootComponents${types?.let { " " + token(it.joinToString(","), VALUE_LIMIT) }.orEmpty()}")
    }

    private fun beginInvokeDotNet(args: Args): Summary {
        val callId = args.string(0)
        val assembly = args.string(1)
        val method = args.string(2) ?: "?"
        if (assembly == null && method == "DispatchEventAsync") return dispatchEvent(callId, args.string(4), null)
        val target = if (assembly != null) "${token(assembly, VALUE_LIMIT)}::${token(method, VALUE_LIMIT)}"
            else "obj${args.long(3)}.${token(method, VALUE_LIMIT)}"
        callId?.let { dotNetCalls[it] = target }
        return Summary(Kind.CALL, "$target ${raw(args.string(4) ?: "", VALUE_LIMIT)}${callId?.let { " (call ${token(it, VALUE_LIMIT)})" }.orEmpty()}")
    }

    /**
     * .NET 6+ sends [descriptor, eventArgs] in one JSON array with an eventName; earlier versions sent two arguments
     * and named only the event-args type, so the event's own "type" is the better name there.
     */
    private fun dispatchEvent(callId: String?, firstJson: String?, secondJson: String?): Summary {
        val combined = if (secondJson == null) jsonArray(firstJson) else null
        val descriptor = combined?.optJSONObject(0) ?: jsonObject(firstJson)
        val eventArgs = combined?.optJSONObject(1) ?: jsonObject(secondJson)
        val handler = descriptor?.opt("eventHandlerId")?.toString()?.let(EventHandlerId::parse)
        val eventName = descriptor?.optString("eventName")?.ifEmpty { null }
            ?: eventArgs?.optString("type")?.ifEmpty { null }
            ?: descriptor?.optString("eventArgsType")?.ifEmpty { null } ?: "event"
        val subject = "${token(eventName, VALUE_LIMIT)} listener=${handler?.let(tree::element)?.describe(LABEL_TEXT_LIMIT) ?: "unknown"}"
        callId?.let { dotNetCalls[it] = subject }
        val ids = listOfNotNull(handler?.let { "handler $it" }, callId?.let { "call ${token(it, VALUE_LIMIT)}" })
        return Summary(Kind.UI, "$subject${eventDetails(descriptor, eventArgs)}${if (ids.isEmpty()) "" else ids.joinToString(", ", " (", ")")}")
    }

    private fun eventDetails(descriptor: JSONObject?, eventArgs: JSONObject?): String {
        val value = eventArgs?.opt("value") ?: descriptor?.optJSONObject("eventFieldInfo")?.opt("fieldValue")
        val key = eventArgs?.opt("key") as? String
        return buildString {
            if (value != null && value != JSONObject.NULL) append(" value=").append(jsonValue(value))
            if (key != null) append(" key=").append(quote(key, VALUE_LIMIT))
        }
    }

    private fun endInvokeJs(args: Args): Summary {
        val handle = args.long(0)
        val identifier = handle?.let(jsCalls::remove)
        val outcome = if (args.bool(1) == true) "ok" else "failed"
        val subject = identifier?.let { " for ${token(it, VALUE_LIMIT)}" }.orEmpty()
        return Summary(Kind.RESULT, "js completed $outcome (async $handle)$subject result=${raw(args.string(2) ?: "", VALUE_LIMIT)}")
    }

    private fun endInvokeDotNet(args: Args): Summary {
        val callId = args.string(0)
        val subject = callId?.let(dotNetCalls::remove)?.let { " for $it" }.orEmpty()
        val success = args.bool(1) == true
        val detail = if (success) {
            args.string(2)?.takeUnless { it == "null" }?.let { " result=${raw(it, VALUE_LIMIT)}" }.orEmpty()
        } else {
            " error=${quote(args.string(2) ?: "", ERROR_LIMIT)}"
        }
        return Summary(Kind.RESULT, "dotnet completed ${if (success) "ok" else "failed"} (call ${token(callId ?: "?", VALUE_LIMIT)})$subject$detail")
    }

    private fun renderCompleted(args: Args): Summary {
        val error = args.string(1) ?: return Summary(Kind.NOISE, "OnRenderCompleted ${args.long(0)}")
        tree.invalidate()
        return Summary(Kind.ERROR, "browser failed to apply batch ${args.long(0)} ${quote(error, ERROR_LIMIT)} (element labels reset)")
    }

    private fun beginInvokeJs(args: Args): Summary {
        val handle = args.long(0) ?: 0
        val identifier = args.string(1) ?: "?"
        val argsJson = args.string(2) ?: ""
        if (handle != 0L) jsCalls[handle] = identifier
        val async = if (handle != 0L) " (async $handle)" else ""
        if (identifier.removePrefix("window.").removePrefix("globalThis.") in CODE_EVALUATING_FUNCTIONS) {
            val code = jsonArray(argsJson)?.opt(0) as? String ?: argsJson
            return Summary(Kind.JS, "${token(identifier, VALUE_LIMIT)} requested ${quote(code, VALUE_LIMIT)}$async", alert = true)
        }
        return Summary(Kind.JS, "${token(identifier, VALUE_LIMIT)} ${raw(argsJson, VALUE_LIMIT)}$async")
    }

    private fun renderBatch(args: Args): Summary {
        val batchId = args.long(0) ?: return Summary(Kind.ERROR, "render batch without a batch id")
        val batch = runCatching { RenderBatch.decode(args.binary(1) ?: ByteArray(0)) }.getOrElse {
            tree.invalidate()
            return Summary(Kind.ERROR, "render batch $batchId undecodable ${quote(it.message ?: "", ERROR_LIMIT)} (element labels reset)")
        }
        return when (val outcome = tree.apply(batchId, batch)) {
            BatchOutcome.Retransmitted -> Summary(Kind.NOISE, "render batch $batchId retransmitted (already applied)")
            is BatchOutcome.Applied -> describeRender(batchId, outcome.changes)
        }
    }

    private fun describeRender(batchId: Long, changes: List<RenderChange>): Summary {
        val items = mutableListOf<String>()
        var removed = 0
        val unsynchronized = sortedSetOf<Int>()
        var alert = false
        for (change in changes) when (change) {
            is RenderChange.Inserted -> {
                items += "+" + change.element.describe(RENDER_TEXT_LIMIT)
                alert = alert || change.element.tag.equals("script", ignoreCase = true)
            }
            is RenderChange.TextShown -> items += "text " + quote(change.text.collapseWhitespace(), VALUE_LIMIT)
            is RenderChange.MarkupShown -> {
                items += "markup " + quote(change.markup, VALUE_LIMIT)
                alert = alert || SCRIPT_TAG.containsMatchIn(change.markup)
            }
            is RenderChange.AttributeSet -> {
                items += "set ${change.target?.describe(RENDER_TEXT_LIMIT) ?: "?"} ${token(change.name, VALUE_LIMIT)}=${quote(change.value, VALUE_LIMIT)}"
                alert = alert || change.name.startsWith("on", ignoreCase = true)
            }
            is RenderChange.AttributeRemoved ->
                items += "unset ${change.target?.describe(RENDER_TEXT_LIMIT) ?: "?"} ${token(change.name, VALUE_LIMIT)}"
            RenderChange.Removed -> removed++
            is RenderChange.Unsynchronized -> unsynchronized += change.componentId
            RenderChange.Overflow -> items += "tree exceeds the node budget (element labels reset)"
        }
        if (removed > 0) items += "removed $removed"
        if (unsynchronized.isNotEmpty()) items += "unsynced components ${unsynchronized.take(5).joinToString(",")}" +
            if (unsynchronized.size > 5) ",…" else ""
        val detail = if (items.isEmpty()) "no visible change" else fitItems(items, RENDER_ITEMS_LIMIT)
        return Summary(Kind.RENDER, "patch batch $batchId: $detail", alert)
    }

    private fun Flow.opposite() = if (this == Flow.CLIENT_TO_SERVER) Flow.SERVER_TO_CLIENT else Flow.CLIENT_TO_SERVER

    private class Recent<K, V> : LinkedHashMap<K, V>() {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<K, V>?) = size > MAX_PENDING_CALLS
    }

    /** Positional Hub arguments; a missing or mistyped argument reads as null rather than failing the note. */
    private class Args(private val values: ImmutableArrayValue) {
        private fun at(index: Int): Value? = if (index < values.size()) values[index] else null
        fun string(index: Int): String? = at(index)?.takeIf { it.isStringValue }?.let { runCatching { it.asStringValue().asString() }.getOrNull() }
        fun long(index: Int): Long? = at(index)?.takeIf { it.isIntegerValue }?.asIntegerValue()?.takeIf { it.isInLongRange }?.toLong()
        fun bool(index: Int): Boolean? = at(index)?.takeIf { it.isBooleanValue }?.asBooleanValue()?.boolean
        fun binary(index: Int): ByteArray? = at(index)?.takeIf { it.isBinaryValue }?.asBinaryValue()?.asByteArray()
        fun json(index: Int): String = at(index)?.toJson() ?: "null"
        fun json(): String = values.toJson()
    }

    private companion object {
        const val MAX_PENDING_CALLS = 256
        const val MAX_SUMMARIES = 64
        const val MAX_JSON_CHARS = 64 * 1024
        const val RENDER_ITEMS_LIMIT = 300
        val CODE_EVALUATING_FUNCTIONS = setOf("eval", "Function", "setTimeout", "setInterval", "execScript",
            "document.write", "document.writeln")
        val SCRIPT_TAG = Regex("<script", RegexOption.IGNORE_CASE)

        fun jsonArray(text: String?): JSONArray? =
            text?.takeIf { it.length <= MAX_JSON_CHARS }?.let { runCatching { JSONArray(it) }.getOrNull() }

        fun jsonObject(text: String?): JSONObject? =
            text?.takeIf { it.length <= MAX_JSON_CHARS }?.let { runCatching { JSONObject(it) }.getOrNull() }

        fun jsonValue(value: Any): String = if (value is String) quote(value, VALUE_LIMIT) else raw(value.toString(), VALUE_LIMIT)

        fun progress(pending: HubFrameStream.Pending): String {
            val expected = pending.expected ?: return "${pending.received} B so far"
            return if (expected < 1024) "${pending.received}/$expected B"
            else "${pending.received / 1024}/${(expected + 1023) / 1024} KB"
        }

        fun fitItems(items: List<String>, limit: Int): String {
            val kept = mutableListOf<String>()
            var length = 0
            for (item in items) {
                val cost = item.codePointCount(0, item.length) + 1
                if (length + cost > limit && kept.isNotEmpty()) break
                kept += item
                length += cost
            }
            val hidden = items.size - kept.size
            return kept.joinToString(" ") + if (hidden > 0) " +$hidden more" else ""
        }
    }
}

internal fun ElementLabel.describe(textLimit: Int): String = buildString {
    append(token(tag ?: "?", VALUE_LIMIT))
    id?.let { append('#').append(token(it, VALUE_LIMIT)) }
    if (id == null) name?.let { append("[name=").append(token(it, VALUE_LIMIT)).append(']') }
    type?.let { append("[type=").append(token(it, VALUE_LIMIT)).append(']') }
    if (text != null) append(' ').append(quote(text, textLimit))
    else placeholder?.let { append("[placeholder=").append(quote(it, textLimit)).append(']') }
    if (disabled) append(" disabled(last-render)")
}

/** One line per WebSocket message, at most [MAX_NOTE] code points, wire order kept and alerts never dropped. */
fun formatNote(flow: Flow, summaries: List<Summary>, omitted: Int = 0): String {
    val prefix = flow.arrow + " "
    val parts = summaries.map(Summary::toString)
    val budget = MAX_NOTE - prefix.length
    fun width(text: String) = text.codePointCount(0, text.length)
    val full = parts.joinToString(SEPARATOR) + if (omitted > 0) "$SEPARATOR+$omitted more" else ""
    if (width(full) <= budget) return prefix + full

    val room = budget - MORE_RESERVE
    val alerts = summaries.indices.filter { summaries[it].alert }
        .take(maxOf(1, room / (MIN_PART + SEPARATOR.length))).toSet()
    val alertWidth = alerts.sumOf { width(parts[it]) + SEPARATOR.length }
    val alertLimit = if (alertWidth <= room) Int.MAX_VALUE else room / alerts.size - SEPARATOR.length
    var left = room - minOf(alertWidth, room)
    var hidden = omitted
    val kept = mutableListOf<String>()
    for ((index, part) in parts.withIndex()) {
        val cost = width(part) + SEPARATOR.length
        when {
            index in alerts -> kept += truncate(part, alertLimit)
            summaries[index].alert -> hidden++
            cost <= left -> { kept += part; left -= cost }
            left - SEPARATOR.length >= MIN_PART -> { kept += truncate(part, left - SEPARATOR.length); left = 0 }
            else -> hidden++
        }
    }
    if (hidden > 0) kept += "+$hidden more"
    return prefix + kept.joinToString(SEPARATOR)
}

/** Attacker-controlled text inside double quotes. */
internal fun quote(value: String, limit: Int): String = "\"" + escape(value, limit, quoted = true, token = false) + "\""

/** Attacker-controlled text shown bare, such as an element ID or JS identifier; whitespace is escaped too. */
internal fun token(value: String, limit: Int): String = escape(value, limit, quoted = true, token = true)

/** Attacker-controlled JSON shown as written, without surrounding quotes. */
internal fun raw(value: String, limit: Int): String = escape(value, limit, quoted = false, token = false)

private fun escape(value: String, limit: Int, quoted: Boolean, token: Boolean): String = buildString {
    var count = 0
    for (codePoint in value.codePoints()) {
        if (count++ == limit) {
            append('…')
            break
        }
        when {
            codePoint == '\\'.code -> append("\\\\")
            codePoint == '|'.code -> append("\\|")
            codePoint == '"'.code && quoted -> append("\\\"")
            codePoint == '\n'.code -> append("\\n")
            codePoint == '\r'.code -> append("\\r")
            codePoint == '\t'.code -> append("\\t")
            Character.getType(codePoint).toByte() in INVISIBLE_TYPES || (token && Character.isWhitespace(codePoint)) ->
                append("\\u{").append(Integer.toHexString(codePoint).uppercase()).append('}')
            else -> appendCodePoint(codePoint)
        }
    }
}

private fun truncate(text: String, limit: Int): String =
    if (text.codePointCount(0, text.length) <= limit) text
    else text.substring(0, text.offsetByCodePoints(0, maxOf(0, limit - 1))) + "…"

private fun String.collapseWhitespace() = trim().replace(Regex("\\s+"), " ")

internal const val VALUE_LIMIT = 60
private const val URI_LIMIT = 120
private const val ERROR_LIMIT = 120
private const val LABEL_TEXT_LIMIT = 40
private const val RENDER_TEXT_LIMIT = 24
private const val MAX_NOTE = 400
private const val SEPARATOR = " | "
private const val MORE_RESERVE = 16
private const val MIN_PART = 24
private val INVISIBLE_TYPES = setOf(Character.CONTROL, Character.FORMAT, Character.LINE_SEPARATOR,
    Character.PARAGRAPH_SEPARATOR, Character.SURROGATE, Character.PRIVATE_USE, Character.UNASSIGNED)
