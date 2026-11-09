package com.gdssecurity.helpers

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.ui.contextmenu.WebSocketMessage

/** History-only reconstruction. Connection identity and ambiguous payload matches remain isolated. */
internal class WebSocketMessageReassembler(private val montoya: MontoyaApi) {
    fun reassemble(current: WebSocketMessage, payload: ByteArray): ByteArray? {
        if (payload.isEmpty() || payload.size > MAX_BYTES) return null
        val upgrade = current.upgradeRequest() ?: return null
        val direction = current.direction()
        val socket = (current as? ProxyWebSocketMessage)?.webSocketId()
        val history = montoya.proxy().webSocketHistory {
            (socket == null || it.webSocketId() == socket) &&
                it.direction() == direction && sameUpgrade(it.upgradeRequest(), upgrade)
        }
        var result: ByteArray? = null
        // Sort each connection once, even when an unidentified message has many matching rows.
        for (entries in history.groupBy { it.webSocketId() }.values) {
            val stream = entries.sortedBy { it.id() }
            for ((index, candidate) in stream.withIndex()) {
                val matches = if (current is ProxyWebSocketMessage) candidate.id() == current.id() else
                    candidate.payload().let { it.length() == payload.size && it.bytes.contentEquals(payload) }
                if (!matches) continue
                val assembled = reassembleAt(stream, index) ?: return null
                if (result != null && !result.contentEquals(assembled)) return null
                result = assembled
            }
        }
        return result
    }

    private fun reassembleAt(stream: List<ProxyWebSocketMessage>, index: Int): ByteArray? {
        val selectedSize = stream[index].payload().length()
        if (selectedSize !in 1..MAX_BYTES) return null
        // A valid candidate containing the selected row cannot cross either size boundary.
        // Bound both sides using metadata before loading bytes: at most 2 * MAX_BYTES retained.
        var start = index
        var remaining = MAX_BYTES - selectedSize
        while (start > 0 && index - start + 1 < MAX_CHUNKS) {
            val length = stream[start - 1].payload().length()
            if (length !in 1..remaining) break
            remaining -= length
            start--
        }
        var end = index + 1
        remaining = MAX_BYTES - selectedSize
        while (end < stream.size && end - index < MAX_CHUNKS) {
            val length = stream[end].payload().length()
            if (length !in 1..remaining) break
            remaining -= length
            end++
        }
        val payloads = stream.subList(start, end).map { it.payload() }
        val loaded = arrayOfNulls<ByteArray>(payloads.size)
        val attempted = BooleanArray(payloads.size)
        val chunks = object : AbstractList<ByteArray?>() {
            override val size = payloads.size
            override fun get(index: Int): ByteArray? {
                if (!attempted[index]) {
                    attempted[index] = true
                    val source = payloads[index]
                    loaded[index] = source.bytes.takeIf { it.size == source.length() }
                }
                return loaded[index]
            }
        }
        return BlazorFrameValidator.reassembleContaining(chunks, index - start, MAX_CHUNKS, MAX_BYTES)
    }

    private fun sameUpgrade(first: HttpRequest?, second: HttpRequest): Boolean {
        if (first == null || first.path() != second.path()) return false
        val firstService = first.httpService() ?: return false
        val secondService = second.httpService() ?: return false
        val firstHost = firstService.host() ?: return false
        val secondHost = secondService.host() ?: return false
        return firstHost.equals(secondHost, ignoreCase = true) &&
            firstService.port() == secondService.port() && firstService.secure() == secondService.secure()
    }

    private companion object {
        const val MAX_CHUNKS = 32
        const val MAX_BYTES = 8 * 1024 * 1024
    }
}
