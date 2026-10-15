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
package com.gdssecurity.editors

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.contextmenu.WebSocketMessage
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.helpers.BlazorFrameValidator
import com.gdssecurity.helpers.BlazorHelper
import com.gdssecurity.views.withEditorContextMenu
import java.awt.Component
import java.nio.charset.StandardCharsets

private typealias Reassembly = Triple<WebSocketMessage, ByteArray, ByteArray?>

/** Human-readable BlazorPack editor for native WebSocket history and interception. */
class BTPWebSocketMessageEditor(
    private val montoya: MontoyaApi,
    private val editorMode: EditorMode,
) : ExtensionProvidedWebSocketMessageEditor {
    private val editor = montoya.userInterface().createRawEditor().apply {
        setEditable(editorMode != EditorMode.READ_ONLY)
    }
    private val blazorHelper = BlazorHelper()
    private val logging = montoya.logging()
    private var currentMessage: WebSocketMessage? = null
    private var displayingReassembledPayload = false
    private var decoded = false
    private var lastReassembly: Reassembly? = null

    override fun getMessage(): BurpByteArray {
        val message = currentMessage ?: return BurpByteArray.byteArray(*byteArrayOf())
        if (!isModified()) return message.payload().copy()
        return blazorHelper.packJson(String(editor.contents.bytes, StandardCharsets.UTF_8), message.payload().bytes)
            .mapCatching { BurpByteArray.byteArray(*it) }.getOrElse {
            logging.logToError("[-] WebSocket editor kept the original message: " + it.message)
            message.payload().copy()
        }
    }

    override fun setMessage(message: WebSocketMessage?) {
        val cached = lastReassembly.also { lastReassembly = null }
        currentMessage = message
        displayingReassembledPayload = false
        decoded = false
        editor.setEditable(false)
        if (message == null) {
            editor.contents = BurpByteArray.byteArray(*byteArrayOf())
            return
        }
        try {
            val payload = payloadForDisplay(message, cached)
            if (payload == null) {
                editor.contents = BurpByteArray.byteArray("Unable to decode BlazorPack payload.")
                return
            }
            displayingReassembledPayload = !payload.contentEquals(message.payload().bytes)
            val json = blazorHelper.unpackJson(payload, indent = 2).getOrThrow()
            editor.contents = BurpByteArray.byteArray(json)
            decoded = true
            editor.setEditable(editorMode != EditorMode.READ_ONLY && !displayingReassembledPayload)
        } catch (exception: Exception) {
            logging.logToError("[-] WebSocket editor could not decode BlazorPack: " + exception.message)
            editor.contents = BurpByteArray.byteArray("Unable to decode BlazorPack payload.")
        }
    }

    override fun isEnabledFor(message: WebSocketMessage?): Boolean {
        lastReassembly = null
        if (message == null || message.upgradeRequest() == null || message.payload() == null) return false
        val path = message.upgradeRequest().pathWithoutQuery() ?: return false
        return (path == "/_blazor" || path.endsWith("/_blazor")) && payloadForDisplay(message, store = true) != null
    }

    /** setMessage reuses, once, the history scan that the immediately preceding isEnabledFor made for it. */
    private fun payloadForDisplay(current: WebSocketMessage, cached: Reassembly? = null, store: Boolean = false): ByteArray? {
        val payload = current.payload().bytes
        if (BlazorFrameValidator.isBlazorPack(payload)) return payload
        if (editorMode != EditorMode.READ_ONLY || current.upgradeRequest() == null) return null
        if (cached != null && cached.first === current && cached.second.contentEquals(payload)) return cached.third
        return reassemble(current, payload).also { if (store) lastReassembly = Triple(current, payload, it) }
    }

    private fun reassemble(current: WebSocketMessage, payload: ByteArray): ByteArray? {
        val history = montoya.proxy().webSocketHistory {
            it.direction() == current.direction() && sameUpgrade(it.upgradeRequest(), current.upgradeRequest())
        }
        // A history row is identified exactly; otherwise every row with the same bytes must agree.
        val candidates = if (current is ProxyWebSocketMessage) {
            history.filter { it.webSocketId() == current.webSocketId() && it.id() == current.id() }
        } else {
            history.filter { it.payload().length() == payload.size && it.payload().bytes.contentEquals(payload) }
        }
        val results = candidates.map { candidate ->
            val stream = history.filter { it.webSocketId() == candidate.webSocketId() }.sortedBy { it.id() }
            val index = stream.indexOfFirst { it.id() == candidate.id() }
            val start = maxOf(0, index - MAX_REASSEMBLY_CHUNKS + 1)
            val window = stream.subList(start, minOf(stream.size, index + MAX_REASSEMBLY_CHUNKS))
            BlazorFrameValidator.reassembleContaining(
                window.map { it.payload().bytes }, index - start, MAX_REASSEMBLY_CHUNKS, MAX_REASSEMBLY_BYTES
            )
        }
        val first = results.firstOrNull() ?: return null
        return first.takeIf { results.all { it != null && it.contentEquals(first) } }
    }

    private fun sameUpgrade(first: HttpRequest?, second: HttpRequest?): Boolean {
        if (first == null || second == null || first.path() != second.path()) return false
        val firstService = first.httpService() ?: return false
        val secondService = second.httpService() ?: return false
        val firstHost = firstService.host() ?: return false
        val secondHost = secondService.host() ?: return false
        return firstHost.equals(secondHost, ignoreCase = true) &&
            firstService.port() == secondService.port() && firstService.secure() == secondService.secure()
    }

    override fun caption(): String = BTPConstants.CAPTION
    override fun uiComponent(): Component = editor.uiComponent().withEditorContextMenu()
    override fun selectedData(): Selection? = editor.selection().orElse(null)
    override fun isModified(): Boolean =
        decoded && editorMode != EditorMode.READ_ONLY && !displayingReassembledPayload && editor.isModified

    private companion object {
        const val MAX_REASSEMBLY_CHUNKS = 32
        const val MAX_REASSEMBLY_BYTES = 8 * 1024 * 1024
    }
}
