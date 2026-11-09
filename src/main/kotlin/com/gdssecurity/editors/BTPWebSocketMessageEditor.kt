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
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.contextmenu.WebSocketMessage
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor
import com.gdssecurity.settings.BTPSettings
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.helpers.BlazorHelper
import com.gdssecurity.helpers.BlazorFrames
import com.gdssecurity.helpers.WebSocketMessageReassembler
import com.gdssecurity.messages.HubMessage
import com.gdssecurity.views.UnicodeTextEditor
import com.gdssecurity.views.withEditorContextMenu
import java.awt.Component
import java.awt.Font
import javax.swing.BorderFactory
import javax.swing.JScrollPane

private data class PreparedMessage(
    val message: WebSocketMessage,
    val originalBytes: ByteArray,
    val messages: List<HubMessage>?,
    val reassembled: Boolean,
    val reassemblyEnabled: Boolean,
)

/** Human-readable BlazorPack editor for native WebSocket history and interception. */
class BTPWebSocketMessageEditor(
    private val montoya: MontoyaApi,
    private val editorMode: EditorMode,
    private val settings: BTPSettings = BTPSettings(),
) : ExtensionProvidedWebSocketMessageEditor {
    // RawEditor is byte-oriented and has no charset API. Keep decoded JSON as Unicode text.
    private val editor = UnicodeTextEditor()
    private val component = JScrollPane(editor).apply {
        montoya.userInterface().applyThemeToComponent(this)
        // Match Burp's built-in message editors: borderless, using the configured editor font.
        border = BorderFactory.createEmptyBorder()
        viewportBorder = null
        editor.font = montoya.userInterface().currentEditorFont() ?: Font(Font.MONOSPACED, Font.PLAIN, editor.font.size)
    }.withEditorContextMenu()
    private fun display(text: String, json: Boolean = false) = editor.display(text, json)
    private val reassembler = WebSocketMessageReassembler(montoya)
    private val blazorHelper = BlazorHelper()
    private val logging = montoya.logging()
    private var currentMessage: WebSocketMessage? = null
    private var displayingReassembledPayload = false
    private var decoded = false
    private var lastPrepared: PreparedMessage? = null

    override fun getMessage(): BurpByteArray {
        val message = currentMessage ?: return BurpByteArray.byteArray(*byteArrayOf())
        if (!isModified()) return message.payload().copy()
        return blazorHelper.packJson(editor.text, message.payload().bytes)
            .mapCatching { BurpByteArray.byteArray(*it) }.getOrElse {
            logging.logToError("[-] WebSocket editor kept the original message: " + it.message)
            message.payload().copy()
        }
    }

    override fun setMessage(message: WebSocketMessage?) {
        val cached = lastPrepared.also { lastPrepared = null }
        currentMessage = message
        displayingReassembledPayload = false
        decoded = false
        editor.setEditable(false)
        if (message == null) {
            display("")
            return
        }
        try {
            val prepared = prepare(message, cached)
            if (prepared?.messages == null) {
                display("Unable to decode BlazorPack payload.")
                return
            }
            displayingReassembledPayload = prepared.reassembled
            display(blazorHelper.toJson(prepared.messages, settings.current.binaryAnalysis).toString(2), json = true)
            decoded = true
            editor.setEditable(editorMode != EditorMode.READ_ONLY && !displayingReassembledPayload)
        } catch (exception: Exception) {
            logging.logToError("[-] WebSocket editor could not decode BlazorPack: " + exception.message)
            display("Unable to decode BlazorPack payload.")
        }
    }

    override fun isEnabledFor(message: WebSocketMessage?): Boolean {
        lastPrepared = null
        if (message == null || message.upgradeRequest() == null || message.payload() == null) return false
        val path = message.upgradeRequest().pathWithoutQuery() ?: return false
        if (!settings.current.matchesPath(path)) return false
        lastPrepared = prepare(message)
        return lastPrepared?.messages != null
    }

    /** Reuse only the immediately preceding lookup, with matching identity, bytes and reassembly setting. */
    private fun prepare(current: WebSocketMessage, cached: PreparedMessage? = null): PreparedMessage? {
        val source = current.payload()
        if (source.length() !in 1..BlazorFrames.MAX_PAYLOAD_BYTES) return null
        val payload = source.bytes
        val reassemblyEnabled = settings.current.reassembleMessages
        if (cached != null && cached.message === current && cached.originalBytes.contentEquals(payload) &&
            cached.reassemblyEnabled == reassemblyEnabled) return cached
        val messages = blazorHelper.unpack(payload).getOrNull()?.takeIf { it.isNotEmpty() }
        if (messages != null) return PreparedMessage(current, payload, messages, false, reassemblyEnabled)
        val assembled = if (reassemblyEnabled && editorMode == EditorMode.READ_ONLY)
            reassembler.reassemble(current, payload) else null
        return PreparedMessage(current, payload, assembled?.let { blazorHelper.unpack(it).getOrNull() },
            assembled != null, reassemblyEnabled)
    }

    override fun caption(): String = BTPConstants.CAPTION
    override fun uiComponent(): Component = component
    override fun selectedData(): Selection? {
        val selected = editor.selectedText ?: return null
        val bytes = selected.toByteArray(Charsets.UTF_8)
        val start = editor.text.substring(0, editor.selectionStart).toByteArray(Charsets.UTF_8).size
        return Selection.selection(BurpByteArray.byteArray(*bytes), start, start + bytes.size)
    }
    override fun isModified(): Boolean =
        decoded && editorMode != EditorMode.READ_ONLY && !displayingReassembledPayload && editor.isContentModified()

}
