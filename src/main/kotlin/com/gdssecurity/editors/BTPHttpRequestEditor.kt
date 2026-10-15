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
import burp.api.montoya.http.message.ContentType
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.helpers.BlazorFrameValidator
import com.gdssecurity.helpers.BlazorHelper
import com.gdssecurity.views.withEditorContextMenu
import java.awt.Component

class BTPHttpRequestEditor(
    private val montoya: MontoyaApi,
    private val editorMode: EditorMode,
) : ExtensionProvidedHttpRequestEditor {
    private var originalRequest: HttpRequest? = null
    private var decoded = false
    private val editor = montoya.userInterface().createRawEditor().apply { setEditable(false) }
    private val codec = BlazorHelper()
    private val logging = montoya.logging()

    override fun getRequest(): HttpRequest? {
        val original = originalRequest ?: return null
        if (!isModified()) return original
        return runCatching {
            val bytes = editor.contents.bytes
            val offset = codec.getBodyOffset(bytes)
            require(offset > 0) { "HTTP header/body separator is missing." }
            val packed = codec.packJson(String(bytes, offset, bytes.size - offset, Charsets.UTF_8), original.body().bytes).getOrThrow()
            original.withBody(BurpByteArray.byteArray(*packed))
        }.getOrElse {
            logging.logToError("[-] HTTP editor kept the original request: " + it.message)
            original
        }
    }

    override fun setRequestResponse(requestResponse: HttpRequestResponse?) {
        val original = requestResponse?.request()
        originalRequest = original
        decoded = false
        editor.setEditable(false)
        editor.contents = BurpByteArray.byteArray("")
        if (original == null) return
        codec.unpackJson(original.body().bytes).mapCatching { json ->
            original.withBody(BurpByteArray.byteArray(json)).toByteArray()
        }.fold(
            onSuccess = {
                editor.contents = it
                decoded = true
                editor.setEditable(editorMode != EditorMode.READ_ONLY)
            },
            onFailure = {
                logging.logToError("[-] HTTP editor could not decode the request: " + it.message)
                editor.contents = BurpByteArray.byteArray("Unable to decode BlazorPack payload.")
            },
        )
    }

    override fun isEnabledFor(requestResponse: HttpRequestResponse?): Boolean {
        return try {
            val request = requestResponse?.request() ?: return false
            val url = request.url() ?: return false
            url.contains(BTPConstants.BLAZOR_URL) && request.httpVersion() != null &&
                request.contentType() != ContentType.JSON && montoya.scope().isInScope(url) &&
                BlazorFrameValidator.isBlazorPack(request.body()?.bytes)
        } catch (_: MalformedRequestException) {
            // Burp also queries editor availability for incomplete or malformed requests.
            false
        }
    }

    override fun caption(): String = BTPConstants.CAPTION
    override fun uiComponent(): Component = editor.uiComponent().withEditorContextMenu()
    override fun selectedData(): Selection? = editor.selection().orElse(null)
    override fun isModified(): Boolean = decoded && editorMode != EditorMode.READ_ONLY && editor.isModified
}
