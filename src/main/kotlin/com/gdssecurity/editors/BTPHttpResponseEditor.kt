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
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.MalformedRequestException
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.Selection
import burp.api.montoya.ui.editor.extension.EditorMode
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.helpers.BlazorFrameValidator
import com.gdssecurity.helpers.BlazorHelper
import com.gdssecurity.views.withEditorContextMenu
import java.awt.Component

/** Response conversion is a read-only preview; the original response is always returned. */
class BTPHttpResponseEditor(private val montoya: MontoyaApi, editorMode: EditorMode) : ExtensionProvidedHttpResponseEditor {
    private var originalResponse: HttpResponse? = null
    private val editor = montoya.userInterface().createRawEditor().apply { setEditable(false) }
    private val codec = BlazorHelper()
    private val logging = montoya.logging()

    override fun getResponse(): HttpResponse? = originalResponse

    override fun setRequestResponse(requestResponse: HttpRequestResponse?) {
        val original = requestResponse?.response()
        originalResponse = original
        editor.contents = BurpByteArray.byteArray("")
        if (original == null) return
        codec.unpackJson(original.body().bytes).mapCatching { json ->
            original.withBody(BurpByteArray.byteArray(json)).toByteArray()
        }.fold(
            onSuccess = { editor.contents = it },
            onFailure = {
                logging.logToError("[-] HTTP editor could not decode the response: " + it.message)
                editor.contents = BurpByteArray.byteArray("Unable to decode BlazorPack payload.")
            },
        )
    }

    override fun isEnabledFor(requestResponse: HttpRequestResponse?): Boolean {
        return try {
            val response = requestResponse?.response() ?: return false
            val url = requestResponse.request()?.url() ?: return false
            url.contains(BTPConstants.BLAZOR_URL) && response.httpVersion() != null &&
                montoya.scope()?.isInScope(url) == true && BlazorFrameValidator.isBlazorPack(response.body()?.bytes)
        } catch (_: MalformedRequestException) {
            // The associated request may not have a valid URL yet.
            false
        }
    }

    override fun caption(): String = BTPConstants.CAPTION
    override fun uiComponent(): Component = editor.uiComponent().withEditorContextMenu()
    override fun selectedData(): Selection? = editor.selection().orElse(null)
    override fun isModified(): Boolean = false
}
