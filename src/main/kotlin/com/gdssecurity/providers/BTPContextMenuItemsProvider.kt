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
package com.gdssecurity.providers

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.views.BTPView
import java.awt.Component
import javax.swing.JMenuItem

class BTPContextMenuItemsProvider(montoya: MontoyaApi, private val btpTab: BTPView) : ContextMenuItemsProvider {
    private val logging = montoya.logging()

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val selection = event.selectedRequestResponses().firstOrNull()
            ?: event.messageEditorRequestResponse().map { it.requestResponse() }.orElse(null)
            ?: return emptyList()
        val sendToBTP = JMenuItem(BTPConstants.SEND_TO_BTP_CAPTION)
        sendToBTP.addActionListener { sendSelectionToBTP(selection) }
        return listOf(sendToBTP)
    }

    private fun sendSelectionToBTP(selection: HttpRequestResponse) {
        val url = selection.request()?.url()
        if (url != null && !url.contains(BTPConstants.BLAZOR_URL)) {
            logging.logToError("[-] sendSelectionToBTP - Selected message is not BlazorPack.")
            return
        }
        val requestBody = selection.request()?.body()
        val responseBody = selection.response()?.body()
        if (requestBody != null && requestBody.length() != 0) {
            btpTab.setEditorText(requestBody)
        } else if (responseBody != null && responseBody.length() != 0) {
            btpTab.setEditorText(responseBody)
        }
    }
}
