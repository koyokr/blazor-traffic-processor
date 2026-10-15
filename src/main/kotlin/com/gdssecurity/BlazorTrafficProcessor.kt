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
package com.gdssecurity

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.api.montoya.extension.ExtensionUnloadingHandler
import burp.api.montoya.logging.Logging
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.providers.*
import com.gdssecurity.views.BTPView

/** Public no-argument entry point loaded by Burp as a Java extension. */
class BlazorTrafficProcessor : BurpExtension, ExtensionUnloadingHandler {
    private lateinit var logging: Logging

    override fun initialize(api: MontoyaApi) {
        api.extension().setName(BTPConstants.EXTENSION_NAME)
        logging = api.logging()
        val ui = api.userInterface()
        ui.registerHttpRequestEditorProvider(BTPHttpRequestEditorProvider(api))
        ui.registerHttpResponseEditorProvider(BTPHttpResponseEditorProvider(api))
        ui.registerWebSocketMessageEditorProvider(BTPWebSocketMessageEditorProvider(api))
        val tab = BTPView(api)
        ui.registerSuiteTab(BTPConstants.CAPTION, tab)
        ui.registerContextMenuItemsProvider(BTPContextMenuItemsProvider(api, tab))
        api.extension().registerUnloadingHandler(this)
        logging.logToOutput(BTPConstants.LOADED_LOG_MSG)
    }

    override fun extensionUnloaded() {
        logging.logToOutput(BTPConstants.UNLOADED_LOG_MSG)
    }
}
