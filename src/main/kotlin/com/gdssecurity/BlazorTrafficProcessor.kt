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
import com.gdssecurity.annotations.BTPWebSocketAnnotator
import com.gdssecurity.helpers.BTPConstants
import com.gdssecurity.providers.*
import com.gdssecurity.settings.BTPSettings
import com.gdssecurity.views.BTPSettingsView

/** Public no-argument entry point loaded by Burp as a Java extension. */
class BlazorTrafficProcessor : BurpExtension, ExtensionUnloadingHandler {
    private lateinit var logging: Logging
    private var annotator: BTPWebSocketAnnotator? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName(BTPConstants.EXTENSION_NAME)
        logging = api.logging()
        val ui = api.userInterface()
        val settings = BTPSettings(api.persistence().extensionData())
        ui.registerHttpRequestEditorProvider(BTPHttpRequestEditorProvider(api, settings))
        ui.registerHttpResponseEditorProvider(BTPHttpResponseEditorProvider(api, settings))
        ui.registerWebSocketMessageEditorProvider(BTPWebSocketMessageEditorProvider(api, settings))
        annotator = BTPWebSocketAnnotator(api.proxy(), settings, logging).also {
            it.update(settings.current)
            settings.addListener(it::update)
        }
        val tab = BTPSettingsView(settings)
        ui.applyThemeToComponent(tab)
        ui.registerSuiteTab(BTPConstants.CAPTION, tab)
        api.extension().registerUnloadingHandler(this)
        logging.logToOutput(BTPConstants.LOADED_LOG_MSG)
    }

    override fun extensionUnloaded() {
        annotator?.close()
        logging.logToOutput(BTPConstants.UNLOADED_LOG_MSG)
    }
}
