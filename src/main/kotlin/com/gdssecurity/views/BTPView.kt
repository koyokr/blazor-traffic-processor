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
package com.gdssecurity.views

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray as BurpByteArray
import com.gdssecurity.helpers.BlazorHelper
import java.awt.BorderLayout
import java.awt.GridLayout
import javax.swing.JButton
import javax.swing.JComboBox
import javax.swing.JComponent
import javax.swing.JPanel

class BTPView(montoya: MontoyaApi) : JComponent() {
    private val logging = montoya.logging()
    private val blazorHelper = BlazorHelper()
    private val editor = montoya.userInterface().createRawEditor()
    private val results = montoya.userInterface().createRawEditor()
    private val convertButton = JButton("Deserialize")
    private val dropDownMenu = JComboBox(arrayOf("Blazor->JSON", "JSON->Blazor"))

    init {
        layout = BorderLayout(10, 10)
        val mainView = JPanel(GridLayout(1, 2)).apply {
            add(editor.uiComponent().withEditorContextMenu())
            add(results.uiComponent().withEditorContextMenu())
        }
        convertButton.addActionListener { handleButtonClick() }
        dropDownMenu.addActionListener {
            when (dropDownMenu.selectedIndex) {
                DESERIALIZE_IDX -> convertButton.text = "Deserialize"
                SERIALIZE_IDX -> convertButton.text = "Serialize"
            }
        }
        val clearButton = JButton("Clear").apply {
            addActionListener {
                editor.contents = BurpByteArray.byteArray("")
                results.contents = BurpByteArray.byteArray("")
            }
        }
        val buttons = JPanel(GridLayout(1, 3)).apply {
            add(convertButton)
            add(dropDownMenu)
            add(clearButton)
        }
        add(JPanel(BorderLayout(10, 10)).apply {
            add(buttons, BorderLayout.NORTH)
            add(mainView, BorderLayout.CENTER)
        })
    }

    fun setEditorText(text: BurpByteArray) {
        editor.contents = text
    }

    private fun handleButtonClick() {
        val content = editor.contents
        if (content == null || content.length() == 0) {
            results.contents = BurpByteArray.byteArray("Error: editor input cannot be empty.")
            return
        }
        val conversion = when (dropDownMenu.selectedIndex) {
            SERIALIZE_IDX -> blazorHelper.packJson(content.toString()).mapCatching { BurpByteArray.byteArray(*it) }
            DESERIALIZE_IDX -> blazorHelper.unpackJson(content.bytes).mapCatching { BurpByteArray.byteArray(it) }
            else -> return
        }
        conversion.fold(
            onSuccess = { results.contents = it },
            onFailure = {
                logging.logToError("[-] BTP conversion failed: " + it.message)
                results.contents = BurpByteArray.byteArray("Unable to convert input: " + it.message)
            },
        )
    }

    private companion object {
        const val DESERIALIZE_IDX = 0
        const val SERIALIZE_IDX = 1
    }
}
