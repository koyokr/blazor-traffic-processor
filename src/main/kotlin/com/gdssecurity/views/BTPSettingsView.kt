package com.gdssecurity.views

import com.gdssecurity.settings.BTPSettings
import java.awt.BorderLayout
import java.awt.Color
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSeparator
import javax.swing.JTextArea
import javax.swing.UIManager
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener

class BTPSettingsView(private val settings: BTPSettings) : JPanel(BorderLayout()) {
    private val analysis = JCheckBox("Analyze binary payloads")
    private val reassembly = JCheckBox("Reassemble fragmented WebSocket messages")
    private val annotation = JCheckBox("Write a summary of each message to the Notes column")
    private val paths = JTextArea(6, 48).apply {
        font = Font(Font.MONOSPACED, Font.PLAIN, font.size)
        margin = Insets(4, 6, 4, 6)
    }
    private val apply = JButton("Apply")
    private val status = Hint("")
    private val form = JPanel(GridBagLayout())
    private var row = 0

    init {
        val indent = (UIManager.getIcon("CheckBox.icon")?.iconWidth ?: 16) + analysis.iconTextGap + analysis.insets.left

        heading("Blazor Traffic Processor", 5f, top = 0)
        line(Hint("Settings are saved with the current Burp project. Reopen a message to apply changes."), top = 4)
        line(JSeparator(), top = 14, fill = true)

        heading("Message decoding", 2f)
        line(analysis, top = 8)
        line(Hint("Decode binary contents into the BinaryAnalysis view (UTF-8 text, RenderBatch structure). HEX is always kept."), left = indent)
        line(reassembly, top = 8)
        line(Hint("Applies to read-only history only. When off, incomplete messages are shown without a history lookup."), left = indent)

        heading("WebSocket history notes", 2f)
        line(annotation, top = 8)
        line(Hint("Names the element behind each UI event, what the server rendered and any JavaScript it asked the browser to run."), left = indent)
        line(Hint("Applies to connections opened after saving. Existing notes are never overwritten."), left = indent)

        heading("Endpoints", 2f)
        line(Hint("/_blazor and any path ending in /_blazor are always processed. Add other hub paths, one per line."), top = 6)
        line(JScrollPane(paths).apply { withEditorContextMenu() }, top = 8, fill = true)
        line(Hint("Exact, case-sensitive paths such as /app/hub, without a host, query string, fragment or wildcard."), top = 4)

        line(JPanel(FlowLayout(FlowLayout.LEADING, 0, 0)).apply {
            isOpaque = false
            add(apply)
            add(status.apply { border = BorderFactory.createEmptyBorder(0, 12, 0, 0) })
        }, top = 20)

        form.border = BorderFactory.createEmptyBorder(20, 24, 20, 24)
        val page = JPanel(BorderLayout()).apply { add(form, BorderLayout.WEST) }
        add(JScrollPane(JPanel(BorderLayout()).apply { add(page, BorderLayout.NORTH) }).apply {
            border = BorderFactory.createEmptyBorder()
            verticalScrollBar.unitIncrement = 16
        })

        reset()
        analysis.addActionListener { refresh() }
        reassembly.addActionListener { refresh() }
        annotation.addActionListener { refresh() }
        paths.document.addDocumentListener(object : DocumentListener {
            override fun insertUpdate(e: DocumentEvent) = refresh()
            override fun removeUpdate(e: DocumentEvent) = refresh()
            override fun changedUpdate(e: DocumentEvent) = refresh()
        })
        apply.addActionListener { save() }
    }

    private fun reset() {
        val options = settings.current
        analysis.isSelected = options.binaryAnalysis
        reassembly.isSelected = options.reassembleMessages
        annotation.isSelected = options.annotateMessages
        paths.text = options.customPaths.joinToString("\n")
        refresh()
    }

    private fun isModified(): Boolean = settings.current.let {
        analysis.isSelected != it.binaryAnalysis || reassembly.isSelected != it.reassembleMessages ||
            annotation.isSelected != it.annotateMessages ||
            paths.text.lines().map(String::trim).filter(String::isNotEmpty) != it.customPaths
    }

    private fun refresh() {
        apply.isEnabled = isModified()
        if (apply.isEnabled) show(UNSAVED, error = false) else if (status.text == UNSAVED) show("", error = false)
    }

    private fun save() = runCatching {
        settings.save(analysis.isSelected, reassembly.isSelected, paths.text, annotation.isSelected)
    }.fold(
        onSuccess = { reset(); show("Saved. Reopen messages to apply these settings.", error = false) },
        onFailure = { show(it.message ?: "Unable to save settings.", error = true) },
    )

    private fun show(message: String, error: Boolean) {
        status.text = message
        status.error = error
    }

    private fun heading(text: String, grow: Float, top: Int = 24) =
        line(JLabel(text).apply { font = font.deriveFont(Font.BOLD, font.size2D + grow) }, top)

    private fun line(component: JComponent, top: Int = 2, left: Int = 0, fill: Boolean = false) {
        form.add(component, GridBagConstraints().apply {
            gridx = 0
            gridy = row++
            anchor = GridBagConstraints.LINE_START
            this.fill = if (fill) GridBagConstraints.HORIZONTAL else GridBagConstraints.NONE
            insets = Insets(top, left, 0, 0)
        })
    }

    private companion object {
        const val UNSAVED = "Unsaved changes."
    }

    /** Secondary text whose colour follows Burp theme changes. */
    private class Hint(text: String) : JLabel(text) {
        var error = false
            set(value) { field = value; updateColor() }

        override fun updateUI() {
            super.updateUI()
            updateColor()
        }

        private fun updateColor() {
            foreground = if (error) UIManager.getColor("Actions.Red") ?: Color(0xD0, 0x3A, 0x2F)
            else UIManager.getColor("Label.disabledForeground") ?: Color.GRAY
        }
    }
}
