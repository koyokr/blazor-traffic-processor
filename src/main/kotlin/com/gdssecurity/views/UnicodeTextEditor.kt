package com.gdssecurity.views

import java.awt.Color
import java.awt.Font
import java.awt.event.ActionEvent
import javax.swing.AbstractAction
import javax.swing.JMenuItem
import javax.swing.JTextPane
import javax.swing.JViewport
import javax.swing.KeyStroke
import javax.swing.Timer
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.text.DefaultEditorKit
import javax.swing.text.DefaultStyledDocument
import javax.swing.text.DefaultStyledDocument.ElementSpec
import javax.swing.text.SimpleAttributeSet
import javax.swing.text.StyleConstants
import javax.swing.text.StyleContext
import javax.swing.text.StyledDocument
import javax.swing.undo.UndoManager

/**
 * Unicode editing with per-document undo history and a cached comparison to the displayed text.
 *
 * Like Burp's Pretty view, JSON indentation is drawn as a paragraph margin rather than stored as
 * spaces, so copied text keeps line breaks but carries no indentation.
 */
internal class UnicodeTextEditor : JTextPane() {
    private val undo = UndoManager()
    private var originalText = ""
    private var comparisonNeeded = false
    private var modified = false
    private var json = false
    // Character range edited since the last restyle; -1 when clean.
    private var dirtyStart = -1
    private var dirtyEnd = -1
    private val restyle = Timer(RESTYLE_DELAY_MS) { highlightDirtyLines() }.apply { isRepeats = false }
    private val changes = object : DocumentListener {
        override fun insertUpdate(event: DocumentEvent) = textChanged(event.offset, event.length, inserted = true)
        override fun removeUpdate(event: DocumentEvent) = textChanged(event.offset, event.length, inserted = false)
        override fun changedUpdate(event: DocumentEvent) = Unit
    }

    init {
        font = Font(Font.MONOSPACED, Font.PLAIN, font.size)
        isEditable = false
        document.addUndoableEditListener(undo)
        document.addDocumentListener(changes)
        val undoAction = object : AbstractAction("Undo") {
            override fun isEnabled() = isEditable && undo.canUndo()
            override fun actionPerformed(event: ActionEvent?) { if (isEnabled) undo.undo() }
        }
        val redoAction = object : AbstractAction("Redo") {
            override fun isEnabled() = isEditable && undo.canRedo()
            override fun actionPerformed(event: ActionEvent?) { if (isEnabled) undo.redo() }
        }
        actionMap.put("undo", undoAction)
        actionMap.put("redo", redoAction)
        for (modifier in listOf("control", "meta")) {
            inputMap.put(KeyStroke.getKeyStroke("$modifier Z"), "undo")
            inputMap.put(KeyStroke.getKeyStroke("$modifier Y"), "redo")
            inputMap.put(KeyStroke.getKeyStroke("$modifier shift Z"), "redo")
        }
        withEditorContextMenu()
        componentPopupMenu.insert(JMenuItem(redoAction), 0)
        componentPopupMenu.insert(JMenuItem(undoAction), 0)
        // JMenuItem caches Action.enabled, so refresh it when the menu opens.
        componentPopupMenu.addPopupMenuListener(object : javax.swing.event.PopupMenuListener {
            override fun popupMenuWillBecomeVisible(event: javax.swing.event.PopupMenuEvent) {
                componentPopupMenu.getComponent(0).isEnabled = undoAction.isEnabled
                componentPopupMenu.getComponent(1).isEnabled = redoAction.isEnabled
            }
            override fun popupMenuWillBecomeInvisible(event: javax.swing.event.PopupMenuEvent) = Unit
            override fun popupMenuCanceled(event: javax.swing.event.PopupMenuEvent) = Unit
        })
    }

    /** Displays [value]; when [json] is set, leading indentation becomes a visual margin and syntax is colored. */
    fun display(value: String, json: Boolean = false) {
        restyle.stop()
        this.json = json
        dirtyStart = -1
        val lines = value.split('\n')
        val shown = if (json) lines.joinToString("\n") { it.trimStart(' ') } else value
        // Build the whole styled document in one pass while detached; per-run attribute changes are far slower.
        val doc = BulkStyledDocument()
        // Content already carries its line breaks; do not translate LF to the host OS separator.
        doc.putProperty(DefaultEditorKit.EndOfLineStringProperty, "\n")
        val base = doc.getStyle(StyleContext.DEFAULT_STYLE).apply {
            StyleConstants.setFontFamily(this, font.family)
            StyleConstants.setFontSize(this, font.size)
        }
        val space = spaceWidth()
        val paragraphs = HashMap<Int, SimpleAttributeSet>()
        val plain = SimpleAttributeSet()
        val palette = if (isDark()) DARK else LIGHT
        val colors = TokenKind.entries.associateWith { kind ->
            SimpleAttributeSet().apply { StyleConstants.setForeground(this, palette.color(kind)) }
        }
        // create() expects the empty paragraph of a new document to be closed first.
        val specs = arrayListOf(ElementSpec(null, ElementSpec.EndTagType))
        for (line in lines) {
            val depth = if (json) line.length - line.trimStart(' ').length else 0
            specs += ElementSpec(paragraphs.getOrPut(depth) {
                SimpleAttributeSet().apply {
                    resolveParent = base
                    if (depth > 0) StyleConstants.setLeftIndent(this, depth * space)
                }
            }, ElementSpec.StartTagType)
            val chars = line.toCharArray(depth, line.length) + '\n'
            var position = 0
            if (json) for (token in jsonTokens(String(chars))) {
                if (token.start > position) specs += ElementSpec(plain, ElementSpec.ContentType, chars, position, token.start - position)
                specs += ElementSpec(colors.getValue(token.kind), ElementSpec.ContentType, chars, token.start, token.end - token.start)
                position = token.end
            }
            specs += ElementSpec(plain, ElementSpec.ContentType, chars, position, chars.size - position)
            specs += ElementSpec(null, ElementSpec.EndTagType)
        }
        doc.load(specs)
        // Every line was given a break; drop the last so the final paragraph ends at the document's implied one.
        doc.remove(doc.length - 1, 1)
        document.removeUndoableEditListener(undo)
        document.removeDocumentListener(changes)
        document = doc
        doc.addUndoableEditListener(undo)
        doc.addDocumentListener(changes)
        caretPosition = 0
        originalText = shown
        undo.discardAllEdits()
        comparisonNeeded = false
        modified = false
    }

    fun isContentModified(): Boolean {
        if (comparisonNeeded) {
            modified = text != originalText
            comparisonNeeded = false
        }
        return modified
    }

    // Keep long lines on one line, as Burp's editors do by default.
    override fun getScrollableTracksViewportWidth(): Boolean {
        val viewport = parent as? JViewport ?: return true
        return ui.getPreferredSize(this).width <= viewport.width
    }

    private fun textChanged(offset: Int, length: Int, inserted: Boolean) {
        comparisonNeeded = true
        if (!json) return
        if (dirtyStart < 0) {
            dirtyStart = offset
            dirtyEnd = offset
        } else if (offset <= dirtyEnd) {
            // Keep the pending range aligned with text that moved.
            dirtyEnd = if (inserted) dirtyEnd + length else maxOf(offset, dirtyEnd - length)
        }
        dirtyStart = minOf(dirtyStart, offset)
        dirtyEnd = maxOf(dirtyEnd, if (inserted) offset + length else offset)
        restyle.restart()
    }

    private fun spaceWidth(): Float = getFontMetrics(font).charWidth(' ').toFloat()

    /** JSON strings cannot contain raw line breaks, so recoloring only the edited lines is exact. */
    internal fun highlightDirtyLines() {
        if (dirtyStart < 0) return
        val doc = styledDocument
        val root = doc.defaultRootElement
        val first = root.getElement(root.getElementIndex(minOf(dirtyStart, doc.length)))
        val last = root.getElement(root.getElementIndex(minOf(dirtyEnd, doc.length)))
        dirtyStart = -1
        val start = first.startOffset
        val end = minOf(last.endOffset, doc.length)
        // Styling is presentation only, so it must not appear in the undo history.
        doc.removeUndoableEditListener(undo)
        try {
            colorTokens(doc, doc.getText(start, end - start), start)
        } finally {
            doc.addUndoableEditListener(undo)
        }
    }

    private fun colorTokens(doc: StyledDocument, content: String, offset: Int) {
        val palette = if (isDark()) DARK else LIGHT
        doc.setCharacterAttributes(offset, content.length, SimpleAttributeSet(), true)
        for (token in jsonTokens(content)) {
            val color = palette.color(token.kind)
            doc.setCharacterAttributes(offset + token.start, token.end - token.start,
                SimpleAttributeSet().apply { StyleConstants.setForeground(this, color) }, false)
        }
    }

    private fun isDark(): Boolean {
        val bg = background ?: return false
        return (bg.red * 299 + bg.green * 587 + bg.blue * 114) / 1000 < 128
    }

    private class Palette(val key: Color, val string: Color, val literal: Color) {
        fun color(kind: TokenKind) = when (kind) {
            TokenKind.KEY -> key
            TokenKind.STRING -> string
            TokenKind.LITERAL -> literal
        }
    }

    private class BulkStyledDocument : DefaultStyledDocument() {
        fun load(specs: List<ElementSpec>) = create(specs.toTypedArray())
    }

    private companion object {
        const val RESTYLE_DELAY_MS = 200
        val LIGHT = Palette(Color(0x000080), Color(0x008000), Color(0x0000FF))
        val DARK = Palette(Color(0x9CDCFE), Color(0x8FCF7F), Color(0xB5A0FF))
    }
}

internal enum class TokenKind { KEY, STRING, LITERAL }
internal data class JsonToken(val start: Int, val end: Int, val kind: TokenKind)

/** Lenient JSON tokenizer for coloring; tolerates partially edited text. */
internal fun jsonTokens(text: String): List<JsonToken> = buildList {
    var index = 0
    while (index < text.length) {
        val char = text[index]
        when {
            char == '"' -> {
                val start = index++
                while (index < text.length && text[index] != '"' && text[index] != '\n') {
                    // An escape never consumes a line break, so an unfinished string stays on its line.
                    index += if (text[index] == '\\' && index + 1 < text.length && text[index + 1] != '\n') 2 else 1
                }
                if (index < text.length && text[index] == '"') index++
                var next = index
                while (next < text.length && text[next].isWhitespace()) next++
                add(JsonToken(start, index, if (next < text.length && text[next] == ':') TokenKind.KEY else TokenKind.STRING))
            }
            char == '-' || char.isLetterOrDigit() -> {
                val start = index
                while (index < text.length && (text[index].isLetterOrDigit() || text[index] in "+-.")) index++
                add(JsonToken(start, index, TokenKind.LITERAL))
            }
            else -> index++
        }
    }
}
