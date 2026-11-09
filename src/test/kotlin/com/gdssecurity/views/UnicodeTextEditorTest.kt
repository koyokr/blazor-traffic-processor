package com.gdssecurity.views

import javax.swing.JMenuItem
import javax.swing.KeyStroke
import javax.swing.SwingUtilities
import javax.swing.event.PopupMenuEvent
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class UnicodeTextEditorTest {
    @Test
    fun unicodeUndoRedoRestoresTheUnmodifiedStateAndResetsBetweenMessages() = SwingUtilities.invokeAndWait {
        val editor = UnicodeTextEditor()
        editor.display("한글 中文 日本語 𠮷")
        editor.isEditable = true
        assertFalse(editor.isContentModified())
        editor.document.insertString(editor.document.length, " 수정", null)
        repeat(3) { assertTrue(editor.isContentModified()) }
        fun key(binding: String) {
            val action = editor.inputMap.get(KeyStroke.getKeyStroke(binding))
            assertNotNull(action)
            editor.actionMap.get(action).actionPerformed(null)
        }
        key("control Z")
        assertEquals("한글 中文 日本語 𠮷", editor.text)
        assertFalse(editor.isContentModified())
        key("meta shift Z")
        assertTrue(editor.isContentModified())
        assertEquals("한글 中文 日本語 𠮷 수정", editor.text)
        editor.isEditable = false
        key("meta Z")
        assertTrue(editor.text.endsWith(" 수정"))
        editor.display("다음 메시지")
        editor.isEditable = true
        assertFalse(editor.actionMap.get("undo").isEnabled)
        assertFalse(editor.actionMap.get("redo").isEnabled)
        key("control Z")
        assertEquals("다음 메시지", editor.text)
        assertFalse(editor.isContentModified())
    }

    @Test
    fun contextMenuReflectsUndoRedoAndEditability() = SwingUtilities.invokeAndWait {
        val editor = UnicodeTextEditor()
        editor.display("원문")
        editor.isEditable = true
        val popup = editor.componentPopupMenu
        fun refresh() = popup.popupMenuListeners.forEach { it.popupMenuWillBecomeVisible(PopupMenuEvent(popup)) }
        val undo = popup.getComponent(0) as JMenuItem
        val redo = popup.getComponent(1) as JMenuItem
        refresh()
        assertFalse(undo.isEnabled)
        assertFalse(redo.isEnabled)
        editor.document.insertString(editor.document.length, " 추가", null)
        refresh()
        assertTrue(undo.isEnabled)
        undo.doClick()
        refresh()
        assertTrue(redo.isEnabled)
        assertFalse(editor.isContentModified())
        editor.isEditable = false
        refresh()
        assertFalse(undo.isEnabled)
        assertFalse(redo.isEnabled)
    }

    @Test
    fun manualRestorationAndEmptyDocumentsResetTheComparison() = SwingUtilities.invokeAndWait {
        val editor = UnicodeTextEditor()
        editor.display("원문")
        editor.text = "변경"
        assertTrue(editor.isContentModified())
        editor.text = "원문"
        repeat(3) { assertFalse(editor.isContentModified()) }
        editor.display("")
        assertFalse(editor.isContentModified())
        editor.document.insertString(editor.document.length, "값", null)
        assertTrue(editor.isContentModified())
    }

    @Test
    fun jsonIndentationIsVisualOnlyAndStylingIsNotUndoable() = SwingUtilities.invokeAndWait {
        val editor = UnicodeTextEditor()
        editor.display("[{\n  \"Key\": \"a  b\",\n  \"N\": [\n    1\n  ]\n}]", json = true)
        assertEquals("[{\n\"Key\": \"a  b\",\n\"N\": [\n1\n]\n}]", editor.text)
        val root = editor.styledDocument.defaultRootElement
        val indents = (0 until root.elementCount).map {
            javax.swing.text.StyleConstants.getLeftIndent(root.getElement(it).attributes)
        }
        assertEquals(0f, indents[0])
        assertTrue(indents[1] > 0f)
        assertEquals(indents[1] * 2, indents[3])
        val keyColor = javax.swing.text.StyleConstants.getForeground(editor.styledDocument.getCharacterElement(3).attributes)
        val valueColor = javax.swing.text.StyleConstants.getForeground(editor.styledDocument.getCharacterElement(12).attributes)
        assertNotEquals(keyColor, valueColor)
        assertFalse(editor.isContentModified())
        editor.isEditable = true
        assertFalse(editor.actionMap.get("undo").isEnabled)
        editor.display("plain\n  text")
        assertEquals("plain\n  text", editor.text)
        assertEquals(0f, javax.swing.text.StyleConstants.getLeftIndent(
            editor.styledDocument.defaultRootElement.getElement(1).attributes))
    }

    @Test
    fun tokenizerClassifiesKeysStringsAndLiterals() {
        val text = """{"k": "v\"x", "n": -1.5e3, "b": true, "z": null}"""
        val kinds = jsonTokens(text).map { text.substring(it.start, it.end) to it.kind }
        assertEquals(listOf(
            "\"k\"" to TokenKind.KEY, "\"v\\\"x\"" to TokenKind.STRING,
            "\"n\"" to TokenKind.KEY, "-1.5e3" to TokenKind.LITERAL,
            "\"b\"" to TokenKind.KEY, "true" to TokenKind.LITERAL,
            "\"z\"" to TokenKind.KEY, "null" to TokenKind.LITERAL,
        ), kinds)
    }

    @Test
    fun editsRecolorOnlyTheirLinesWithoutUndoEntriesAndKeepTheEditorFont() = SwingUtilities.invokeAndWait {
        val editor = UnicodeTextEditor()
        editor.display("[{\n  \"a\": 1,\n  \"b\": 2\n}]", json = true)
        editor.isEditable = true
        val doc = editor.styledDocument
        fun color(offset: Int) = javax.swing.text.StyleConstants.getForeground(doc.getCharacterElement(offset).attributes)
        assertEquals(editor.font.family, doc.getFont(doc.getCharacterElement(3).attributes).family)
        val keyColor = color(3)
        val numberColor = color(8)
        // Turn the value of "b" into a string, then a key.
        val line = doc.defaultRootElement.getElement(2).startOffset
        doc.remove(line + 5, 1)
        doc.insertString(line + 5, "\"x\"", null)
        editor.highlightDirtyLines()
        assertNotEquals(numberColor, color(line + 6))
        assertNotEquals(keyColor, color(line + 6))
        assertEquals(keyColor, color(line))
        assertEquals(numberColor, color(8))
        editor.actionMap.get("undo").actionPerformed(null)
        editor.actionMap.get("undo").actionPerformed(null)
        assertEquals("[{\n\"a\": 1,\n\"b\": 2\n}]", editor.text)
        assertFalse(editor.isContentModified())
    }

    @Test
    fun unfinishedStringsDoNotCrossLineBreaks() {
        for (text in listOf("\"abc\n1", "\"abc\\\n1")) {
            val tokens = jsonTokens(text)
            assertEquals(text.indexOf('\n'), tokens[0].end)
            assertEquals(TokenKind.LITERAL, tokens[1].kind)
        }
    }
}
