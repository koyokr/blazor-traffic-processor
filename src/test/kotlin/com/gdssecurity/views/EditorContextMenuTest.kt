package com.gdssecurity.views

import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import javax.swing.event.PopupMenuEvent
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class EditorContextMenuTest {
    @Test
    fun menuTracksSelectionAndReadOnlyState() = SwingUtilities.invokeAndWait {
        val text = JTextArea().apply {
            // Exercise document and menu behavior without requiring host fonts.
            setUI(null)
            caret = javax.swing.text.DefaultCaret()
            setText("hello")
            withEditorContextMenu()
        }
        val popup = text.componentPopupMenu
        fun refresh() = popup.popupMenuListeners.forEach {
            it.popupMenuWillBecomeVisible(PopupMenuEvent(popup))
        }
        fun item(index: Int) = popup.getComponent(index) as JMenuItem
        refresh()
        assertFalse(item(0).isEnabled)
        assertFalse(item(1).isEnabled)
        assertTrue(item(2).isEnabled)
        item(4).doClick()
        assertEquals("hello", text.selectedText)
        refresh()
        assertTrue(item(0).isEnabled)
        assertTrue(item(1).isEnabled)
        text.isEditable = false
        refresh()
        assertTrue(item(0).isEnabled)
        assertFalse(item(1).isEnabled)
        assertFalse(item(2).isEnabled)
    }

    @Test
    fun handlesNewChildrenWithoutReplacingExistingMenusOrDuplicatingListeners() = SwingUtilities.invokeAndWait {
        val panel = JPanel().apply { withEditorContextMenu() }
        val listenerCount = panel.containerListeners.size
        panel.withEditorContextMenu()
        assertEquals(listenerCount, panel.containerListeners.size)
        val text = JTextArea()
        panel.add(JPanel().apply { add(text) })
        assertNotNull(text.componentPopupMenu)
        val existing = JPopupMenu()
        val nativeEditor = JTextArea().apply { componentPopupMenu = existing }
        panel.add(nativeEditor)
        assertSame(existing, nativeEditor.componentPopupMenu)
    }
}
