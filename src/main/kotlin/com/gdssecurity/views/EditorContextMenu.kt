package com.gdssecurity.views

import java.awt.Component
import java.awt.Container
import java.awt.event.ContainerAdapter
import java.awt.event.ContainerEvent
import javax.swing.JMenuItem
import javax.swing.JPopupMenu
import javax.swing.event.PopupMenuEvent
import javax.swing.event.PopupMenuListener
import javax.swing.text.JTextComponent

/** Supply standard editing actions where the embedded editor has no popup of its own. */
internal fun Component.withEditorContextMenu(): Component = apply {
    if (this is JTextComponent && componentPopupMenu == null) {
        val text = this
        componentPopupMenu = JPopupMenu().apply {
            val copy = add(JMenuItem("Copy").apply { addActionListener { text.copy() } })
            val cut = add(JMenuItem("Cut").apply { addActionListener { text.cut() } })
            val paste = add(JMenuItem("Paste").apply { addActionListener { text.paste() } })
            addSeparator()
            add(JMenuItem("Select all").apply { addActionListener { text.selectAll() } })
            addPopupMenuListener(object : PopupMenuListener {
                override fun popupMenuWillBecomeVisible(event: PopupMenuEvent) {
                    copy.isEnabled = text.isEnabled && text.selectionStart != text.selectionEnd
                    cut.isEnabled = copy.isEnabled && text.isEditable
                    paste.isEnabled = text.isEnabled && text.isEditable
                }
                override fun popupMenuWillBecomeInvisible(event: PopupMenuEvent) = Unit
                override fun popupMenuCanceled(event: PopupMenuEvent) = Unit
            })
        }
    }
    if (this is Container && containerListeners.none { it is EditorChildListener }) {
        components.forEach { it.withEditorContextMenu() }
        addContainerListener(EditorChildListener())
    }
}

private class EditorChildListener : ContainerAdapter() {
    override fun componentAdded(event: ContainerEvent) {
        event.child.withEditorContextMenu()
    }
}
