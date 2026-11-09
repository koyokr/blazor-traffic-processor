package com.gdssecurity.settings

import burp.api.montoya.persistence.PersistedObject
import com.gdssecurity.views.BTPSettingsView
import java.awt.Container
import java.lang.reflect.Proxy
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JTextArea
import javax.swing.SwingUtilities
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class BTPSettingsTest {
    @Test
    fun persistsOptionsAndRejectsInvalidPathsWithoutChangingSavedSettings() {
        val values = mutableMapOf<String, Any>()
        val storage = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(PersistedObject::class.java)) { _, method, args ->
            when (method.name) {
                "getBoolean", "getString" -> values[args[0]]
                "setBoolean", "setString" -> { values[args[0] as String] = args[1]; null }
                else -> error(method)
            }
        } as PersistedObject
        val settings = BTPSettings(storage)
        assertTrue(settings.current.binaryAnalysis)
        assertTrue(settings.current.reassembleMessages)
        settings.save(false, false, " /app/hub \n/app/hub\n/한글\n")
        assertEquals(listOf("/app/hub", "/한글"), settings.current.customPaths)
        assertEquals(settings.current, BTPSettings(storage).current)
        val before = settings.current
        for (invalid in listOf("https://example.test/hub", "//example.test", "/hub?q=1", "/hub#x", "/hub/*", "/a b")) {
            assertThrows(IllegalArgumentException::class.java) { settings.save(true, true, invalid) }
            assertEquals(before, settings.current)
            assertEquals(before, BTPSettings(storage).current)
        }
        assertTrue(before.matchesPath("/_blazor"))
        assertTrue(before.matchesPath("/app/_blazor"))
        assertTrue(before.matchesPath("/app/hub"))
        assertFalse(before.matchesPath("/App/hub"))
        assertFalse(before.matchesPath("/app/hub/extra"))
        assertFalse(before.matchesPath(null))
    }

    @Test
    fun settingsFormAppliesAllThreeOptions() {
        SwingUtilities.invokeAndWait {
            val settings = BTPSettings()
            val view = BTPSettingsView(settings)
            fun children(container: Container): List<java.awt.Component> = container.components.flatMap {
                listOf(it) + if (it is Container) children(it) else emptyList()
            }
            val controls = children(view)
            val apply = controls.filterIsInstance<JButton>().single { it.text == "Apply" }
            assertFalse(apply.isEnabled)
            controls.filterIsInstance<JCheckBox>().forEach { it.doClick() }
            controls.filterIsInstance<JTextArea>().single().text = "/custom/hub"
            assertTrue(apply.isEnabled)
            apply.doClick()
            assertEquals(BTPSettings.Options(false, false, listOf("/custom/hub")), settings.current)
            assertFalse(apply.isEnabled)
        }
    }
}
