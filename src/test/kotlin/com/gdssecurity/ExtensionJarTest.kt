package com.gdssecurity

import burp.api.montoya.MontoyaApi
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.net.URLClassLoader
import java.nio.file.Path
import java.util.jar.JarFile
import javax.swing.JPanel
import javax.swing.SwingUtilities

class ExtensionJarTest {
    @Test
    fun loadsAndRegistersFromTheStandaloneJarWithOnlyBurpProvidedByTheHost() {
        val artifact = Path.of(System.getProperty("btp.jar"))
        val apiJar = MontoyaApi::class.java.protectionDomain.codeSource.location
        // The platform parent deliberately cannot supply Gradle's Kotlin or library dependencies.
        URLClassLoader(arrayOf(artifact.toUri().toURL(), apiJar), ClassLoader.getPlatformClassLoader()).use { loader ->
            JarFile(artifact.toFile()).use { jar ->
                assertEquals("com.gdssecurity.BlazorTrafficProcessor", jar.manifest.mainAttributes.getValue("Main-Class"))
                assertNotNull(jar.getEntry("kotlin/jvm/internal/Intrinsics.class"))
                val entries = jar.entries().toList()
                assertTrue(entries.none { it.name.startsWith("burp/api/") })
                // Every packaged class, bundled dependencies included, must load on Burp's Java 21 runtime.
                for (entry in entries.filter { it.name.endsWith(".class") }) {
                    val header = jar.getInputStream(entry).use { it.readNBytes(8) }
                    val major = (header[6].toInt() and 0xff) shl 8 or (header[7].toInt() and 0xff)
                    assertTrue(major <= 65, "${entry.name} targets Java 22+")
                }
                for (entry in entries.filter { it.name.startsWith("com/gdssecurity/") && it.name.endsWith(".class") }) {
                    Class.forName(entry.name.replace('/', '.').removeSuffix(".class"), true, loader)
                }
            }

            val calls = mutableListOf<String>()
            val providers = mutableListOf<Any>()
            val apiType = loader.loadClass("burp.api.montoya.MontoyaApi")
            val api = stub(apiType, calls, providers)
            val entryType = loader.loadClass("com.gdssecurity.BlazorTrafficProcessor")
            val extension = entryType.getConstructor().newInstance()
            assertTrue(loader.loadClass("burp.api.montoya.BurpExtension").isInstance(extension))
            SwingUtilities.invokeAndWait {
                try {
                    entryType.getMethod("initialize", apiType).invoke(extension, api)
                    val context = loader.loadClass("burp.api.montoya.ui.editor.extension.EditorCreationContext")
                    for (provider in providers) {
                        val factory = provider.javaClass.methods.first {
                            it.name.startsWith("provide") && it.parameterCount == 1 && it.parameterTypes[0] == context
                        }
                        assertNotNull(factory.invoke(provider, stub(context, calls, providers)))
                    }
                    entryType.getMethod("extensionUnloaded").invoke(extension)
                } catch (e: InvocationTargetException) {
                    throw AssertionError(e.targetException)
                }
            }
            assertEquals(3, providers.size)
            for (registration in listOf("registerHttpRequestEditorProvider", "registerHttpResponseEditorProvider",
                "registerWebSocketMessageEditorProvider", "registerSuiteTab", "registerContextMenuItemsProvider",
                "registerUnloadingHandler")) {
                assertEquals(1, calls.count { it.endsWith(".$registration") })
            }
            assertEquals(2, calls.count { it == "Logging.logToOutput" })
            assertFalse(calls.any { it.startsWith("Proxy.") || it == "MontoyaApi.proxy" || it == "MontoyaApi.http" })
        }
    }

    private fun stub(type: Class<*>, calls: MutableList<String>, providers: MutableList<Any>): Any =
        Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { _, method, args ->
            val name = method.name
            calls += "${type.simpleName}.$name"
            if (name.startsWith("register") && name.endsWith("EditorProvider")) providers += args[0]
            val result = method.returnType
            when {
                name == "uiComponent" -> JPanel()
                result == Void.TYPE -> null
                result.isEnum -> result.enumConstants[0]
                result.isInterface -> stub(result, calls, providers)
                else -> throw AssertionError("Unexpected API call: $method")
            }
        }
}
