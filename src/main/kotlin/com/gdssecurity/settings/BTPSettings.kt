package com.gdssecurity.settings

import burp.api.montoya.persistence.PersistedObject
import java.util.concurrent.CopyOnWriteArrayList

/** One shared snapshot per extension, persisted with the Burp project. */
class BTPSettings(private val storage: PersistedObject? = null) {
    data class Options(
        val binaryAnalysis: Boolean = true,
        val reassembleMessages: Boolean = true,
        val customPaths: List<String> = emptyList(),
        val annotateMessages: Boolean = true,
    ) {
        fun matchesPath(path: String?): Boolean = path != null &&
            (path == "/_blazor" || path.endsWith("/_blazor") || path in customPaths)
    }

    @Volatile
    var current = Options(
        binaryAnalysis = storage?.getBoolean("binaryAnalysis") ?: true,
        reassembleMessages = storage?.getBoolean("reassembleMessages") ?: true,
        customPaths = runCatching { parsePaths(storage?.getString("customPaths").orEmpty()) }.getOrDefault(emptyList()),
        annotateMessages = storage?.getBoolean("annotateMessages") ?: true,
    )
        private set

    private val listeners = CopyOnWriteArrayList<(Options) -> Unit>()

    /** Called after every successful save, on the saving thread. */
    fun addListener(listener: (Options) -> Unit) {
        listeners += listener
    }

    fun save(binaryAnalysis: Boolean, reassembleMessages: Boolean, customPaths: String, annotateMessages: Boolean) {
        val options = Options(binaryAnalysis, reassembleMessages, parsePaths(customPaths), annotateMessages)
        storage?.setBoolean("binaryAnalysis", options.binaryAnalysis)
        storage?.setBoolean("reassembleMessages", options.reassembleMessages)
        storage?.setString("customPaths", options.customPaths.joinToString("\n"))
        storage?.setBoolean("annotateMessages", options.annotateMessages)
        current = options
        listeners.forEach { it(options) }
    }

    private fun parsePaths(text: String): List<String> = text.lineSequence().map(String::trim)
        .filter(String::isNotEmpty).distinct().onEach { path ->
            require(path.startsWith('/') && !path.startsWith("//") &&
                path.none { it.isWhitespace() || it in "?#*\\" }) {
                "Use paths such as /app/hub, one per line, without a host, query, fragment or wildcard."
            }
        }.toList()
}
