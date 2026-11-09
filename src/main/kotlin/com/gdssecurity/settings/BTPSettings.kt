package com.gdssecurity.settings

import burp.api.montoya.persistence.PersistedObject

/** One shared snapshot per extension, persisted with the Burp project. */
class BTPSettings(private val storage: PersistedObject? = null) {
    data class Options(
        val binaryAnalysis: Boolean = true,
        val reassembleMessages: Boolean = true,
        val customPaths: List<String> = emptyList(),
    ) {
        fun matchesPath(path: String?): Boolean = path != null &&
            (path == "/_blazor" || path.endsWith("/_blazor") || path in customPaths)
    }

    @Volatile
    var current = Options(
        binaryAnalysis = storage?.getBoolean("binaryAnalysis") ?: true,
        reassembleMessages = storage?.getBoolean("reassembleMessages") ?: true,
        customPaths = runCatching { parsePaths(storage?.getString("customPaths").orEmpty()) }.getOrDefault(emptyList()),
    )
        private set

    fun save(binaryAnalysis: Boolean, reassembleMessages: Boolean, customPaths: String) {
        val options = Options(binaryAnalysis, reassembleMessages, parsePaths(customPaths))
        storage?.setBoolean("binaryAnalysis", options.binaryAnalysis)
        storage?.setBoolean("reassembleMessages", options.reassembleMessages)
        storage?.setString("customPaths", options.customPaths.joinToString("\n"))
        current = options
    }

    private fun parsePaths(text: String): List<String> = text.lineSequence().map(String::trim)
        .filter(String::isNotEmpty).distinct().onEach { path ->
            require(path.startsWith('/') && !path.startsWith("//") &&
                path.none { it.isWhitespace() || it in "?#*\\" }) {
                "Use paths such as /app/hub, one per line, without a host, query, fragment or wildcard."
            }
        }.toList()
}
