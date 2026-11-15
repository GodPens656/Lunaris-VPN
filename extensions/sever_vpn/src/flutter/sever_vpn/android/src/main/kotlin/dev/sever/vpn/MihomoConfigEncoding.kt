package dev.sever.vpn

internal object MihomoConfigEncoding {
    /** Android JSONStringer escapes '/' as '\/', which Mihomo's YAML parser rejects. */
    fun toYamlJson(json: String): String = buildString(json.length) {
        var index = 0
        while (index < json.length) {
            val current = json[index++]
            if (current == '\\' && index < json.length) {
                val escaped = json[index++]
                // Consume whole escape pairs so a literal backslash before a slash
                // is preserved. A global replacement can change the string's value.
                if (escaped != '/') append('\\')
                append(escaped)
            } else {
                append(current)
            }
        }
    }
}
