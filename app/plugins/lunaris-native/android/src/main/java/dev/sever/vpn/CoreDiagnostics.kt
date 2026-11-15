package dev.sever.vpn

/** Keep only bounded, redacted process output in memory, never in Logcat. */
internal class CoreDiagnostics(sensitiveValues: Collection<String>) {
    private val secrets = sensitiveValues.filter { it.isNotEmpty() }.distinct().sortedByDescending { it.length }
    private val lines = ArrayDeque<String>()
    private var failure: String? = null

    fun redact(raw: String): String {
        var text = raw.replace(Regex("\u001b\\[[0-9;]*m"), "")
        for (secret in secrets) text = text.replace(secret, "[скрыто]")
        text = text.replace(Regex("(?i)\\b(?:https?|vless|trojan|hy2|hysteria2|socks5?)://[^\\s\"'<>]+"), "[URL скрыт]")
        text = text.replace(Regex("(?i)\\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\b"), "[UUID скрыт]")
        text = text.replace(Regex("\\b[A-Za-z0-9_+/-]{32,}={0,2}\\b"), "[ключ скрыт]")
        return text.replace(Regex("[\\p{Cntrl}&&[^\\t]]"), " ").take(600)
    }

    @Synchronized fun add(raw: String) {
        val safe = redact(raw).trim()
        if (safe.isEmpty()) return
        if (lines.size == 8) lines.removeFirst()
        lines.addLast(safe)
        val summary = Regex("(?i)^configuration (test failed|file .* test failed)$").matches(safe)
        if (!summary && Regex("(?i)fatal|error|panic|failed|invalid|denied").containsMatchIn(safe)) failure = safe
    }

    @Synchronized fun detail(): String {
        // Prefer the actual parser/runtime failure over trailing Go stack frames.
        return (failure ?: lines.lastOrNull()).orEmpty()
    }
}
