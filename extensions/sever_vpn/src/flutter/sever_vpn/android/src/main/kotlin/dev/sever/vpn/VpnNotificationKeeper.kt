package dev.sever.vpn

/** Serializes notification updates/restoration with VPN teardown. */
internal class VpnNotificationKeeper<T : Any>(
    private val show: (T) -> Unit,
    private val isVisible: () -> Boolean,
    private val nowMillis: () -> Long,
) {
    private var enabled = false
    private var latest: T? = null
    private var lastPublishedAt = 0L

    val active: Boolean
        @Synchronized get() = enabled

    @Synchronized fun start() {
        latest = null
        enabled = true
        lastPublishedAt = 0L
    }

    @Synchronized fun update(notice: T) {
        if (!enabled) return
        latest = notice
        publish(notice)
    }

    @Synchronized fun restore() {
        if (enabled) latest?.let(::publish)
    }

    @Synchronized fun checkVisibility() {
        if (!enabled || latest == null) return
        // A system/OEM may retain the record while hiding the notification in the shade.
        // Refresh periodically even when getActiveNotifications still reports it as active.
        if (nowMillis() - lastPublishedAt >= 30_000L ||
            !runCatching(isVisible).getOrDefault(false)) restore()
    }

    private fun publish(notice: T) {
        show(notice)
        // Failed posts must remain eligible for retry on the next check.
        lastPublishedAt = nowMillis()
    }

    @Synchronized fun stop() {
        enabled = false
        latest = null
        lastPublishedAt = 0L
    }
}
