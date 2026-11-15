package dev.sever.vpn

/** One user-initiated VPN takeover, including Android's optional consent activity. */
internal class VpnPermissionRequest<T>(
    private val prepare: () -> T?,
    private val requestPermission: (T) -> Unit,
    private val start: () -> Unit,
    private val finish: (String?) -> Unit,
) {
    private var pending = false

    fun begin() {
        check(!pending)
        pending = true
        try {
            // Android transfers ownership here when consent was granted earlier,
            // automatically revoking the other VPN. Never cache this permission.
            val intent = prepare()
            if (intent == null) startPrepared() else requestPermission(intent)
        } catch (_: Exception) {
            complete("permission_unavailable")
        }
    }

    fun onResult(granted: Boolean) {
        if (!pending) return // The user may have cancelled the start meanwhile.
        if (!granted) {
            complete("permission_denied")
            return
        }
        try {
            // Another VPN or device policy can take ownership while the dialog
            // is open. Do not start the cores with an obsolete RESULT_OK.
            if (prepare() == null) startPrepared() else complete("permission_denied")
        } catch (_: Exception) {
            complete("permission_unavailable")
        }
    }

    fun cancel(code: String = "cancelled") { complete(code) }

    private fun startPrepared() {
        try {
            start()
            complete(null)
        } catch (_: Exception) {
            complete("unavailable")
        }
    }

    private fun complete(code: String?) {
        if (!pending) return
        pending = false
        finish(code)
    }
}
