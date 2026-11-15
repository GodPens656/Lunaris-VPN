package dev.sever.vpn

import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.concurrent.Executors

/** OS permissions, Keystore and Binder only; application logic runs in Rust. */
@TauriPlugin
class LunarisPlugin(private val activity: Activity) : Plugin(activity) {
    private val executor = Executors.newCachedThreadPool()
    private val bridge = NativeBridge(activity)

    override fun onNewIntent(intent: Intent) { bridge.acceptIntent(intent) }
    override fun onDestroy(activity: AppCompatActivity) {
        bridge.close()
        executor.shutdown()
    }

    @Command
    fun native(invoke: Invoke) {
        val args = invoke.getArgs()
        val method = args.optString("method")
        val payload = args.optJSONObject("args")?.toString() ?: "{}"
        executor.execute {
            try {
                if (method == "storage_directory") {
                    val root = activity.filesDir
                    val candidates = listOf(java.io.File(root, "sever"),
                        java.io.File(root.parentFile, "app_flutter/sever"),
                        java.io.File(root, "flet/sever"))
                    val directory = candidates.firstOrNull { java.io.File(it, "state.enc").isFile } ?: candidates.first()
                    invoke.resolve(JSObject().put("ok", directory.absolutePath))
                } else {
                    invoke.resolve(JSObject(bridge.call(method, payload)))
                }
            } catch (_: Exception) {
                invoke.reject("Не удалось выполнить системную операцию Android.")
            }
        }
    }
}
