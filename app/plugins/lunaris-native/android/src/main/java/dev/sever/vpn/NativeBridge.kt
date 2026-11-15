package dev.sever.vpn

import android.app.Activity
import android.content.*
import android.net.VpnService
import android.os.*
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

import org.json.JSONObject
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

private interface NativeResult {
    fun success(value: Any?)
    fun error(code: String, message: String, details: Any?)
    fun notImplemented() = error("unknown", "Unknown native command", null)
}
private class NativeCall(val method: String, private val args: JSONObject) {
    @Suppress("UNCHECKED_CAST")
    fun <T> argument(key: String): T? = if (args.isNull(key)) null else args.opt(key) as? T
}

/** Only permission, protected storage and Binder IPC; VPN packets stay in :vpn. */
class NativeBridge(private val activity: Activity) {
    private val context: Context = activity.applicationContext
    private var service: Messenger? = null
    private var bound = false
    private val importLinks = java.util.ArrayDeque<String>()
    private var snapshot: Map<String, Any?> = mapOf("status" to "disconnected")
    private val pendingSnapshots = mutableListOf<NativeResult>()
    private val pendingStops = mutableListOf<NativeResult>()
    private var permissionResult: NativeResult? = null
    private var pendingConfig: String? = null
    private var pendingProbe: String? = null
    private var pendingVerifyConnection = true
    private var pendingServerName: String? = null
    private val permissionRequest = VpnPermissionRequest<Intent>(
        prepare = {
            VpnService.prepare(activity)
        },
        requestPermission = { intent ->
            VpnPermissionActivity.launch(activity, intent) { granted -> onPermissionResult(granted) }
        },
        start = { startVpn() },
        finish = { code ->
            val result = permissionResult
            permissionResult = null
            pendingConfig = null
            pendingProbe = null
            pendingVerifyConnection = true
            pendingServerName = null
            if (code == null) result?.success(mapOf("status" to "connecting"))
            else result?.error(code, "VPN permission or start unavailable", null)
        },
    )
    private val handler = Handler(Looper.getMainLooper())
    private val reply = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(message: Message) {
            if (message.what != 10 && message.what != 11) return
            snapshot = message.data.keySet().associateWith { message.data.get(it) }
            pendingSnapshots.toList().forEach { it.success(snapshot) }
            pendingSnapshots.clear()
            // A queued pre-stop snapshot is not an acknowledgement of STOP.
            if (message.what == 11 && snapshot["status"] == "disconnected") completeStops()
        }
    })
    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            service = Messenger(binder)
            requestSnapshot()
        }
        override fun onServiceDisconnected(name: ComponentName) {
            service = null
            snapshot = if (pendingStops.isNotEmpty()) mapOf("status" to "disconnected")
                else mapOf("status" to "error", "error" to "VPN service process stopped")
            pendingSnapshots.toList().forEach { it.success(snapshot) }
            pendingSnapshots.clear()
            completeStops()
        }
    }

    init {
        bound = context.bindService(Intent(context, SeverVpnService::class.java), connection, Context.BIND_AUTO_CREATE)
        activity.intent?.let { acceptIntent(it) }
    }

    fun acceptIntent(intent: Intent) {
        val link = intent.dataString ?: return
        if (intent.action == Intent.ACTION_VIEW && link.startsWith("lunaris://", ignoreCase = true) && link.length <= 25000 && importLinks.size < 16) {
            importLinks.addLast(link)
            intent.data = null
        }
    }

    private fun onPermissionResult(granted: Boolean) { permissionRequest.onResult(granted) }

    fun close() {
        permissionRequest.cancel("unavailable")
        VpnPermissionActivity.cancel()
        if (bound) context.unbindService(connection)
        bound = false
        service = null
        handler.removeCallbacksAndMessages(null)
        pendingSnapshots.forEach { it.error("unavailable", "Bridge closed", null) }
        pendingSnapshots.clear()
        pendingStops.forEach { it.error("unavailable", "Bridge closed", null) }
        pendingStops.clear()
        // The foreground :vpn service keeps running after the UI is destroyed.
    }

    /** Rust calls this on a worker; Android operations always run on main. */
    fun call(method: String, arguments: String): String {
        val future = CompletableFuture<String>()
        val result = object : NativeResult {
            override fun success(value: Any?) {
                val json = JSONObject()
                json.put("ok", if (value is Map<*, *>) JSONObject(value) else value ?: JSONObject.NULL)
                future.complete(json.toString())
            }
            override fun error(code: String, message: String, details: Any?) {
                val safe = when (code) {
                    "vault_unavailable" -> "Защищённое хранилище Android недоступно."
                    "permission_denied" -> "Разрешение VPN не выдано. Проверьте режим постоянной VPN другого клиента."
                    "stop_timeout" -> "VPN-служба не подтвердила отключение. Повторите попытку."
                    else -> "Android VPN-служба недоступна. Повторите попытку."
                }
                future.complete(JSONObject().put("error", safe).toString())
            }
        }
        handler.post {
            try { onNativeCall(NativeCall(method, JSONObject(arguments)), result) }
            catch (_: Exception) { result.error("unavailable", "Native bridge unavailable", null) }
        }
        return try { future.get(120, TimeUnit.SECONDS) }
        catch (_: Exception) {
            if (method == "connect") handler.post { permissionRequest.cancel("permission_denied") }
            JSONObject().put("error", "Android VPN-служба не ответила вовремя.").toString()
        }
    }

    private fun requestSnapshot() {
        try {
            service?.send(Message.obtain(null, 1).apply { replyTo = reply })
        } catch (_: RemoteException) {
            snapshot = mapOf("status" to "error", "error" to "VPN IPC unavailable")
        }
    }

    private fun completeStops() {
        pendingStops.toList().forEach { it.success(snapshot) }
        pendingStops.clear()
    }

    private fun onNativeCall(call: NativeCall, result: NativeResult) {
        when (call.method) {
            "take_import_link" -> result.success(importLinks.pollFirst())
            "vault_encrypt", "vault_decrypt" -> {
                try {
                    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    val alias = "sever.storage.v2"
                    var key = store.getKey(alias, null) as? SecretKey
                    if (key == null) {
                        if (call.method == "vault_decrypt") throw IllegalStateException()
                        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(256).build())
                        key = generator.generateKey()
                    }
                    val bytes = Base64.decode(call.argument<String>("data"), Base64.DEFAULT)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    val output = if (call.method == "vault_encrypt") {
                        cipher.init(Cipher.ENCRYPT_MODE, key)
                        cipher.updateAAD("SEVER2".toByteArray())
                        cipher.iv + cipher.doFinal(bytes)
                    } else {
                        if (bytes.size < 28) throw IllegalStateException()
                        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
                        cipher.updateAAD("SEVER2".toByteArray())
                        cipher.doFinal(bytes.copyOfRange(12, bytes.size))
                    }
                    result.success(Base64.encodeToString(output, Base64.NO_WRAP))
                } catch (_: Exception) { result.error("vault_unavailable", "Protected storage unavailable", null) }
            }
            "snapshot" -> {
                pendingSnapshots.add(result)
                requestSnapshot()
                handler.postDelayed({
                    if (pendingSnapshots.remove(result)) result.success(mapOf("status" to "error", "error" to "VPN service did not respond"))
                }, 5000)
            }
            "connect" -> {
                val config = call.argument<String>("config")
                val probe = call.argument<String>("probe_url")
                if (config == null || probe == null || config.length > 262144 || permissionResult != null) {
                    result.error("unavailable", "VPN start is unavailable", null)
                    return
                }
                pendingConfig = config
                pendingProbe = probe
                pendingVerifyConnection = call.argument<Boolean>("verify_connection") ?: true
                pendingServerName = call.argument<String>("server_name")
                permissionResult = result
                permissionRequest.begin()
            }
            "disconnect" -> {
                permissionRequest.cancel()
                if (service == null) {
                    result.error("unavailable", "VPN service is not bound; retry stop", null)
                    return
                }
                pendingStops.add(result)
                try {
                    service!!.send(Message.obtain(null, 2).apply { replyTo = reply })
                    handler.postDelayed({
                        if (pendingStops.remove(result)) result.error("stop_timeout", "VPN stop did not complete", null)
                    }, 35000)
                } catch (_: RemoteException) {
                    pendingStops.remove(result)
                    result.error("unavailable", "VPN stop failed", null)
                }
            }
            else -> result.notImplemented()
        }
    }

    private fun startVpn() {
        val current = activity
        if (Build.VERSION.SDK_INT >= 33 &&
            current.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            current.requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 43103)
        }
        val intent = Intent(context, SeverVpnService::class.java).apply {
            action = "CONNECT"
            putExtra("config", pendingConfig)
            putExtra("probe", pendingProbe)
            putExtra("verify_connection", pendingVerifyConnection)
            putExtra("server_name", pendingServerName)
        }
        context.startForegroundService(intent)
    }

}
