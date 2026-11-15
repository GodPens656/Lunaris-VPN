package dev.sever.vpn

import android.app.Activity
import android.content.*
import android.net.VpnService
import android.os.*
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.*
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Permission and IPC only. The Flutter/Python process never handles VPN packets. */
class SeverVpnPlugin : FlutterPlugin, ActivityAware, MethodChannel.MethodCallHandler,
    EventChannel.StreamHandler, PluginRegistry.ActivityResultListener, PluginRegistry.NewIntentListener {
    private lateinit var context: Context
    private lateinit var methods: MethodChannel
    private lateinit var events: EventChannel
    private var activityBinding: ActivityPluginBinding? = null
    private var service: Messenger? = null
    private var bound = false
    private var eventSink: EventChannel.EventSink? = null
    private val importLinks = java.util.ArrayDeque<String>()
    private var snapshot: Map<String, Any?> = mapOf("status" to "disconnected")
    private val pendingSnapshots = mutableListOf<MethodChannel.Result>()
    private val pendingStops = mutableListOf<MethodChannel.Result>()
    private var permissionResult: MethodChannel.Result? = null
    private var pendingConfig: String? = null
    private var pendingProbe: String? = null
    private var pendingVerifyConnection = true
    private var pendingServerName: String? = null
    private var permissionRequestCode: Int? = null
    private var nextPermissionRequestCode = 44000
    private val permissionRequest = VpnPermissionRequest<Intent>(
        prepare = {
            val current = activityBinding?.activity ?: throw IllegalStateException()
            VpnService.prepare(current)
        },
        requestPermission = { intent ->
            val current = activityBinding?.activity ?: throw IllegalStateException()
            val code = nextPermissionRequestCode
            nextPermissionRequestCode = if (code == 65535) 44000 else code + 1
            permissionRequestCode = code
            current.startActivityForResult(intent, code)
        },
        start = { startVpn() },
        finish = { code ->
            val result = permissionResult
            permissionResult = null
            permissionRequestCode = null
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
            eventSink?.success(snapshot)
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
            eventSink?.success(snapshot)
            pendingSnapshots.toList().forEach { it.success(snapshot) }
            pendingSnapshots.clear()
            completeStops()
        }
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        methods = MethodChannel(binding.binaryMessenger, "dev.sever/vpn")
        events = EventChannel(binding.binaryMessenger, "dev.sever/vpn/events")
        methods.setMethodCallHandler(this)
        events.setStreamHandler(this)
        bound = context.bindService(Intent(context, SeverVpnService::class.java), connection, Context.BIND_AUTO_CREATE)
    }

    private fun requestSnapshot() {
        try {
            service?.send(Message.obtain(null, 1).apply { replyTo = reply })
        } catch (_: RemoteException) {
            snapshot = mapOf("status" to "error", "error" to "VPN IPC unavailable")
            eventSink?.success(snapshot)
        }
    }

    private fun completeStops() {
        pendingStops.toList().forEach { it.success(snapshot) }
        pendingStops.clear()
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
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
                val activity = activityBinding?.activity
                val config = call.argument<String>("config")
                val probe = call.argument<String>("probe_url")
                if (activity == null || config == null || probe == null || config.length > 262144 || permissionResult != null) {
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
        val current = activityBinding?.activity
        if (Build.VERSION.SDK_INT >= 33 && current != null &&
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

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean {
        if (requestCode != permissionRequestCode) return false
        permissionRequest.onResult(resultCode == Activity.RESULT_OK)
        return true
    }

    override fun onListen(arguments: Any?, sink: EventChannel.EventSink) { eventSink = sink; requestSnapshot() }
    override fun onCancel(arguments: Any?) { eventSink = null }
    override fun onNewIntent(intent: Intent): Boolean {
        val link = intent.dataString ?: return false
        if (intent.action != Intent.ACTION_VIEW || !link.startsWith("lunaris://", ignoreCase = true)) return false
        if (link.length <= 25000 && importLinks.size < 16) importLinks.addLast(link)
        // Do not replay an already delivered link after an activity reattachment.
        intent.data = null
        return true
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activityBinding = binding
        binding.addActivityResultListener(this)
        binding.addOnNewIntentListener(this)
        binding.activity.intent?.let { onNewIntent(it) }
    }
    override fun onDetachedFromActivityForConfigChanges() { onDetachedFromActivity() }
    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) { onAttachedToActivity(binding) }
    override fun onDetachedFromActivity() {
        activityBinding?.removeActivityResultListener(this)
        activityBinding?.removeOnNewIntentListener(this)
        activityBinding = null
    }
    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        permissionRequest.cancel("unavailable")
        methods.setMethodCallHandler(null)
        events.setStreamHandler(null)
        if (bound) context.unbindService(connection)
        bound = false
        handler.removeCallbacksAndMessages(null)
        pendingSnapshots.forEach { it.error("unavailable", "Flutter bridge closed", null) }
        pendingSnapshots.clear()
        pendingStops.forEach { it.error("unavailable", "Flutter bridge closed", null) }
        pendingStops.clear()
        // A running foreground service remains alive after this engine is detached.
    }
}
