package dev.sever.vpn

import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Calls the FlClash Go core inside the dedicated Mihomo VPN service process. */
internal object MihomoNative {
    init { System.loadLibrary("lunaris_mihomo") }

    private external fun invoke(request: ByteArray): ByteArray?
    private external fun startTun(service: VpnService, fd: Int, addresses: String, dns: String): Boolean
    private external fun stopTun()
    external fun resetNetwork()

    private fun request(method: String, arguments: Any = JSONObject.NULL): Any {
        val id = UUID.randomUUID().toString()
        val message = JSONObject().put("id", id).put("method", method).put("arguments", arguments)
        val reply = invoke(message.toString().encodeToByteArray()) ?: error("FlClashCore did not respond")
        val result = JSONObject(reply.decodeToString())
        check(result.getString("id") == id && result.isNull("error") && result.has("result"))
        return result.get("result")
    }

    fun configure(home: File, config: JSONObject, probeUrl: String) {
        check(home.isDirectory || home.mkdirs())
        val file = File(home, "config.yaml")
        try {
            file.writeText(MihomoConfigEncoding.toYamlJson(config.toString()))
            request("core.init", JSONObject().put("home-dir", home.absolutePath).put("version", android.os.Build.VERSION.SDK_INT))
            request("config.setup", JSONObject().put("selected-map", JSONObject())
                .put("options", JSONObject().put("test-url", probeUrl)))
            request("traffic.reset")
        } finally {
            file.delete()
        }
    }

    fun attach(service: VpnService, descriptor: ParcelFileDescriptor, addresses: List<String>, dns: String) {
        val fd = ParcelFileDescriptor.dup(descriptor.fileDescriptor).detachFd()
        check(startTun(service, fd, addresses.joinToString(","), dns))
    }

    fun traffic(): Pair<Long, Long> {
        val counters = request("traffic.total", JSONObject().put("only-proxy", false)) as JSONObject
        return counters.getLong("up") to counters.getLong("down")
    }

    fun checkProxy(url: String): Boolean {
        val result = request("proxy.testDelay", JSONObject().put("proxy-name", "proxy")
            .put("test-url", url).put("timeout", 10000)) as? JSONObject
        return (result?.optInt("value") ?: 0) > 0
    }

    fun stop(proxyOnly: Boolean = false) {
        if (!proxyOnly) stopTun()
        try {
            request("connection.closeAll")
        } finally {
            val changes = JSONObject().put("external-controller", "").put("secret", "")
            if (proxyOnly) changes.put("mixed-port", 0)
            request("config.update", changes)
        }
    }
}
