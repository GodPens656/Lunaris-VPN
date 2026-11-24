package dev.sever.vpn

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.Handler
import android.os.IBinder
import android.os.Message
import android.os.Messenger
import android.os.RemoteException

/** Owns the binding to a proxy-only core for one measurement. Runs on the UI looper. */
internal class ProxyProbeBinding(private val context: Context, private val handler: Handler) {
    private var active: Session? = null
    private val cancelled = LinkedHashSet<String>()

    fun start(id: String, config: String, url: String, port: Int, mihomo: Boolean, ready: (Boolean) -> Unit) {
        if (cancelled.remove(id)) { ready(false); return }
        close()
        val type = if (mihomo) MihomoProxyProbeService::class.java else SingBoxProxyProbeService::class.java
        val session = Session(id, config, url, port, ready)
        active = session
        session.bound = runCatching {
            context.bindService(Intent(context, type), session, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        if (session.bound) handler.postDelayed(session.timeout, 24_000)
        else close()
    }

    fun stop(id: String) {
        if (active?.id == id) close()
        else {
            // A cancellation can arrive before a queued start reaches the UI looper.
            cancelled.add(id)
            if (cancelled.size > 16) cancelled.remove(cancelled.first())
        }
    }

    fun close() {
        val session = active ?: return
        active = null
        session.close()
    }

    private inner class Session(
        val id: String, config: String, url: String, port: Int, private var ready: ((Boolean) -> Unit)?,
    ) : ServiceConnection {
        var bound = false
        private var service: Messenger? = null
        private val payload = Bundle().apply {
            putString("id", id)
            putString("config", config)
            putString("probe_url", url)
            putInt("port", port)
        }
        val timeout = Runnable { if (active === this) this@ProxyProbeBinding.close() }
        private val reply = Messenger(Handler(handler.looper) { message ->
            if (active === this && message.what == READY) {
                handler.removeCallbacks(timeout)
                if (message.arg1 == 1) report(true) else this@ProxyProbeBinding.close()
            }
            true
        })

        private fun report(success: Boolean) {
            val callback = ready
            ready = null
            callback?.invoke(success)
        }

        override fun onServiceConnected(name: ComponentName, binder: IBinder) {
            if (active !== this) return
            try {
                service = Messenger(binder).also { core ->
                    core.send(Message.obtain(null, START).apply { data = payload; replyTo = reply })
                }
            } catch (_: RemoteException) { this@ProxyProbeBinding.close() }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            if (active === this) this@ProxyProbeBinding.close()
        }
        override fun onBindingDied(name: ComponentName) = onServiceDisconnected(name)
        override fun onNullBinding(name: ComponentName) = onServiceDisconnected(name)

        fun close() {
            handler.removeCallbacks(timeout)
            runCatching { service?.send(Message.obtain(null, STOP).apply { data.putString("id", id) }) }
            if (bound) context.unbindService(this)
            report(false)
        }
    }

    companion object {
        const val START = 1
        const val STOP = 2
        const val READY = 3
    }
}
