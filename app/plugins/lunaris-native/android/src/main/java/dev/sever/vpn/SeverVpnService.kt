package dev.sever.vpn

import android.app.*
import android.content.Intent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.*
import android.os.*
import android.system.OsConstants
import go.Seq
import io.nekohasekai.libbox.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface as JavaInterface
import java.net.URL
import java.net.URLEncoder
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.Collections

/** Independent :vpn process: TUN, network changes, health checks and traffic counters. */
open class SeverVpnService(private val proxyOnly: Boolean = false) : VpnService(), PlatformInterface, CommandServerHandler {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val serial = Mutex()
    private var command: CommandServer? = null
    private var xray: java.lang.Process? = null
    private var xrayLogs: Job? = null
    @Volatile private var mihomoActive = false
    private var tun: ParcelFileDescriptor? = null
    private var network: Network? = null
    private var interfaceListener: InterfaceUpdateListener? = null
    private lateinit var connectivity: ConnectivityManager
    @Volatile private var state = "disconnected"
    @Volatile private var serverName = ""
    @Volatile private var initializing = false
    @Volatile private var error: String? = null
    private var upload = 0L
    private var download = 0L
    private var started = 0L
    private var apiPort = 0
    private var apiSecret = ""
    private var probeUrl = ""
    private var verifyConnection = true
    private var poll: Job? = null
    private var startup: Job? = null
    private var proxyProbeId: String? = null
    private var notificationMonitor: Job? = null
    private var wakeReceiverRegistered = false
    @Volatile private var stopping = false
    @Volatile private var apiConnection: HttpURLConnection? = null
    private var networkRegistered = false
    private val subscribers = mutableSetOf<Messenger>()
    private val main = Handler(Looper.getMainLooper())
    private val notifications = VpnNotificationKeeper<android.app.Notification>(
        show = { notice ->
            if (Build.VERSION.SDK_INT >= 34)
                startForeground(NOTIFICATION_ID, notice, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            else startForeground(NOTIFICATION_ID, notice)
            // Publish explicitly as well: foreground registration alone is not a visibility check.
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notice)
        },
        isVisible = {
            getSystemService(NotificationManager::class.java).activeNotifications.any { it.id == NOTIFICATION_ID }
        },
        nowMillis = { SystemClock.elapsedRealtime() }, // Includes time spent in deep sleep.
    )
    private val wakeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (intent.action == Intent.ACTION_SCREEN_ON || intent.action == Intent.ACTION_USER_PRESENT) {
                // Do not wait for the delayed timer when the device wakes from Doze/deep sleep.
                scope.launch { runCatching { notifications.restore() } }
            }
        }
    }
    private val messenger = Messenger(object : Handler(Looper.getMainLooper()) {
        override fun handleMessage(msg: Message) {
            if (proxyOnly) {
                if (msg.what == ProxyProbeBinding.START) startProxyProbe(msg)
                if (msg.what == ProxyProbeBinding.STOP && msg.data.getString("id") == proxyProbeId) startup?.cancel()
                return
            }
            msg.replyTo?.let { subscribers.add(it) }
            if (msg.what == 2) requestStop(msg.replyTo)
            else broadcast()
        }
    })

    override fun onCreate() {
        super.onCreate()
        connectivity = getSystemService(ConnectivityManager::class.java)
        if (proxyOnly) return
        if (this is MihomoVpnService) File(filesDir, "mihomo-core/config.yaml").delete()
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel("sever-vpn", "Lunaris client", NotificationManager.IMPORTANCE_LOW))
        val wakeFilter = IntentFilter(Intent.ACTION_SCREEN_ON).apply { addAction(Intent.ACTION_USER_PRESENT) }
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(wakeReceiver, wakeFilter, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(wakeReceiver, wakeFilter)
        wakeReceiverRegistered = true
    }

    override fun onBind(intent: Intent): IBinder? {
        return if (intent.action == SERVICE_INTERFACE) super.onBind(intent) else messenger.binder
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (proxyOnly) { stopSelfResult(startId); return START_NOT_STICKY }
        if (intent?.action == RESTORE_NOTIFICATION) {
            notifications.restore()
            // A late dismissal must never restart a stopped VPN or leave an idle service.
            if (!notifications.active) stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (intent?.action == "STOP") { requestStop(); return START_NOT_STICKY }
        if (intent?.action != "CONNECT") { stopSelf(); return START_NOT_STICKY }
        if (initializing || hasCore() || state == "disconnecting") return START_NOT_STICKY
        initializing = true
        stopping = false
        notifications.start()
        serverName = intent.getStringExtra("server_name")?.trim().orEmpty()
        foreground("Подключается…") // Before potentially slow native initialization.
        notificationMonitor?.cancel()
        notificationMonitor = scope.launch {
            // Independent of both the UI looper and potentially slow core API requests.
            while (isActive && notifications.active) {
                delay(2000)
                runCatching { notifications.checkVisibility() }
            }
        }
        val config = intent.getStringExtra("config")
        val probe = intent.getStringExtra("probe")
        if (config == null || probe == null) { scope.launch { fail("VPN configuration is missing") }; return START_NOT_STICKY }
        state = "connecting"
        error = null
        broadcast()
        startup = scope.launch {
            serial.withLock {
                ensureActive()
                if (hasCore()) { return@withLock }
                var startupStep = "Не удалось подготовить конфигурацию Android VPN."
                try {
                    if (prepare(this@SeverVpnService) != null)
                        throw ProbeFailure("Android не предоставил разрешение VPN. Разрешите подключение и повторите запуск.")
                    val doc = JSONObject(config)
                    val mihomoConfig = doc.optJSONObject("sever_mihomo")
                    check((this@SeverVpnService is MihomoVpnService) == (mihomoConfig != null))
                    probeUrl = probe
                    verifyConnection = intent.getBooleanExtra("verify_connection", true)
                    if (mihomoConfig != null) {
                        startupStep = "Не удалось создать VPN-туннель FlClashCore."
                        startMihomo(mihomoConfig)
                    } else {
                        if (doc.has("sever_xray")) {
                            startupStep = "Не удалось запустить Xray на Android."
                            startXrayBridge(doc)
                        }
                        startupStep = "Не удалось создать Android VPN-туннель sing-box. Проверьте разрешение VPN."
                        startSingBox(doc)
                    }
                    ensureActive()
                    if (tun == null) throw IllegalStateException()
                    probeConnection()
                    ensureActive()
                    upload = 0; download = 0
                    started = SystemClock.elapsedRealtime()
                    state = "connected"
                    initializing = false
                    foreground("Подключено")
                    broadcast()
                    poll = scope.launch {
                        var failures = 0
                        while (isActive) {
                            delay(1000)
                            if (xray?.isAlive == false) { fail("Xray exited; VPN was stopped"); break }
                            try {
                                if (mihomoActive) {
                                    val (up, down) = MihomoNative.traffic()
                                    upload = up; download = down
                                } else {
                                    val counters = api("/connections")
                                    upload = counters.getLong("uploadTotal")
                                    download = counters.getLong("downloadTotal")
                                }
                                failures = 0
                                broadcast()
                            } catch (_: Exception) {
                                if (!isActive) break
                                if (++failures >= 3) { fail("Connection to native core was lost"); break }
                            }
                            if (state == "connecting" && network != null) {
                                runCatching {
                                    probeConnection()
                                    if (network != null && hasCore()) {
                                        state = "connected"; foreground("Подключено"); broadcast()
                                    }
                                }
                            }
                        }
                    }
                } catch (cancelled: CancellationException) {
                    cleanup()
                    throw cancelled
                } catch (failure: ProbeFailure) { if (!stopping) failLocked(failure.safeMessage) }
                catch (_: Exception) { if (!stopping) failLocked(startupStep) }
                catch (_: LinkageError) { if (!stopping) failLocked(startupStep) }
            }
        }
        return START_NOT_STICKY // No plaintext config is persisted for automatic restart.
    }

    private fun foreground(label: String) {
        val text = if (serverName.isBlank()) label else "$label: $serverName"
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val open = launch?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT) }
        val stop = PendingIntent.getService(this, 1, Intent(this, javaClass).setAction("STOP"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val restore = PendingIntent.getService(this, 2,
            Intent(this, javaClass).setAction(RESTORE_NOTIFICATION),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notice = android.app.Notification.Builder(this, "sever-vpn")
            .setSmallIcon(android.R.drawable.ic_lock_lock).setContentTitle("Lunaris client").setContentText(text)
            .setStyle(android.app.Notification.BigTextStyle().bigText(text))
            .setOngoing(true).setOnlyAlertOnce(true).setDeleteIntent(restore)
            .setContentIntent(open).addAction(android.app.Notification.Action.Builder(null, "Отключить", stop).build())
            .apply {
                if (Build.VERSION.SDK_INT >= 31) setForegroundServiceBehavior(android.app.Notification.FOREGROUND_SERVICE_IMMEDIATE)
            }.build()
        notifications.update(notice)
    }

    private fun api(path: String): JSONObject {
        val conn = URL("http://127.0.0.1:$apiPort$path").openConnection() as HttpURLConnection
        apiConnection = conn
        conn.setRequestProperty("Authorization", "Bearer $apiSecret")
        conn.connectTimeout = 12000; conn.readTimeout = 12000
        try {
            if (conn.responseCode != 200) throw IllegalStateException()
            return conn.inputStream.bufferedReader().use { JSONObject(it.readText()) }
        } finally {
            conn.disconnect()
            if (apiConnection === conn) apiConnection = null
        }
    }

    private class ProbeFailure(val safeMessage: String) : Exception()

    private fun probeConnection() {
        if (!verifyConnection) {
            // Still require a responsive core, including after a network change.
            api("/version")
            return
        }
        // URL-test dials the selected outbound directly. A SOCKS sidecar can
        // resolve its hostname remotely even while the TUN's DNS is broken.
        // Exercise sing-box's configured DNS (the same resolver as hijack-dns)
        // as well, before reporting a usable connection.
        val host = URL(probeUrl).host
        val numericHost = host.contains(':') || host.split('.').let { parts ->
            parts.size == 4 && parts.all { part -> part.toIntOrNull()?.let { it in 0..255 } == true }
        }
        // A user-supplied literal-IP probe does not need DNS resolution.
        if (!numericHost) {
            val dns = try {
                api("/dns/query?type=A&name=" + URLEncoder.encode(host, "UTF-8"))
            } catch (_: Exception) {
                throw ProbeFailure("DNS через VPN не отвечает. Проверьте DNS в настройках и доступность VPN-сервера.")
            }
            val answers = dns.optJSONArray("Answer")
            if (dns.optInt("Status", -1) != 0 || answers == null ||
                (0 until answers.length()).none { answers.getJSONObject(it).optInt("type") == 1 }) {
                throw ProbeFailure("DNS через VPN не вернул адрес сайта проверки.")
            }
        }
        val passed = try {
            if (mihomoActive) MihomoNative.checkProxy(probeUrl)
            else api("/proxies/proxy/delay?timeout=10000&url=" + URLEncoder.encode(probeUrl, "UTF-8")).has("delay")
        } catch (_: Exception) {
            throw ProbeFailure("HTTPS через VPN недоступен. Проверьте сервер и адрес проверки соединения.")
        }
        if (!passed) throw ProbeFailure("HTTPS-проверка VPN не завершилась.")
    }

    private fun startProxyProbe(message: Message) {
        val id = message.data.getString("id") ?: return
        val config = message.data.getString("config") ?: return
        val url = message.data.getString("probe_url") ?: return
        val port = message.data.getInt("port")
        val reply = message.replyTo ?: return
        fun report(ready: Boolean) {
            runCatching { reply.send(Message.obtain(null, ProxyProbeBinding.READY, if (ready) 1 else 0, 0)) }
        }
        startup?.cancel()
        proxyProbeId = id
        startup = scope.launch {
            // An immediately rebound service must wait for the previous instance's cleanup.
            proxyCore.withLock {
                try {
                    withTimeout(30_000) {
                        val doc = JSONObject(config)
                        val mihomo = doc.optJSONObject("sever_mihomo")
                        check((this@SeverVpnService is MihomoProxyProbeService) == (mihomo != null))
                        if (mihomo != null) {
                            mihomoActive = true
                            MihomoNative.configure(File(filesDir, "probe-mh"), mihomo, url)
                        } else {
                            startXrayBridge(doc)
                            startSingBox(doc)
                        }
                        ensureActive()
                        Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 500) }
                        report(true)
                        awaitCancellation()
                    }
                } catch (_: TimeoutCancellationException) {
                    report(false)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    report(false)
                } catch (_: LinkageError) {
                    report(false)
                } finally {
                    cleanup()
                }
            }
        }
    }

    private suspend fun startXrayBridge(doc: JSONObject) {
        val config = doc.remove("sever_xray") as? JSONObject ?: return
        val port = ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }
        config.getJSONArray("inbounds").getJSONObject(0).put("port", port)
        doc.getJSONArray("outbounds").getJSONObject(0).put("server_port", port)
        startXray(config.toString(), port)
    }

    private suspend fun startXray(config: String, port: Int) {
        // An executable in nativeLibraryDir is permitted by Android 10+ W^X policy.
        // Keep it in a separate process: libbox and Xray each embed a Go runtime.
        val executable = File(applicationInfo.nativeLibraryDir, "libxray.so")
        if (!executable.canExecute()) throw IllegalStateException("Xray is missing for this ABI")
        val version = ProcessBuilder(executable.absolutePath, "version").redirectErrorStream(true).start()
        try {
            check(runInterruptible { version.waitFor(10, TimeUnit.SECONDS) })
            check(version.exitValue() == 0 && version.inputStream.bufferedReader().use { it.readText() }.startsWith("Xray 26.11.9 "))
        } finally {
            if (version.isAlive) version.destroyForcibly()
        }
        val process = ProcessBuilder(executable.absolutePath, "run", "-c", "stdin:")
            .redirectErrorStream(true).start()
        xray = process
        xrayLogs = scope.launch {
            // Drain without retaining credentials or forwarding raw logs to Logcat.
            runCatching { process.inputStream.bufferedReader().use { while (it.readLine() != null) { } } }
        }
        process.outputStream.use { it.write(config.toByteArray(Charsets.UTF_8)) }
        repeat(80) {
            if (!process.isAlive) throw IllegalStateException()
            if (runCatching { Socket().use { it.connect(java.net.InetSocketAddress("127.0.0.1", port), 100) }; true }.getOrDefault(false)) return
            delay(50)
        }
        throw IllegalStateException()
    }

    private fun hasCore() = command != null || mihomoActive

    private fun startSingBox(doc: JSONObject) {
        val nativeConfig = doc.toString()
        val api = doc.getJSONObject("experimental").getJSONObject("clash_api")
        apiPort = api.getString("external_controller").substringAfterLast(':').toInt()
        apiSecret = api.getString("secret")
        Seq.setContext(applicationContext)
        val base = File(filesDir, if (proxyOnly) "probe-sb" else "native-core").apply { mkdirs() }
        Libbox.setup(SetupOptions().apply {
            basePath = base.absolutePath
            workingPath = base.absolutePath
            tempPath = cacheDir.absolutePath
            fixAndroidStack = true
            logMaxLines = 0
            debug = false
        })
        check(Libbox.version() == "1.14.4")
        Libbox.checkConfig(nativeConfig)
        if (!proxyOnly) registerNetwork()
        val server = CommandServer(this, this)
        command = server
        server.start()
        server.startOrReloadService(nativeConfig, OverrideOptions())
    }

    private fun startMihomo(config: JSONObject) {
        apiPort = config.getString("external-controller").substringAfterLast(':').toInt()
        apiSecret = config.getString("secret")
        val home = File(filesDir, "mihomo-core")
        mihomoActive = true
        MihomoNative.configure(home, config, probeUrl)
        registerNetwork()
        val dns = "172.19.0.2"
        val addresses = mutableListOf("172.19.0.1/30")
        val builder = Builder().setSession("Lunaris client").setMtu(1500)
            .addAddress("172.19.0.1", 30).addDnsServer(dns)
            .addRoute("0.0.0.0", 0).addRoute("::", 0)
            .setUnderlyingNetworks(network?.let { arrayOf(it) })
        if (config.optBoolean("ipv6")) {
            builder.addAddress("fdfe:dcba:9876::1", 126)
            addresses += "fdfe:dcba:9876::1/126"
        }
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        val descriptor = checkNotNull(builder.establish())
        tun = descriptor
        MihomoNative.attach(this, descriptor, addresses, dns)
    }

    private fun resetCoreNetwork() {
        if (mihomoActive) MihomoNative.resetNetwork() else command?.resetNetwork()
    }

    private fun snapshot(): Bundle = Bundle().apply {
        putString("status", state)
        putBoolean("mihomo", this@SeverVpnService is MihomoVpnService)
        error?.let { putString("error", it) }
        putLong("upload", upload); putLong("download", download)
        putLong("duration", if (started > 0 && state == "connected") (SystemClock.elapsedRealtime() - started) / 1000 else 0)
    }
    private fun broadcast() { main.post {
        val message = snapshot()
        subscribers.toList().forEach { subscriber ->
            try { subscriber.send(Message.obtain(null, 10).apply { data = message }) }
            catch (_: RemoteException) { subscribers.remove(subscriber) }
        }
    } }

    private fun requestStop(requester: Messenger? = null) {
        stopping = true
        stopNotificationRecovery()
        state = "disconnecting"; broadcast()
        startup?.cancel()
        runCatching { apiConnection?.disconnect() }
        scope.launch {
            stopVpn()
            requester?.let { target -> main.post {
                runCatching { target.send(Message.obtain(null, 11).apply { data = snapshot() }) }
            } }
        }
    }
    private suspend fun stopVpn() { serial.withLock {
        state = "disconnecting"; broadcast()
        cleanup()
        state = "disconnected"; error = null; broadcast()
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    } }
    private suspend fun fail(message: String) { serial.withLock { failLocked(message) } }
    private fun failLocked(message: String) {
        cleanup()
        state = "error"; error = message; broadcast()
        stopForeground(STOP_FOREGROUND_REMOVE); stopSelf()
    }
    private fun cleanup() {
        stopNotificationRecovery()
        poll?.cancel(); poll = null
        runCatching { apiConnection?.disconnect() }; apiConnection = null
        if (networkRegistered) runCatching { connectivity.unregisterNetworkCallback(networkCallback) }
        networkRegistered = false
        // Release Android's descriptor before waiting for native workers, as
        // the upstream Android client does. libbox owns its duplicated fd.
        runCatching { tun?.close() }; tun = null
        val server = command
        command = null
        runCatching { server?.closeService() }
        runCatching { server?.close() }
        if (mihomoActive) {
            mihomoActive = false
            runCatching { MihomoNative.stop(proxyOnly) }
        }
        xray?.let { process ->
            runCatching {
                process.destroy()
                if (!process.waitFor(3, TimeUnit.SECONDS)) {
                    process.destroyForcibly()
                    process.waitFor(3, TimeUnit.SECONDS)
                }
            }
        }
        xray = null
        xrayLogs?.cancel(); xrayLogs = null
        network = null; interfaceListener = null
        if (!proxyOnly) runCatching { setUnderlyingNetworks(null) }
        apiSecret = ""; started = 0
        initializing = false
    }
    private fun stopNotificationRecovery() {
        notifications.stop()
        notificationMonitor?.cancel()
        notificationMonitor = null
    }

    private companion object {
        const val NOTIFICATION_ID = 4001
        const val RESTORE_NOTIFICATION = "dev.sever.vpn.RESTORE_NOTIFICATION"
        val proxyCore = Mutex()
    }
    override fun onRevoke() {
        if (proxyOnly) { main.post { startup?.cancel() }; return }
        // Android has switched to another VPN (or the user disconnected in
        // Settings). Cancel startup/probes immediately and release our session
        // normally, so the next tap can take ownership back through prepare().
        main.post { requestStop() }
    }
    override fun onDestroy() {
        if (proxyOnly) {
            scope.cancel()
            super.onDestroy()
            return
        }
        cleanup()
        if (wakeReceiverRegistered) runCatching { unregisterReceiver(wakeReceiver) }
        wakeReceiverRegistered = false
        scope.cancel()
        if (state != "error") state = "disconnected"
        broadcast()
        super.onDestroy()
    }
    override fun onTaskRemoved(rootIntent: Intent?) { /* Foreground service survives UI task removal. */ }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(next: Network) {
            if (!networkRegistered || stopping) return
            val changed = network != next
            network = next
            if (changed && state == "connected") { state = "connecting"; foreground("Проверяем новую сеть…"); broadcast() }
            updateInterface()
            if (changed && !initializing) resetCoreNetwork()
        }
        override fun onLinkPropertiesChanged(next: Network, properties: LinkProperties) {
            if (networkRegistered && !stopping && network == next) updateInterface()
        }
        override fun onLost(lost: Network) {
            if (!networkRegistered || stopping) return
            if (network == lost) {
                network = null; setUnderlyingNetworks(null); updateInterface(); resetCoreNetwork()
                if (state == "connected") { state = "connecting"; foreground("Ожидаем сеть…"); broadcast() }
            }
        }
        override fun onCapabilitiesChanged(next: Network, caps: NetworkCapabilities) {
            if (networkRegistered && !stopping && network == next) updateInterface()
        }
    }
    private fun registerNetwork() {
        networkRegistered = true
        connectivity.requestNetwork(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), networkCallback)
        // Seed a physical network before the asynchronous callback arrives.
        fun physical(candidate: Network): Boolean {
            val caps = connectivity.getNetworkCapabilities(candidate) ?: return false
            return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        network = connectivity.activeNetwork?.takeIf(::physical) ?: connectivity.allNetworks
            .filter(::physical).maxByOrNull {
                if (connectivity.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true) 1 else 0
            }
    }
    private fun updateInterface() {
        val current = network
        val props = current?.let { connectivity.getLinkProperties(it) }
        val name = props?.interfaceName ?: ""
        val index = if (name.isNotEmpty()) runCatching { JavaInterface.getByName(name)?.index ?: -1 }.getOrDefault(-1) else -1
        if (!proxyOnly) setUnderlyingNetworks(current?.let { arrayOf(it) })
        interfaceListener?.updateDefaultInterface(name, index, current?.let { connectivity.getNetworkCapabilities(it)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false } ?: false, false)
    }

    override fun usePlatformAutoDetectInterfaceControl() = !proxyOnly
    override fun autoDetectInterfaceControl(fd: Int) { if (!protect(fd)) throw IllegalStateException() }
    override fun openTun(options: TunOptions): Int {
        check(!proxyOnly)
        if (prepare(this) != null) throw IllegalStateException()
        val builder = Builder().setSession("Lunaris client").setMtu(options.mtu)
        // Child cores cannot call VpnService.protect themselves. Excluding
        // this app's UID keeps its physical TCP/DNS sockets outside the tunnel.
        if (xray != null) builder.addDisallowedApplication(packageName)
        if (Build.VERSION.SDK_INT >= 29) builder.setMetered(false)
        val addresses4 = options.inet4Address
        var has4 = false
        while (addresses4.hasNext()) { val p = addresses4.next(); builder.addAddress(p.address(), p.prefix()); has4 = true }
        val addresses6 = options.inet6Address
        var has6 = false
        while (addresses6.hasNext()) { val p = addresses6.next(); builder.addAddress(p.address(), p.prefix()); has6 = true }
        if (has4) builder.addRoute("0.0.0.0", 0)
        if (has6) builder.addRoute("::", 0)
        if (!has6) builder.addRoute("::", 0) // Capture and reject IPv6 rather than bypassing the VPN.
        if (options.dnsMode.value != Libbox.DNSModeDisabled) {
            val dns = options.dnsServerAddress
            while (dns.hasNext()) builder.addDnsServer(dns.next())
        }
        tun = builder.establish() ?: throw IllegalStateException()
        return tun!!.fd
    }
    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener) { interfaceListener = listener; updateInterface() }
    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener) { interfaceListener = null }
    override fun getInterfaces(): NetworkInterfaceIterator {
        val values = connectivity.allNetworks.mapNotNull { n ->
            val caps = connectivity.getNetworkCapabilities(n) ?: return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return@mapNotNull null
            val props = connectivity.getLinkProperties(n) ?: return@mapNotNull null
            val j = JavaInterface.getByName(props.interfaceName) ?: return@mapNotNull null
            io.nekohasekai.libbox.NetworkInterface().apply {
                name = j.name; index = j.index; mtu = if (props.mtu > 0) props.mtu else j.mtu
                flags = OsConstants.IFF_UP or OsConstants.IFF_RUNNING or if (j.isLoopback) OsConstants.IFF_LOOPBACK else 0
                addresses = Strings(props.linkAddresses.map { it.toString() })
                dnsServer = Strings(props.dnsServers.mapNotNull { it.hostAddress })
                type = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    else -> Libbox.InterfaceTypeOther
                }
                metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }
        }.iterator()
        return object : NetworkInterfaceIterator {
            override fun hasNext() = values.hasNext()
            override fun next() = values.next()
        }
    }
    private class Strings(values: List<String>) : StringIterator {
        private val iterator = values.iterator()
        private val size = values.size
        override fun hasNext() = iterator.hasNext()
        override fun next() = iterator.next()
        override fun len() = size
    }
    override fun localDNSTransport(): LocalDNSTransport = object : LocalDNSTransport {
        override fun raw() = false
        override fun exchange(ctx: ExchangeContext, message: ByteArray) { ctx.errorCode(2) }
        override fun lookup(ctx: ExchangeContext, name: String, family: String) {
            try {
                val physical = network ?: throw IllegalStateException()
                val addresses = physical.getAllByName(name).filter { family != "ip4" || it is Inet4Address }.filter { family != "ip6" || it is Inet6Address }
                ctx.success(addresses.joinToString("\n") { it.hostAddress ?: "" })
            } catch (_: Exception) { ctx.errorCode(2) }
        }
    }
    override fun findConnectionOwner(protocol: Int, source: String, sourcePort: Int, dest: String, destPort: Int): ConnectionOwner = throw UnsupportedOperationException()
    override fun underNetworkExtension() = false
    override fun includeAllNetworks() = false
    override fun readWIFIState(): WIFIState = Libbox.newWIFIState("", "")
    override fun clearDNSCache() {}
    override fun sendNotification(notification: io.nekohasekai.libbox.Notification) {}
    override fun cancelNotification(identifier: String, typeID: Int) {}
    override fun startNeighborMonitor(listener: NeighborUpdateListener) {}
    override fun closeNeighborMonitor(listener: NeighborUpdateListener) {}
    override fun registerMyInterface(name: String) {}
    override fun usePlatformShell() = false
    override fun checkPlatformShell() { throw UnsupportedOperationException() }
    override fun openShellSession(user: PlatformUser, command: String, environ: StringIterator, term: String, rows: Int, cols: Int): ShellSession = throw UnsupportedOperationException()
    override fun lookupUser(username: String): PlatformUser = throw UnsupportedOperationException()
    override fun lookupSFTPServer(): String = throw UnsupportedOperationException()
    override fun readSystemSSHHostKey(): String = throw UnsupportedOperationException()
    override fun tailscaleHostname() = "Lunaris"
    override fun usePlatformBridge() = false
    override fun createBridge(options: BridgeOptions): BridgeSession = throw UnsupportedOperationException()
    override fun serviceStop() { requestStop() }
    override fun serviceReload() { throw UnsupportedOperationException() }
    override fun getSystemProxyStatus() = SystemProxyStatus()
    override fun setSystemProxyEnabled(enabled: Boolean) { throw UnsupportedOperationException() }
    override fun triggerNativeCrash() { throw UnsupportedOperationException() }
    override fun writeDebugMessage(message: String?) { /* Secrets must never reach Logcat. */ }
    override fun connectSSHAgent() = -1
}

/** Separate Go runtime and lifecycle for the FlClash VPN core. */
class MihomoVpnService : SeverVpnService()
class SingBoxProxyProbeService : SeverVpnService(proxyOnly = true)
class MihomoProxyProbeService : SeverVpnService(proxyOnly = true)
