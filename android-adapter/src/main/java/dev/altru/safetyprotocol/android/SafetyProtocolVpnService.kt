package dev.altru.safetyprotocol.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

class SafetyProtocolVpnService : VpnService() {
    private lateinit var connectivityManager: ConnectivityManager
    private var tunnelInterface: ParcelFileDescriptor? = null
    private var tunnelInput: FileInputStream? = null
    private var dropThread: Thread? = null
    private val dropLoopRunning = AtomicBoolean(false)

    private val vpnNetworkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            updateOsVpnObservation(network)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                SafetyProtocolVpnRuntime.update { it.copy(osVpnTransportObserved = true) }
            }
        }

        override fun onLost(network: Network) {
            SafetyProtocolVpnRuntime.update { it.copy(osVpnTransportObserved = false) }
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(ConnectivityManager::class.java)
        SafetyProtocolVpnRuntime.reset()
        SafetyProtocolVpnRuntime.update {
            it.copy(
                serviceRunning = true,
                alwaysOn = platformAlwaysOn(),
                lockdownEnabled = platformLockdownEnabled(),
            )
        }
        registerVpnObservation()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdownCapture()
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, protectionNotification())
        establishFailClosedCapture()
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        shutdownCapture()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        shutdownCapture()
        runCatching { connectivityManager.unregisterNetworkCallback(vpnNetworkCallback) }
        SafetyProtocolVpnRuntime.update {
            it.copy(
                serviceRunning = false,
                captureEstablished = false,
                osVpnTransportObserved = false,
            )
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun establishFailClosedCapture() {
        if (tunnelInterface != null) return

        val underlyingNetwork = connectivityManager.activeNetwork
        val builder = Builder()
            .setSession(SESSION_NAME)
            .setBlocking(true)
            .setMtu(MTU)
            .addAddress(IPV4_ADDRESS, 32)
            .addRoute("0.0.0.0", 0)
            .addAddress(IPV6_ADDRESS, 128)
            .addRoute("::", 0)

        if (underlyingNetwork != null) {
            builder.setUnderlyingNetworks(arrayOf(underlyingNetwork))
        }

        val established = try {
            builder.establish()
        } catch (_: SecurityException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }

        if (established == null) {
            SafetyProtocolVpnRuntime.update { it.copy(captureEstablished = false) }
            stopSelf()
            return
        }

        tunnelInterface = established
        SafetyProtocolVpnRuntime.update {
            it.copy(
                captureEstablished = true,
                alwaysOn = platformAlwaysOn(),
                lockdownEnabled = platformLockdownEnabled(),
            )
        }
        startDropLoop(established)
    }

    private fun startDropLoop(descriptor: ParcelFileDescriptor) {
        if (!dropLoopRunning.compareAndSet(false, true)) return

        val input = FileInputStream(descriptor.fileDescriptor)
        tunnelInput = input
        dropThread = Thread({
            Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND)
            val buffer = ByteArray(PACKET_BUFFER_BYTES)
            try {
                while (dropLoopRunning.get()) {
                    val read = input.read(buffer)
                    if (read < 0) break
                }
            } catch (_: IOException) {
                // Closing the TUN descriptor is the normal shutdown path.
            } finally {
                SafetyProtocolVpnRuntime.update { it.copy(captureEstablished = false) }
            }
        }, DROP_THREAD_NAME).apply {
            isDaemon = true
            start()
        }
    }

    private fun shutdownCapture() {
        dropLoopRunning.set(false)
        runCatching { tunnelInput?.close() }
        tunnelInput = null
        runCatching { tunnelInterface?.close() }
        tunnelInterface = null
        dropThread = null
        SafetyProtocolVpnRuntime.update {
            it.copy(
                captureEstablished = false,
                osVpnTransportObserved = false,
            )
        }
    }

    private fun registerVpnObservation() {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        connectivityManager.registerNetworkCallback(request, vpnNetworkCallback)
    }

    private fun updateOsVpnObservation(network: Network) {
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            SafetyProtocolVpnRuntime.update { it.copy(osVpnTransportObserved = true) }
        }
    }

    private fun platformAlwaysOn(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) isAlwaysOn else false

    private fun platformLockdownEnabled(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) isLockdownEnabled else false

    private fun protectionNotification(): Notification {
        val notificationManager = getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "SafetyProtocol protection",
            NotificationManager.IMPORTANCE_LOW,
        )
        notificationManager.createNotificationChannel(channel)

        return Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle("SafetyProtocol protection")
            .setContentText("Fail-closed traffic capture is active")
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val ACTION_START_PROTECTED = "dev.altru.safetyprotocol.action.START_PROTECTED"
        const val ACTION_STOP = "dev.altru.safetyprotocol.action.STOP"

        private const val SESSION_NAME = "SafetyProtocol"
        private const val NOTIFICATION_CHANNEL_ID = "safetyprotocol_protection"
        private const val NOTIFICATION_ID = 5301
        private const val MTU = 1280
        private const val IPV4_ADDRESS = "10.245.0.1"
        private const val IPV6_ADDRESS = "fd7a:53af:e001::1"
        private const val PACKET_BUFFER_BYTES = 32 * 1024
        private const val DROP_THREAD_NAME = "SafetyProtocol-Drop"
    }
}
