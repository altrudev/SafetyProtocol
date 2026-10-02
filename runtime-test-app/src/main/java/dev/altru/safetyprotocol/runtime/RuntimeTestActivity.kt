package dev.altru.safetyprotocol.runtime

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import dev.altru.safetyprotocol.android.SafetyProtocolVpnRuntime
import dev.altru.safetyprotocol.android.SafetyProtocolVpnService
import java.net.InetSocketAddress
import java.net.Socket

class RuntimeTestActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Thread { runSmokeTest() }.start()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST && resultCode == RESULT_OK) {
            Thread { startCaptureAndVerify(preProbe = probeHost()) }.start()
        } else if (requestCode == VPN_REQUEST) {
            Log.e(TAG, "RUNTIME_RESULT consent=false")
        }
    }

    private fun runSmokeTest() {
        val before = probeHost()
        Log.i(TAG, "PRE_PROBE success=$before")

        runOnUiThread {
            val preparation = VpnService.prepare(this)
            if (preparation == null) {
                Thread { startCaptureAndVerify(before) }.start()
            } else {
                startActivityForResult(preparation, VPN_REQUEST)
            }
        }
    }

    private fun startCaptureAndVerify(preProbe: Boolean) {
        val intent = Intent(this, SafetyProtocolVpnService::class.java)
            .setAction(SafetyProtocolVpnService.ACTION_START_PROTECTED)
        startForegroundService(intent)

        val deadline = System.currentTimeMillis() + 8_000
        var snapshot = SafetyProtocolVpnRuntime.snapshot()
        while (System.currentTimeMillis() < deadline) {
            snapshot = SafetyProtocolVpnRuntime.snapshot()
            if (snapshot.captureEstablished && snapshot.osVpnTransportObserved) break
            Thread.sleep(100)
        }

        Thread.sleep(300)
        snapshot = SafetyProtocolVpnRuntime.snapshot()
        val after = probeHost()
        val enforcement = SafetyProtocolVpnRuntime.enforcement()

        Log.i(
            TAG,
            "RUNTIME_RESULT pre=$preProbe capture=${snapshot.captureEstablished} " +
                "osVpn=${snapshot.osVpnTransportObserved} alwaysOn=${snapshot.alwaysOn} " +
                "lockdown=${snapshot.lockdownEnabled} sessionFailClosed=${enforcement.sessionFailClosedVerified} " +
                "persistentFailClosed=${enforcement.persistentFailClosedVerified} post=$after",
        )
    }

    private fun probeHost(): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(HOST_ALIAS, HOST_PORT), CONNECT_TIMEOUT_MS)
        }
        true
    } catch (_: Exception) {
        false
    }

    companion object {
        private const val TAG = "SafetyProtocolRuntime"
        private const val VPN_REQUEST = 5301
        private const val HOST_ALIAS = "10.0.2.2"
        private const val HOST_PORT = 18080
        private const val CONNECT_TIMEOUT_MS = 1_500
    }
}
