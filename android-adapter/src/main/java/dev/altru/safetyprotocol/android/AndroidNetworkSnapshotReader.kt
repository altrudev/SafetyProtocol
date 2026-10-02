package dev.altru.safetyprotocol.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

class AndroidNetworkSnapshotReader(context: Context) {
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)

    fun read(
        protectedTunnelReady: Boolean,
        contradictoryEvidence: Boolean = false,
        hardDrift: Boolean = false,
    ): RawAndroidNetworkObservation {
        val network = connectivityManager.activeNetwork
            ?: return emptyObservation(protectedTunnelReady, contradictoryEvidence, hardDrift)
        val capabilities = connectivityManager.getNetworkCapabilities(network)
            ?: return emptyObservation(protectedTunnelReady, contradictoryEvidence, hardDrift)

        val transport = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Transport.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Transport.CELLULAR
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Transport.ETHERNET
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> Transport.VPN
            else -> Transport.OTHER
        }

        return RawAndroidNetworkObservation(
            transport = transport,
            userApproved = false,
            ssidKnown = false,
            validatedInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            captivePortal = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            security = if (transport == Transport.WIFI) WifiSecurity.UNKNOWN else WifiSecurity.NOT_APPLICABLE,
            protectedTunnelReady = protectedTunnelReady,
            contradictoryEvidence = contradictoryEvidence,
            hardDrift = hardDrift,
        )
    }

    private fun emptyObservation(
        protectedTunnelReady: Boolean,
        contradictoryEvidence: Boolean,
        hardDrift: Boolean,
    ) = RawAndroidNetworkObservation(
        transport = Transport.NONE,
        userApproved = false,
        ssidKnown = false,
        validatedInternet = false,
        captivePortal = false,
        security = WifiSecurity.NOT_APPLICABLE,
        protectedTunnelReady = protectedTunnelReady,
        contradictoryEvidence = contradictoryEvidence,
        hardDrift = hardDrift,
    )
}
