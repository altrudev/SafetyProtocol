package dev.altru.safetyprotocol.android

enum class Transport { WIFI, CELLULAR, ETHERNET, VPN, OTHER, NONE }

enum class WifiSecurity { OPEN, WPA2_OR_BETTER, UNKNOWN, NOT_APPLICABLE }

enum class NetworkClass { PUBLIC_UNTRUSTED, CELLULAR_FALLBACK, OTHER_UNTRUSTED, NONE }

enum class AdapterRecommendation { FORWARD_TO_POLICY, DENY }

data class RawAndroidNetworkObservation(
    val transport: Transport,
    val userApproved: Boolean,
    val ssidKnown: Boolean,
    val validatedInternet: Boolean,
    val captivePortal: Boolean,
    val security: WifiSecurity,
    val protectedTunnelReady: Boolean,
    val contradictoryEvidence: Boolean,
    val hardDrift: Boolean,
)

data class AndroidNetworkObservation(
    val networkClass: NetworkClass,
    val authenticatedIdentity: Boolean,
    val familiarityObserved: Boolean,
    val validatedInternet: Boolean,
    val captivePortal: Boolean,
    val protectedTunnelRequired: Boolean,
    val protectedTunnelReady: Boolean,
    val localNetworkAuthority: Boolean,
    val directDnsAuthority: Boolean,
    val recommendation: AdapterRecommendation,
)

object AndroidNetworkObservationMapper {
    fun map(raw: RawAndroidNetworkObservation): AndroidNetworkObservation {
        val networkClass = when (raw.transport) {
            Transport.WIFI -> NetworkClass.PUBLIC_UNTRUSTED
            Transport.CELLULAR -> NetworkClass.CELLULAR_FALLBACK
            Transport.NONE -> NetworkClass.NONE
            else -> NetworkClass.OTHER_UNTRUSTED
        }

        val protectedTunnelRequired = raw.transport == Transport.WIFI
        val unsafe = raw.contradictoryEvidence || raw.hardDrift ||
            (protectedTunnelRequired && !raw.protectedTunnelReady)

        return AndroidNetworkObservation(
            networkClass = networkClass,
            authenticatedIdentity = false,
            familiarityObserved = raw.ssidKnown,
            validatedInternet = raw.validatedInternet,
            captivePortal = raw.captivePortal,
            protectedTunnelRequired = protectedTunnelRequired,
            protectedTunnelReady = raw.protectedTunnelReady,
            localNetworkAuthority = false,
            directDnsAuthority = false,
            recommendation = if (unsafe) AdapterRecommendation.DENY else AdapterRecommendation.FORWARD_TO_POLICY,
        )
    }
}
