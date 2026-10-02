package dev.altru.safetyprotocol.android

enum class TrafficDisposition {
    NOT_ENFORCED,
    DROP_FAIL_CLOSED,
}

data class VpnRuntimeSnapshot(
    val serviceRunning: Boolean = false,
    val captureEstablished: Boolean = false,
    val osVpnTransportObserved: Boolean = false,
    val alwaysOn: Boolean = false,
    val lockdownEnabled: Boolean = false,
    val transportReadiness: TransportSessionReadiness? = null,
)

data class VpnEnforcementDecision(
    val disposition: TrafficDisposition,
    val sessionFailClosedVerified: Boolean,
    val persistentFailClosedVerified: Boolean,
    val osCorroborated: Boolean,
)

object VpnEnforcementPolicy {
    fun evaluate(state: VpnRuntimeSnapshot): VpnEnforcementDecision {
        val sessionFailClosed = state.serviceRunning && state.captureEstablished
        return VpnEnforcementDecision(
            disposition = if (sessionFailClosed) {
                TrafficDisposition.DROP_FAIL_CLOSED
            } else {
                TrafficDisposition.NOT_ENFORCED
            },
            sessionFailClosedVerified = sessionFailClosed,
            persistentFailClosedVerified = state.alwaysOn && state.lockdownEnabled,
            osCorroborated = state.osVpnTransportObserved,
        )
    }
}

class TunnelEnforcementEvidence internal constructor(
    internal val localCaptureEstablished: Boolean,
    internal val osVpnTransportObserved: Boolean,
    internal val protectedSessionAuthenticated: Boolean,
    val sessionFailClosedVerified: Boolean,
    val persistentFailClosedVerified: Boolean,
) {
    internal val protectedTunnelReady: Boolean
        get() = localCaptureEstablished &&
            osVpnTransportObserved &&
            protectedSessionAuthenticated
}
