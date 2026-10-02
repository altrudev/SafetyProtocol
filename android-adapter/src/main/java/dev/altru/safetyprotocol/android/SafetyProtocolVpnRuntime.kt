package dev.altru.safetyprotocol.android

object SafetyProtocolVpnRuntime {
    @Volatile
    private var current = VpnRuntimeSnapshot()

    fun snapshot(): VpnRuntimeSnapshot = current

    fun enforcement(): VpnEnforcementDecision = VpnEnforcementPolicy.evaluate(current)

    fun evidence(): TunnelEnforcementEvidence {
        val snapshot = current
        val enforcement = VpnEnforcementPolicy.evaluate(snapshot)
        return TunnelEnforcementEvidence(
            localCaptureEstablished = snapshot.captureEstablished,
            osVpnTransportObserved = snapshot.osVpnTransportObserved,
            protectedSessionAuthenticated = false,
            sessionFailClosedVerified = enforcement.sessionFailClosedVerified,
            persistentFailClosedVerified = enforcement.persistentFailClosedVerified,
        )
    }

    @Synchronized
    internal fun update(transform: (VpnRuntimeSnapshot) -> VpnRuntimeSnapshot) {
        current = transform(current)
    }

    @Synchronized
    internal fun reset() {
        current = VpnRuntimeSnapshot()
    }
}
