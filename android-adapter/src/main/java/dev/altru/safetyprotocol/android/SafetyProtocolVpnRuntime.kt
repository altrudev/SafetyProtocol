package dev.altru.safetyprotocol.android

object SafetyProtocolVpnRuntime {
    @Volatile
    private var current = VpnRuntimeSnapshot()

    fun snapshot(): VpnRuntimeSnapshot = current

    fun enforcement(): VpnEnforcementDecision = VpnEnforcementPolicy.evaluate(current)

    fun evidence(nowMs: Long = monotonicNowMs()): TunnelEnforcementEvidence {
        val snapshot = current
        val enforcement = VpnEnforcementPolicy.evaluate(snapshot)
        return TunnelEnforcementEvidence(
            localCaptureEstablished = snapshot.captureEstablished,
            osVpnTransportObserved = snapshot.osVpnTransportObserved,
            protectedSessionAuthenticated = snapshot.transportReadiness?.isReadyAt(nowMs) == true,
            sessionFailClosedVerified = enforcement.sessionFailClosedVerified,
            persistentFailClosedVerified = enforcement.persistentFailClosedVerified,
        )
    }


    @Synchronized
    internal fun updateProtectedSession(readiness: TransportSessionReadiness) {
        current = current.copy(transportReadiness = readiness)
    }

    @Synchronized
    internal fun clearProtectedSession() {
        current = current.copy(transportReadiness = null)
    }

    @Synchronized
    internal fun update(transform: (VpnRuntimeSnapshot) -> VpnRuntimeSnapshot) {
        current = transform(current)
    }

    @Synchronized
    internal fun reset() {
        current = VpnRuntimeSnapshot()
    }

    private fun monotonicNowMs(): Long = System.nanoTime() / 1_000_000L
}
