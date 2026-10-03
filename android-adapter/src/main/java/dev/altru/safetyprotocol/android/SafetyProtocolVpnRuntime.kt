package dev.altru.safetyprotocol.android

object SafetyProtocolVpnRuntime {
    @Volatile
    private var current = VpnRuntimeSnapshot()

    @Volatile
    private var currentRevision: Long = 0

    private var executionLeaseActive = false

    fun snapshot(): VpnRuntimeSnapshot = current

    fun revision(): Long = currentRevision

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
    internal fun <T> withStableSnapshot(
        block: (VpnRuntimeSnapshot, Long) -> T,
    ): T {
        check(!executionLeaseActive) { "VPN runtime execution lease is already active" }
        executionLeaseActive = true
        return try {
            block(current, currentRevision)
        } finally {
            executionLeaseActive = false
        }
    }

    @Synchronized
    internal fun updateProtectedSession(readiness: TransportSessionReadiness) {
        mutate { it.copy(transportReadiness = readiness) }
    }

    @Synchronized
    internal fun clearProtectedSession() {
        mutate { it.copy(transportReadiness = null) }
    }

    @Synchronized
    internal fun update(transform: (VpnRuntimeSnapshot) -> VpnRuntimeSnapshot) {
        mutate(transform)
    }

    @Synchronized
    internal fun reset() {
        mutate { VpnRuntimeSnapshot() }
    }

    private fun mutate(transform: (VpnRuntimeSnapshot) -> VpnRuntimeSnapshot) {
        check(!executionLeaseActive) { "VPN runtime cannot mutate during an active execution lease" }
        val nextRevision = Math.addExact(currentRevision, 1L)
        val next = transform(current)
        current = next
        currentRevision = nextRevision
    }

    private fun monotonicNowMs(): Long = System.nanoTime() / 1_000_000L
}
