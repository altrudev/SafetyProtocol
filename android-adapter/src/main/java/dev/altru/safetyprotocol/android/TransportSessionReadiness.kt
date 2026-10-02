package dev.altru.safetyprotocol.android

class TransportSessionReadiness internal constructor(
    val authenticatedEstablishment: Boolean,
    val freshLiveness: Boolean,
    val protectedSessionReady: Boolean,
    val validUntilMs: Long?,
    val forwardingAuthorized: Boolean,
) {
    fun isReadyAt(nowMs: Long): Boolean =
        authenticatedEstablishment &&
            freshLiveness &&
            protectedSessionReady &&
            validUntilMs != null &&
            nowMs >= 0 &&
            nowMs < validUntilMs

    companion object {
        fun evaluate(
            establishment: ProtectedTransportEvidence,
            liveness: TransportLivenessSnapshot,
        ): TransportSessionReadiness {
            val ready = establishment.authenticated && liveness.fresh
            return TransportSessionReadiness(
                authenticatedEstablishment = establishment.authenticated,
                freshLiveness = liveness.fresh,
                protectedSessionReady = ready,
                validUntilMs = if (ready) liveness.freshUntilMs else null,
                forwardingAuthorized = false,
            )
        }
    }
}
