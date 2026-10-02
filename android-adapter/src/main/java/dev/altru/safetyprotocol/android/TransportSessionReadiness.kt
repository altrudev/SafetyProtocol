package dev.altru.safetyprotocol.android

data class TransportSessionReadiness(
    val authenticatedEstablishment: Boolean,
    val freshLiveness: Boolean,
    val protectedSessionReady: Boolean,
    val forwardingAuthorized: Boolean,
) {
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
                forwardingAuthorized = false,
            )
        }
    }
}
