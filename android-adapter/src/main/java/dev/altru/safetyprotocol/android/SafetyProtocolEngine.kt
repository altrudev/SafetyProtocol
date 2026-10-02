package dev.altru.safetyprotocol.android

object SafetyProtocolEngine {
    fun evaluate(
        observation: RawAndroidNetworkObservation,
        allowCellularFallback: Boolean = false,
        remainingCellularBudgetMb: Long = 0,
    ): CoreConnectivityDecision = SafetyProtocolNative.evaluate(
        observation = observation,
        enforcementEvidence = SafetyProtocolVpnRuntime.evidence(),
        allowCellularFallback = allowCellularFallback,
        remainingCellularBudgetMb = remainingCellularBudgetMb,
    )
}
