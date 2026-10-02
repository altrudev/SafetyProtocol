package dev.altru.safetyprotocol.android

import android.annotation.SuppressLint

enum class CoreConnectivityAuthority(val code: Int) {
    TRUSTED(0),
    PROTECTED_TRANSPORT(1),
    CELLULAR_FALLBACK(2),
    DENIED(3);

    companion object {
        fun fromCode(code: Int) = entries.firstOrNull { it.code == code } ?: DENIED
    }
}

enum class CoreDecisionReason(val code: Int) {
    TRUSTED_EVIDENCE_SATISFIED(0),
    PROTECTED_TRANSPORT_ONLY(1),
    PROTECTED_TRANSPORT_UNAVAILABLE(2),
    CONTRADICTORY_EVIDENCE(3),
    HARD_DRIFT(4),
    CELLULAR_FALLBACK_ALLOWED(5),
    CELLULAR_BUDGET_EXHAUSTED(6),
    INSUFFICIENT_EVIDENCE(7);

    companion object {
        fun fromCode(code: Int) = entries.firstOrNull { it.code == code } ?: INSUFFICIENT_EVIDENCE
    }
}

data class CoreAuthority(
    val transport: Boolean,
    val read: Boolean,
    val write: Boolean,
    val execute: Boolean,
    val localNetwork: Boolean,
    val directDns: Boolean,
    val credentialUse: Boolean,
    val dataEgress: Boolean,
)

data class CoreConnectivityDecision(
    val authority: CoreConnectivityAuthority,
    val reason: CoreDecisionReason,
    val effective: CoreAuthority,
    val protectedTunnelRequired: Boolean,
)

internal object SafetyProtocolNative {
    const val EXPECTED_ABI_VERSION = 1

    init {
        loadNativeLibrary()
    }

    @SuppressLint("UnsafeDynamicallyLoadedCode")
    private fun loadNativeLibrary() {
        val explicitPath = System.getProperty("safetyprotocol.native.path")
        if (explicitPath.isNullOrBlank()) {
            System.loadLibrary("safetyprotocol")
        } else {
            // Host-JVM tests load the exact locally built Rust artifact by absolute path.
            // Android production packaging never sets this property and uses loadLibrary above.
            System.load(explicitPath)
        }
    }

    @JvmStatic
    external fun nativeAbiVersion(): Int

    @JvmStatic
    external fun nativeEvaluateConnectivity(
        transport: Int,
        validatedInternet: Int,
        captivePortal: Int,
        protectedTunnelReady: Int,
        contradictoryEvidence: Int,
        hardDrift: Int,
        allowCellularFallback: Int,
        remainingCellularBudgetMb: Long,
    ): Long

    internal fun evaluate(
        observation: RawAndroidNetworkObservation,
        enforcementEvidence: TunnelEnforcementEvidence,
        allowCellularFallback: Boolean = false,
        remainingCellularBudgetMb: Long = 0,
    ): CoreConnectivityDecision {
        check(nativeAbiVersion() == EXPECTED_ABI_VERSION) { "SafetyProtocol native ABI mismatch" }

        val encoded = nativeEvaluateConnectivity(
            transport = observation.transport.nativeCode,
            validatedInternet = observation.validatedInternet.asNativeInt(),
            captivePortal = observation.captivePortal.asNativeInt(),
            protectedTunnelReady = enforcementEvidence.protectedTunnelReady.asNativeInt(),
            contradictoryEvidence = observation.contradictoryEvidence.asNativeInt(),
            hardDrift = observation.hardDrift.asNativeInt(),
            allowCellularFallback = allowCellularFallback.asNativeInt(),
            remainingCellularBudgetMb = remainingCellularBudgetMb.coerceAtLeast(0),
        )
        return decode(encoded)
    }

    internal fun decode(encoded: Long): CoreConnectivityDecision {
        val authority = CoreConnectivityAuthority.fromCode((encoded and 0xff).toInt())
        val reason = CoreDecisionReason.fromCode(((encoded ushr 8) and 0xff).toInt())
        val bits = ((encoded ushr 16) and 0xff).toInt()
        return CoreConnectivityDecision(
            authority = authority,
            reason = reason,
            effective = CoreAuthority(
                transport = bits and (1 shl 0) != 0,
                read = bits and (1 shl 1) != 0,
                write = bits and (1 shl 2) != 0,
                execute = bits and (1 shl 3) != 0,
                localNetwork = bits and (1 shl 4) != 0,
                directDns = bits and (1 shl 5) != 0,
                credentialUse = bits and (1 shl 6) != 0,
                dataEgress = bits and (1 shl 7) != 0,
            ),
            protectedTunnelRequired = ((encoded ushr 24) and 1L) != 0L,
        )
    }
}

private val Transport.nativeCode: Int
    get() = when (this) {
        Transport.NONE -> 0
        Transport.WIFI -> 1
        Transport.CELLULAR -> 2
        Transport.ETHERNET -> 3
        Transport.VPN -> 4
        Transport.OTHER -> 5
    }

private fun Boolean.asNativeInt() = if (this) 1 else 0
