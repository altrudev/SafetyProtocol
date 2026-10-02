package dev.altru.safetyprotocol.android

import java.security.MessageDigest

internal enum class ForwardingGateDisposition {
    DROP,
    ELIGIBLE,
}

internal enum class ForwardingGateReason {
    ELIGIBLE,
    SERVICE_NOT_RUNNING,
    CAPTURE_NOT_ESTABLISHED,
    OS_VPN_NOT_CORROBORATED,
    PROTECTED_SESSION_NOT_READY,
    POLICY_NOT_AUTHORIZED,
    AUTHORITY_SCOPE_MISMATCH,
    ENDPOINT_BINDING_MISMATCH,
    NOT_DATA_FRAME,
    EMPTY_DATA,
    PACKET_PARSE_REJECTED,
    DATA_FLOW_NOT_AUTHORIZED,
}

internal data class ForwardingGateDecision(
    val disposition: ForwardingGateDisposition,
    val reason: ForwardingGateReason,
    val packetMetadata: PacketMetadata? = null,
    val packetFlowReason: PacketFlowReason? = null,
    val forwardingActive: Boolean = false,
) {
    val eligible: Boolean
        get() = disposition == ForwardingGateDisposition.ELIGIBLE
}

internal object ForwardingGate {
    fun evaluate(
        runtime: VpnRuntimeSnapshot,
        policy: CoreConnectivityDecision,
        authenticatedEndpoint: ProtectedTransportEndpoint,
        candidateEndpoint: ProtectedTransportEndpoint,
        frame: TransportFrame,
        nowMs: Long,
    ): ForwardingGateDecision {
        if (!runtime.serviceRunning) return drop(ForwardingGateReason.SERVICE_NOT_RUNNING)
        if (!runtime.captureEstablished) return drop(ForwardingGateReason.CAPTURE_NOT_ESTABLISHED)
        if (!runtime.osVpnTransportObserved) return drop(ForwardingGateReason.OS_VPN_NOT_CORROBORATED)
        val readiness = runtime.transportReadiness
            ?: return drop(ForwardingGateReason.PROTECTED_SESSION_NOT_READY)
        if (!readiness.isReadyAt(nowMs)) {
            return drop(ForwardingGateReason.PROTECTED_SESSION_NOT_READY)
        }

        if (policy.authority != CoreConnectivityAuthority.PROTECTED_TRANSPORT ||
            policy.reason != CoreDecisionReason.PROTECTED_TRANSPORT_ONLY ||
            !policy.protectedTunnelRequired
        ) {
            return drop(ForwardingGateReason.POLICY_NOT_AUTHORIZED)
        }

        if (!hasExactProtectedTransportScope(policy.effective)) {
            return drop(ForwardingGateReason.AUTHORITY_SCOPE_MISMATCH)
        }

        if (!sameEndpoint(authenticatedEndpoint, candidateEndpoint)) {
            return drop(ForwardingGateReason.ENDPOINT_BINDING_MISMATCH)
        }

        if (frame.type != TransportFrameType.DATA) return drop(ForwardingGateReason.NOT_DATA_FRAME)
        if (frame.payload.isEmpty()) return drop(ForwardingGateReason.EMPTY_DATA)

        val parsed = PacketMetadataParser.parse(frame.payload)
        if (parsed !is PacketParseResult.Parsed) {
            return drop(ForwardingGateReason.PACKET_PARSE_REJECTED)
        }

        val flow = PacketFlowPolicy.evaluate(parsed.metadata)
        if (flow.disposition != PacketFlowDisposition.ALLOW_TO_FORWARDING_GATE) {
            return ForwardingGateDecision(
                disposition = ForwardingGateDisposition.DROP,
                reason = ForwardingGateReason.DATA_FLOW_NOT_AUTHORIZED,
                packetMetadata = parsed.metadata,
                packetFlowReason = flow.reason,
                forwardingActive = false,
            )
        }

        return ForwardingGateDecision(
            disposition = ForwardingGateDisposition.ELIGIBLE,
            reason = ForwardingGateReason.ELIGIBLE,
            packetMetadata = parsed.metadata,
            packetFlowReason = flow.reason,
            forwardingActive = false,
        )
    }

    private fun hasExactProtectedTransportScope(authority: CoreAuthority): Boolean =
        authority.transport &&
            authority.dataEgress &&
            !authority.read &&
            !authority.write &&
            !authority.execute &&
            !authority.localNetwork &&
            !authority.directDns &&
            !authority.credentialUse

    private fun sameEndpoint(
        authenticated: ProtectedTransportEndpoint,
        candidate: ProtectedTransportEndpoint,
    ): Boolean =
        authenticated.host.equals(candidate.host, ignoreCase = true) &&
            authenticated.port == candidate.port &&
            MessageDigest.isEqual(authenticated.spkiSha256, candidate.spkiSha256)

    private fun drop(reason: ForwardingGateReason) = ForwardingGateDecision(
        disposition = ForwardingGateDisposition.DROP,
        reason = reason,
        forwardingActive = false,
    )
}
