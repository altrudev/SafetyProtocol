package dev.altru.safetyprotocol.android

internal data class ForwardingExecutionRevision(
    val contextRevision: Long,
    val runtimeRevision: Long,
)

internal class ForwardingExecutionContext internal constructor(
    val revision: Long,
    val policy: CoreConnectivityDecision,
    val authenticatedEndpoint: ProtectedTransportEndpoint,
    val candidateEndpoint: ProtectedTransportEndpoint,
    val destinationPolicy: DestinationPolicy,
)

internal class ForwardingExecutionSession(
    policy: CoreConnectivityDecision,
    authenticatedEndpoint: ProtectedTransportEndpoint,
    candidateEndpoint: ProtectedTransportEndpoint,
    destinationPolicy: DestinationPolicy,
) {
    private var revision: Long = 1
    private var policyState = policy
    private var authenticatedEndpointState = authenticatedEndpoint.defensiveCopy()
    private var candidateEndpointState = candidateEndpoint.defensiveCopy()
    private var destinationPolicyState = destinationPolicy
    private var executionLeaseActive = false

    @Synchronized
    fun revision(): Long = revision

    @Synchronized
    fun updatePolicy(policy: CoreConnectivityDecision) {
        mutate {
            policyState = policy
        }
    }

    @Synchronized
    fun updateAuthenticatedEndpoint(endpoint: ProtectedTransportEndpoint) {
        val copied = endpoint.defensiveCopy()
        mutate {
            authenticatedEndpointState = copied
        }
    }

    @Synchronized
    fun updateCandidateEndpoint(endpoint: ProtectedTransportEndpoint) {
        val copied = endpoint.defensiveCopy()
        mutate {
            candidateEndpointState = copied
        }
    }

    @Synchronized
    fun updateDestinationPolicy(policy: DestinationPolicy) {
        mutate {
            destinationPolicyState = policy
        }
    }

    @Synchronized
    internal fun <T> withStableContext(
        block: (ForwardingExecutionContext) -> T,
    ): T {
        check(!executionLeaseActive) { "Execution context lease is already active" }
        executionLeaseActive = true
        return try {
            block(snapshotUnsafe())
        } finally {
            executionLeaseActive = false
        }
    }

    private fun mutate(commit: () -> Unit) {
        check(!executionLeaseActive) { "Execution context cannot mutate during an active execution lease" }
        val nextRevision = Math.addExact(revision, 1L)
        commit()
        revision = nextRevision
    }

    private fun snapshotUnsafe() = ForwardingExecutionContext(
        revision = revision,
        policy = policyState,
        authenticatedEndpoint = authenticatedEndpointState.defensiveCopy(),
        candidateEndpoint = candidateEndpointState.defensiveCopy(),
        destinationPolicy = destinationPolicyState,
    )
}

private fun ProtectedTransportEndpoint.defensiveCopy() = ProtectedTransportEndpoint(
    host = host,
    port = port,
    spkiSha256 = spkiSha256.copyOf(),
)
