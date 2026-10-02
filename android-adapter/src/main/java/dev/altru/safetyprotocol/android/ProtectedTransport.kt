package dev.altru.safetyprotocol.android

import android.net.VpnService
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

enum class ProtectedTransportPhase {
    IDLE,
    CONNECTING,
    AUTHENTICATED,
    FAILED,
    CLOSED,
}

data class ProtectedTransportEvidence(
    val socketProtectedFromVpn: Boolean = false,
    val tlsHandshakeComplete: Boolean = false,
    val hostnameVerified: Boolean = false,
    val publicKeyPinVerified: Boolean = false,
    val sessionEstablished: Boolean = false,
    val localSocketOpen: Boolean = false,
) {
    val authenticated: Boolean
        get() = socketProtectedFromVpn &&
            tlsHandshakeComplete &&
            hostnameVerified &&
            publicKeyPinVerified &&
            sessionEstablished &&
            localSocketOpen
}

data class ProtectedTransportState(
    val phase: ProtectedTransportPhase,
    val evidence: ProtectedTransportEvidence,
    val forwardingAuthorized: Boolean = false,
) {
    companion object {
        fun fromEvidence(evidence: ProtectedTransportEvidence): ProtectedTransportState =
            ProtectedTransportState(
                phase = if (evidence.authenticated) {
                    ProtectedTransportPhase.AUTHENTICATED
                } else {
                    ProtectedTransportPhase.FAILED
                },
                evidence = evidence,
                forwardingAuthorized = false,
            )
    }
}

data class ProtectedTransportEndpoint(
    val host: String,
    val port: Int,
    val spkiSha256: ByteArray,
) {
    init {
        require(host.isNotBlank())
        require(port in 1..65535)
        require(spkiSha256.size == SHA256_BYTES)
    }

    companion object {
        private const val SHA256_BYTES = 32

        fun fromHexPin(host: String, port: Int, sha256Hex: String): ProtectedTransportEndpoint {
            require(sha256Hex.length == SHA256_BYTES * 2)
            val bytes = ByteArray(SHA256_BYTES) { index ->
                sha256Hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
            return ProtectedTransportEndpoint(host, port, bytes)
        }
    }
}

internal fun interface VpnSocketProtector {
    fun protect(socket: Socket): Boolean
}

class ProtectedTransportSession internal constructor(
    internal val socket: SSLSocket,
    val endpoint: ProtectedTransportEndpoint,
    val evidence: ProtectedTransportEvidence,
) : AutoCloseable {
    val authenticatedAtEstablishment: Boolean
        get() = evidence.authenticated

    override fun close() {
        socket.close()
    }
}

class PinnedTlsProtectedTransport internal constructor(
    private val socketProtector: VpnSocketProtector,
    private val sslSocketFactory: SSLSocketFactory = SSLSocketFactory.getDefault() as SSLSocketFactory,
) {
    constructor(vpnService: VpnService) : this(VpnSocketProtector(vpnService::protect))

    fun connect(
        endpoint: ProtectedTransportEndpoint,
        connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
        readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS,
    ): ProtectedTransportSession {
        val rawSocket = Socket()
        var protected = false
        try {
            protected = socketProtector.protect(rawSocket)
            check(protected) { "Underlying transport socket could not be protected from the VPN loop" }

            rawSocket.connect(InetSocketAddress(endpoint.host, endpoint.port), connectTimeoutMs)
            rawSocket.soTimeout = readTimeoutMs

            val tlsSocket = sslSocketFactory.createSocket(
                rawSocket,
                endpoint.host,
                endpoint.port,
                true,
            ) as SSLSocket

            tlsSocket.useClientMode = true
            val params = tlsSocket.sslParameters ?: SSLParameters()
            params.endpointIdentificationAlgorithm = "HTTPS"
            tlsSocket.sslParameters = params
            tlsSocket.startHandshake()

            val peer = tlsSocket.session.peerCertificates.firstOrNull() as? X509Certificate
                ?: throw SecurityException("No X.509 peer certificate")
            val actualPin = MessageDigest.getInstance("SHA-256").digest(peer.publicKey.encoded)
            val pinVerified = MessageDigest.isEqual(endpoint.spkiSha256, actualPin)
            if (!pinVerified) {
                tlsSocket.close()
                throw SecurityException("Protected transport public-key pin mismatch")
            }

            val evidence = ProtectedTransportEvidence(
                socketProtectedFromVpn = protected,
                tlsHandshakeComplete = true,
                hostnameVerified = true,
                publicKeyPinVerified = true,
                sessionEstablished = true,
                localSocketOpen = !tlsSocket.isClosed,
            )
            check(evidence.authenticated) { "Protected transport authentication incomplete" }
            return ProtectedTransportSession(tlsSocket, endpoint, evidence)
        } catch (t: Throwable) {
            runCatching { rawSocket.close() }
            throw t
        }
    }

    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_MS = 10_000
        private const val DEFAULT_READ_TIMEOUT_MS = 15_000
    }
}
