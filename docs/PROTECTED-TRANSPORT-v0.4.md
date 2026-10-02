# SafetyProtocol Protected Transport v0.4

Status: experimental authenticated-session establishment.

## Purpose

v0.4 adds a concrete protected TLS transport primitive without yet enabling packet forwarding.

The transport:

- creates its own underlying TCP socket
- requires VpnService.protect(socket) before connect
- uses the platform default TLS trust store
- enables HTTPS endpoint identification for hostname verification
- completes the TLS handshake
- verifies a configured SHA-256 pin over the peer certificate public key (SPKI encoding)
- returns authenticated establishment evidence only when all checks succeed

## Authority boundary

Successful transport authentication does not authorize forwarding in v0.4.

ProtectedTransportState.forwardingAuthorized remains false by construction, and SafetyProtocolVpnRuntime continues to report protectedSessionAuthenticated=false.

This is intentional. A TLS handshake establishes authenticated session creation at one point in time. It does not by itself provide continuous liveness evidence after the handshake.

## Required evidence

Authenticated establishment requires:

1. underlying socket protected from the VPN loop
2. TLS handshake completed
3. platform hostname verification
4. configured SPKI SHA-256 pin match
5. session established with the local TLS socket still open at the completion point

If any boundary fails, the session is not authenticated.

## Pinning

The pin is SHA-256 over X509Certificate.publicKey.encoded, which is the DER SubjectPublicKeyInfo representation.

The pin is configuration, not a secret. Private keys and credentials are never accepted by this client API.

## Network permission

v0.4 adds android.permission.INTERNET because the protected underlying socket must reach the configured remote endpoint. The VPN service still requires the socket to be explicitly protected from capture before connect.

## Claim ceiling

v0.4 does not claim:

- continuous remote-session liveness
- packet forwarding
- tunnel throughput
- DNS protection
- remote service authorization beyond certificate/hostname/pin identity
- anonymity
- resilience or reconnection

Those require explicit later evidence.
