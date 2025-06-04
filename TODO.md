# TODO

### [ ] Implement ChaCha20-Poly1305 encryption for packet security (chacha20poly1305 or ring)

WireGuard encrypts packets using ChaCha20 for confidentiality and Poly1305 for authentication, forming the ChaCha20-Poly1305 AEAD construction. This task implements encryption for HTTP/HTTPS packets sent from your browser to the Nginx server, ensuring they remain confidential and untampered within the tunnel. For your scenario, this protects webpage data (e.g., GET requests or responses) as it travels over UDP (or TCP via relays). The ring crate offers a battle-tested alternative used by boringtun, ensuring high performance and security.

### [ ] Implement BLAKE2s for hashing in handshake and key derivation (blake2)

BLAKE2s is used in WireGuard’s handshake for generating construction identifiers and integrity checks, ensuring the protocol’s messages are consistent and secure. This task involves hashing handshake data and deriving keys for your browser-Nginx server tunnel. In your scenario, BLAKE2s ensures the handshake between 100.64.1.1 and 100.64.1.2 is secure, preventing man-in-the-middle attacks. The blake2 crate provides a fast, secure implementation critical for reliable tunnel setup.****

### [ ] Implement HKDF for session key derivation (hkdf, sha2)

WireGuard uses HKDF (with SHA-256) to derive multiple session keys (for encryption and authentication) from the Curve25519 shared secret. This task ensures that each tunnel session between your browser and Nginx server uses unique, secure keys. In your scenario, HKDF generates keys to encrypt HTTP/HTTPS traffic, maintaining security even if a session is compromised. The hkdf and sha2 crates provide a robust implementation, ensuring reliable key derivation.



### [ ] Implement WireGuard handshake protocol (tokio, x25519-dalek, blake2, hkdf)

The WireGuard handshake protocol establishes a secure tunnel between peers via a 1-RTT (round-trip time) exchange, using UDP packets. This task implements the initiator (browser) and responder (Nginx server) roles, handling message formats and retries for lost UDP packets. In your scenario, this ensures the browser can securely connect to 100.64.1.2, even on unreliable networks. Using tokio for async networking and retries enhances reliability, while x25519-dalek, blake2, and hkdf secure the handshake.



### [ ] Implement packet encapsulation/decapsulation (chacha20poly1305, tokio)

WireGuard encapsulates IP packets (e.g., TCP-based HTTP/HTTPS requests) into encrypted UDP packets, with sequence numbers for ordering and replay protection. This task handles encapsulation of your browser’s HTTP/HTTPS requests and decapsulation of the Nginx server’s responses. In your scenario, it ensures webpage data is securely tunneled to 100.64.1.2, with TCP providing data reliability and WireGuard’s sequence numbers preventing replay attacks. tokio manages UDP packet I/O, and chacha20poly1305 secures the payload.



### [ ] Implement keepalives for tunnel stability (tokio::time)

WireGuard sends periodic keepalive packets to maintain NAT mappings, ensuring the tunnel between your browser and Nginx server remains active, especially behind NATs (e.g., home routers). This task implements sending empty UDP packets every 25 seconds (configurable). In your scenario, keepalives prevent the connection to 100.64.1.2 from dropping during idle periods, enhancing UDP reliability. tokio::time schedules these packets asynchronously.

# 2. Networking and Tunneling





### [ ] Create virtual network interface for tunneling (tun or tun-tap)

WireGuard uses a virtual network interface (e.g., wg0) to route IP packets, such as your browser’s HTTP/HTTPS traffic to the Nginx server’s virtual IP (100.64.1.2). This task creates a TUN interface in Rust to handle packet routing. In your scenario, it allows your browser to send requests to 100.64.1.2 as if it’s on a local network, with the tunnel encapsulating TCP traffic in UDP packets. The tun or tun-tap crate provides cross-platform support for Linux, Windows, and macOS.



### [ ] Implement UDP transport for WireGuard packets (tokio::net::UdpSocket)

WireGuard uses UDP as its primary transport protocol for low latency and simplicity. This task implements sending and receiving encrypted WireGuard packets over UDP (default port 51820). In your scenario, it enables the browser (100.64.1.1) to send HTTP/HTTPS requests to the Nginx server (100.64.1.2) via a UDP-based tunnel. tokio::net::UdpSocket provides asynchronous UDP networking, ensuring efficient packet handling despite UDP’s lack of built-in reliability.



### [ ] Implement NAT hole punching for peer-to-peer connections (libp2p or udp_hole_punching)

NAT hole punching allows direct UDP connections between peers behind NATs (e.g., your browser’s machine and the Nginx server). This task coordinates simultaneous UDP packet sends to create NAT mappings, enabling a direct tunnel. In your scenario, it connects 100.64.1.1 to 100.64.1.2 without manual port forwarding, critical for home or mobile networks. libp2p offers robust STUN/ICE support, while udp_hole_punching is simpler for basic setups. Reliability depends on retries and keepalives.



### [ ] Integrate STUN/ICE for NAT traversal (libp2p or stun)

STUN (Session Traversal Utilities for NAT) and ICE (Interactive Connectivity Establishment) discover public IP/port mappings and negotiate connection paths. This task enhances NAT hole punching by identifying viable UDP paths. In your scenario, it ensures your browser can find the Nginx server’s public endpoint (e.g., 192.168.1.100:51820) for a direct tunnel. libp2p provides a complete STUN/ICE implementation, while the stun crate focuses on STUN alone, improving connection success rates.



### [ ] Implement TCP relay for fallback (DERP equivalent) (tokio::net::TcpListener, tokio::net::TcpStream)

When UDP is blocked (e.g., by a firewall), Net uses DERP relays over TCP/443 to forward WireGuard packets. This task builds a TCP-based relay server to ensure connectivity in restrictive networks. In your scenario, it guarantees your browser can reach the Nginx server even if UDP fails, maintaining reliability via TCP’s retransmissions. tokio::net::TcpListener and tokio::net::TcpStream enable asynchronous TCP networking, mimicking DERP’s functionality.

# 3. Control Plane (Rendezvous Server)





### [ ] Build a rendezvous server for peer discovery (libp2p::rendezvous or tokio::net::UdpSocket)

Net’s control plane acts as a rendezvous server, coordinating peer discovery by exchanging public IP/port mappings for NAT hole punching. This task builds a server to register peers (browser and Nginx server) and share their endpoints. In your scenario, it enables 100.64.1.1 to discover 100.64.1.2’s public address (e.g., 192.168.1.100:51820) for a direct UDP tunnel. libp2p::rendezvous offers a robust protocol, while tokio::net::UdpSocket allows a custom, lightweight server.



### [ ] Implement peer authentication (x25519-dalek, ed25519-dalek)

The rendezvous server must verify peer identities to prevent unauthorized access. This task uses public-key cryptography to authenticate peers during registration. In your scenario, it ensures only your browser and Nginx server can join the network, securing the tunnel to 100.64.1.2. x25519-dalek handles WireGuard’s key exchange, while ed25519-dalek can be used for signing registration messages, ensuring a secure control plane.



### [ ] Manage peer metadata (serde, sqlx or sled)

The control plane stores peer information (public keys, allowed IPs, endpoints) to coordinate connections. This task implements a database or in-memory store for metadata. In your scenario, it tracks the browser (100.64.1.1) and Nginx server (100.64.1.2), enabling dynamic updates if endpoints change (e.g., due to roaming). serde serializes data, while sqlx (SQL database) or sled (embedded key-value store) provides persistent storage.



### [ ] Signal TCP relay fallback (tokio, libp2p::relay)

If NAT hole punching fails (e.g., due to symmetric NATs), the rendezvous server signals peers to use a TCP relay. This task implements logic to detect failed UDP connections and provide relay server addresses. In your scenario, it ensures your browser can reach the Nginx server via a TCP relay when UDP is blocked, maintaining connectivity. libp2p::relay handles this natively, while tokio enables custom signaling over UDP or TCP.



### [ ] Implement secure API for control plane (axum or warp, tokio-tungstenite)

Clients (e.g., browser’s machine) interact with the control plane via a secure API to register, query peers, or get relay details. This task builds REST or WebSocket endpoints with TLS. In your scenario, it allows programmatic management of the tunnel to 100.64.1.2, similar to Net’s API. axum or warp provides HTTP servers, and tokio-tungstenite supports WebSockets for real-time updates, ensuring secure communication.

# 4. Reliability Mechanisms


### [ ] Implement handshake retries (tokio::time)

UDP’s unreliability can cause handshake packets to be lost, disrupting tunnel setup. This task implements retries (e.g., every 2 seconds) to ensure successful handshakes. In your scenario, it guarantees the browser can establish a tunnel to the Nginx server despite packet loss, enhancing UDP reliability. tokio::time schedules retries asynchronously, ensuring robust tunnel initialization.



### [ ] Handle connection roaming (tokio, x25519-dalek)

Net supports seamless roaming (e.g., switching from Wi-Fi to mobile data) by tracking peers via public keys, not IP addresses. This task updates endpoint addresses dynamically when a peer’s network changes. In your scenario, it ensures the browser stays connected to 100.64.1.2 during network switches, using tokio for networking and x25519-dalek for key-based peer identification.



### [ ] Monitor connection quality (tokio, libp2p)

To maintain performance, Net monitors packet loss and latency, switching to a TCP relay if UDP degrades. This task implements metrics collection and failover logic. In your scenario, it ensures optimal performance for HTTP/HTTPS traffic to the Nginx server, falling back to a relay if UDP packet loss is high. tokio handles async monitoring, and libp2p provides NAT traversal insights.



### [ ] Ensure TCP reliability for HTTP/HTTPS (Built-in to TCP)

Your browser’s HTTP/HTTPS traffic to the Nginx server uses TCP, which provides retransmissions and ordering. This task ensures the WireGuard tunnel correctly encapsulates TCP packets without interference. In your scenario, TCP guarantees webpage data delivery to 100.64.1.2, complementing UDP’s tunnel reliability. No additional library is needed, as TCP is handled by the OS.

# 5. User-Friendly Features (Net-like)





### [ ] Implement MagicDNS equivalent (trust-dns-resolver or custom DNS with tokio)

Net’s MagicDNS resolves hostnames (e.g., nginx-server.Net.ts.net) to virtual IPs (e.g., 100.64.1.2). This task builds a DNS resolver for your VPN network. In your scenario, it allows your browser to access the Nginx server via a hostname instead of an IP, improving usability. trust-dns-resolver provides a full DNS client, or a custom tokio-based resolver can map hostnames to IPs.



### [ ] Implement access control lists (ACLs) (serde, sqlx)

Net uses ACLs to define which peers can access each other (e.g., browser accessing Nginx server). This task implements a policy engine to enforce access rules. In your scenario, it restricts access to 100.64.1.2 to authorized devices, enhancing security. serde parses ACL configurations, and sqlx stores policies in a database for scalability.



### [ ] Create a CLI for configuration (clap)

Net’s CLI (e.g., Net up) simplifies network setup. This task builds a command-line interface to manage peers, keys, and interfaces. In your scenario, it allows users to configure the tunnel to the Nginx server easily, similar to Net’s user experience. clap handles argument parsing for commands like vpn up or vpn add-peer.



### [ ] Implement device management (sqlx or sled, serde)

Net tracks devices and assigns virtual IPs within a Net. This task builds a system to manage devices (e.g., browser’s machine, Nginx server) and their IPs. In your scenario, it ensures 100.64.1.1 and 100.64.1.2 are correctly assigned and discoverable. sqlx or sled stores device data, and serde serializes it for API interactions.

# 6. Integration and Testing





### [ ] Integrate with Nginx server (reqwest)

To verify functionality, this task tests HTTP/HTTPS access from a browser to the Nginx server over the VPN tunnel. It involves sending test requests to 100.64.1.2:80 or :443 and checking responses. In your scenario, it confirms the tunnel works for webpage delivery, with TCP ensuring data reliability. reqwest provides an HTTP client for testing.



### [ ] Test NAT traversal (stun or libp2p)

NAT traversal is critical for direct UDP connections. This task tests hole punching with various NAT types (full cone, restricted cone, symmetric) using a STUN client. In your scenario, it ensures the browser can connect to the Nginx server’s public endpoint (e.g., 192.168.1.100:51820). libp2p or stun verifies NAT behavior, improving connection reliability.



### [ ] Test TCP relay fallback (tokio, libp2p::relay)

When UDP is blocked, a TCP relay ensures connectivity. This task simulates UDP-blocking networks and tests relay performance. In your scenario, it guarantees the browser can reach 100.64.1.2 via a relay, using TCP’s reliability. tokio and libp2p::relay enable testing and implementation of the relay server.



### [ ] Implement logging and diagnostics (log, env_logger)

Net’s Net status provides connection insights. This task implements logging for connection status, packet loss, and relay usage. In your scenario, it helps debug issues with the browser-to-Nginx tunnel, identifying whether UDP or TCP is used. log and env_logger provide flexible logging for diagnostics.



### [ ] Write unit tests (tokio::test, quickcheck)

To ensure correctness, this task writes tests for cryptographic functions, handshake logic, and packet handling. In your scenario, it verifies the tunnel to 100.64.1.2 is secure and reliable. tokio::test supports async tests, and quickcheck generates random inputs for robustness.

# 7. Security and Performance





### [ ] Audit cryptographic implementations (x25519-dalek, chacha20poly1305, ring)

Security is critical for a VPN. This task audits cryptographic code for constant-time operations and vulnerabilities. In your scenario, it ensures the tunnel to the Nginx server is secure against attacks. Using audited libraries like x25519-dalek and ring minimizes risks, ensuring a robust implementation.



### [ ] Optimize performance (ring, tokio)

Net is known for low latency and CPU efficiency. This task optimizes encryption and packet processing for performance. In your scenario, it ensures fast HTTP/HTTPS delivery to 100.64.1.2, especially for large webpages. ring provides optimized crypto, and tokio enables efficient async networking.



### [ ] Implement replay protection (chacha20poly1305)

WireGuard uses sequence numbers to prevent replay attacks. This task implements checks to discard replayed packets. In your scenario, it secures the tunnel to the Nginx server against malicious packet injection. chacha20poly1305 includes sequence number handling for authenticated encryption.



### [ ] Secure control plane communication (rustls or tokio-rustls)

The control plane’s API must be secure to prevent unauthorized access. This task implements TLS for API endpoints. In your scenario, it protects peer registration and relay signaling for the browser-Nginx connection. rustls provides a lightweight, secure TLS implementation for Rust.

# 8. Optional Enhancements





### [ ] Support userspace WireGuard (boringtun)

Net uses wireguard-go for userspace WireGuard on platforms without kernel support. This task implements a userspace stack for broader compatibility. In your scenario, it ensures the browser-Nginx tunnel works on non-Linux platforms (e.g., macOS, Windows). boringtun provides a reference implementation to adapt or use directly.



### [ ] Add single sign-on (SSO) (openidconnect or oauth2)

Net supports SSO for user authentication. This task integrates with identity providers for seamless login. In your scenario, it simplifies access to the Nginx server for multiple users. openidconnect or oauth2 handles SSO protocols, enhancing user experience.



### [ ] Implement subnet routing (tun, ipnet)

Net allows routing to non-Net networks via a peer. This task enables access to the Nginx server’s LAN (e.g., 192.168.1.0/24) through 100.64.1.2. In your scenario, it supports advanced use cases like accessing other services on the Nginx server’s network. tun and ipnet handle routing logic.



### [ ] Support mobile platforms (jni for Android, objc for iOS)

Net supports mobile devices with seamless roaming. This task ensures compatibility with Android/iOS, handling network changes. In your scenario, it allows your browser on a mobile device to access the Nginx server reliably. jni and objc provide platform-specific bindings for mobile integration.

# Notes

Existing Libraries: Leverage boringtun for a production-ready WireGuard implementation or wg for protocol components to reduce development effort.



Reliability: UDP reliability is ensured by handshake retries, keepalives, and TCP relay fallbacks. HTTP/HTTPS traffic relies on TCP’s retransmissions for data delivery.



Testing: Use stunc to test NAT traversal and simulate UDP-blocking networks for relay testing. Test with real HTTP/HTTPS requests to the Nginx server.



Security: Use audited libraries (ring, x25519-dalek, rustls) and follow the WireGuard protocol spec (https://www.wireguard.com/protocol/) for correctness.



Net Features: MagicDNS, ACLs, and SSO are complex; prioritize core VPN functionality (WireGuard, NAT traversal, relays) for initial implementation.



Scenario Focus: The implementation ensures your browser can securely and reliably access the Nginx server (100.64.1.2) via direct UDP tunnels or TCP relays, mimicking Net’s functionality.