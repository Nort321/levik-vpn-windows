# Levik Game

Game is opt-in and visible only after the selected subscription's encrypted profile confirms Game Squad access. The bridge derives endpoint identity from squad inbound IDs and enabled hosts, not their display names. The profile service also identifies app-only TUIC endpoints for authorized nodes. Game candidates are excluded from ordinary automatic server selection.

Selected executable names route TCP and UDP to a separate Xray balancer before split-tunnel and geographic bypass. LAN and DNS interception retain their existing paths. Catalog entries avoid shared launchers and anti-cheat processes. Custom .exe selections are validated in the main process.

The balancer initially selects a blackhole. Authenticated loopback SOCKS listeners can only probe UDP DNS to two fixed public resolvers. Each route gets eight probes across two separate associations; selection weighs median latency, jitter and missing replies. No successful measurement means games stay blocked while ordinary VPN remains connected. These measurements are control-point RTTs, not match latency, packet-loss guarantees, or an optimization of the game publisher's network.

The default minimum-latency mode pins one route until reconnect. Selection penalizes missing replies, then compares measured RTT without a fixed protocol penalty; jitter breaks ties. Periodic probes update the recommendation without moving existing game flows. Manual preference applies on the next connection. Measurements still target control DNS servers, not the match server.

The optional Multipath mode duplicates selected IPv4 UDP traffic over two authenticated native-UDP Game transports. A loopback VLESS hop carries each game association to the Electron main process; it adds an opaque session/flow/sequence envelope and sends copies through the existing authenticated loopback SOCKS listeners. The node relay forwards the first arrival immediately, without waiting for earlier sequence numbers, using one UDP socket per flow. Replies are duplicated and deduplicated at the client. TCP and IPv6 retain the pinned primary Game route. The UI distinguishes node-echo RTT, DNS control-point history, and packet counters; neither is advertised as match ping or packets saved from proven loss.

Both paths must report the same relay instance before activation. An unavailable path does not change the surviving flow's source address or port. A relay restart requires reconnecting; this is not session migration across server restarts. If no compatible pair is found, game IPv4 UDP stays blocked while ordinary VPN continues. Disabling Multipath and reconnecting restores the direct single-tunnel Game route. At present, two transports to the same node do not provide independent geographic routes, and duplication consumes additional traffic and can increase average latency. Minimum-latency mode remains the default.

## Relay deployment

Bundle `tools/game-relay.ts` with the existing esbuild dependency for Node 22 or newer. The service listens **only on 127.0.0.1:37079**, must run without privileges, and must never be published as an unauthenticated public UDP proxy. Only authenticated Game inbounds may route that exact UDP destination to a dedicated Freedom outbound. On current Xray, the outbound additionally requires `finalRules` allowing UDP `127.0.0.1/32`, port `37079`, followed by a block rule; a routing exception alone does not override the built-in private-address protection. Keep all other private-address blocks unchanged.

The relay rejects non-loopback sources, private/reserved/non-IPv4 destinations, malformed frames, and unsolicited data before the handshake. Opaque random session and flow ids isolate associations; each session is limited to two paths and 32 flows, with 128 sessions and 1024 flows globally, rate/byte budgeting, and 60-second expiry. It does not log payloads, credentials or destinations. Authentication is inherited from the Game tunnels, not from the opaque session id. The test-only loopback-destination override is never enabled by the production entry point.

Game TUIC outbounds use a separate managed sing-box process with pinned TLS trust, per-session loopback credentials and physical-interface binding. Ordinary TUIC remains independent. No new credentials are stored in plaintext or exported to renderer snapshots by the Game state.

## Verification

Unit coverage includes entitlement rejection, endpoint/protocol identity, process-rule priority, failed-route blocking, route scoring, cancellation and route pinning. A bundled-core integration test verifies authenticated SOCKS UDP, actual balancer override, blocked unselected games, and separate ordinary/game UDP destinations using loopback mocks. It deliberately does not create a TUN on the development machine.

Multipath coverage uses real Xray SOCKS associations, two independently impaired local paths and a UDP echo destination. It verifies first-arrival deduplication in both directions and an unchanged source port after dropping the first path. Wire tests cover replay/reordering, malformed frames, and reserved-address restrictions. Production validation must additionally send actual UDP through both authenticated remote Game transports and check single-path failure. The client does not claim that this replaces a Windows TUN, anti-cheat or real-match acceptance test.

Windows acceptance still requires a real game: enable Game for VALORANT, connect a regular VPN node, verify the gameplay process exits through Game and a browser through the ordinary node, then check anti-cheat, a match, reconnect, disabled Game, expired/revoked access and network changes. CI/build success alone does not establish those outcomes.
