# Levik Game

Game is opt-in and visible only after the selected subscription's encrypted profile confirms Game Squad access. The bridge derives endpoint identity from squad inbound IDs and enabled hosts, not their display names. The profile service also identifies app-only TUIC endpoints for authorized nodes. Game candidates are excluded from ordinary automatic server selection.

Selected executable names route TCP and UDP to a separate Xray balancer before split-tunnel and geographic bypass. LAN and DNS interception retain their existing paths. Catalog entries avoid shared launchers and anti-cheat processes. Custom .exe selections are validated in the main process.

The balancer initially selects a blackhole. Authenticated loopback SOCKS listeners can only probe UDP DNS to two fixed public resolvers. Each route gets eight probes across two separate associations; selection weighs median latency, jitter and missing replies. No successful measurement means games stay blocked while ordinary VPN remains connected. These measurements are control-point RTTs, not match latency, packet-loss guarantees, or an optimization of the game publisher's network.

The active route stays pinned until reconnect. Periodic probes update the recommendation and report degradation without changing the address of an ongoing match. Manual route preference applies on the next connection. There is no packet duplication, bonding, multipath transport or seamless migration of an existing UDP association. A single Game node provides transport choices, not geographic diversity.

Game TUIC outbounds use a separate managed sing-box process with pinned TLS trust, per-session loopback credentials and physical-interface binding. Ordinary TUIC remains independent. No new credentials are stored in plaintext or exported to renderer snapshots by the Game state.

## Verification

Unit coverage includes entitlement rejection, endpoint/protocol identity, process-rule priority, failed-route blocking, route scoring, cancellation and route pinning. A bundled-core integration test verifies authenticated SOCKS UDP, actual balancer override, blocked unselected games, and separate ordinary/game UDP destinations using loopback mocks. It deliberately does not create a TUN on the development machine.

Windows acceptance still requires a real game: enable Game for VALORANT, connect a regular VPN node, verify the gameplay process exits through Game and a browser through the ordinary node, then check anti-cheat, a match, reconnect, disabled Game, expired/revoked access and network changes. CI/build success alone does not establish those outcomes.
