# Windows Client Architecture

## Repository boundary

This repository is independent from the Android source tree. It consumes the same versioned Mobile API and VPN profile contract but does not import or modify Android files.

## Trust boundaries

1. The sandboxed renderer has no Node.js, filesystem, process, or network access.
2. A narrow typed preload bridge exposes only application actions.
3. The main process owns the RSA device identity, API token, decrypted profile, and Xray process.
4. Sensitive persisted values are encrypted with Electron `safeStorage`, backed by Windows DPAPI.
5. The Mobile API independently validates every canonical request signature and subscription entitlement.
6. Xray receives validated configuration through a one-way standard-input pipe; decrypted runtime configuration is not persisted to disk.

## VPN lifecycle

1. User authorizes the Windows device through Levik Account in the system browser.
2. The client polls the short-lived challenge and stores the resulting access token with DPAPI.
3. The client requests an RSA-OAEP/AES-GCM encrypted tunnel profile.
4. The profile is decrypted locally, validated, and converted into selectable Xray outbounds.
5. Xray creates a Windows TUN adapter through Wintun and applies two half-default routes per IP family. Their longer prefixes take precedence over physical-adapter default routes, so TCP and UDP traffic from games and other non-proxy-aware applications enters the tunnel.
6. When Kill Switch is enabled, boot-scoped Windows Filtering Platform rules are installed before Xray starts and remain active across process failure and bounded exponential reconnection. Windows removes them during shutdown or reboot even if the application could not clean up.
7. Intentional disconnect or application shutdown removes the WFP rules and stops the TUN process.
8. Resume and unlock events probe the local Xray API and recreate an unresponsive tunnel.

## Windows integration

- Server selection uses bounded parallel TCP/UDP endpoint probes and prefers the lowest measured non-Russian latency.
- Process split rules store exact Windows executable names including `.exe`; arbitrary executables can be selected through the native file dialog.
- Process bypass is the first routing rule, with `network: "tcp,udp"`, `outboundTag: "direct"` and `ruleTag: "process-bypass"`. It takes precedence over LAN, domain and general proxy policies. The `only` process rule also explicitly covers TCP and UDP.
- Before each Xray start, the client reads Windows ActiveStore default routes and selects an active hardware adapter by combined route and interface metric (IPv4 first, IPv6 as a fallback). It sets TUN `autoOutboundsInterface` to that adapter name and explicitly sets `direct.streamSettings.sockopt.interface`. This covers outbound TCP/UDP and local DNS sockets without pinning a DHCP address with `sendThrough`. Missing physical default routes stop startup with an actionable error. Reconnect after changing the primary adapter; separate adapters for IPv4 and IPv6 are not selected independently.
- SMHNR protection is applied before Xray starts and the previous registry policy is restored when the tunnel stops cleanly.
- Kill Switch permits recovery traffic only from the application and Xray until the protected TUN interface is available; existing Windows Firewall policy remains in effect.
- An encrypted local token keeps the application in offline session mode during temporary API or network outages; only a definitive unauthorized API response returns the user to login.
- The tray icon, tooltip, and actions follow the live connection state. Window-close behavior is user-configurable.
- `electron-updater` consumes `latest.yml` and the matching installer from the latest public GitHub Release.

## Packaging

Electron-builder creates an NSIS installer for Windows x64. Every successful `main` build is published as a GitHub Release. Production distribution requires Authenticode signing; CI accepts the certificate only through `WINDOWS_CSC_LINK` and `WINDOWS_CSC_KEY_PASSWORD` repository secrets.

## Temporary process bypass diagnostics

When bypass has at least one selected process, Xray uses `info` logging; other modes keep `warning`. The existing application log buffer receives the core output and retains at most 200 lines. Remove the conditional `info` level after investigating the voice-chat issue.

On Windows, reconnect VPN and restart VALORANT so that fresh TCP connections and UDP associations are routed. Confirm the startup line `Xray: outbound interface [Ethernet] (TCP/UDP, direct)` (or the actual Wi-Fi alias), then look for `Hit route rule: [process-bypass] so taking detour [direct] for [udp:...]`. TCP produces the same rule tag with `tcp:`. A rule hit proves that one of the selected processes matched; it does not identify which selected executable owns the socket. Correlate the source UDP port in the same Xray session with `Get-NetUDPEndpoint` and its `OwningProcess` when distinguishing VALORANT from Riot services. Process lookup failures appear as `Unables to find local process name` in this core version.

Use `Get-NetRoute -PolicyStore ActiveStore` and `Get-NetAdapter` to verify the selected adapter against the default route metrics. Capture the voice endpoint on both LevikVPN and that physical adapter: an outbound UDP packet and its reply on the physical adapter confirm actual egress, while repeated recapture without physical egress indicates a binding/routing problem. Also inspect `failed to apply socket options` and `[tun] falied to set interface` in the core log. No live Windows/Vivox packet capture is performed by the cross-platform unit tests.

The pinned Xray v26.7.28 already supports Windows UDP process lookup, including wildcard-bound UDP sockets; omitting `network` did not itself disable UDP. Its automatic Windows adapter selection scores names/addresses rather than default-route metrics, so the client now supplies the chosen hardware adapter explicitly. References: [TUN binding](https://xtls.github.io/en/config/inbounds/tun.html), [routing and ruleTag](https://xtls.github.io/en/config/routing.html), [pinned Windows adapter selection](https://github.com/XTLS/Xray-core/blob/v26.7.28/proxy/tun/tun_windows.go), [pinned Windows process lookup](https://github.com/XTLS/Xray-core/blob/v26.7.28/common/net/find_process_windows.go).
