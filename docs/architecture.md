# Windows Client Architecture

## Repository boundary

This repository is independent from the Android source tree. It consumes the same versioned Mobile API and VPN profile contract but does not import or modify Android files.

## Trust boundaries

1. The sandboxed renderer has no Node.js, filesystem, process, or network access.
2. A narrow typed preload bridge exposes only application actions.
3. The main process owns the RSA device identity, API token, decrypted profile, and Xray process.
4. Sensitive persisted values are encrypted with Electron `safeStorage`, backed by Windows DPAPI.
5. The Mobile API independently validates every canonical request signature and subscription entitlement.
6. Xray receives a temporary configuration file only while the tunnel is running.

## VPN lifecycle

1. User authorizes the Windows device through Levik Account in the system browser.
2. The client polls the short-lived challenge and stores the resulting access token with DPAPI.
3. The client requests an RSA-OAEP/AES-GCM encrypted tunnel profile.
4. The profile is decrypted locally, validated, and converted into selectable Xray outbounds.
5. Xray creates a Windows TUN adapter through Wintun and applies two half-default routes per IP family. Their longer prefixes take precedence over physical-adapter default routes, so TCP and UDP traffic from games and other non-proxy-aware applications enters the tunnel.
6. Unexpected process termination triggers bounded exponential reconnection.
7. Intentional disconnect or application shutdown removes the temporary profile and TUN process.
8. Resume and unlock events probe the local Xray API and recreate an unresponsive tunnel.

## Windows integration

- Server selection uses bounded parallel TCP/UDP endpoint probes and prefers the lowest measured non-Russian latency.
- Process split rules store exact Windows executable names including `.exe`; arbitrary executables can be selected through the native file dialog.
- SMHNR protection is applied before Xray starts and the previous registry policy is restored when the tunnel stops cleanly.
- The tray icon, tooltip, and actions follow the live connection state. Window-close behavior is user-configurable.
- `electron-updater` consumes `latest.yml` and the matching installer from the latest public GitHub Release.

## Packaging

Electron-builder creates an NSIS installer for Windows x64. Every successful `main` build is published as a GitHub Release. Production distribution requires Authenticode signing; CI accepts the certificate only through `WINDOWS_CSC_LINK` and `WINDOWS_CSC_KEY_PASSWORD` repository secrets.
