# Desktop architecture

Owner decision: 2026-11-05.

- Keep all future desktop features and updates on Electron, TypeScript and Node.js.
- The Rust/Slint migration is cancelled. Do not add or restore Rust, Cargo, `levik-core` or Node-API migration dependencies without a new explicit owner instruction.
- Preserve the Electron main/preload/renderer security boundary and existing IPC patterns.
- Preserve the existing Xray/sing-box binaries and platform helpers; this decision does not replace those components.
- Use this package's npm scripts and lockfile for checks and builds.
- Releases stay drafts. Do not publish a release or send OTA updates without explicit owner authorization.
