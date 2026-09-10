# Third-Party Notices

Levik VPN for Windows bundles the following runtime components:

## Xray-core

- Project: https://github.com/XTLS/Xray-core
- Version: `v26.7.28+levik-process-v1` (Windows executable-name matching patch)
- License: Mozilla Public License 2.0
- Integrity: upstream runtime assets are verified against the official release `.dgst`; the core is built from commit `5ca6f4b7d4dc20a881d4330e498892697627ec0c`, with a pinned source archive SHA-256 and the checked-in `scripts/patches/xray-windows-process-names.patch`.

The upstream license is included in the installed `resources/xray` directory.
Modified MPL-covered source files, the patch and its upstream source manifest are included in `resources/xray/levik-source`.

## Wintun

- Project: https://www.wintun.net/
- License: included in `resources/xray/LICENSE-Wintun`

Wintun is distributed as part of the official Xray Windows release archive.

## Electron

- Project: https://www.electronjs.org/
- License: MIT
