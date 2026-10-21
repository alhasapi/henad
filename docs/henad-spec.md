# Henad — Project Spec

Oct 19, 2026 · @Moktar

Henad is a cross-platform, offline-first peer-to-peer file transfer app, named after the Proclean unity-principle.

## Overview and motivation

Henad is a cross-platform desktop app for moving files directly between two machines on a local network or a direct Ethernet link, with no internet connection, router, or server required. It targets non-technical users — friends, family, or small businesses — who need a simple, secure way to copy files offline, similar in spirit to AirDrop but cross-platform (Windows, Linux, and eventually Mac).

Existing tools like FileZilla and WinSCP already provide cross-platform SFTP transfer, but they assume the user already knows what SFTP is and can supply a server address and credentials. Henad's gap to fill is the onboarding: zero-configuration discovery of nearby machines and one-time, code-based pairing, so a non-technical user never types an IP address, configures SSH, or manages a password.

The standalone-app path was chosen over contributing auto-discovery to FileZilla, since FileZilla's core development (C++/wxWidgets, SVN + Trac-based contribution process) is slow-moving and not well suited to a quick, scoped feature addition.

## Architecture

| Layer | Choice | Why |
| --- | --- | --- |
| GUI framework | Tauri | Native cross-platform window with a web-based front end; one codebase for Windows, Linux, and macOS |
| File transfer protocol | SSH/SFTP | Mature, secure, well-understood protocol for authenticated file transfer |
| SSH implementation | `russh` (pure Rust) | Avoids linking against the C library `libssh2` (used by the alternative `ssh2` crate), which simplifies cross-compilation for all three target platforms |
| Device discovery | mDNS | Same local-network discovery protocol used by AirDrop and Chromecast; broadcasts presence with no manual IP entry |
| Authentication | SSH public-key auth | Each machine generates its own key pair automatically; trust is established once per device pair via the pairing flow below, then reused silently like a paired Bluetooth device |

The system is designed for local-network or direct-cable use only — no internet traversal, NAT handling, or relay servers are in scope, since offline operation is the core design constraint.

Build targets: separate native binaries for Windows (x64) and Linux (x64), built from the same Rust/Tauri codebase; macOS is a possible future target, not in v1 scope.

## Discovery and pairing model

1. On launch, the app broadcasts its presence over the local network via mDNS and listens for other instances, so nearby devices appear in a list by friendly name (hostname or a user-set name) with no IP address entry.
2. On first contact between two machines, each generates its own SSH key pair locally and automatically — no user action required.
3. A short numeric code is derived from a hash of both machines' public keys combined, unique to that specific pair of devices, and displayed on both screens.
4. The user visually confirms the code matches on both screens — this is the one human-in-the-loop step, confirming the two intended machines are the ones connecting, not an impersonator.
5. Once confirmed, each machine writes the other's public key to its own trusted-keys list (conceptually like SSH's `authorized_keys`), establishing permanent trust for that device pair.
6. All subsequent connections between the two machines authenticate silently via public-key auth — no password, no code, no re-pairing — matching the familiar feel of a previously paired Bluetooth device.

## Version 1 feature list

- **Discovery**: mDNS broadcast on launch; list of nearby devices by friendly name, no manual IP entry
- **Pairing**: one-time numeric-code confirmation on first contact between two machines, then permanent trust via SSH public-key auth
- **Transfer UI**: drag-and-drop file or folder transfer to a connected device, with a progress bar
- **Resume support**: interrupted transfers can resume rather than restart, important for large files over a direct link
- **Transfer history**: a log of what was sent, to whom, and when
- **Recently connected devices**: previously paired devices are remembered and ready to go without re-pairing
- **Cross-platform parity**: identical experience on Windows and Linux at launch, macOS planned, built once via Tauri

## Open questions / next steps

- [ ] Choose the exact mDNS crate/library for Rust and confirm it works identically across Windows and Linux network stacks
- [ ] Decide where trusted keys and transfer history are stored on disk per platform
- [ ] Design the actual pairing-code and transfer-progress screens (wireframes)
- [ ] Decide macOS support timing relative to the Windows/Linux v1 release
- [ ] Mobile support (Android/iOS) is a future phase, not v1 — Tauri has mobile targets, but discovery, permissions, and UI would need meaningfully different design work, not just a recompile
- [ ] Scope a minimal first build: discovery + pairing + basic drag-and-drop transfer, before adding resume support and history
