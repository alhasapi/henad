# Henad

[![CI](https://github.com/alhasapi/henad/actions/workflows/ci.yml/badge.svg)](https://github.com/alhasapi/henad/actions/workflows/ci.yml)

Henad is a local-network desktop file-transfer app for Windows and Linux: zero-configuration
discovery, a one-time numeric pairing code, and SSH-authenticated single-file transfers with live
progress. No internet connection, router, or account is required.

## Status

Milestone 1 is implemented end to end:

- **Discovery** — every instance advertises `_henad._tcp.local.` over mDNS and lists nearby devices by name.
- **Pairing** — first contact exchanges real ed25519 identities over SSH; both screens derive the same 8-digit code from both host keys, both client keys, and a nonce from each side. Confirming pins the peer's keys.
- **Transfer** — a single regular file is streamed over a dedicated SSH channel with blake3 verification on arrival, saved to `Downloads/Henad`, and shown with live progress and speed.
- **Folders** — a folder is sent as one session with a signed manifest (paths, sizes, digest), per-file verification, nested directories recreated under `Downloads/Henad`, and aggregate progress.
- **Drag and drop** — dropping files or folders on a device card sends them; files go through the single-file pipeline, folders through the manifest pipeline.
- **Resume** — an interrupted transfer keeps its partial file; "Resume" continues from the exact byte the receiver already has, and the final hash still covers the whole file.
- **Consent** — incoming files wait for an accept/decline prompt with an optional "always accept this device"; a declined offer is recorded on both sides.
- **Trust store and history** — SQLite at the platform data directory; paired devices reconnect silently and transfers survive restarts.

Deferred to later milestones: folder resume, transfer history filtering, and settings (friendly
name, destination folder). macOS binaries are built by the release workflow but are not yet
verified on Apple hardware.

## Download

Installers are attached to [releases](https://github.com/alhasapi/henad/releases):

| Platform | File | Notes |
| --- | --- | --- |
| Windows 10/11 | `Henad_<version>_x64-setup.exe`, `.msi` | Unsigned, so SmartScreen asks for confirmation: *More info → Run anyway*. |
| Linux | `.deb` (Debian/Ubuntu), `.AppImage` | `chmod +x` the AppImage and run it. |
| macOS | `.dmg` | Unsigned and un-notarized: right-click the app → *Open* the first time. |

Shipping a version means pushing a `v*` tag; the [release workflow](.github/workflows/release.yml)
builds every platform and attaches the files to the GitHub release. It can also be started from the
Actions tab with a tag name to produce a draft release first.

## Run it

Prerequisites: current Rust, Node 20+, and the platform dependencies required by
[Tauri 2](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run tauri dev
```

## Checks

`scripts/check.sh` is the local CI: frontend typecheck and build, `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and all Rust tests including the loopback
integration tests.

```bash
./scripts/check.sh
```

CI is local: nothing runs on push. The [`CI` workflow](.github/workflows/ci.yml) is manual-only —
start it from the Actions tab when you want the same checks on a Linux runner, the tests on a
Windows runner, and `deb`/AppImage bundles uploaded as artifacts.

## How it works

| Layer | Choice |
| --- | --- |
| Shell | Tauri 2 (Rust backend, React front end) |
| Discovery | `mdns-sd`, advertising `_henad._tcp.local.` with the SSH port in the SRV record |
| Transport | `russh` (pure Rust SSH), ed25519 host and client keys generated on first launch |
| Pairing | SSH with trust-on-first-use host key + a 8-digit code derived from a canonical transcript |
| Transfer | Dedicated SSH `session` channels; length-prefixed JSON control frames plus a raw byte stream; resumable by offset |
| Integrity | blake3 of the whole file, compared by the receiver; failures never finalize the file |
| Storage | SQLite (`user_version` 3) in the platform data dir; keys in `identity_host` / `identity_client` |

See [`docs/protocol.md`](docs/protocol.md) for the wire format and [`docs/verification.md`](docs/verification.md)
for the two-machine acceptance checklist.

App icons live in `src-tauri/icons/` and are regenerated from `icon-1024.png` with
`npm run tauri icon src-tauri/icons/icon-1024.png`.

## Security boundary

The UI never treats discovery metadata as trust:

- Discovery TXT records are hints. A peer's advertised fingerprint must match the host key it presents, and once paired the host key must match the pinned key exactly — otherwise the transfer is refused with a "key changed" error.
- A device must be paired before it can send a file; the receiving side checks the authenticated SSH client key against its trust store, not the claimed device name.
- Pairing signatures are `sshsig` signatures over the transcript hash in a dedicated namespace, verified against the exact client key that was bound into the code.
- Remote filenames must be a single safe relative component: no traversal, no absolute paths, no Windows-incompatible characters or trailing dots/spaces.
- The SSH server accepts only `session` channels, never a shell or `exec`, caps concurrent connections (8 overall, 4 per address) so one host cannot exhaust it, and limits control frames to 64 KiB. Private keys are never logged.
- Sources are never followed through links: a symlinked file or folder is refused with an explanation, and symlinks inside a sent folder are skipped.

## License

MIT — see [`LICENSE`](LICENSE).
