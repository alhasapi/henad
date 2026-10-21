# Henad

Henad is a local-network desktop file-transfer app for Windows and Linux. This initial prototype provides the Tauri desktop shell, durable local records, pairing-code primitives, and a deliberately constrained single-file send queue.

## Run it

Prerequisites: current Rust, Node 20+, and the platform dependencies required by [Tauri 2](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run tauri dev
```

Use `npm run build` for the web UI check and `cd src-tauri && cargo test` for protocol/safety tests.

## Security boundary

The UI never treats discovery metadata as trust. A device must be paired before queuing a file; the pairing code uses a canonical, versioned transcript. The control protocol explicitly versions and identifies every pairing, offer, decision, progress, cancellation, and resume message. Remote paths are rejected unless they are safe relative paths, including Windows filename compatibility checks. The next implementation step is wiring mDNS discovery and the authenticated `russh` control/SFTP transport to these primitives; no shell or unrestricted SFTP endpoint is exposed by this scaffold.
