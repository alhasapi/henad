# Henad protocol, version 2

Everything below runs inside an SSH session authenticated with ed25519 keys. There is no
plaintext side channel: even first-contact pairing happens over SSH, with the host key held as a
caveat until the human confirms the code.

## Identities

Each installation generates two keypairs on first launch, stored as OpenSSH private keys in the
app data directory:

| File | Purpose |
| --- | --- |
| `identity_host` | SSH server host key; advertised as the device fingerprint |
| `identity_client` | Outbound authentication; pinned by the peer during pairing |

The advertised fingerprint is the first 8 bytes of `blake3(host public key)`, hex encoded.

## Framing

Control frames on a channel are `u32` big-endian length + UTF-8 JSON (`serde` tagged enum). A frame
may not exceed 64 KiB (65536 bytes). File payload bytes are never framed: after `transfer_offer`
is accepted, exactly `bytes` octets follow on the data channel, then framing resumes.

## Channels

| Channel | Messages |
| --- | --- |
| Pairing channel | `pair_offer`, `pair_accept`, `pair_confirm` |
| Transfer control channel | `transfer_offer`, `transfer_decision`, `cancel_transfer`, `transfer_complete`, `transfer_status` |
| Transfer data channel | `transfer_data` frame, then raw file bytes |

Each message carries `protocol_version: u16` (currently `2`) and a `request_id: Uuid`. Peers
speaking any other version are rejected with `error_code: unsupported_version`; `resume_transfer` is
defined but answered with `transfer_rejected` until the resume milestone.

## Pairing

1. The initiator connects, accepts the responder's host key on first use, and sends:

   ```
   pair_offer {
     protocol_version, request_id, initiator_id, initiator_name,
     host_public_key, client_public_key, nonce
   }
   ```

2. The responder checks that `client_public_key` equals the key that authenticated the SSH session,
   then answers with its own half of the transcript:

   ```
   pair_accept { protocol_version, request_id, host_public_key, client_public_key, nonce }
   ```

3. Both sides build the canonical transcript and display its code:

   ```
   transcript = version:u16be
              || len(id_a):u32be || id_a  || len(id_b):u32be || id_b
              || len(host_a):u32be || host_a || len(host_b):u32be || host_b
              || len(client_a):u32be || client_a || len(client_b):u32be || client_b
              || nonce_a (32 bytes) || nonce_b (32 bytes)
   code = be64(blake3(transcript)[0..8]) mod 100_000_000, zero padded to 8 digits
   ```

   The initiator also verifies that the responder's claimed host key equals the host key used by the
   SSH session, so a man in the middle cannot substitute keys without changing the code.

4. A human compares the codes on both screens. Each side then sends:

   ```
   pair_confirm {
     protocol_version, request_id, accepted,
     transcript_hash,        // blake3(transcript), 32 bytes
     signature               // sshsig PEM over transcript_hash, namespace "henad-pairing-v2"
   }
   ```

5. Trust is written only when the local user accepted **and** the peer's confirmation verified: same
   transcript hash, signature valid against the peer's client key, and the accepted flag set. The
   peer's host key, client key, and fingerprint are stored; later connections must present exactly
   that host key.

A peer that proposes a different host key for an already-trusted device is refused with
`key_changed`; the user has to unpair first.

## Transfer

1. The sender offers a file: `transfer_offer { transfer_id, name, bytes, blake3: null }`.
2. The receiver validates the filename (one safe relative component), resolves collisions with
   `name (1).ext`, creates `<name>.henad-part`, records the row, and accepts.
3. The sender opens the data channel, sends `transfer_data { transfer_id }`, and streams the bytes,
   hashing them as they go. Progress is emitted at most every 250 ms and persisted at most every 2 s.
4. The sender sends `transfer_complete { completed_bytes, blake3 }` on the control channel.
5. The receiver compares its own blake3. On success it `fsync`s and renames the staging file, then
   answers `transfer_status { error: null }`. On mismatch it keeps the `.henad-part` file, records
   `failed`, and answers `transfer_status { error: hash_mismatch }`.

`cancel_transfer` travels on the control channel, so it can never be confused with file bytes. Both
sides delete the staging file and record `cancelled`.

## Error codes

`unsupported_version`, `unauthorized`, `key_changed`, `pairing_expired`, `pairing_rejected`,
`invalid_path`, `transfer_rejected`, `transfer_not_found`, `hash_mismatch`, `cancelled`, `internal`.

## Limits

- 8 concurrent inbound connections, 3 authentication attempts, 15 s handshake timeout.
- Pairing prompts expire after 120 s.
- `session` channels only: no PTY, no shell, no `exec`, no port forwarding.
- Control frames are capped at 64 KiB and control buffers at 256 KiB.
