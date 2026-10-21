# Henad protocol, version 4

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
| Resume control channel | `resume_query`, `resume_state`, `resume_transfer`, then the transfer control exchange |
| Folder control channel | `folder_offer`, `folder_manifest`*, `folder_manifest_end`, `folder_decision`, `folder_status` |
| Folder data channel | `folder_data`, then per file: `file_start`, raw bytes, `file_end` |
| Transfer data channel | `transfer_data` frame, then raw file bytes |

Each message carries `protocol_version: u16` (currently `4`) and a `request_id: Uuid`. Peers
speaking any other version are rejected with `error_code: unsupported_version`.

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
2. The receiver validates the filename (one safe relative component) and then asks its user, unless
   that device was marked "always accept". A declined or unanswered offer (60 s) is answered with
   `transfer_decision { accepted: false, error: transfer_rejected }` and recorded as `declined` on
   both sides; no file or staging file is created.
3. Once accepted, the receiver resolves collisions with `name (1).ext`, creates
   `<name>.henad-part`, records the row, and answers `transfer_decision { accepted: true }`.
4. The sender opens the data channel, sends `transfer_data { transfer_id }`, and streams the bytes,
   hashing them as they go. Progress is emitted at most every 250 ms and persisted at most every 2 s.
5. The sender sends `transfer_complete { completed_bytes, blake3 }` on the control channel.
6. The receiver compares its own blake3. On success it `fsync`s and renames the staging file, then
   answers `transfer_status { error: null }`. On mismatch it keeps the `.henad-part` file, records
   `failed`, and answers `transfer_status { error: hash_mismatch }`.

`cancel_transfer` travels on the control channel, so it can never be confused with file bytes. Both
sides delete the staging file and record `cancelled`.

An interrupted transfer keeps `<name>.henad-part` on the receiver and a `failed` row on the sender.
Nothing is deleted automatically, so the partial data stays available for resume.

## Resume

The sender re-opens a control channel for the same `transfer_id`:

1. `resume_query { transfer_id }` — the receiver looks up its own row for that id, confirms the row
   belongs to this authenticated client key, and checks `<name>.henad-part` on disk.
2. `resume_state { transfer_id, ok, offset, total }` — `offset` is the current size of the staging
   file. `ok` is false when there is no partial file, the file is empty, or it is already complete.
3. If `ok` is false the sender stops and asks the user to send the file again; nothing is written.
4. Otherwise the sender offers `resume_transfer { transfer_id, completed_bytes }`, which the receiver
   only accepts when its staging file length equals `completed_bytes` exactly.
5. The data channel carries the remaining `total - offset` octets. Both sides hash the existing
   prefix (the receiver reads its staging file, the sender re-reads that range of the source) and
   then hash the appended bytes, so `transfer_complete` still carries a blake3 of the **whole** file.
6. Verification, rename, and `transfer_status` behave exactly as in a fresh transfer.

Because the offset is authenticated by the pinned client key and the end-to-end hash covers the
prefix, a resumed file cannot be assembled from bytes the sender did not agree to.

## Folders

A folder transfer is one session with one manifest and one data channel; files are sent strictly in
manifest order.

1. `folder_offer { session_id, root_name, file_count, total_bytes }`.
2. The manifest follows in `folder_manifest { session_id, start, entries }` frames of up to 256
   entries (each frame stays well below the 64 KiB cap), then `folder_manifest_end { manifest_hash }`.
   The hash is `blake3(count || for each entry: len(path) || path || u64be(size))`, so the receiver
   can prove the manifest it assembled is exactly the one the sender committed to.
3. The receiver rejects the session if `root_name` is not a single safe component, if the entry count
   or total size disagrees with the offer, if any path fails validation, or if the digest differs.
   It then asks its user (unless the device is marked "always accept") and answers `folder_decision`.
4. On acceptance the receiver creates `Downloads/Henad/<root_name>` (collision-renamed), never
   following a pre-existing symlink, and opens one data channel: `folder_data { session_id }`.
5. For each manifest index the sender sends `file_start { index }`, exactly `bytes` raw octets, and
   `file_end { index, blake3 }`. The receiver verifies each file individually and appends the bytes
   to the session's aggregate progress.
6. `folder_status { completed_files, error }` closes the session. Any mismatch aborts the session and
   removes the partially created directory.

Limits: at most 10,000 files per folder; symlinks and special files are skipped when the sender builds
the manifest; the consent prompt expires after 60 s like a single file.

## Error codes

`unsupported_version`, `unauthorized`, `key_changed`, `pairing_expired`, `pairing_rejected`,
`invalid_path`, `transfer_rejected`, `transfer_not_found`, `hash_mismatch`, `cancelled`, `internal`.

## Limits

- 8 concurrent inbound connections, 3 authentication attempts, 15 s handshake timeout.
- Pairing prompts expire after 120 s; incoming file offers after 60 s.
- Accept/decline is a local policy: "always accept" is stored per device in the trust store and is
  never negotiated on the wire.
- `session` channels only: no PTY, no shell, no `exec`, no port forwarding.
- Control frames are capped at 64 KiB and control buffers at 256 KiB.
