# Two-machine verification checklist

Automated coverage lives in `src-tauri/tests/` (loopback pairing, transfer, corruption, unpaired
rejection). This checklist covers the parts that need real hardware, two operating systems, and a
real network.

## Prerequisites

- Two machines on the same LAN (or a direct Ethernet link), no internet required.
- Henad built and running on both: `npm install && npm run tauri dev`.
- Both on the same protocol version (shown in the footer of the app window).

## Discovery

- [ ] Each machine lists the other by name within ~5 seconds, marked **online** and **not paired**.
- [ ] The advertised fingerprint matches the fingerprint shown on the other machine's footer.
- [ ] Turning off Wi-Fi/Ethernet on one machine removes it from the other's list within ~15 seconds.
- [ ] If mDNS is blocked (some corporate networks), the app shows the discovery warning banner and
      does not crash.

## Pairing

- [ ] Click **Pair** on machine A; machine B shows a pairing request with a code.
- [ ] The two codes are identical (compare all 8 digits).
- [ ] Confirm on both: both devices become **paired**, and no warning appears.
- [ ] Rejecting on either side leaves both devices unpaired and shows the reason.
- [ ] Letting the prompt expire (2 minutes) removes it and records no trust.
- [ ] Re-pairing an already-paired device is refused until it is unpaired.

## Transfers

- [ ] Send a small text file; the receiver shows an accept prompt naming the sender and file, and the
      file arrives in `Downloads/Henad` with identical content after accepting.
- [ ] Decline an offer: the sender reports that the receiver declined, nothing is written on either
      side, and the receiver's history shows `declined`.
- [ ] Tick "always accept files from this device", accept, then send a second file: it arrives with no
      prompt.
- [ ] Ignore an incoming offer: after 60 seconds the prompt disappears and the sender is told the
      offer expired.
- [ ] Send a 1 GB file; the progress bar advances, speed is plausible, and the received file's
      checksum matches (`sha256sum` / `certutil -hashfile`).
- [ ] Sending a second file with the same name produces `name (1).ext` rather than overwriting.
- [ ] Cancel mid-transfer: both machines show `cancelled` and no `.henad-part` file remains.
- [ ] Unplug the network mid-transfer: the sender shows `failed`, the receiver does not finalize the
      file, and no partial file is presented as complete.
- [ ] Restart both apps: the device is still listed as paired and a new transfer works without any
      code prompt.
- [ ] Interrupt a large transfer (unplug the network, then reconnect), press **Resume** on the sender:
      the transfer continues from the partial file and the received file's checksum matches.
- [ ] Resume after the receiver deleted the `.henad-part` file: the sender explains that the file must
      be sent again, and nothing is overwritten.
- [ ] Delete `identity_host` on one machine and try to transfer: the other machine refuses with a
      "key changed" error and requires an explicit unpair.

## Cross-platform

- [ ] Linux → Windows and Windows → Linux both work with the same steps.
- [ ] A filename containing characters invalid on Windows (`: * ? " < > |`) is rejected by the
      receiver instead of writing a broken path.
- [ ] No console window, crash dialog, or silent exit occurs on either platform.
