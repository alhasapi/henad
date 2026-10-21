import type { Device } from "../lib/ipc";

type Props = {
  devices: Device[];
  onPair: (device: Device) => void;
  onSend: (device: Device) => void;
  onSendFolder: (device: Device) => void;
  onUnpair: (device: Device) => void;
  busyDevice: string | null;
};

export function DeviceList({
  devices,
  onPair,
  onSend,
  onSendFolder,
  onUnpair,
  busyDevice,
}: Props) {
  if (devices.length === 0) {
    return (
      <div className="empty">
        No devices found yet. Make sure both devices are on the same network and
        Henad is open on both.
      </div>
    );
  }

  return (
    <div className="devices">
      {devices.map((device) => {
        const busy = busyDevice === device.id;
        return (
          <article className="device" key={device.id}>
            <div className="device-main">
              <strong>{device.name}</strong>
              <small>
                <i className={device.state} /> {device.state}
                {device.trusted ? " · paired" : " · not paired"} ·{" "}
                <code>{device.fingerprint || "unknown key"}</code>
              </small>
            </div>
            <div className="device-actions">
              {device.trusted ? (
                <>
                  <button disabled={!device.state.startsWith("online") || busy} onClick={() => onSend(device)}>
                    Send file
                  </button>
                  <button
                    className="secondary"
                    disabled={!device.state.startsWith("online") || busy}
                    onClick={() => onSendFolder(device)}
                  >
                    Send folder
                  </button>
                  <button className="secondary" disabled={busy} onClick={() => onUnpair(device)}>
                    Unpair
                  </button>
                </>
              ) : (
                <button disabled={!device.state.startsWith("online") || busy} onClick={() => onPair(device)}>
                  {busy ? "Pairing…" : "Pair"}
                </button>
              )}
            </div>
          </article>
        );
      })}
    </div>
  );
}
