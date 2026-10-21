import { useCallback, useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { DeviceList } from "./components/DeviceList";
import { PairingDialog } from "./components/PairingDialog";
import { TransferList } from "./components/TransferList";
import { subscribe } from "./lib/events";
import {
  api,
  type AppStatus,
  type Device,
  type IdentityInfo,
  type PairingPrompt,
  type PairingResult,
  type Transfer,
  type TransferResult,
} from "./lib/ipc";

type ActivePrompt = { prompt: PairingPrompt; mode: "outgoing" | "incoming" };

export default function App() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const [identity, setIdentity] = useState<IdentityInfo | null>(null);
  const [status, setStatus] = useState<AppStatus | null>(null);
  const [prompt, setPrompt] = useState<ActivePrompt | null>(null);
  const [message, setMessage] = useState("Looking for nearby devices…");
  const [busyDevice, setBusyDevice] = useState<string | null>(null);

  useEffect(() => {
    let disposed = false;
    const unlisteners: Array<() => void> = [];

    const load = async () => {
      const [nextDevices, nextTransfers, nextIdentity, nextStatus] = await Promise.all([
        api.listDevices(),
        api.listTransfers(),
        api.localIdentity(),
        api.appStatus(),
      ]);
      if (disposed) return;
      setDevices(nextDevices);
      setTransfers(nextTransfers);
      setIdentity(nextIdentity);
      setStatus(nextStatus);
      if (nextDevices.length > 0) {
        setMessage(
          nextDevices.some((d) => d.state === "online")
            ? "Nearby devices are ready."
            : "No devices are online right now.",
        );
      }
    };

    const register = async () => {
      unlisteners.push(
        await subscribe<Device[]>("devices://changed", (payload) => {
          setDevices(payload);
        }),
        await subscribe<Transfer[]>("transfer://progress", (payload) => {
          setTransfers(payload);
        }),
        await subscribe<PairingPrompt>("pairing://code", (payload) => {
          setPrompt({ prompt: payload, mode: "outgoing" });
        }),
        await subscribe<PairingPrompt>("pairing://incoming", (payload) => {
          setPrompt({ prompt: payload, mode: "incoming" });
        }),
        await subscribe<PairingResult>("pairing://result", (payload) => {
          setPrompt(null);
          setBusyDevice(null);
          setMessage(
            payload.ok
              ? "Devices are paired. They will reconnect silently from now on."
              : payload.error ?? "Pairing did not complete.",
          );
        }),
        await subscribe<TransferResult>("transfer://finished", (payload) => {
          setMessage(
            payload.state === "complete"
              ? `${payload.file_name} transferred.`
              : `${payload.file_name}: ${payload.error ?? payload.state}`,
          );
        }),
      );
    };

    load()
      .then(register)
      .catch((error) => setMessage(String(error)));

    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  const pair = useCallback(async (device: Device) => {
    setBusyDevice(device.id);
    setMessage(`Starting a pairing with ${device.name}…`);
    try {
      const started = await api.startPairing(device.id);
      setPrompt({ prompt: started, mode: "outgoing" });
    } catch (error) {
      setBusyDevice(null);
      setMessage(
        error === "the other device's identity changed since pairing"
          ? `${device.name} presented a different identity. Unpair it first if you trust the change.`
          : String(error),
      );
    }
  }, []);

  const confirm = useCallback(async () => {
    if (!prompt) return;
    const deviceId = prompt.prompt.device_id;
    setPrompt(null);
    try {
      await api.confirmPairing(deviceId, true);
      setMessage("Waiting for the other device to confirm…");
    } catch (error) {
      setBusyDevice(null);
      setMessage(String(error));
    }
  }, [prompt]);

  const cancel = useCallback(async () => {
    if (!prompt) return;
    const deviceId = prompt.prompt.device_id;
    setPrompt(null);
    setBusyDevice(null);
    await api.cancelPairing(deviceId).catch(() => undefined);
    setMessage("Pairing cancelled.");
  }, [prompt]);

  const send = useCallback(async (device: Device) => {
    const picked = await open({
      multiple: false,
      directory: false,
      title: `Send a file to ${device.name}`,
    });
    if (typeof picked !== "string") return;
    try {
      await api.sendFile(device.id, picked);
      setMessage(`Sending to ${device.name}…`);
    } catch (error) {
      setMessage(String(error));
    }
  }, []);

  const unpair = useCallback(async (device: Device) => {
    setBusyDevice(device.id);
    try {
      await api.unpair(device.id);
      setMessage(`${device.name} was unpaired.`);
    } catch (error) {
      setMessage(String(error));
    } finally {
      setBusyDevice(null);
    }
  }, []);

  const cancelTransfer = useCallback(async (transfer: Transfer) => {
    await api.cancelTransfer(transfer.id).catch((error) => setMessage(String(error)));
  }, []);

  return (
    <main>
      <header>
        <div>
          <h1>Henad</h1>
          <p>Private file sharing, on your local network.</p>
        </div>
        <span className="status">● Ready</span>
      </header>

      {status?.discovery_error ? (
        <p className="notice error">
          Discovery is unavailable: {status.discovery_error}. Paired devices can
          still connect when you start a transfer from the other machine.
        </p>
      ) : null}

      <p className="notice">{message}</p>

      <section>
        <h2>Nearby devices</h2>
        <DeviceList
          devices={devices}
          onPair={pair}
          onSend={send}
          onUnpair={unpair}
          busyDevice={busyDevice}
        />
      </section>

      <section>
        <h2>Transfers</h2>
        <TransferList transfers={transfers} onCancel={cancelTransfer} />
      </section>

      <footer className="identity">
        {identity ? (
          <>
            This device: <strong>{identity.name}</strong> · key{" "}
            <code>{identity.fingerprint}</code>
            {status ? ` · port ${status.port} · protocol v${status.protocol_version}` : null}
          </>
        ) : null}
      </footer>

      {prompt ? (
        <PairingDialog
          prompt={prompt.prompt}
          mode={prompt.mode}
          onConfirm={confirm}
          onCancel={cancel}
        />
      ) : null}
    </main>
  );
}
